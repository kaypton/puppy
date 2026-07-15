package tunproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/puppy/pkg/adapter/direct"
	"github.com/puppy/pkg/common"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

type blockingBackend struct {
	calls   atomic.Int32
	started chan struct{}
	extra   chan struct{}
	once    sync.Once
}

type capabilityBackend struct {
	capabilities []common.Capability
}

func (b *capabilityBackend) Capabilities() []common.Capability { return b.capabilities }

func (b *capabilityBackend) Dial(context.Context, common.Target, common.Dialer) (io.ReadWriteCloser, error) {
	return nil, errors.New("not used")
}

func newBlockingBackend() *blockingBackend {
	return &blockingBackend{started: make(chan struct{}), extra: make(chan struct{}, 1)}
}

func (b *blockingBackend) Capabilities() []common.Capability {
	return []common.Capability{{Network: "udp", Protocol: common.ProtocolAny}}
}

func (b *blockingBackend) Dial(ctx context.Context, target common.Target, dialer common.Dialer) (io.ReadWriteCloser, error) {
	if b.calls.Add(1) == 1 {
		b.once.Do(func() { close(b.started) })
	} else {
		select {
		case b.extra <- struct{}{}:
		default:
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDispatcher_HandleUDPRegistersFlowBeforeBackendDial(t *testing.T) {
	device := newEAGAINDevice()
	ns, err := newNetworkStack(device, device.MTU())
	if err != nil {
		t.Fatalf("newNetworkStack: %v", err)
	}
	defer ns.stop()
	if err := ns.addAddress("10.0.0.1/24"); err != nil {
		t.Fatalf("addAddress: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	backend := newBlockingBackend()
	dispatcher := newDispatcher(
		ctx, ns, []common.Backend{backend}, commonFallback(), nil, 0, time.Second, time.Second, defaultProtocolDetectMaxBytes,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	ns.handler = dispatcher

	injectIPv4UDP(t, ns, []byte("first"))
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("backend Dial was not called")
	}

	// The first Dial is deliberately blocked. A second datagram must go to the
	// registered endpoint instead of starting another forwarded UDP session.
	injectIPv4UDP(t, ns, []byte("second"))
	select {
	case <-backend.extra:
		t.Fatal("second datagram started a duplicate backend Dial")
	case <-time.After(50 * time.Millisecond):
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("backend Dial calls = %d, want 1", got)
	}

	cancel()
	done := make(chan struct{})
	go func() {
		dispatcher.wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop after cancellation")
	}
}

func TestDispatcher_SelectBackendByPriorityAndProtocol(t *testing.T) {
	httpBackend := &capabilityBackend{capabilities: []common.Capability{{Network: "tcp", Protocol: common.ProtocolHTTP}}}
	tlsBackend := &capabilityBackend{capabilities: []common.Capability{{Network: "tcp", Protocol: common.ProtocolTLS}}}
	wildcardBackend := &capabilityBackend{capabilities: []common.Capability{{Network: "tcp", Protocol: common.ProtocolAny}}}
	fallback := direct.NewBackend()
	dispatcher := &dispatcher{
		backends: []common.Backend{httpBackend, tlsBackend, wildcardBackend},
		fallback: fallback,
	}

	tests := []struct {
		name      string
		target    common.Target
		want      common.Backend
		wantIndex int
		fallback  bool
	}{
		{"HTTP uses first", common.Target{Network: "tcp", Protocol: common.ProtocolHTTP}, httpBackend, 0, false},
		{"TLS uses second", common.Target{Network: "tcp", Protocol: common.ProtocolTLS}, tlsBackend, 1, false},
		{"unknown uses wildcard", common.Target{Network: "tcp", Protocol: common.ProtocolUnknown}, wildcardBackend, 2, false},
		{"UDP uses fallback", common.Target{Network: "udp", Protocol: common.ProtocolUnknown}, fallback, -1, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, index, usedFallback := dispatcher.selectBackend(test.target)
			if got != test.want || index != test.wantIndex || usedFallback != test.fallback {
				t.Fatalf("selectBackend() = (%T, %d, %t), want (%T, %d, %t)", got, index, usedFallback, test.want, test.wantIndex, test.fallback)
			}
		})
	}

	got, index, usedFallback := dispatcher.selectTCPBackend(common.Target{Network: "tcp"})
	if got != httpBackend || index != 0 || usedFallback {
		t.Fatalf("selectTCPBackend() = (%T, %d, %t), want first restricted backend", got, index, usedFallback)
	}
}

func commonFallback() common.Backend { return direct.NewBackend() }

func injectIPv4UDP(t *testing.T, ns *networkStack, payload []byte) {
	t.Helper()
	src := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	dst := tcpip.AddrFrom4([4]byte{203, 0, 113, 9})
	data := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(data)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(data)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	udp := header.UDP(data[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: 49152,
		DstPort: 53,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(data[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	ns.linkEP.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

var _ common.Backend = (*blockingBackend)(nil)
