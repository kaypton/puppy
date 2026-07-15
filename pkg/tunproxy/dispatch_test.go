package tunproxy

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func newBlockingBackend() *blockingBackend {
	return &blockingBackend{started: make(chan struct{}), extra: make(chan struct{}, 1)}
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
		ctx, ns, backend, nil, 0, time.Second,
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
