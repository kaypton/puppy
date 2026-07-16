package tunproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
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

type dialBackend struct {
	capabilities []common.Capability
	conn         io.ReadWriteCloser
	targets      chan common.Target
}

func (b *capabilityBackend) Capabilities() []common.Capability { return b.capabilities }

func (b *capabilityBackend) Dial(context.Context, common.Target, common.Dialer) (io.ReadWriteCloser, error) {
	return nil, errors.New("not used")
}

func (b *dialBackend) Capabilities() []common.Capability { return b.capabilities }

func (b *dialBackend) Dial(_ context.Context, target common.Target, _ common.Dialer) (io.ReadWriteCloser, error) {
	b.targets <- target
	return b.conn, nil
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
		ctx,
		DispatcherConfiguration{
			NS:             ns,
			Backends:       []common.Backend{backend},
			Fallback:       commonFallback(),
			Dialer:         nil,
			ShimBuf:        0,
			UDPIdle:        time.Second,
			DetectTimeout:  time.Second,
			DetectMaxBytes: defaultProtocolDetectMaxBytes,
			Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			Name:           "",
			Stats:          nil,
			ConnReg:        nil,
			Bus:            nil,
		},
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

func TestDispatcher_RedirectDNS(t *testing.T) {
	dns := common.Target{Network: "tcp", Protocol: common.ProtocolDNS, Host: "1.1.1.1", Port: 5353}
	dispatcher := &dispatcher{dns: &dns}

	redirected, ok := dispatcher.redirectDNS(common.Target{Network: "udp", Host: "192.0.2.53", Port: 53})
	if !ok || redirected != dns {
		t.Fatalf("redirectDNS() = (%#v, %t), want (%#v, true)", redirected, ok, dns)
	}

	original := common.Target{Network: "udp", Host: "192.0.2.53", Port: 5353}
	redirected, ok = dispatcher.redirectDNS(original)
	if ok || redirected != original {
		t.Fatalf("non-DNS redirectDNS() = (%#v, %t), want (%#v, false)", redirected, ok, original)
	}

	dispatcher.dns = nil
	original.Port = 53
	redirected, ok = dispatcher.redirectDNS(original)
	if ok || redirected != original {
		t.Fatalf("disabled redirectDNS() = (%#v, %t), want (%#v, false)", redirected, ok, original)
	}
}

func TestDispatcher_ServeUDPDNSFramesAndRoutesTCP(t *testing.T) {
	frontend, client := net.Pipe()
	upstream, resolver := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = resolver.Close()
	})

	dnsTarget := common.Target{Network: "tcp", Protocol: common.ProtocolDNS, Host: "1.1.1.1", Port: 53}
	backend := &dialBackend{
		capabilities: []common.Capability{{Network: "tcp", Protocol: common.ProtocolDNS}},
		conn:         upstream,
		targets:      make(chan common.Target, 1),
	}
	dispatcher := &dispatcher{
		backends: []common.Backend{backend},
		fallback: commonFallback(),
		ctx:      context.Background(),
		udpIdle:  time.Second,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan struct{})
	go func() {
		dispatcher.serveUDPDNS(frontend, common.Target{Network: "udp", Host: "192.0.2.53", Port: 53}, dnsTarget)
		close(done)
	}()

	select {
	case got := <-backend.targets:
		if got != dnsTarget {
			t.Fatalf("backend target = %#v, want %#v", got, dnsTarget)
		}
	case <-time.After(time.Second):
		t.Fatal("backend was not dialed")
	}

	query := []byte{0x12, 0x34, 0x01, 0x00}
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(query)
		writeDone <- err
	}()
	framedQuery := make([]byte, len(query)+2)
	if _, err := io.ReadFull(resolver, framedQuery); err != nil {
		t.Fatalf("read framed query: %v", err)
	}
	if got := binary.BigEndian.Uint16(framedQuery[:2]); got != uint16(len(query)) || !bytes.Equal(framedQuery[2:], query) {
		t.Fatalf("framed query = %x", framedQuery)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write query: %v", err)
	}

	response := []byte{0x12, 0x34, 0x81, 0x80}
	framedResponse := make([]byte, len(response)+2)
	binary.BigEndian.PutUint16(framedResponse, uint16(len(response)))
	copy(framedResponse[2:], response)
	go func() { _, _ = resolver.Write(framedResponse) }()
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(client, gotResponse); err != nil {
		t.Fatalf("read UDP response: %v", err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("response = %x, want %x", gotResponse, response)
	}

	_ = client.Close()
	_ = resolver.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP DNS relay did not stop")
	}
}

func TestDispatcher_ResolveInterceptedDNSDatagram(t *testing.T) {
	upstream, resolver := net.Pipe()
	t.Cleanup(func() { _ = resolver.Close() })
	dnsTarget := common.Target{Network: "tcp", Protocol: common.ProtocolDNS, Host: "1.1.1.1", Port: 53}
	backend := &dialBackend{
		capabilities: []common.Capability{{Network: "tcp", Protocol: common.ProtocolDNS}},
		conn:         upstream,
		targets:      make(chan common.Target, 1),
	}
	dispatcher := &dispatcher{
		backends: []common.Backend{backend},
		fallback: commonFallback(),
		dns:      &dnsTarget,
		ctx:      context.Background(),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	query := []byte{0x12, 0x34, 0x01, 0x00}
	wantResponse := []byte{0x12, 0x34, 0x81, 0x80}
	resolverErr := make(chan error, 1)
	go func() {
		frame := make([]byte, len(query)+2)
		if _, err := io.ReadFull(resolver, frame); err != nil {
			resolverErr <- err
			return
		}
		if binary.BigEndian.Uint16(frame[:2]) != uint16(len(query)) || !bytes.Equal(frame[2:], query) {
			resolverErr <- errors.New("unexpected framed query")
			return
		}
		response := make([]byte, len(wantResponse)+2)
		binary.BigEndian.PutUint16(response, uint16(len(wantResponse)))
		copy(response[2:], wantResponse)
		_, err := resolver.Write(response)
		resolverErr <- err
	}()

	response, err := dispatcher.resolveInterceptedDNSDatagram(query)
	if err != nil {
		t.Fatalf("ResolveInterceptedDNSDatagram: %v", err)
	}
	if !bytes.Equal(response, wantResponse) {
		t.Fatalf("response = %x, want %x", response, wantResponse)
	}
	if err := <-resolverErr; err != nil {
		t.Fatalf("resolver: %v", err)
	}
	select {
	case target := <-backend.targets:
		if target != dnsTarget {
			t.Fatalf("target = %#v, want %#v", target, dnsTarget)
		}
	default:
		t.Fatal("backend target was not recorded")
	}

	if _, err := dispatcher.resolveInterceptedDNSDatagram(nil); err == nil || !strings.Contains(err.Error(), "empty UDP DNS") {
		t.Fatalf("empty query error = %v", err)
	}
}

type datagramReader struct {
	messages [][]byte
	index    int
}

func (r *datagramReader) Read(p []byte) (int, error) {
	if r.index == len(r.messages) {
		return 0, io.EOF
	}
	message := r.messages[r.index]
	r.index++
	return copy(p, message), nil
}

type datagramWriter struct {
	messages [][]byte
	short    bool
}

type limitedWriter struct {
	bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.Buffer.Write(p)
}

type closeRecorder struct {
	once   sync.Once
	closed chan struct{}
}

func newCloseRecorder() *closeRecorder {
	return &closeRecorder{closed: make(chan struct{})}
}

func (r *closeRecorder) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func (w *datagramWriter) Write(p []byte) (int, error) {
	message := append([]byte(nil), p...)
	w.messages = append(w.messages, message)
	if w.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestDNSStreamConversion(t *testing.T) {
	queries := [][]byte{{0x00, 0x01, 0x01}, {0x00, 0x02, 0x02, 0x03}}
	stream := &limitedWriter{max: 1}
	err := pipeUDPToDNSStream(stream, &datagramReader{messages: queries}, make(chan struct{}, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("pipeUDPToDNSStream error = %v, want EOF", err)
	}
	var wantStream bytes.Buffer
	for _, query := range queries {
		_ = binary.Write(&wantStream, binary.BigEndian, uint16(len(query)))
		_, _ = wantStream.Write(query)
	}
	if !bytes.Equal(stream.Bytes(), wantStream.Bytes()) {
		t.Fatalf("stream = %x, want %x", stream.Bytes(), wantStream.Bytes())
	}

	writer := &datagramWriter{}
	err = pipeDNSStreamToUDP(writer, oneByteReader{Reader: bytes.NewReader(stream.Bytes())}, make(chan struct{}, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("pipeDNSStreamToUDP error = %v, want EOF", err)
	}
	if len(writer.messages) != len(queries) {
		t.Fatalf("messages = %d, want %d", len(writer.messages), len(queries))
	}
	for i := range queries {
		if !bytes.Equal(writer.messages[i], queries[i]) {
			t.Fatalf("message %d = %x, want %x", i, writer.messages[i], queries[i])
		}
	}
}

func TestDispatcher_WatchUDPIdleClosesBothSides(t *testing.T) {
	tests := []struct {
		name    string
		idle    time.Duration
		trigger func(context.CancelFunc)
	}{
		{
			name: "idle timeout",
			idle: 10 * time.Millisecond,
			trigger: func(context.CancelFunc) {
				time.Sleep(20 * time.Millisecond)
			},
		},
		{
			name: "context cancellation",
			idle: time.Hour,
			trigger: func(cancel context.CancelFunc) {
				cancel()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			frontend := newCloseRecorder()
			upstream := newCloseRecorder()
			dispatcher := &dispatcher{ctx: ctx, udpIdle: test.idle}
			stop := make(chan struct{})
			go dispatcher.watchUDPIdle(frontend, upstream, make(chan struct{}), stop)

			test.trigger(cancel)
			for name, closed := range map[string]<-chan struct{}{"frontend": frontend.closed, "upstream": upstream.closed} {
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatalf("%s was not closed", name)
				}
			}
			close(stop)
		})
	}
}

func TestDNSStreamConversionRejectsMalformedFrames(t *testing.T) {
	t.Run("empty UDP message", func(t *testing.T) {
		err := pipeUDPToDNSStream(io.Discard, &datagramReader{messages: [][]byte{{}}}, make(chan struct{}, 1))
		if err == nil || !strings.Contains(err.Error(), "empty UDP") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("empty TCP frame", func(t *testing.T) {
		err := pipeDNSStreamToUDP(io.Discard, bytes.NewReader([]byte{0, 0}), make(chan struct{}, 1))
		if err == nil || !strings.Contains(err.Error(), "empty TCP") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("truncated TCP frame", func(t *testing.T) {
		err := pipeDNSStreamToUDP(io.Discard, bytes.NewReader([]byte{0, 3, 1}), make(chan struct{}, 1))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error = %v, want unexpected EOF", err)
		}
	})
	t.Run("short UDP write", func(t *testing.T) {
		err := pipeDNSStreamToUDP(&datagramWriter{short: true}, bytes.NewReader([]byte{0, 1, 1}), make(chan struct{}, 1))
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("error = %v, want short write", err)
		}
	})
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
