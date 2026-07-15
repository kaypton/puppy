package tunproxy

import (
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

type eagainDevice struct {
	reads  atomic.Int32
	closed chan struct{}
	once   sync.Once
}

func TestNetworkStack_AllowsForwardedEndpointAddress(t *testing.T) {
	device := newEAGAINDevice()
	ns, err := newNetworkStack(device, device.MTU())
	if err != nil {
		t.Fatalf("newNetworkStack: %v", err)
	}
	defer ns.stop()
	if err := ns.addAddress("10.0.0.1/24"); err != nil {
		t.Fatalf("addAddress: %v", err)
	}

	var queue waiter.Queue
	ep, tcpErr := ns.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &queue)
	if tcpErr != nil {
		t.Fatalf("NewEndpoint: %s", tcpErr)
	}
	defer ep.Close()

	originalDestination := tcpip.AddrFrom4([4]byte{203, 0, 113, 9})
	if tcpErr := ep.Bind(tcpip.FullAddress{
		NIC: nicID, Addr: originalDestination, Port: 443,
	}); tcpErr != nil {
		t.Fatalf("Bind intercepted destination: %s", tcpErr)
	}
	hostTUNAddress := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	if tcpErr := ep.Connect(tcpip.FullAddress{
		NIC: nicID, Addr: hostTUNAddress, Port: 49152,
	}); tcpErr != nil {
		t.Fatalf("Connect intercepted client: %s", tcpErr)
	}

	tcpEP, tcpErr := ns.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &queue)
	if tcpErr != nil {
		t.Fatalf("New TCP endpoint: %s", tcpErr)
	}
	defer tcpEP.Close()
	if tcpErr := tcpEP.Bind(tcpip.FullAddress{
		NIC: nicID, Addr: originalDestination, Port: 8443,
	}); tcpErr != nil {
		t.Fatalf("Bind intercepted TCP destination: %s", tcpErr)
	}
	if tcpErr := tcpEP.Connect(tcpip.FullAddress{
		NIC: nicID, Addr: hostTUNAddress, Port: 49153,
	}); tcpErr != nil {
		if _, ok := tcpErr.(*tcpip.ErrConnectStarted); !ok {
			t.Fatalf("Connect intercepted TCP client: %s", tcpErr)
		}
	}
}

func newEAGAINDevice() *eagainDevice {
	return &eagainDevice{closed: make(chan struct{})}
}

func (d *eagainDevice) Name() string { return "test-tun" }
func (d *eagainDevice) MTU() uint32  { return 1500 }

func (d *eagainDevice) Read([]byte) (int, error) {
	if d.reads.Add(1) == 1 {
		return 0, syscall.EAGAIN
	}
	<-d.closed
	return 0, ErrDeviceClosed
}

func (d *eagainDevice) Write(p []byte) (int, error) { return len(p), nil }

func (d *eagainDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func TestNetworkStack_EAGAINIsNotFatal(t *testing.T) {
	device := newEAGAINDevice()
	ns, err := newNetworkStack(device, device.MTU())
	if err != nil {
		t.Fatalf("newNetworkStack: %v", err)
	}
	errs := ns.startPumps()
	defer ns.stop()

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for device.reads.Load() < 2 {
		select {
		case err := <-errs:
			t.Fatalf("EAGAIN reported as fatal: %v", err)
		case <-deadline.C:
			t.Fatalf("Read calls = %d, want retry after EAGAIN", device.reads.Load())
		case <-time.After(time.Millisecond):
		}
	}
}

var _ Device = (*eagainDevice)(nil)
