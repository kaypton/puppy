package tunproxy

import (
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type eagainDevice struct {
	reads  atomic.Int32
	closed chan struct{}
	once   sync.Once
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
