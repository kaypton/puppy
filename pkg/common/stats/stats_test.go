package stats

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/puppy/pkg/common"
)

func withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func TestStatsRegistry_Counters(t *testing.T) {
	r := NewStatsRegistry()

	r.IncTotal()
	r.IncTotal()
	r.IncTotal()
	r.IncActive()
	r.IncActive()
	r.DecActive()
	r.IncDialSuccess()
	r.IncDialFailure()
	r.IncDialFailure()
	r.AddBytesIn(100)
	r.AddBytesIn(50)
	r.AddBytesOut(200)

	snap := r.Snapshot()
	if snap.TotalConnections != 3 {
		t.Errorf("TotalConnections = %d, want 3", snap.TotalConnections)
	}
	if snap.ActiveConnections != 1 {
		t.Errorf("ActiveConnections = %d, want 1", snap.ActiveConnections)
	}
	if snap.DialSuccesses != 1 {
		t.Errorf("DialSuccesses = %d, want 1", snap.DialSuccesses)
	}
	if snap.DialFailures != 2 {
		t.Errorf("DialFailures = %d, want 2", snap.DialFailures)
	}
	if snap.BytesIn != 150 {
		t.Errorf("BytesIn = %d, want 150", snap.BytesIn)
	}
	if snap.BytesOut != 200 {
		t.Errorf("BytesOut = %d, want 200", snap.BytesOut)
	}
	if snap.StartedAt.IsZero() {
		t.Error("StartedAt should not be zero")
	}
}

func TestStatsRegistry_NilSafe(t *testing.T) {
	var r *StatsRegistry
	r.IncTotal()
	r.IncActive()
	r.DecActive()
	r.IncDialSuccess()
	r.IncDialFailure()
	r.AddBytesIn(10)
	r.AddBytesOut(10)
	snap := r.Snapshot()
	if snap != (StatsSnapshot{}) {
		t.Errorf("nil registry snapshot should be zero, got %+v", snap)
	}
}

func TestStatsRegistry_Concurrent(t *testing.T) {
	r := NewStatsRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.IncTotal()
			r.IncActive()
			r.AddBytesIn(10)
			r.AddBytesOut(20)
			r.DecActive()
		}()
	}
	wg.Wait()
	snap := r.Snapshot()
	if snap.TotalConnections != 100 {
		t.Errorf("TotalConnections = %d, want 100", snap.TotalConnections)
	}
	if snap.ActiveConnections != 0 {
		t.Errorf("ActiveConnections = %d, want 0", snap.ActiveConnections)
	}
	if snap.BytesIn != 1000 {
		t.Errorf("BytesIn = %d, want 1000", snap.BytesIn)
	}
	if snap.BytesOut != 2000 {
		t.Errorf("BytesOut = %d, want 2000", snap.BytesOut)
	}
}

func TestConnectionRegistry_RegisterRemove(t *testing.T) {
	r := NewConnectionRegistry()
	info1 := &ConnectionInfo{ID: "conn-1", Frontend: "fe1", RemoteAddr: "1.2.3.4:1234"}
	info2 := &ConnectionInfo{ID: "conn-2", Frontend: "fe2", RemoteAddr: "5.6.7.8:5678"}

	r.Register(info1)
	r.Register(info2)

	if r.Count() != 2 {
		t.Errorf("Count = %d, want 2", r.Count())
	}
	if got := r.Get("conn-1"); got != info1 {
		t.Errorf("Get(conn-1) returned %v, want %v", got, info1)
	}
	if got := r.Get("missing"); got != nil {
		t.Errorf("Get(missing) returned %v, want nil", got)
	}

	r.Remove("conn-1")
	if r.Count() != 1 {
		t.Errorf("Count after remove = %d, want 1", r.Count())
	}
	if r.Get("conn-1") != nil {
		t.Error("conn-1 should have been removed")
	}
	if info1.ClosedAt.IsZero() {
		t.Error("ClosedAt should be set after Remove")
	}
}

func TestConnectionRegistry_Active(t *testing.T) {
	r := NewConnectionRegistry()
	r.Register(&ConnectionInfo{ID: "a", Frontend: "fe1"})
	r.Register(&ConnectionInfo{ID: "b", Frontend: "fe1"})
	r.Register(&ConnectionInfo{ID: "c", Frontend: "fe2"})

	all := r.Active()
	if len(all) != 3 {
		t.Errorf("Active() len = %d, want 3", len(all))
	}

	fe1 := r.ActiveByFrontend("fe1")
	if len(fe1) != 2 {
		t.Errorf("ActiveByFrontend(fe1) len = %d, want 2", len(fe1))
	}
	fe2 := r.ActiveByFrontend("fe2")
	if len(fe2) != 1 {
		t.Errorf("ActiveByFrontend(fe2) len = %d, want 1", len(fe2))
	}
	none := r.ActiveByFrontend("nope")
	if len(none) != 0 {
		t.Errorf("ActiveByFrontend(nope) len = %d, want 0", len(none))
	}
}

func TestConnectionRegistry_NilSafe(t *testing.T) {
	var r *ConnectionRegistry
	if r.Register(nil) != nil {
		t.Error("nil registry Register should return nil")
	}
	r.Remove("x")
	if r.Get("x") != nil {
		t.Error("nil registry Get should return nil")
	}
	if r.Active() != nil {
		t.Error("nil registry Active should return nil")
	}
	if r.ActiveByFrontend("x") != nil {
		t.Error("nil registry ActiveByFrontend should return nil")
	}
	if r.Count() != 0 {
		t.Error("nil registry Count should return 0")
	}
}

func TestConnectionInfo_Bytes(t *testing.T) {
	info := &ConnectionInfo{
		ID:         "c1",
		Frontend:   "fe",
		RemoteAddr: "1.2.3.4:5",
		Target:     common.Target{Host: "example.com", Port: 443},
		Protocol:   common.ProtocolTLS,
		Network:    "tcp",
	}
	if !info.StartedAt.IsZero() {
		// StartedAt set by Register, not here
	}

	info.AddBytesIn(100)
	info.AddBytesIn(50)
	info.AddBytesOut(300)

	if info.BytesIn() != 150 {
		t.Errorf("BytesIn = %d, want 150", info.BytesIn())
	}
	if info.BytesOut() != 300 {
		t.Errorf("BytesOut = %d, want 300", info.BytesOut())
	}

	// Non-positive additions are ignored
	info.AddBytesIn(0)
	info.AddBytesIn(-1)
	info.AddBytesOut(0)
	info.AddBytesOut(-1)
	if info.BytesIn() != 150 {
		t.Errorf("BytesIn after no-op = %d, want 150", info.BytesIn())
	}
	if info.BytesOut() != 300 {
		t.Errorf("BytesOut after no-op = %d, want 300", info.BytesOut())
	}
}

func TestConnectionInfo_ConcurrentBytes(t *testing.T) {
	info := &ConnectionInfo{ID: "c1"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			info.AddBytesIn(10)
		}()
		go func() {
			defer wg.Done()
			info.AddBytesOut(20)
		}()
	}
	wg.Wait()
	if info.BytesIn() != 500 {
		t.Errorf("BytesIn = %d, want 500", info.BytesIn())
	}
	if info.BytesOut() != 1000 {
		t.Errorf("BytesOut = %d, want 1000", info.BytesOut())
	}
}

func TestEventBus_PublishSubscribe(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := withTimeout()
	defer cancel()

	ch := bus.Subscribe(ctx)

	bus.Publish(Event{Type: EventConnect, Frontend: "fe1", ConnectionID: "c1", Target: "example.com:443"})
	bus.Publish(Event{Type: EventDisconnect, ConnectionID: "c1"})

	ev1 := <-ch
	if ev1.Type != EventConnect {
		t.Errorf("first event type = %s, want %s", ev1.Type, EventConnect)
	}
	if ev1.Frontend != "fe1" {
		t.Errorf("first event frontend = %s, want fe1", ev1.Frontend)
	}
	if ev1.Time.IsZero() {
		t.Error("event time should be set by Publish")
	}

	ev2 := <-ch
	if ev2.Type != EventDisconnect {
		t.Errorf("second event type = %s, want %s", ev2.Type, EventDisconnect)
	}
}

func TestEventBus_MultipleSubscribers(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := withTimeout()
	defer cancel()

	ch1 := bus.Subscribe(ctx)
	ch2 := bus.Subscribe(ctx)

	if bus.SubscriberCount() != 2 {
		t.Errorf("SubscriberCount = %d, want 2", bus.SubscriberCount())
	}

	bus.Publish(Event{Type: EventConnect})

	ev1 := <-ch1
	ev2 := <-ch2
	if ev1.Type != EventConnect || ev2.Type != EventConnect {
		t.Error("both subscribers should receive the event")
	}
}

func TestEventBus_UnsubscribeOnCancel(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := context.WithCancel(context.Background())

	ch := bus.Subscribe(ctx)
	if bus.SubscriberCount() != 1 {
		t.Errorf("SubscriberCount = %d, want 1", bus.SubscriberCount())
	}

	cancel()

	// drain any buffered events then expect channel close
	for range ch {
	}
	if bus.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount after cancel = %d, want 0", bus.SubscriberCount())
	}
}

func TestEventBus_DropsOnFullBuffer(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := bus.Subscribe(ctx)
	// Fill the buffer beyond capacity to trigger drops.
	for i := 0; i < subscriberBufferSize+50; i++ {
		bus.Publish(Event{Type: EventConnect})
	}
	// Should not block; received count should be <= buffer size.
	received := 0
loop:
	for {
		select {
		case <-ch:
			received++
		default:
			break loop
		}
	}
	if received > subscriberBufferSize {
		t.Errorf("received %d, expected at most %d (drops should occur)", received, subscriberBufferSize)
	}
}

func TestEventBus_NilSafe(t *testing.T) {
	var bus *EventBus
	ch := bus.Subscribe(context.Background())
	if ch == nil {
		t.Error("nil bus Subscribe should return non-nil channel")
	}
	bus.Publish(Event{Type: EventConnect})
	bus.Close()
	if bus.SubscriberCount() != 0 {
		t.Error("nil bus SubscriberCount should be 0")
	}
}

func TestEventBus_Close(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = bus.Subscribe(ctx)
	_ = bus.Subscribe(ctx)
	if bus.SubscriberCount() != 2 {
		t.Fatalf("SubscriberCount = %d, want 2", bus.SubscriberCount())
	}

	bus.Close()
	if bus.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount after Close = %d, want 0", bus.SubscriberCount())
	}
}

func TestEventBus_SubscribeWithFilter(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := withTimeout()
	defer cancel()

	ch := bus.Subscribe(ctx, EventConnect)

	bus.Publish(Event{Type: EventConnect, ConnectionID: "c1"})
	bus.Publish(Event{Type: EventDisconnect, ConnectionID: "c1"})
	bus.Publish(Event{Type: EventDialFailed, Target: "x:443"})

	ev := <-ch
	if ev.Type != EventConnect {
		t.Errorf("event type = %s, want %s", ev.Type, EventConnect)
	}

	select {
	case ev := <-ch:
		t.Errorf("received unexpected filtered event: %s", ev.Type)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestEventBus_SubscribeMultipleTopics(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := withTimeout()
	defer cancel()

	ch := bus.Subscribe(ctx, EventConnect, EventDisconnect)

	bus.Publish(Event{Type: EventConnect, ConnectionID: "c1"})
	bus.Publish(Event{Type: EventDisconnect, ConnectionID: "c1"})
	bus.Publish(Event{Type: EventShutdown})

	ev1 := <-ch
	if ev1.Type != EventConnect {
		t.Errorf("first event type = %s, want %s", ev1.Type, EventConnect)
	}
	ev2 := <-ch
	if ev2.Type != EventDisconnect {
		t.Errorf("second event type = %s, want %s", ev2.Type, EventDisconnect)
	}

	select {
	case ev := <-ch:
		t.Errorf("received unexpected filtered event: %s", ev.Type)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestEventBus_SubscribeNoMatch(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := withTimeout()
	defer cancel()

	ch := bus.Subscribe(ctx, EventDialFailed)

	bus.Publish(Event{Type: EventConnect})
	bus.Publish(Event{Type: EventDisconnect})
	bus.Publish(Event{Type: EventShutdown})

	select {
	case ev := <-ch:
		t.Errorf("received unexpected event: %s", ev.Type)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestEventBus_SubscribeAllWhenNoTypes(t *testing.T) {
	bus := NewEventBus()
	ctx, cancel := withTimeout()
	defer cancel()

	ch := bus.Subscribe(ctx)

	bus.Publish(Event{Type: EventConnect})
	bus.Publish(Event{Type: EventShutdown})

	ev1 := <-ch
	if ev1.Type != EventConnect {
		t.Errorf("first event type = %s, want %s", ev1.Type, EventConnect)
	}
	ev2 := <-ch
	if ev2.Type != EventShutdown {
		t.Errorf("second event type = %s, want %s", ev2.Type, EventShutdown)
	}
}
