package counting

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/puppy/pkg/common/stats"
)

// pipeConn is a minimal io.ReadWriteCloser backed by a bytes.Buffer for
// predictable test data. Close sets a flag so we can assert it was called.
type pipeConn struct {
	buf    bytes.Buffer
	closed bool
}

func (p *pipeConn) Read(b []byte) (int, error) {
	if p.buf.Len() == 0 {
		return 0, io.EOF
	}
	return p.buf.Read(b)
}

func (p *pipeConn) Write(b []byte) (int, error) {
	return p.buf.Write(b)
}

func (p *pipeConn) Close() error {
	p.closed = true
	return nil
}

// errorConn returns err on every Read/Write.
type errorConn struct{ err error }

func (e *errorConn) Read([]byte) (int, error)  { return 0, e.err }
func (e *errorConn) Write([]byte) (int, error) { return 0, e.err }
func (e *errorConn) Close() error              { return nil }

func TestCountingConn_ReadCountsBytesIn(t *testing.T) {
	conn := &pipeConn{}
	_, _ = conn.Write([]byte("hello world"))

	info := &stats.ConnectionInfo{ID: "c1"}
	registry := stats.NewStatsRegistry()
	cc := NewConn(conn, info, registry)

	buf := make([]byte, 32)
	n, err := cc.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != 11 {
		t.Errorf("Read n = %d, want 11", n)
	}
	if info.BytesIn() != 11 {
		t.Errorf("info.BytesIn = %d, want 11", info.BytesIn())
	}
	snap := registry.Snapshot()
	if snap.BytesIn != 11 {
		t.Errorf("registry.BytesIn = %d, want 11", snap.BytesIn)
	}
}

func TestCountingConn_WriteCountsBytesOut(t *testing.T) {
	conn := &pipeConn{}
	info := &stats.ConnectionInfo{ID: "c1"}
	registry := stats.NewStatsRegistry()
	cc := NewConn(conn, info, registry)

	data := []byte("response data")
	n, err := cc.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write n = %d, want %d", n, len(data))
	}
	if info.BytesOut() != uint64(len(data)) {
		t.Errorf("info.BytesOut = %d, want %d", info.BytesOut(), len(data))
	}
	snap := registry.Snapshot()
	if snap.BytesOut != uint64(len(data)) {
		t.Errorf("registry.BytesOut = %d, want %d", snap.BytesOut, len(data))
	}
}

func TestCountingConn_NilInfoAndRegistry(t *testing.T) {
	conn := &pipeConn{}
	_, _ = conn.Write([]byte("test"))

	// Both nil — should still pass through without panic.
	cc := NewConn(conn, nil, nil)
	buf := make([]byte, 4)
	n, err := cc.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != 4 {
		t.Errorf("Read n = %d, want 4", n)
	}
	n, err = cc.Write([]byte("ok"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 2 {
		t.Errorf("Write n = %d, want 2", n)
	}
}

func TestCountingConn_CloseClosesUnderlying(t *testing.T) {
	conn := &pipeConn{}
	cc := NewConn(conn, nil, nil)
	if err := cc.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if !conn.closed {
		t.Error("underlying conn should be closed")
	}
}

func TestCountingConn_PropagatesErrors(t *testing.T) {
	expectedErr := errors.New("boom")
	conn := &errorConn{err: expectedErr}
	cc := NewConn(conn, nil, nil)

	_, err := cc.Read(make([]byte, 1))
	if !errors.Is(err, expectedErr) {
		t.Errorf("Read err = %v, want %v", err, expectedErr)
	}
	_, err = cc.Write([]byte("x"))
	if !errors.Is(err, expectedErr) {
		t.Errorf("Write err = %v, want %v", err, expectedErr)
	}
}

func TestCountingConn_MultipleReadsAndWrites(t *testing.T) {
	conn := &pipeConn{}
	info := &stats.ConnectionInfo{ID: "c1"}
	registry := stats.NewStatsRegistry()
	cc := NewConn(conn, info, registry)

	// Simulate several read/write cycles
	_, _ = conn.Write([]byte("aaa"))
	buf := make([]byte, 3)
	_, _ = cc.Read(buf)

	_, _ = cc.Write([]byte("bb"))

	_, _ = conn.Write([]byte("cccc"))
	buf2 := make([]byte, 4)
	_, _ = cc.Read(buf2)

	_, _ = cc.Write([]byte("ddddd"))

	if info.BytesIn() != 7 { // 3 + 4
		t.Errorf("BytesIn = %d, want 7", info.BytesIn())
	}
	if info.BytesOut() != 7 { // 2 + 5
		t.Errorf("BytesOut = %d, want 7", info.BytesOut())
	}
	snap := registry.Snapshot()
	if snap.BytesIn != 7 || snap.BytesOut != 7 {
		t.Errorf("registry: BytesIn=%d BytesOut=%d, want 7/7", snap.BytesIn, snap.BytesOut)
	}
}
