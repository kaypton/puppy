package shim

import (
	"context"
	"errors"
	"io"
	"sync"
)

const defaultBufferSize = 32 * 1024

type ShimServer struct {
	frontend io.ReadWriteCloser
	backend  io.ReadWriteCloser
	bufSize  int

	feOnce sync.Once
	beOnce sync.Once
}

type ShimServerConfiguration struct {
	Frontend   io.ReadWriteCloser
	Backend    io.ReadWriteCloser
	BufferSize int
}

// Validate checks the runtime configuration fields.
func (c ShimServerConfiguration) Validate() error {
	if c.Frontend == nil {
		return errors.New("shim: frontend is nil")
	}
	if c.Backend == nil {
		return errors.New("shim: backend is nil")
	}
	return nil
}

func NewShimServer(config ShimServerConfiguration) (*ShimServer, error) {
	bufSize := config.BufferSize
	if bufSize <= 0 {
		bufSize = defaultBufferSize
	}
	return &ShimServer{
		frontend: config.Frontend,
		backend:  config.Backend,
		bufSize:  bufSize,
	}, nil
}

func (s *ShimServer) closeFrontend() {
	s.feOnce.Do(func() { _ = s.frontend.Close() })
}

func (s *ShimServer) closeBackend() {
	s.beOnce.Do(func() { _ = s.backend.Close() })
}

// Run copies bytes between the frontend and backend connections until both
// directions complete or ctx is cancelled. It returns the number of bytes
// copied in each direction: clientToBackend (frontend→backend) and
// backendToClient (backend→frontend). The error return is always nil and is
// retained for API stability.
func (s *ShimServer) Run(ctx context.Context) (clientToBackend, backendToClient int64, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	var feToBe, beToFe int64

	// frontend -> backend: when this direction ends, the frontend side has
	// stopped sending; close the backend so the other goroutine can exit.
	go func() {
		defer wg.Done()
		defer s.closeBackend()
		buf := make([]byte, s.bufSize)
		n, _ := io.CopyBuffer(s.backend, s.frontend, buf)
		feToBe = n
	}()

	// backend -> frontend: symmetric to the above.
	go func() {
		defer wg.Done()
		defer s.closeFrontend()
		buf := make([]byte, s.bufSize)
		n, _ := io.CopyBuffer(s.frontend, s.backend, buf)
		beToFe = n
	}()

	// On ctx cancellation, close both ends to unblock any pending reads.
	go func() {
		<-ctx.Done()
		s.closeFrontend()
		s.closeBackend()
	}()

	wg.Wait()
	return feToBe, beToFe, nil
}
