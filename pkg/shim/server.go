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

func NewShimServer(config ShimServerConfiguration) (*ShimServer, error) {
	if config.Frontend == nil {
		return nil, errors.New("shim: frontend is nil")
	}
	if config.Backend == nil {
		return nil, errors.New("shim: backend is nil")
	}
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

func (s *ShimServer) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// frontend -> backend: when this direction ends, the frontend side has
	// stopped sending; close the backend so the other goroutine can exit.
	go func() {
		defer wg.Done()
		defer s.closeBackend()
		buf := make([]byte, s.bufSize)
		_, _ = io.CopyBuffer(s.backend, s.frontend, buf)
	}()

	// backend -> frontend: symmetric to the above.
	go func() {
		defer wg.Done()
		defer s.closeFrontend()
		buf := make([]byte, s.bufSize)
		_, _ = io.CopyBuffer(s.frontend, s.backend, buf)
	}()

	// On ctx cancellation, close both ends to unblock any pending reads.
	go func() {
		<-ctx.Done()
		s.closeFrontend()
		s.closeBackend()
	}()

	wg.Wait()
	return nil
}
