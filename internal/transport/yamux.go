package transport

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

type yamuxListener struct {
	l net.Listener
}

type yamuxSession struct {
	s *yamux.Session
}

func (yl *yamuxListener) Accept(ctx context.Context) (Session, error) {
	conn, err := yl.l.Accept()
	if err != nil {
		return nil, err
	}
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 5 * time.Second
	session, err := yamux.Server(conn, cfg)
	if err != nil {
		return nil, err
	}

	return &yamuxSession{session}, nil
}

func (yl *yamuxListener) Close() error {
	return yl.l.Close()
}

func (ys *yamuxSession) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	return ys.s.Open()
}

func (ys *yamuxSession) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	return ys.s.Accept()
}

func (ys *yamuxSession) Close() error {
	return ys.s.Close()
}

func (ys *yamuxSession) Done() <-chan struct{} {
	return ys.s.CloseChan()
}
