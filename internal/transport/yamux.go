package transport

import (
	"context"
	"crypto/tls"
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
	c net.Conn
}

func NewYamuxListener(addr string, tlsCfg *tls.Config) (Listener, error) {
	var listener net.Listener
	var err error
	if tlsCfg == nil {
		listener, err = net.Listen("tcp", addr)
	} else {
		listener, err = tls.Listen("tcp", addr, tlsCfg)
	}
	if err != nil {
		return nil, err
	}
	return &yamuxListener{listener}, nil
}

func YamuxDial(addr string, tlsCfg *tls.Config) (Session, error) {
	var conn net.Conn
	var err error
	if tlsCfg == nil {
		conn, err = net.Dial("tcp", addr)
	} else {
		conn, err = tls.Dial("tcp", addr, tlsCfg)
	}
	if err != nil {
		return nil, err
	}
	session, err := yamux.Client(conn, nil)
	if err != nil {
		return nil, err
	}
	return &yamuxSession{s: session, c: conn}, nil
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

	return &yamuxSession{s: session, c: conn}, nil
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
	if err := ys.s.Close(); err != nil {
		return err
	}
	return ys.c.Close()
}

func (ys *yamuxSession) Done() <-chan struct{} {
	return ys.s.CloseChan()
}
