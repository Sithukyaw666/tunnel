package transport

import (
	"context"
	"crypto/tls"
	"io"
	"time"

	"github.com/quic-go/quic-go"
)

type quicListener struct {
	l *quic.Listener
}

type quicSession struct {
	c *quic.Conn
}

func NewQUICListener(addr string, tlsConfig *tls.Config) (Listener, error) {
	listener, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	})

	if err != nil {
		return nil, err
	}
	return &quicListener{listener}, nil
}

func (ql *quicListener) Accept(ctx context.Context) (Session, error) {
	conn, err := ql.l.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &quicSession{conn}, nil
}

func (ql *quicListener) Close() error {
	return ql.l.Close()
}

func (qs *quicSession) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	return qs.c.OpenStreamSync(ctx)
}

func (qs *quicSession) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	return qs.c.AcceptStream(ctx)
}

func (qs *quicSession) Close() error {
	return qs.c.CloseWithError(0, "close")
}

func (qs *quicSession) Done() <-chan struct{} {
	return qs.c.Context().Done()
}
