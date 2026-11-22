package transport

import (
	"context"
	"io"
)

type Session interface {
	Open(ctx context.Context) (io.ReadWriteCloser, error)
	Accept(ctx context.Context) (io.ReadWriteCloser, error)
	Close() error
	Done() <-chan struct{}
}

type Listener interface {
	Accept(ctx context.Context) (Session, error)
	Close() error
}
