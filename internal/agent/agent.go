package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"sithukyaw666/tunnel/internal/pipe"
	"sithukyaw666/tunnel/internal/proto"
	"time"

	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/quic-go/quic-go"
)

type Config struct {
	ServerEndpoint     string
	LocalEndpoint      string
	Secret             string
	InsecureSkipVerify bool
}

type Agent struct {
	cfg    Config
	logger *slog.Logger
	conn   *quic.Conn
}

func New(logger *slog.Logger, cfg Config) *Agent {
	return &Agent{
		cfg:    cfg,
		logger: logger,
	}
}

func (a *Agent) HandleHandShake(ctx context.Context) error {
	cfg := &tls.Config{
		InsecureSkipVerify: a.cfg.InsecureSkipVerify,
	}
	conn, err := quic.DialAddr(ctx, a.cfg.ServerEndpoint, cfg, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	})
	if err != nil {
		a.logger.Error("[HandShake] error dialing server", "endpoint", a.cfg.ServerEndpoint, "error", err)
		return err
	}
	stream, err := conn.OpenStream()
	if err != nil {
		a.logger.Error("[HandShake] error opening quic stream", "error", err)
		return err
	}
	if err := proto.Send(stream, a.cfg.Secret); err != nil {
		a.logger.Error("[HandShake] error sending secret", "error", err)
		stream.Close()
		return err
	}
	signal, err := proto.Receive(stream)
	if err != nil {
		a.logger.Error("[HandShake] error reading signal", "error", err)
		stream.Close()
		return err
	}

	switch string(signal) {
	case proto.AuthSucceed:
		a.conn = conn
		stream.Close()
		return nil
	case proto.AuthFail:
		a.logger.Error("[HandShake] bad secret")
		stream.Close()
		conn.CloseWithError(0, "bad secret")
		return errors.New("bad secret")
	default:
		a.logger.Error("[HandShake] unknown signal received", "signal",
			string(signal))
		stream.Close()
		conn.CloseWithError(0, "unknown signal")
		return fmt.Errorf("unexpected handshake signal: %s", string(signal))
	}

}

func (a *Agent) Handle(ctx context.Context) {
	go func() {
		<-ctx.Done()
		a.logger.Info("[Agent] shutting down", "cause", context.Cause(ctx))
		if a.conn != nil {
			a.conn.CloseWithError(0, "connection closed")
		}
	}()
	a.handleRequest(ctx)
}

func (a *Agent) handleRequest(ctx context.Context) {
	for {
		stream, err := a.conn.AcceptStream(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrStreamClosed) || a.conn.Context().Err() != nil || errors.Is(err, context.Canceled) {
				a.logger.Error("[Agent] connection closed")
				break
			} else {
				a.logger.Error("[Agent] error accepting connection", "error", err)
				continue
			}
		}
		go a.pipeLocal(stream)

	}
}

func (a *Agent) pipeLocal(conn io.ReadWriteCloser) {
	local, err := net.Dial("tcp", a.cfg.LocalEndpoint)
	if err != nil {
		a.logger.Error("[Local] error dialing local", "endpoint", a.cfg.LocalEndpoint)
		conn.Close()
		return
	}
	pipe.Pipe(conn, local)
}
