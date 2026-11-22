package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"sithukyaw666/tunnel/internal/pipe"
	"sithukyaw666/tunnel/internal/proto"
	"sithukyaw666/tunnel/internal/transport"

	"errors"
	"io"
	"log/slog"
	"net"
)

type Config struct {
	ServerEndpoint     string
	LocalEndpoint      string
	Secret             string
	InsecureSkipVerify bool
	Transport          string
}

type Agent struct {
	cfg     Config
	logger  *slog.Logger
	session transport.Session
}

func New(logger *slog.Logger, cfg Config) *Agent {
	return &Agent{
		cfg:    cfg,
		logger: logger,
	}
}

func (a *Agent) HandleHandShake(ctx context.Context) error {
	var session transport.Session
	var err error
	cfg := &tls.Config{
		InsecureSkipVerify: a.cfg.InsecureSkipVerify,
	}
	switch a.cfg.Transport {
	case "quic":
		session, err = transport.QUICDial(ctx, a.cfg.ServerEndpoint, cfg)
		if err != nil {
			a.logger.Error("[HandShake] error dialing server", "endpoint", a.cfg.ServerEndpoint, "transport", "quic", "error", err)
			return err
		}
	case "yamux":
		session, err = transport.YamuxDial(a.cfg.ServerEndpoint, cfg)
		if err != nil {
			a.logger.Error("[HandShake] error dialing server", "endpoint", a.cfg.ServerEndpoint, "transport", "yamux", "error", err)
			return err
		}
	default:
		return fmt.Errorf("unsupported transport: %s", a.cfg.Transport)
	}
	stream, err := session.Open(ctx)
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
		a.session = session
		stream.Close()
		return nil
	case proto.AuthFail:
		a.logger.Error("[HandShake] bad secret")
		stream.Close()
		session.Close()
		return errors.New("bad secret")
	default:
		a.logger.Error("[HandShake] unknown signal received", "signal",
			string(signal))
		stream.Close()
		session.Close()
		return fmt.Errorf("unexpected handshake signal: %s", string(signal))
	}

}

func (a *Agent) Handle(ctx context.Context) {
	go func() {
		<-ctx.Done()
		a.logger.Info("[Agent] shutting down", "cause", context.Cause(ctx))
		if a.session != nil {
			a.session.Close()
		}
	}()
	a.handleRequest(ctx)
}

func (a *Agent) handleRequest(ctx context.Context) {
	for {
		stream, err := a.session.Accept(ctx)
		if err != nil {
			select {
			case <-a.session.Done():
				a.logger.Error("[Agent] connection closed")
				return
			default:
			}
			if errors.Is(err, context.Canceled) {
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
