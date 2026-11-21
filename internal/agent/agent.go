package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"sithukyaw666/tunnel/internal/pipe"
	"sithukyaw666/tunnel/internal/proto"

	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/hashicorp/yamux"
)

type Config struct {
	ServerEndpoint     string
	LocalEndpoint      string
	Secret             string
	InsecureSkipVerify bool
}

type Agent struct {
	cfg     Config
	logger  *slog.Logger
	session *yamux.Session
	conn    net.Conn
}

func New(logger *slog.Logger, cfg Config) *Agent {
	return &Agent{
		cfg:    cfg,
		logger: logger,
	}
}

func (a *Agent) HandleHandShake() error {
	cfg := &tls.Config{
		InsecureSkipVerify: a.cfg.InsecureSkipVerify,
	}
	conn, err := tls.Dial("tcp", a.cfg.ServerEndpoint, cfg)
	if err != nil {
		a.logger.Error("[HandShake] error dialing server", "endpoint", a.cfg.ServerEndpoint, "error", err)
		return err
	}
	if err := proto.Send(conn, a.cfg.Secret); err != nil {
		a.logger.Error("[HandShake] error sending secret", "error", err)
		conn.Close()
		return err
	}
	signal, err := proto.Receive(conn)
	if err != nil {
		a.logger.Error("[HandShake] error reading signal", "error", err)
		conn.Close()
		return err
	}

	switch string(signal) {
	case proto.AuthSucceed:
		session, err := yamux.Client(conn, nil)
		if err != nil {
			a.logger.Error("[HandShake] error creating session", "error", err)
			conn.Close()
			return err
		}
		a.conn = conn
		a.session = session
		return nil
	case proto.AuthFail:
		a.logger.Error("[HandShake] bad secret")
		return errors.New("bad secret")
	default:
		a.logger.Error("[HandShake] unknown signal received", "signal",
			string(signal))
		conn.Close()
		return fmt.Errorf("unexpected handshake signal: %s", string(signal))

	}

}

func (a *Agent) Handle(ctx context.Context) {
	go func() {
		<-ctx.Done()
		a.logger.Info("[Agent] shutting down", "cause", context.Cause(ctx))
		a.session.Close()
		a.conn.Close()
	}()
	a.handleRequest()
}

func (a *Agent) handleRequest() {
	for {
		conn, err := a.session.Accept()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, yamux.ErrSessionShutdown) || a.session.IsClosed() {
				a.logger.Error("[Agent] connection closed")
				break
			} else {
				a.logger.Error("[Agent] error accepting connection", "error", err)
				continue
			}
		}
		go a.pipeLocal(conn)

	}
}

func (a *Agent) pipeLocal(conn net.Conn) {
	local, err := net.Dial("tcp", a.cfg.LocalEndpoint)
	if err != nil {
		a.logger.Error("[Local] error dialing local", "endpoint", a.cfg.LocalEndpoint)
		conn.Close()
		return
	}
	pipe.Pipe(conn, local)
}
