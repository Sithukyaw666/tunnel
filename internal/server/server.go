package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sithukyaw666/tunnel/internal/pipe"
	"sithukyaw666/tunnel/internal/proto"
	"sithukyaw666/tunnel/internal/registry"

	"time"

	"github.com/hashicorp/yamux"
)

// default hostname hardcoded
var hostname = "www.example.com"

type Config struct {
	PublicEndpoint  string
	PrivateEndpoint string
	Secret          string
}

type Server struct {
	logger   *slog.Logger
	public   net.Listener
	private  net.Listener
	registry *registry.Registry
	cfg      Config
}

func New(logger *slog.Logger, cfg Config) *Server {
	registry := registry.NewRegistry()
	return &Server{
		logger:   logger,
		registry: registry,
		cfg:      cfg,
	}
}

func (s *Server) Run(ctx context.Context) error {
	var err error
	if s.public, err = net.Listen("tcp", s.cfg.PublicEndpoint); err != nil {
		return fmt.Errorf("listen public: %w", err)
	}
	if s.private, err = net.Listen("tcp", s.cfg.PrivateEndpoint); err != nil {
		s.public.Close()
		return fmt.Errorf("listen agent: %w", err)
	}
	s.logger.Info("public listening", "endpoint", s.cfg.PublicEndpoint)
	s.logger.Info("agent listening", "endpoint", s.cfg.PrivateEndpoint)

	go func() {
		<-ctx.Done()
		s.logger.Info("shutting down", "cause", context.Cause(ctx))
		s.private.Close()
		s.public.Close()
	}()

	go s.servePrivate()
	s.servePublic() // blocks until the public listener is closed
	return nil
}

func (s *Server) servePublic() {
	s.logger.Info("Accepting public connection...")
	for {
		conn, err := s.public.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.logger.Error("[Public] closed connection")
				break
			} else {
				s.logger.Warn("[Public] error accepting connection", "error", err)
				continue
			}
		}
		go s.handlePublic(conn)
	}
}

func (s *Server) handlePublic(conn net.Conn) {

	session, err := s.registry.GetSession(hostname)
	if err != nil {
		s.logger.Error("[Public] error getting tunnel", "error", err)
		conn.Close()
		return

	}
	muxedConn, err := session.Open()
	if err != nil {
		s.logger.Error("[Public], error opening muxed conn over session", "error", err)
		conn.Close()
		return
	}
	pipe.Pipe(conn, muxedConn)
}

func (s *Server) servePrivate() {
	for {
		conn, err := s.private.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.logger.Error("[Private] closed connection")
				break
			} else {
				s.logger.Warn("[Private] error accepting connection", "error", err)
				continue
			}
		}
		go s.handlePrivate(conn)
	}
}

func (s *Server) handlePrivate(conn net.Conn) {

	s.logger.Info("[Server] handshake request received from agent")
	err := s.authenticate(conn)
	if err != nil {
		s.logger.Error("[HandShake] authentication failed", "error", err)
		if err := proto.Send(conn, proto.AuthFail); err != nil {
			s.logger.Error("[HandShake] error sending fail signal", "error", err)
		}

		conn.Close()
		return

	}
	s.logger.Info("[Server] handshake completed successfully")
	if err := proto.Send(conn, proto.AuthSucceed); err != nil {
		s.logger.Error("[HandShake] error sending success signal", "error", err)
		conn.Close()
		return
	}

	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 5 * time.Second
	session, err := yamux.Server(conn, cfg)
	if err != nil {
		s.logger.Error("[Private] error creating mux session", "error", err)
		conn.Close()
		return
	}

	s.registry.AddSession(hostname, session)

	//healthcheck

	go func() {
		<-session.CloseChan()
		s.logger.Warn("[HealthCheck] Agent somehow close the connection")
		s.logger.Info("[HealthCheck] removing tunnel from registry", "hostname", hostname)
		s.registry.RemoveSession(hostname)
		conn.Close()
	}()

}

func (s *Server) authenticate(conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	secret, err := proto.Receive(conn)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(secret, []byte(s.cfg.Secret)) != 1 {
		return errors.New("bad secret")
	}
	return nil
}
