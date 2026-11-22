package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sithukyaw666/tunnel/internal/pipe"
	"sithukyaw666/tunnel/internal/proto"
	"sithukyaw666/tunnel/internal/registry"
	"sithukyaw666/tunnel/internal/transport"
	"time"

	quic "github.com/quic-go/quic-go"
)

// default hostname hardcoded
var hostname = "www.example.com"

type Config struct {
	PublicEndpoint  string
	PrivateEndpoint string
	Secret          string
	TlsEnabled      bool
	Cert            string
	Key             string
}

type Server struct {
	logger   *slog.Logger
	public   net.Listener
	private  transport.Listener
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
	if !s.cfg.TlsEnabled {
		s.logger.Error("[TLS] quic requied tls")
		return errors.New("tls not enabled")
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.Cert, s.cfg.Key)
	if err != nil {
		s.logger.Error("[TLS] error loading certificate", "error", err)
		s.public.Close()
		return fmt.Errorf("error loading certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	s.private, err = transport.NewQUICListener(s.cfg.PrivateEndpoint, cfg)
	if err != nil {
		s.public.Close()
		return fmt.Errorf("error listen private: %w", err)
	}
	s.logger.Info("public listening", "endpoint", s.cfg.PublicEndpoint)
	s.logger.Info("agent listening", "endpoint", s.cfg.PrivateEndpoint)

	go func() {
		<-ctx.Done()
		s.logger.Info("shutting down", "cause", context.Cause(ctx))
		s.private.Close()
		s.public.Close()
	}()

	go s.servePrivate(ctx)
	s.servePublic(ctx) // blocks until the public listener is closed
	return nil
}

func (s *Server) servePublic(ctx context.Context) {
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
		go s.handlePublic(ctx, conn)
	}
}

func (s *Server) handlePublic(ctx context.Context, conn net.Conn) {

	session, err := s.registry.GetSession(hostname)
	if err != nil {
		s.logger.Error("[Public] error getting tunnel", "error", err)
		conn.Close()
		return

	}
	muxedConn, err := session.Open(ctx)
	if err != nil {
		s.logger.Error("[Public], error opening muxed conn over session", "error", err)
		conn.Close()
		return
	}
	pipe.Pipe(conn, muxedConn)
}

func (s *Server) servePrivate(ctx context.Context) {
	for {
		conn, err := s.private.Accept(ctx)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
				s.logger.Info("[Private] listener closed")
				break

			} else {
				s.logger.Warn("[Private] error accepting connection", "error", err)
				continue
			}
		}
		go s.handlePrivate(ctx, conn)
	}
}

func (s *Server) handlePrivate(ctx context.Context, conn transport.Session) {

	s.logger.Info("[Server] handshake request received from agent")
	stream, err := conn.Accept(ctx)
	if err != nil {
		s.logger.Error("[Server-QUIC] error opening stream", "error", err)
		return
	}

	err = s.authenticate(stream)
	if err != nil {
		s.logger.Error("[HandShake] authentication failed", "error", err)
		if err := proto.Send(stream, proto.AuthFail); err != nil {
			s.logger.Error("[HandShake] error sending fail signal", "error", err)
		}
		stream.Close()
		return

	}
	s.logger.Info("[Server] handshake completed successfully")
	if err := proto.Send(stream, proto.AuthSucceed); err != nil {
		s.logger.Error("[HandShake] error sending success signal", "error", err)
		stream.Close()
		return
	}

	s.registry.AddSession(hostname, conn)

	//healthcheck
	go func() {
		<-conn.Done()
		s.logger.Warn("[HealthCheck] Agent somehow close the connection")
		s.logger.Info("[HealthCheck] removing tunnel from registry", "hostname", hostname)
		s.registry.RemoveSession(hostname)

	}()

}

func (s *Server) authenticate(conn io.ReadWriteCloser) error {
	if qs, ok := conn.(*quic.Stream); ok {
		qs.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer qs.SetReadDeadline(time.Time{})
	}
	secret, err := proto.Receive(conn)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(secret, []byte(s.cfg.Secret)) != 1 {
		return errors.New("bad secret")
	}
	return nil
}
