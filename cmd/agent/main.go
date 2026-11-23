package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sithukyaw666/tunnel/internal/agent"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	secret := os.Getenv("SECRET")
	if secret == "" {
		logger.Warn("[ENV] secret not configured, using default")
		secret = "B45X9TPvkYp5Ij0w18qQi861OdiBjY8dV40xMk1E6cs="
	}
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		logger.Warn("[ENV] env not set, assumed dev")
		env = "dev"
	}

	serverEndpoint := os.Getenv("SERVER_ENDPOINT")
	if serverEndpoint == "" {
		logger.Warn("[ENV] SERVER_ENDPOINT not configured, using default")
		serverEndpoint = "0.0.0.0:3030"
	}

	localEndpoint := os.Getenv("LOCAL_ENDPOINT")
	if localEndpoint == "" {
		logger.Warn("[ENV] LOCAL_ENDPOINT not configured, using default")
		localEndpoint = "0.0.0.0:4444"
	}

	var insecureSkipVerify bool
	if env == "dev" {
		logger.Info("[ENV] dev environment, setting insecureSkipVerify = true")
		insecureSkipVerify = true
	}

	transport := os.Getenv("TRANSPORT_PROTO")
	if transport == "" {
		logger.Warn("[ENV] TRANSPORT_PROTO not configured, using default (yamux)")
		transport = "yamux"
	}
	config := agent.Config{
		ServerEndpoint:     serverEndpoint,
		LocalEndpoint:      localEndpoint,
		Secret:             secret,
		InsecureSkipVerify: insecureSkipVerify,
		Transport:          transport,
	}
	ag := agent.New(logger, config)
	logger.Info("[Agent] initiating handshake...")
	if err := ag.HandleHandShake(ctx); err != nil {
		logger.Error("[Agent] error handshake", "error", err)
		return
	}
	logger.Info("[Agent] handshake completed successfully")
	logger.Info("[Agent] started handling connection...")
	ag.Handle(ctx)
}
