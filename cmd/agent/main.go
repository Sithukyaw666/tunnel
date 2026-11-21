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
	var insecureSkipVerify bool
	if env == "dev" {
		logger.Info("[ENV] dev environment, setting insecureSkipVerify = true")
		insecureSkipVerify = true
	}
	config := agent.Config{
		ServerEndpoint:     "0.0.0.0:3030",
		LocalEndpoint:      "0.0.0.0:4444",
		Secret:             secret,
		InsecureSkipVerify: insecureSkipVerify,
	}
	agent := agent.New(logger, config)
	logger.Info("[Agent] initiating handshake...")
	if err := agent.HandleHandShake(); err != nil {
		logger.Error("[Agent] error handshake", "error", err)
		return
	}
	logger.Info("[Agent] handshake completed successfully")
	logger.Info("[Agent] started handling connection...")
	agent.Handle(ctx)
}
