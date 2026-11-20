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
	config := agent.Config{
		ServerEndpoint: "0.0.0.0:3030",
		LocalEndpoint:  "0.0.0.0:4444",
		Secret:         "secret",
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
