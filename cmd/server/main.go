package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sithukyaw666/tunnel/internal/server"

	"syscall"
)

const EXTERNAL_ENDPOINT = "0.0.0.0:4040"
const INTERNAL_ENDPOINT = "0.0.0.0:3030"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config := server.Config{
		PublicEndpoint:  EXTERNAL_ENDPOINT,
		PrivateEndpoint: INTERNAL_ENDPOINT,
		Secret:          "secret",
	}
	server := server.New(logger, config)
	server.Run(ctx)

}
