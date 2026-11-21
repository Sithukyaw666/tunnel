package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sithukyaw666/tunnel/internal/server"

	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	public_endpoint := os.Getenv("PUBLIC_ENDPOINT")
	if public_endpoint == "" {
		logger.Warn("[ENV] PUBLIC_ENDPOINT not configured, using default")
		public_endpoint = "0.0.0.0:4040"
	}
	private_endpoint := os.Getenv("PRIVATE_ENDPOINT")
	if private_endpoint == "" {
		logger.Warn("[ENV] PRIVATE_ENDPOINT not configured, using default ")
		private_endpoint = "0.0.0.0:3030"
	}

	secret := os.Getenv("SECRET")
	if secret == "" {
		logger.Warn("[ENV] SECRET not configured, using default")
		secret = "B45X9TPvkYp5Ij0w18qQi861OdiBjY8dV40xMk1E6cs="
	}
	var tlsEnabled bool
	key := os.Getenv("CERT_KEY")
	cert := os.Getenv("CERT")
	if key != "" || cert != "" {
		logger.Info("[ENV] TLS enabled")
		tlsEnabled = true
	} else {
		logger.Warn("[ENV] TLS disabled")
	}

	config := server.Config{
		PublicEndpoint:  public_endpoint,
		PrivateEndpoint: private_endpoint,
		Secret:          secret,
		TlsEnabled:      tlsEnabled,
		Key:             key,
		Cert:            cert,
	}
	server := server.New(logger, config)
	server.Run(ctx)

}
