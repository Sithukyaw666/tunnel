package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"sithukyaw666/tunnel/internal/agent"
	"sithukyaw666/tunnel/internal/server"
)

func generateTestCertificate(t testing.TB) (certPath, keyPath string, cleanup func()) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Tunnel Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	return certFile, keyFile, func() {
		os.Remove(certFile)
		os.Remove(keyFile)
	}
}

func startEchoServer(t testing.TB) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	cleanup := func() {
		close(stop)
		ln.Close()
		wg.Wait()
	}

	return ln.Addr().String(), cleanup
}

func setupTunnelEnvironment(t testing.TB, secret string) (publicAddr string, serverCtxCancel context.CancelFunc, agentCtxCancel context.CancelFunc) {
	t.Helper()
	nullLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	pubLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port for public: %v", err)
	}
	publicAddr = pubLn.Addr().String()
	pubLn.Close()

	privLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port for private: %v", err)
	}
	privateAddr := privLn.Addr().String()
	privLn.Close()

	certFile, keyFile, certCleanup := generateTestCertificate(t)

	echoAddr, echoCleanup := startEchoServer(t)

	srvCtx, cancelSrv := context.WithCancel(context.Background())
	srv := server.New(nullLogger, server.Config{
		PublicEndpoint:  publicAddr,
		PrivateEndpoint: privateAddr,
		Secret:          secret,
		TlsEnabled:      true,
		Cert:            certFile,
		Key:             keyFile,
		Transport:       "yamux",
	})

	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- srv.Run(srvCtx)
	}()

	for range 30 {
		testConn, err := net.Dial("tcp", privateAddr)
		if err == nil {
			testConn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	agCtx, cancelAg := context.WithCancel(context.Background())
	ag := agent.New(nullLogger, agent.Config{
		ServerEndpoint:     privateAddr,
		LocalEndpoint:      echoAddr,
		Secret:             secret,
		InsecureSkipVerify: true,
		Transport:          "yamux",
	})

	if err := ag.HandleHandShake(agCtx); err != nil {
		cancelAg()
		cancelSrv()
		echoCleanup()
		certCleanup()
		t.Fatalf("agent failed handshake: %v", err)
	}

	go ag.Handle(agCtx)

	time.Sleep(50 * time.Millisecond)

	cleanupAll := func() {
		cancelAg()
		cancelSrv()
		echoCleanup()
		certCleanup()
	}

	return publicAddr, cancelSrv, cleanupAll
}

func TestEndToEndTunnel(t *testing.T) {
	publicAddr, _, cleanup := setupTunnelEnvironment(t, "test-secret")
	defer cleanup()

	conn, err := net.Dial("tcp", publicAddr)
	if err != nil {
		t.Fatalf("failed to dial public endpoint: %v", err)
	}
	defer conn.Close()

	message := []byte("hello, secure tunnel over TLS!")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("failed to write to public endpoint: %v", err)
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read response from public endpoint: %v", err)
	}

	if !bytes.Equal(response, message) {
		t.Fatalf("expected echo %q, got %q", message, response)
	}
}

func TestEndToEndMultipleSequential(t *testing.T) {
	publicAddr, _, cleanup := setupTunnelEnvironment(t, "test-secret")
	defer cleanup()

	for i := range 5 {
		conn, err := net.Dial("tcp", publicAddr)
		if err != nil {
			t.Fatalf("iter %d: failed to dial public endpoint: %v", i, err)
		}

		msg := fmt.Sprintf("sequential request #%d", i)
		if _, err := conn.Write([]byte(msg)); err != nil {
			conn.Close()
			t.Fatalf("iter %d: write failed: %v", i, err)
		}

		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}

		resp, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			t.Fatalf("iter %d: read failed: %v", i, err)
		}

		if string(resp) != msg {
			t.Fatalf("iter %d: expected %q, got %q", i, msg, string(resp))
		}
	}
}

func TestEndToEndConcurrentClients(t *testing.T) {
	publicAddr, _, cleanup := setupTunnelEnvironment(t, "test-secret")
	defer cleanup()

	concurrency := 10
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := range concurrency {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", publicAddr)
			if err != nil {
				errCh <- fmt.Errorf("client %d dial error: %w", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("concurrent payload from client %d", id)
			if _, err := conn.Write([]byte(msg)); err != nil {
				errCh <- fmt.Errorf("client %d write error: %w", id, err)
				return
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.CloseWrite()
			}

			resp, err := io.ReadAll(conn)
			if err != nil {
				errCh <- fmt.Errorf("client %d read error: %w", id, err)
				return
			}
			if string(resp) != msg {
				errCh <- fmt.Errorf("client %d mismatch: got %q want %q", id, string(resp), msg)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

func TestAgentBadSecretRejected(t *testing.T) {
	nullLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	privLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	privateAddr := privLn.Addr().String()
	privLn.Close()

	certFile, keyFile, certCleanup := generateTestCertificate(t)
	defer certCleanup()

	srvCtx := t.Context()

	srv := server.New(nullLogger, server.Config{
		PublicEndpoint:  "127.0.0.1:0",
		PrivateEndpoint: privateAddr,
		Secret:          "correct-secret",
		TlsEnabled:      true,
		Cert:            certFile,
		Key:             keyFile,
	})
	go srv.Run(srvCtx)

	for range 30 {
		conn, err := net.Dial("tcp", privateAddr)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	ag := agent.New(nullLogger, agent.Config{
		ServerEndpoint:     privateAddr,
		LocalEndpoint:      "127.0.0.1:4444",
		Secret:             "wrong-secret",
		InsecureSkipVerify: true,
	})

	err = ag.HandleHandShake(t.Context())
	if err == nil {
		t.Fatalf("expected agent handshake to fail with bad secret, but it succeeded")
	}
}

func BenchmarkTunnelThroughput(b *testing.B) {
	publicAddr, _, cleanup := setupTunnelEnvironment(b, "bench-secret")
	defer cleanup()

	conn, err := net.Dial("tcp", publicAddr)
	if err != nil {
		b.Fatalf("failed to dial public endpoint: %v", err)
	}
	defer conn.Close()

	chunkSize := 64 * 1024 // 64KB chunk
	buf := make([]byte, chunkSize)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	recvBuf := make([]byte, chunkSize)

	b.SetBytes(int64(chunkSize))
	b.ResetTimer()

	for b.Loop() {
		if _, err := conn.Write(buf); err != nil {
			b.Fatalf("write failed: %v", err)
		}
		if _, err := io.ReadFull(conn, recvBuf); err != nil {
			b.Fatalf("read failed: %v", err)
		}
	}
}
