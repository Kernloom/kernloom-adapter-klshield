// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/kernloom/kernloom-adapter-klshield/internal/adapter"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serve(os.Args[2:])
		return
	}
	describe()
}

func describe() {
	desc, err := adapter.New().Descriptor(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(desc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(args []string) {
	fs := flag.NewFlagSet("kernloom-adapter-klshield serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:18082", "gRPC listen address")
	runtimeStore := fs.String("runtime-store", "memory", "runtime store backend: memory or bpf")
	bpffsRoot := fs.String("bpffs-root", adapter.DefaultBPFFSRoot, "BPF filesystem root for pinned KLShield maps")
	defaultRatePPS := fs.Uint64("default-rate-pps", adapter.DefaultRuntimeRatePPS, "dev fallback per-source rate limit; used only with --dev-allow-default-rate-limit-parameters")
	defaultBurst := fs.Uint64("default-burst", adapter.DefaultRuntimeBurst, "dev fallback per-source burst; used only with --dev-allow-default-rate-limit-parameters")
	devAllowDefaultRateLimitParameters := fs.Bool("dev-allow-default-rate-limit-parameters", false, "allow adapter defaults for missing signed rate_limit parameters; dev/smoke only")
	devInsecureTransport := fs.Bool("dev-insecure-transport", false, "allow plaintext gRPC transport; dev/smoke only")
	tlsCert := fs.String("tls-cert", "", "server TLS certificate for adapter mTLS")
	tlsKey := fs.String("tls-key", "", "server TLS private key for adapter mTLS")
	clientCA := fs.String("client-ca", "", "client CA bundle for adapter mTLS")
	authorityPublicKey := fs.String("authority-public-key", "", "JSON file containing runtime authority Ed25519 public key")
	authorityKeyID := fs.String("authority-key-id", "", "expected runtime authority key_id; optional when present in --authority-public-key")
	devSkipAuthorityVerification := fs.Bool("dev-insecure-skip-authority-verification", false, "skip signed runtime authority verification; dev/smoke only")
	manifestDigest := fs.String("manifest-digest", os.Getenv("KERNLOOM_ADAPTER_MANIFEST_DIGEST"), "sha256 digest of the adapter manifest reported by Describe")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	authority, err := runtimeAuthorityVerifier(*authorityPublicKey, *authorityKeyID, *devSkipAuthorityVerification)
	if err != nil {
		logger.Error("klshield_adapter_authority_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, err := runtimeMapStore(*runtimeStore, *bpffsRoot, *defaultRatePPS, *defaultBurst, *devAllowDefaultRateLimitParameters)
	if err != nil {
		logger.Error("klshield_adapter_store_failed", "runtime_store", *runtimeStore, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	serverOptions, err := grpcServerOptions(*devInsecureTransport, *tlsCert, *tlsKey, *clientCA)
	if err != nil {
		logger.Error("klshield_adapter_transport_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Error("klshield_adapter_listen_failed", "addr", *addr, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := grpc.NewServer(serverOptions...)
	adapterv1.RegisterAdapterServiceServer(server, adapter.NewWithStoreAuthorityAndManifestDigest(store, authority, *manifestDigest))
	logger.Info("adapter_server_starting", "adapter_id", "kernloom.adapter.klshield", "addr", *addr, "runtime_store", storeKind(store), "dev_insecure_transport", *devInsecureTransport, "dev_insecure_authority", *devSkipAuthorityVerification, "dev_allow_default_rate_limit_parameters", *devAllowDefaultRateLimitParameters)
	if err := server.Serve(listener); err != nil {
		logger.Error("adapter_server_failed", "adapter_id", "kernloom.adapter.klshield", "addr", *addr, "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func grpcServerOptions(devInsecure bool, certPath, keyPath, clientCAPath string) ([]grpc.ServerOption, error) {
	if devInsecure {
		return nil, nil
	}
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" || strings.TrimSpace(clientCAPath) == "" {
		return nil, fmt.Errorf("adapter server requires --tls-cert, --tls-key and --client-ca unless --dev-insecure-transport is set")
	}
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	clientCAPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, err
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, fmt.Errorf("client CA %q does not contain a PEM certificate", clientCAPath)
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(config))}, nil
}

func runtimeAuthorityVerifier(publicKeyPath, keyID string, devSkip bool) (adapter.RuntimeAuthorityVerifier, error) {
	if devSkip {
		return adapter.DevInsecureRuntimeAuthorityVerifier{}, nil
	}
	publicKeyPath = strings.TrimSpace(publicKeyPath)
	if publicKeyPath == "" {
		return nil, fmt.Errorf("adapter server requires --authority-public-key unless --dev-insecure-skip-authority-verification is set")
	}
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}
	var file struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if strings.TrimSpace(keyID) == "" {
		keyID = file.KeyID
	}
	if strings.TrimSpace(file.Algorithm) != "" && file.Algorithm != "Ed25519" {
		return nil, fmt.Errorf("runtime authority key algorithm %q is not Ed25519", file.Algorithm)
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(file.PublicKey))
	if err != nil {
		return nil, err
	}
	return adapter.NewStaticRuntimeAuthorityVerifier(keyID, publicKey)
}

func runtimeMapStore(kind, bpffsRoot string, defaultRatePPS, defaultBurst uint64, allowDefaultRateLimitFallback bool) (adapter.RuntimeMapStore, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "memory":
		return adapter.NewMemoryRuntimeMapStore(), nil
	case "bpf":
		return adapter.NewBPFMapRuntimeStore(adapter.BPFMapRuntimeStoreConfig{
			BPFFSRoot:                     bpffsRoot,
			DefaultRatePPS:                defaultRatePPS,
			DefaultBurst:                  defaultBurst,
			AllowDefaultRateLimitFallback: allowDefaultRateLimitFallback,
		})
	default:
		return nil, fmt.Errorf("unknown runtime store %q; expected memory or bpf", kind)
	}
}

func storeKind(store adapter.RuntimeMapStore) string {
	type runtimeStoreKind interface {
		Kind() string
	}
	if typed, ok := store.(runtimeStoreKind); ok {
		return typed.Kind()
	}
	return "unknown"
}
