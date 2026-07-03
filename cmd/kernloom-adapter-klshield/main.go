// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/kernloom/kernloom-adapter-klshield/internal/adapter"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
	"google.golang.org/grpc"
)

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
	defaultRatePPS := fs.Uint64("default-rate-pps", adapter.DefaultRuntimeRatePPS, "per-source rate limit written for rate_limit_source actions")
	defaultBurst := fs.Uint64("default-burst", adapter.DefaultRuntimeBurst, "per-source burst written for rate_limit_source actions")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, err := runtimeMapStore(*runtimeStore, *bpffsRoot, *defaultRatePPS, *defaultBurst)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := grpc.NewServer()
	adapterv1.RegisterAdapterServiceServer(server, adapter.NewWithStore(store))
	fmt.Printf("kernloom-adapter-klshield serving gRPC on %s with %s runtime store\n", *addr, storeKind(store))
	if err := server.Serve(listener); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runtimeMapStore(kind, bpffsRoot string, defaultRatePPS, defaultBurst uint64) (adapter.RuntimeMapStore, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "memory":
		return adapter.NewMemoryRuntimeMapStore(), nil
	case "bpf":
		return adapter.NewBPFMapRuntimeStore(adapter.BPFMapRuntimeStoreConfig{
			BPFFSRoot:      bpffsRoot,
			DefaultRatePPS: defaultRatePPS,
			DefaultBurst:   defaultBurst,
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
