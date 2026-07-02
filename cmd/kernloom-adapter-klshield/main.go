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
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := grpc.NewServer()
	adapterv1.RegisterAdapterServiceServer(server, adapter.New())
	fmt.Printf("kernloom-adapter-klshield serving gRPC on %s\n", *addr)
	if err := server.Serve(listener); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
