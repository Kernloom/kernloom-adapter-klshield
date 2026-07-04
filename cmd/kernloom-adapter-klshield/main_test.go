// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGRPCServerOptionsRejectsPlaintextWithoutDevFlag(t *testing.T) {
	_, err := grpcServerOptions(false, "", "", "")
	if err == nil || !strings.Contains(err.Error(), "requires --tls-cert") {
		t.Fatalf("expected mTLS material to be required, got %v", err)
	}
	opts, err := grpcServerOptions(true, "", "", "")
	if err != nil {
		t.Fatalf("expected explicit dev-insecure transport to be accepted, got %v", err)
	}
	if opts != nil {
		t.Fatalf("expected no server options in dev-insecure mode, got %#v", opts)
	}
}

func TestRuntimeAuthorityVerifierRequiresKeyOutsideDevSkip(t *testing.T) {
	_, err := runtimeAuthorityVerifier("", "", false)
	if err == nil || !strings.Contains(err.Error(), "authority-public-key") {
		t.Fatalf("expected authority key to be required, got %v", err)
	}
	verifier, err := runtimeAuthorityVerifier("", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal("expected dev verifier")
	}
}

func TestRuntimeAuthorityVerifierLoadsPublicKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authority.json")
	data, err := json.Marshal(map[string]string{
		"key_id":     "runtime-authority.test",
		"algorithm":  "Ed25519",
		"public_key": base64.StdEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := runtimeAuthorityVerifier(path, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal("expected verifier")
	}
}
