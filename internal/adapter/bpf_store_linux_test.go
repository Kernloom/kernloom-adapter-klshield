// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

//go:build linux

package adapter

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBPFMapRuntimeStoreDefaults(t *testing.T) {
	store, err := NewBPFMapRuntimeStore(BPFMapRuntimeStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if store.Kind() != "bpf" {
		t.Fatalf("expected bpf kind, got %q", store.Kind())
	}
	if store.root != DefaultBPFFSRoot {
		t.Fatalf("expected default bpffs root %q, got %q", DefaultBPFFSRoot, store.root)
	}
	if store.defaultRatePPS != DefaultRuntimeRatePPS || store.defaultBurst != DefaultRuntimeBurst {
		t.Fatalf("expected default rate config, got rate=%d burst=%d", store.defaultRatePPS, store.defaultBurst)
	}
	if store.allowDefaultRateLimitFallback {
		t.Fatal("expected default rate-limit fallback to be disabled by default")
	}
}

func TestBPFMapRuntimeStoreRejectsRateLimitWithoutSignedParameters(t *testing.T) {
	store := newTestBPFMapRuntimeStore(t, newFakeBPFBackend())
	_, _, err := store.Upsert(context.Background(), RuntimeMapEntry{
		RuntimeActionID: "runtime_action.missing-rate-params",
		IdempotencyKey:  "idem.missing-rate-params",
		AdapterID:       adapterID,
		ActionType:      actionRateLimitSource,
		TargetScope:     "source",
		TargetKey:       "192.0.2.10",
		CapabilityID:    "klshield.runtime.source_mitigation",
		MapName:         mapRateLimit4,
		Status:          statusActive,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	})
	if err == nil || !strings.Contains(err.Error(), "rate_limit.rate_pps") {
		t.Fatalf("expected missing signed rate limit parameters to be rejected, got %v", err)
	}
}

func TestBPFMapRuntimeStoreAllowsExplicitDevRateLimitFallback(t *testing.T) {
	backend := newFakeBPFBackend()
	store, err := NewBPFMapRuntimeStore(BPFMapRuntimeStoreConfig{AllowDefaultRateLimitFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	store.backend = backend
	_, _, err = store.Upsert(context.Background(), RuntimeMapEntry{
		RuntimeActionID: "runtime_action.dev-fallback-rate",
		IdempotencyKey:  "idem.dev-fallback-rate",
		AdapterID:       adapterID,
		ActionType:      actionRateLimitSource,
		TargetScope:     "source",
		TargetKey:       "192.0.2.10",
		CapabilityID:    "klshield.runtime.source_mitigation",
		MapName:         mapRateLimit4,
		Status:          statusActive,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := backend.LookupRateLimit4(bpfKey4Bytes{IP: [4]byte{192, 0, 2, 10}})
	if err != nil {
		t.Fatal(err)
	}
	if !found || value.RatePPS != DefaultRuntimeRatePPS || value.Burst != DefaultRuntimeBurst {
		t.Fatalf("expected dev fallback rate values, found=%t value=%#v", found, value)
	}
}

func TestBPFMapRuntimeStoreRejectsNonIPv4TargetsBeforeMapOpen(t *testing.T) {
	store, err := NewBPFMapRuntimeStore(BPFMapRuntimeStoreConfig{BPFFSRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.Upsert(context.Background(), RuntimeMapEntry{
		RuntimeActionID: "runtime_action.invalid-target",
		IdempotencyKey:  "idem.invalid-target",
		AdapterID:       adapterID,
		ActionType:      actionDenyTemporarilySource,
		TargetScope:     "source",
		TargetKey:       "not-an-ip",
		CapabilityID:    "klshield.runtime.source_mitigation",
		MapName:         mapDeny4,
		Status:          statusActive,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected non-IPv4 target to be rejected")
	}
	if !strings.Contains(err.Error(), "must be an IPv4 source address") {
		t.Fatalf("expected IPv4 validation error, got %v", err)
	}
}

func TestBPFMapRuntimeStoreReportsMissingPinnedMap(t *testing.T) {
	store, err := NewBPFMapRuntimeStore(BPFMapRuntimeStoreConfig{BPFFSRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.Upsert(context.Background(), RuntimeMapEntry{
		RuntimeActionID: "runtime_action.missing-map",
		IdempotencyKey:  "idem.missing-map",
		AdapterID:       adapterID,
		ActionType:      actionDenyTemporarilySource,
		TargetScope:     "source",
		TargetKey:       "192.0.2.10",
		CapabilityID:    "klshield.runtime.source_mitigation",
		MapName:         mapDeny4,
		Status:          statusActive,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected missing pinned map error")
	}
	if !strings.Contains(err.Error(), "open "+mapDeny4) {
		t.Fatalf("expected missing map open error, got %v", err)
	}
}

func TestBPFMapRuntimeStoreRevokesAfterAdapterRestartWithSelector(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBPFBackend()
	store := newTestBPFMapRuntimeStore(t, backend)
	entry := RuntimeMapEntry{
		RuntimeActionID: "runtime_action.restart",
		IdempotencyKey:  "idem.restart",
		AdapterID:       adapterID,
		ActionType:      actionDenyTemporarilySource,
		TargetScope:     "source",
		TargetKey:       "192.0.2.10",
		CapabilityID:    "klshield.runtime.source_mitigation",
		MapName:         mapDeny4,
		Status:          statusActive,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	if _, _, err := store.Upsert(ctx, entry); err != nil {
		t.Fatal(err)
	}

	restarted := newTestBPFMapRuntimeStore(t, backend)
	revoked, ok, err := restarted.Revoke(ctx, RuntimeMapSelector{
		RuntimeActionID: entry.RuntimeActionID,
		IdempotencyKey:  entry.IdempotencyKey,
		AdapterID:       entry.AdapterID,
		ActionType:      entry.ActionType,
		TargetScope:     entry.TargetScope,
		TargetKey:       entry.TargetKey,
		CapabilityID:    entry.CapabilityID,
	}, "ttl expired", "audit.restart", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !ok || revoked.Status != statusExpired {
		t.Fatalf("expected restarted store to revoke by selector, ok=%t entry=%#v", ok, revoked)
	}

	readbackAfterRestart := newTestBPFMapRuntimeStore(t, backend)
	state, ok, err := readbackAfterRestart.Get(ctx, RuntimeMapSelector{
		RuntimeActionID: entry.RuntimeActionID,
		IdempotencyKey:  entry.IdempotencyKey,
		AdapterID:       entry.AdapterID,
		ActionType:      entry.ActionType,
		TargetScope:     entry.TargetScope,
		TargetKey:       entry.TargetKey,
		CapabilityID:    entry.CapabilityID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || state.Status != statusNotFound {
		t.Fatalf("expected deleted BPF key to read back not_found, ok=%t entry=%#v", ok, state)
	}
}

func TestBPFMapRuntimeStoreRevokeMissingKeyIsNotFound(t *testing.T) {
	store := newTestBPFMapRuntimeStore(t, newFakeBPFBackend())
	entry, ok, err := store.Revoke(context.Background(), RuntimeMapSelector{
		RuntimeActionID: "runtime_action.missing-key",
		IdempotencyKey:  "idem.missing-key",
		AdapterID:       adapterID,
		ActionType:      actionDenyTemporarilySource,
		TargetScope:     "source",
		TargetKey:       "192.0.2.11",
		CapabilityID:    "klshield.runtime.source_mitigation",
	}, "ttl expired", "audit.missing-key", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !ok || entry.Status != statusNotFound {
		t.Fatalf("expected missing BPF key to be idempotent not_found, ok=%t entry=%#v", ok, entry)
	}
}

func TestBPFHealthReportsMissingPinnedMaps(t *testing.T) {
	store, err := NewBPFMapRuntimeStore(BPFMapRuntimeStoreConfig{BPFFSRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewWithStore(store).Health(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != "not_serving" {
		t.Fatalf("expected not_serving health for missing pinned maps, got %#v", resp)
	}
}

func newTestBPFMapRuntimeStore(t *testing.T, backend *fakeBPFBackend) *BPFMapRuntimeStore {
	t.Helper()
	store, err := NewBPFMapRuntimeStore(BPFMapRuntimeStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	store.backend = backend
	return store
}

type fakeBPFBackend struct {
	rlPolicy4 map[bpfKey4Bytes]bpfRLCfg
	deny4     map[bpfKey4Bytes]uint8
}

func newFakeBPFBackend() *fakeBPFBackend {
	return &fakeBPFBackend{
		rlPolicy4: map[bpfKey4Bytes]bpfRLCfg{},
		deny4:     map[bpfKey4Bytes]uint8{},
	}
}

func (b *fakeBPFBackend) UpdateRateLimit4(key bpfKey4Bytes, value bpfRLCfg) error {
	b.rlPolicy4[key] = value
	return nil
}

func (b *fakeBPFBackend) LookupRateLimit4(key bpfKey4Bytes) (bpfRLCfg, bool, error) {
	value, ok := b.rlPolicy4[key]
	return value, ok, nil
}

func (b *fakeBPFBackend) DeleteRateLimit4(key bpfKey4Bytes) (bool, error) {
	_, ok := b.rlPolicy4[key]
	delete(b.rlPolicy4, key)
	return ok, nil
}

func (b *fakeBPFBackend) UpdateDeny4(key bpfKey4Bytes, value uint8) error {
	b.deny4[key] = value
	return nil
}

func (b *fakeBPFBackend) LookupDeny4(key bpfKey4Bytes) (uint8, bool, error) {
	value, ok := b.deny4[key]
	return value, ok, nil
}

func (b *fakeBPFBackend) DeleteDeny4(key bpfKey4Bytes) (bool, error) {
	_, ok := b.deny4[key]
	delete(b.deny4, key)
	return ok, nil
}

func (b *fakeBPFBackend) CheckHealth() error {
	return nil
}
