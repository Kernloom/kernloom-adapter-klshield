// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

//go:build linux

package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

type BPFMapRuntimeStore struct {
	root                          string
	defaultRatePPS                uint64
	defaultBurst                  uint64
	allowDefaultRateLimitFallback bool
	backend                       bpfRuntimeMapBackend
	mu                            sync.Mutex
	entries                       map[string]RuntimeMapEntry
}

var _ RuntimeMapStore = (*BPFMapRuntimeStore)(nil)

type bpfKey4Bytes struct{ IP [4]byte }

type bpfRLCfg struct {
	RatePPS uint64
	Burst   uint64
}

type bpfRuntimeMapBackend interface {
	UpdateRateLimit4(key bpfKey4Bytes, value bpfRLCfg) error
	LookupRateLimit4(key bpfKey4Bytes) (bpfRLCfg, bool, error)
	DeleteRateLimit4(key bpfKey4Bytes) (bool, error)
	UpdateDeny4(key bpfKey4Bytes, value uint8) error
	LookupDeny4(key bpfKey4Bytes) (uint8, bool, error)
	DeleteDeny4(key bpfKey4Bytes) (bool, error)
	CheckHealth() error
}

type pinnedBPFMapBackend struct {
	root string
}

func NewBPFMapRuntimeStore(config BPFMapRuntimeStoreConfig) (*BPFMapRuntimeStore, error) {
	root := strings.TrimSpace(config.BPFFSRoot)
	if root == "" {
		root = DefaultBPFFSRoot
	}
	rate := config.DefaultRatePPS
	if rate == 0 {
		rate = DefaultRuntimeRatePPS
	}
	burst := config.DefaultBurst
	if burst == 0 {
		burst = DefaultRuntimeBurst
	}
	return &BPFMapRuntimeStore{
		root:                          root,
		defaultRatePPS:                rate,
		defaultBurst:                  burst,
		allowDefaultRateLimitFallback: config.AllowDefaultRateLimitFallback,
		backend:                       pinnedBPFMapBackend{root: root},
		entries:                       map[string]RuntimeMapEntry{},
	}, nil
}

func (s *BPFMapRuntimeStore) Kind() string {
	return "bpf"
}

func (s *BPFMapRuntimeStore) RateLimitFallback() (uint64, uint64, bool) {
	return s.defaultRatePPS, s.defaultBurst, s.allowDefaultRateLimitFallback
}

func (s *BPFMapRuntimeStore) Upsert(_ context.Context, entry RuntimeMapEntry) (RuntimeMapEntry, bool, error) {
	if _, err := runtimeIPv4Key(entry.TargetKey); err != nil {
		return RuntimeMapEntry{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.entries[entry.IdempotencyKey]; ok {
		if existing.Status != statusExpired {
			if err := s.writeLocked(existing); err != nil {
				return RuntimeMapEntry{}, false, err
			}
			status, err := s.readStatusLocked(existing)
			if err != nil {
				return RuntimeMapEntry{}, false, err
			}
			existing.Status = status
			existing.UpdatedAt = time.Now().UTC()
			s.entries[entry.IdempotencyKey] = existing
		}
		return existing, true, nil
	}

	if entry.MapName == "" {
		_, mapName, err := normalizeAction(entry.ActionType)
		if err != nil {
			return RuntimeMapEntry{}, false, err
		}
		entry.MapName = mapName
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	entry.UpdatedAt = time.Now().UTC()
	entry.Status = statusActive

	if err := s.writeLocked(entry); err != nil {
		return RuntimeMapEntry{}, false, err
	}
	status, err := s.readStatusLocked(entry)
	if err != nil {
		return RuntimeMapEntry{}, false, err
	}
	if status != statusActive {
		return RuntimeMapEntry{}, false, fmt.Errorf("klshield bpf readback did not find active entry for %s in %s", entry.TargetKey, entry.MapName)
	}

	s.entries[entry.IdempotencyKey] = entry
	return entry, false, nil
}

func (s *BPFMapRuntimeStore) CheckHealth() error {
	return s.backend.CheckHealth()
}

func (s *BPFMapRuntimeStore) Get(_ context.Context, selector RuntimeMapSelector) (RuntimeMapEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !selector.Valid() {
		return RuntimeMapEntry{}, false, nil
	}
	entry, ok := s.entries[selector.IdempotencyKey]
	if !ok || !entry.MatchesSelector(selector) {
		entry = entryFromSelector(selector, statusUnknown, time.Now().UTC())
	}
	if entry.Status != statusExpired {
		status, err := s.readStatusLocked(entry)
		if err != nil {
			return RuntimeMapEntry{}, false, err
		}
		entry.Status = status
		entry.UpdatedAt = time.Now().UTC()
		s.entries[selector.IdempotencyKey] = entry
	}
	return entry, true, nil
}

func (s *BPFMapRuntimeStore) Revoke(_ context.Context, selector RuntimeMapSelector, reason, auditID string, revokedAt time.Time) (RuntimeMapEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !selector.Valid() {
		return RuntimeMapEntry{}, false, nil
	}
	entry, ok := s.entries[selector.IdempotencyKey]
	if !ok || !entry.MatchesSelector(selector) {
		entry = entryFromSelector(selector, statusUnknown, revokedAt.UTC())
	}

	switch entry.Status {
	case statusExpired, statusNotFound:
	default:
		status, err := s.deleteLocked(entry)
		if err != nil {
			return RuntimeMapEntry{}, false, err
		}
		entry.Status = status
	}
	entry.Reason = reason
	entry.AuditID = auditID
	entry.UpdatedAt = revokedAt.UTC()
	s.entries[selector.IdempotencyKey] = entry
	return entry, true, nil
}

func (s *BPFMapRuntimeStore) Snapshot(_ context.Context) ([]RuntimeMapEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := make([]string, 0, len(s.entries))
	for key := range s.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make([]RuntimeMapEntry, 0, len(keys))
	for _, key := range keys {
		entry := s.entries[key]
		if entry.Status != statusExpired {
			status, err := s.readStatusLocked(entry)
			if err != nil {
				return nil, err
			}
			entry.Status = status
			entry.UpdatedAt = time.Now().UTC()
			s.entries[key] = entry
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *BPFMapRuntimeStore) writeLocked(entry RuntimeMapEntry) error {
	key, err := runtimeIPv4Key(entry.TargetKey)
	if err != nil {
		return err
	}

	switch entry.ActionType {
	case actionRateLimitSource:
		ratePPS := entry.RatePPS
		burst := entry.Burst
		if (ratePPS == 0 || burst == 0) && s.allowDefaultRateLimitFallback {
			ratePPS = s.defaultRatePPS
			burst = s.defaultBurst
		}
		if ratePPS == 0 || burst == 0 {
			return fmt.Errorf("rate_limit_source requires signed rate_limit.rate_pps and rate_limit.burst")
		}
		value := bpfRLCfg{RatePPS: ratePPS, Burst: burst}
		if err := s.backend.UpdateRateLimit4(key, value); err != nil {
			return fmt.Errorf("write %s target %s: %w", mapRateLimit4, entry.TargetKey, err)
		}
		return nil
	case actionDenyTemporarilySource:
		value := uint8(1)
		if err := s.backend.UpdateDeny4(key, value); err != nil {
			return fmt.Errorf("write %s target %s: %w", mapDeny4, entry.TargetKey, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported KLShield runtime action %q", entry.ActionType)
	}
}

func (s *BPFMapRuntimeStore) readStatusLocked(entry RuntimeMapEntry) (string, error) {
	key, err := runtimeIPv4Key(entry.TargetKey)
	if err != nil {
		return statusUnknown, err
	}

	switch entry.ActionType {
	case actionRateLimitSource:
		value, found, err := s.backend.LookupRateLimit4(key)
		if err != nil {
			return statusUnknown, fmt.Errorf("read %s target %s: %w", mapRateLimit4, entry.TargetKey, err)
		}
		if !found {
			return statusNotFound, nil
		}
		if value.RatePPS == 0 || value.Burst == 0 {
			return statusNotFound, nil
		}
		return statusActive, nil
	case actionDenyTemporarilySource:
		value, found, err := s.backend.LookupDeny4(key)
		if err != nil {
			return statusUnknown, fmt.Errorf("read %s target %s: %w", mapDeny4, entry.TargetKey, err)
		}
		if !found {
			return statusNotFound, nil
		}
		if value == 0 {
			return statusNotFound, nil
		}
		return statusActive, nil
	default:
		return statusUnknown, fmt.Errorf("unsupported KLShield runtime action %q", entry.ActionType)
	}
}

func (s *BPFMapRuntimeStore) deleteLocked(entry RuntimeMapEntry) (string, error) {
	key, err := runtimeIPv4Key(entry.TargetKey)
	if err != nil {
		return statusUnknown, err
	}

	switch entry.ActionType {
	case actionRateLimitSource:
		found, err := s.backend.DeleteRateLimit4(key)
		if err != nil {
			return statusUnknown, fmt.Errorf("delete %s target %s: %w", mapRateLimit4, entry.TargetKey, err)
		}
		if !found {
			return statusNotFound, nil
		}
		return statusExpired, nil
	case actionDenyTemporarilySource:
		found, err := s.backend.DeleteDeny4(key)
		if err != nil {
			return statusUnknown, fmt.Errorf("delete %s target %s: %w", mapDeny4, entry.TargetKey, err)
		}
		if !found {
			return statusNotFound, nil
		}
		return statusExpired, nil
	default:
		return statusUnknown, fmt.Errorf("unsupported KLShield runtime action %q", entry.ActionType)
	}
}

func (b pinnedBPFMapBackend) UpdateRateLimit4(key bpfKey4Bytes, value bpfRLCfg) error {
	m, err := b.openPinnedMap(mapRateLimit4)
	if err != nil {
		return fmt.Errorf("open %s: %w", mapRateLimit4, err)
	}
	defer m.Close()
	return m.Update(&key, &value, ebpf.UpdateAny)
}

func (b pinnedBPFMapBackend) LookupRateLimit4(key bpfKey4Bytes) (bpfRLCfg, bool, error) {
	m, err := b.openPinnedMap(mapRateLimit4)
	if err != nil {
		return bpfRLCfg{}, false, fmt.Errorf("open %s: %w", mapRateLimit4, err)
	}
	defer m.Close()
	var value bpfRLCfg
	if err := m.Lookup(&key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return bpfRLCfg{}, false, nil
		}
		return bpfRLCfg{}, false, err
	}
	return value, true, nil
}

func (b pinnedBPFMapBackend) DeleteRateLimit4(key bpfKey4Bytes) (bool, error) {
	m, err := b.openPinnedMap(mapRateLimit4)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", mapRateLimit4, err)
	}
	defer m.Close()
	if err := m.Delete(&key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b pinnedBPFMapBackend) UpdateDeny4(key bpfKey4Bytes, value uint8) error {
	m, err := b.openPinnedMap(mapDeny4)
	if err != nil {
		return fmt.Errorf("open %s: %w", mapDeny4, err)
	}
	defer m.Close()
	return m.Update(&key, &value, ebpf.UpdateAny)
}

func (b pinnedBPFMapBackend) LookupDeny4(key bpfKey4Bytes) (uint8, bool, error) {
	m, err := b.openPinnedMap(mapDeny4)
	if err != nil {
		return 0, false, fmt.Errorf("open %s: %w", mapDeny4, err)
	}
	defer m.Close()
	var value uint8
	if err := m.Lookup(&key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return value, true, nil
}

func (b pinnedBPFMapBackend) DeleteDeny4(key bpfKey4Bytes) (bool, error) {
	m, err := b.openPinnedMap(mapDeny4)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", mapDeny4, err)
	}
	defer m.Close()
	if err := m.Delete(&key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b pinnedBPFMapBackend) CheckHealth() error {
	for _, name := range []string{mapRateLimit4, mapDeny4} {
		m, err := b.openPinnedMap(name)
		if err != nil {
			return fmt.Errorf("open %s: %w", name, err)
		}
		m.Close()
	}
	return nil
}

func (b pinnedBPFMapBackend) openPinnedMap(name string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(b.root, name), nil)
}

func runtimeIPv4Key(targetKey string) (bpfKey4Bytes, error) {
	ip := net.ParseIP(strings.TrimSpace(targetKey))
	if ip == nil {
		return bpfKey4Bytes{}, fmt.Errorf("klshield bpf runtime target_key %q must be an IPv4 source address", targetKey)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return bpfKey4Bytes{}, fmt.Errorf("klshield bpf runtime target_key %q must be an IPv4 source address", targetKey)
	}
	var key bpfKey4Bytes
	copy(key.IP[:], ip4)
	return key, nil
}
