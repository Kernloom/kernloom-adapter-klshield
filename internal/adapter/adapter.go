// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	adapterID = "kernloom.adapter.klshield"

	statusActive   = "active"
	statusExpired  = "expired"
	statusNotFound = "not_found"
	statusUnknown  = "unknown"

	actionRateLimitSource       = "runtime_action.rate_limit_source"
	actionDenyTemporarilySource = "runtime_action.deny_temporarily_source"

	mapRateLimit4 = "kernloom_rl_policy4"
	mapDeny4      = "kernloom_deny4_hash"
)

type Adapter struct {
	adapterv1.UnimplementedAdapterServiceServer
	store RuntimeMapStore
	now   func() time.Time
}

func New() *Adapter {
	return NewWithStore(NewMemoryRuntimeMapStore())
}

func NewWithStore(store RuntimeMapStore) *Adapter {
	if store == nil {
		store = NewMemoryRuntimeMapStore()
	}
	return &Adapter{store: store, now: time.Now}
}

type RuntimeMapEntry struct {
	RuntimeActionID   string
	IdempotencyKey    string
	AdapterID         string
	ActionType        string
	TargetScope       string
	TargetKey         string
	CapabilityID      string
	CorrelationID     string
	TTL               string
	Reason            string
	AuditID           string
	SourceCommit      string
	CapabilityGrantID string
	MapName           string
	Status            string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type RuntimeMapSelector struct {
	RuntimeActionID string
	IdempotencyKey  string
	AdapterID       string
	ActionType      string
	TargetScope     string
	TargetKey       string
	CapabilityID    string
	CorrelationID   string
}

type RuntimeMapStore interface {
	Upsert(ctx context.Context, entry RuntimeMapEntry) (RuntimeMapEntry, bool, error)
	Get(ctx context.Context, selector RuntimeMapSelector) (RuntimeMapEntry, bool, error)
	Revoke(ctx context.Context, selector RuntimeMapSelector, reason, auditID string, revokedAt time.Time) (RuntimeMapEntry, bool, error)
	Snapshot(ctx context.Context) ([]RuntimeMapEntry, error)
}

var _ RuntimeMapStore = (*MemoryRuntimeMapStore)(nil)

type runtimeStoreKind interface {
	Kind() string
}

type MemoryRuntimeMapStore struct {
	mu      sync.Mutex
	entries map[string]RuntimeMapEntry
}

func NewMemoryRuntimeMapStore() *MemoryRuntimeMapStore {
	return &MemoryRuntimeMapStore{entries: map[string]RuntimeMapEntry{}}
}

func (s *MemoryRuntimeMapStore) Kind() string {
	return "memory"
}

func (s *MemoryRuntimeMapStore) Upsert(_ context.Context, entry RuntimeMapEntry) (RuntimeMapEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.entries[entry.IdempotencyKey]
	if ok {
		return existing, true, nil
	}
	s.entries[entry.IdempotencyKey] = entry
	return entry, false, nil
}

func (s *MemoryRuntimeMapStore) Get(_ context.Context, selector RuntimeMapSelector) (RuntimeMapEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !selector.Valid() {
		return RuntimeMapEntry{}, false, nil
	}
	entry, ok := s.entries[selector.IdempotencyKey]
	if ok && entry.MatchesSelector(selector) {
		return entry, true, nil
	}
	if !ok || !entry.MatchesSelector(selector) {
		return entryFromSelector(selector, statusNotFound, time.Now().UTC()), true, nil
	}
	return RuntimeMapEntry{}, false, nil
}

func (s *MemoryRuntimeMapStore) Revoke(_ context.Context, selector RuntimeMapSelector, reason, auditID string, revokedAt time.Time) (RuntimeMapEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !selector.Valid() {
		return RuntimeMapEntry{}, false, nil
	}
	entry, ok := s.entries[selector.IdempotencyKey]
	if !ok || !entry.MatchesSelector(selector) {
		entry := entryFromSelector(selector, statusNotFound, revokedAt.UTC())
		entry.Reason = reason
		entry.AuditID = auditID
		return entry, true, nil
	}
	entry.Status = statusExpired
	entry.Reason = reason
	entry.AuditID = auditID
	entry.UpdatedAt = revokedAt.UTC()
	s.entries[selector.IdempotencyKey] = entry
	return entry, true, nil
}

func (s *MemoryRuntimeMapStore) Snapshot(_ context.Context) ([]RuntimeMapEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.entries))
	for key := range s.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make([]RuntimeMapEntry, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, s.entries[key])
	}
	return entries, nil
}

func (a *Adapter) Descriptor(context.Context) (*adapterv1.AdapterDescriptor, error) {
	return &adapterv1.AdapterDescriptor{
		AdapterId:       adapterID,
		Name:            "Kernloom KLShield Adapter",
		ProtocolVersion: adapterv1.ProtocolVersion,
		Capabilities: []*adapterv1.CapabilityDescriptor{
			{
				Id:             "klshield.runtime.source_mitigation",
				DisplayName:    "Apply temporary IPv4 source mitigations",
				Kind:           "runtime_executor",
				RuntimeActions: []string{actionRateLimitSource, actionDenyTemporarilySource},
			},
			{
				Id:          "klshield.runtime_action_state_signals",
				DisplayName: "Read adapter-managed runtime action state counts",
				Kind:        "signal_provider",
				Actions:     []string{"read_runtime_action_state_counts"},
			},
		},
		ContextRequirements: []*adapterv1.ContextRequirementDescriptor{
			{
				Fact:        "runtime bundle is signed",
				Freshness:   "bundle_expiry",
				Confidence:  "verified",
				Sensitivity: "runtime",
			},
		},
		Privileges: []*adapterv1.PrivilegeDescriptor{
			{
				Id:     "klshield.bpf.map.write",
				Reason: "Write approved, TTL-bound runtime actions into KLShield maps.",
				Scope:  "local_node",
				Access: "write_bpf_map",
			},
		},
		Facets: []string{
			adapterv1.FacetDescribe,
			adapterv1.FacetHealth,
			adapterv1.FacetReadSignals,
			adapterv1.FacetStreamSignals,
			adapterv1.FacetExecuteRuntimeAction,
			adapterv1.FacetGetRuntimeActionState,
			adapterv1.FacetRevokeRuntimeAction,
			adapterv1.FacetProvideConformanceEvidence,
		},
		FacetDescriptors: []*adapterv1.FacetDescriptor{
			{Name: adapterv1.FacetDescribe, Status: adapterv1.FacetStatusImplemented},
			{Name: adapterv1.FacetHealth, Status: adapterv1.FacetStatusImplemented},
			{Name: adapterv1.FacetReadSignals, Status: adapterv1.FacetStatusImplemented, Message: "Reports adapter-managed runtime action state counts only; packet, flow, drop and rate statistics are not implemented."},
			{Name: adapterv1.FacetStreamSignals, Status: adapterv1.FacetStatusImplemented, Message: "Streams one runtime action state-count snapshot from the configured KLShield runtime store."},
			{Name: adapterv1.FacetExecuteRuntimeAction, Status: adapterv1.FacetStatusImplemented, Message: "Applies TTL-bound runtime actions to the configured KLShield runtime store."},
			{Name: adapterv1.FacetGetRuntimeActionState, Status: adapterv1.FacetStatusImplemented, Message: "Returns configured-store read-back state."},
			{Name: adapterv1.FacetRevokeRuntimeAction, Status: adapterv1.FacetStatusImplemented, Message: "Removes runtime actions from the configured KLShield runtime store."},
			{Name: adapterv1.FacetProvideConformanceEvidence, Status: adapterv1.FacetStatusImplemented, Message: "Returns map write/read-back evidence from the configured KLShield runtime store."},
		},
	}, nil
}

func (a *Adapter) Describe(ctx context.Context, _ *adapterv1.DescribeRequest) (*adapterv1.DescribeResponse, error) {
	desc, err := a.Descriptor(ctx)
	if err != nil {
		return nil, err
	}
	return &adapterv1.DescribeResponse{Adapter: desc}, nil
}

func (a *Adapter) Health(context.Context, *adapterv1.HealthRequest) (*adapterv1.HealthResponse, error) {
	if checker, ok := a.store.(runtimeStoreHealthChecker); ok {
		if err := checker.CheckHealth(); err != nil {
			return &adapterv1.HealthResponse{
				Status:  adapterv1.HealthNotServing,
				Message: fmt.Sprintf("klshield adapter %s runtime store is not ready: %v", storeKind(a.store), err),
			}, nil
		}
	}
	return &adapterv1.HealthResponse{
		Status:  adapterv1.HealthServing,
		Message: fmt.Sprintf("klshield adapter is serving with %s runtime store", storeKind(a.store)),
	}, nil
}

func (a *Adapter) ExecuteRuntimeAction(ctx context.Context, req *adapterv1.ExecuteRuntimeActionRequest) (*adapterv1.ExecuteRuntimeActionResponse, error) {
	if req.GetIdempotencyKey() == "" {
		return &adapterv1.ExecuteRuntimeActionResponse{
			Status:   statusUnknown,
			Evidence: []*adapterv1.Evidence{inputEvidence("execute", "missing idempotency_key")},
		}, nil
	}
	actionType, mapName, err := normalizeAction(req.GetActionType())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := validateExecuteRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	now := a.now().UTC()
	entry := RuntimeMapEntry{
		RuntimeActionID:   req.GetRuntimeActionId(),
		IdempotencyKey:    req.GetIdempotencyKey(),
		AdapterID:         req.GetAdapterId(),
		ActionType:        actionType,
		TargetScope:       req.GetTargetScope(),
		TargetKey:         req.GetTargetKey(),
		CapabilityID:      req.GetCapabilityId(),
		CorrelationID:     req.GetCorrelationId(),
		TTL:               req.GetTtl(),
		Reason:            req.GetReason(),
		AuditID:           req.GetAuditId(),
		SourceCommit:      req.GetSourceCommit(),
		CapabilityGrantID: req.GetCapabilityGrantId(),
		MapName:           mapName,
		Status:            statusActive,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	stored, duplicate, err := a.store.Upsert(ctx, entry)
	if err != nil {
		return nil, err
	}
	if duplicate {
		return &adapterv1.ExecuteRuntimeActionResponse{
			Status:   stored.Status,
			Evidence: []*adapterv1.Evidence{a.evidenceFor(stored, "klshield.map_readback", "duplicate_readback")},
		}, nil
	}
	return &adapterv1.ExecuteRuntimeActionResponse{
		Status: statusActive,
		Evidence: []*adapterv1.Evidence{
			a.evidenceFor(stored, "klshield.map_write", "write"),
			a.evidenceFor(stored, "klshield.map_readback", "readback"),
		},
	}, nil
}

func (a *Adapter) GetRuntimeActionState(ctx context.Context, req *adapterv1.GetRuntimeActionStateRequest) (*adapterv1.GetRuntimeActionStateResponse, error) {
	selector := selectorFromStateRequest(req)
	if !selector.Valid() {
		return &adapterv1.GetRuntimeActionStateResponse{
			Status:   statusUnknown,
			Evidence: []*adapterv1.Evidence{inputEvidence("readback", "missing runtime action selector")},
		}, nil
	}
	entry, ok, err := a.store.Get(ctx, selector)
	if err != nil {
		return nil, err
	}
	if !ok {
		return &adapterv1.GetRuntimeActionStateResponse{
			Status:   statusUnknown,
			Evidence: []*adapterv1.Evidence{inputEvidence("readback", "runtime action not found")},
		}, nil
	}
	return &adapterv1.GetRuntimeActionStateResponse{
		Status:   entry.Status,
		Evidence: []*adapterv1.Evidence{a.evidenceFor(entry, "klshield.map_readback", "readback")},
	}, nil
}

func (a *Adapter) RevokeRuntimeAction(ctx context.Context, req *adapterv1.RevokeRuntimeActionRequest) (*adapterv1.RevokeRuntimeActionResponse, error) {
	selector := selectorFromRevokeRequest(req)
	if !selector.Valid() {
		return &adapterv1.RevokeRuntimeActionResponse{
			Status:   statusUnknown,
			Evidence: []*adapterv1.Evidence{inputEvidence("ttl_cleanup", "missing runtime action selector")},
		}, nil
	}
	entry, ok, err := a.store.Revoke(ctx, selector, req.GetReason(), req.GetAuditId(), a.now())
	if err != nil {
		return nil, err
	}
	if !ok {
		return &adapterv1.RevokeRuntimeActionResponse{
			Status:   statusUnknown,
			Evidence: []*adapterv1.Evidence{inputEvidence("ttl_cleanup", "runtime action not found")},
		}, nil
	}
	return &adapterv1.RevokeRuntimeActionResponse{
		Status:   entry.Status,
		Evidence: []*adapterv1.Evidence{a.evidenceFor(entry, "klshield.ttl_cleanup", "ttl_cleanup")},
	}, nil
}

func (a *Adapter) ReadSignals(ctx context.Context, req *adapterv1.ReadSignalsRequest) (*adapterv1.ReadSignalsResponse, error) {
	signal, err := a.signal(ctx, req.GetScope())
	if err != nil {
		return nil, err
	}
	return &adapterv1.ReadSignalsResponse{Signals: []*adapterv1.Signal{signal}}, nil
}

func (a *Adapter) StreamSignals(req *adapterv1.StreamSignalsRequest, stream grpc.ServerStreamingServer[adapterv1.StreamSignalsResponse]) error {
	signal, err := a.signal(stream.Context(), req.GetScope())
	if err != nil {
		return err
	}
	return stream.Send(&adapterv1.StreamSignalsResponse{Signal: signal})
}

func (a *Adapter) ProvideConformanceEvidence(ctx context.Context, _ *adapterv1.ProvideConformanceEvidenceRequest) (*adapterv1.ProvideConformanceEvidenceResponse, error) {
	entries, err := a.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	evidence := make([]*adapterv1.Evidence, 0, len(entries))
	for _, entry := range entries {
		evidenceType := "klshield.map_readback"
		operation := "readback"
		if entry.Status == statusExpired {
			evidenceType = "klshield.ttl_cleanup"
			operation = "ttl_cleanup"
		}
		evidence = append(evidence, a.evidenceFor(entry, evidenceType, operation))
	}
	return &adapterv1.ProvideConformanceEvidenceResponse{Evidence: evidence}, nil
}

func (a *Adapter) signal(ctx context.Context, scope string) (*adapterv1.Signal, error) {
	entries, err := a.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{
		statusActive:   0,
		statusExpired:  0,
		statusNotFound: 0,
		statusUnknown:  0,
	}
	for _, entry := range entries {
		counts[entry.Status]++
	}
	payload, _ := json.Marshal(map[string]any{
		"active_runtime_actions":    counts[statusActive],
		"expired_runtime_actions":   counts[statusExpired],
		"not_found_runtime_actions": counts[statusNotFound],
		"unknown_runtime_actions":   counts[statusUnknown],
	})
	return &adapterv1.Signal{
		Id:      "klshield.signal." + shortHash(scope+fmt.Sprint(counts)),
		Type:    "klshield.runtime_action_counts",
		Source:  adapterID,
		Scope:   scope,
		Payload: payload,
	}, nil
}

func validateExecuteRequest(req *adapterv1.ExecuteRuntimeActionRequest) error {
	required := map[string]string{
		"runtime_action_id":   req.GetRuntimeActionId(),
		"adapter_id":          req.GetAdapterId(),
		"capability_id":       req.GetCapabilityId(),
		"target_scope":        req.GetTargetScope(),
		"target_key":          req.GetTargetKey(),
		"ttl":                 req.GetTtl(),
		"reason":              req.GetReason(),
		"audit_id":            req.GetAuditId(),
		"source_commit":       req.GetSourceCommit(),
		"capability_grant_id": req.GetCapabilityGrantId(),
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if req.GetAdapterId() != adapterID {
		return fmt.Errorf("adapter_id %q is not served by this adapter", req.GetAdapterId())
	}
	ttl, err := time.ParseDuration(req.GetTtl())
	if err != nil {
		return fmt.Errorf("ttl %q is invalid: %w", req.GetTtl(), err)
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}
	if len(req.GetSignedBundle()) == 0 {
		return fmt.Errorf("signed_bundle is required")
	}
	return nil
}

func normalizeAction(actionType string) (string, string, error) {
	switch actionType {
	case actionRateLimitSource, "rate_limit_source":
		return actionRateLimitSource, mapRateLimit4, nil
	case actionDenyTemporarilySource, "deny_temporarily_source":
		return actionDenyTemporarilySource, mapDeny4, nil
	default:
		return "", "", fmt.Errorf("unsupported KLShield runtime action %q", actionType)
	}
}

func (a *Adapter) evidenceFor(entry RuntimeMapEntry, evidenceType, operation string) *adapterv1.Evidence {
	return evidenceFor(entry, evidenceType, operation, evidenceConfidence(a.store))
}

func evidenceFor(entry RuntimeMapEntry, evidenceType, operation, confidence string) *adapterv1.Evidence {
	payload, _ := json.Marshal(map[string]string{
		"operation":           operation,
		"runtime_action_id":   entry.RuntimeActionID,
		"idempotency_key":     entry.IdempotencyKey,
		"adapter_id":          entry.AdapterID,
		"action_type":         entry.ActionType,
		"target_scope":        entry.TargetScope,
		"target_key":          entry.TargetKey,
		"capability_id":       entry.CapabilityID,
		"correlation_id":      entry.CorrelationID,
		"ttl":                 entry.TTL,
		"status":              entry.Status,
		"map_name":            entry.MapName,
		"audit_id":            entry.AuditID,
		"source_commit":       entry.SourceCommit,
		"capability_grant_id": entry.CapabilityGrantID,
	})
	return &adapterv1.Evidence{
		Id:         "klshield.evidence." + shortHash(entry.IdempotencyKey+"."+operation+"."+entry.Status),
		Type:       evidenceType,
		Subject:    entry.IdempotencyKey,
		Freshness:  "immediate",
		Confidence: confidence,
		Payload:    payload,
	}
}

func storeKind(store RuntimeMapStore) string {
	if typed, ok := store.(runtimeStoreKind); ok {
		return typed.Kind()
	}
	return "unknown"
}

func evidenceConfidence(store RuntimeMapStore) string {
	if storeKind(store) == "bpf" {
		return "bpf_readback"
	}
	return "controlled_substitute"
}

type runtimeStoreHealthChecker interface {
	CheckHealth() error
}

func selectorFromStateRequest(req *adapterv1.GetRuntimeActionStateRequest) RuntimeMapSelector {
	if req == nil {
		return RuntimeMapSelector{}
	}
	return RuntimeMapSelector{
		RuntimeActionID: req.GetRuntimeActionId(),
		IdempotencyKey:  req.GetIdempotencyKey(),
		AdapterID:       req.GetAdapterId(),
		ActionType:      normalizeActionTypeForSelector(req.GetActionType()),
		TargetScope:     req.GetTargetScope(),
		TargetKey:       req.GetTargetKey(),
		CapabilityID:    req.GetCapabilityId(),
		CorrelationID:   req.GetCorrelationId(),
	}
}

func selectorFromRevokeRequest(req *adapterv1.RevokeRuntimeActionRequest) RuntimeMapSelector {
	if req == nil {
		return RuntimeMapSelector{}
	}
	return RuntimeMapSelector{
		RuntimeActionID: req.GetRuntimeActionId(),
		IdempotencyKey:  req.GetIdempotencyKey(),
		AdapterID:       req.GetAdapterId(),
		ActionType:      normalizeActionTypeForSelector(req.GetActionType()),
		TargetScope:     req.GetTargetScope(),
		TargetKey:       req.GetTargetKey(),
		CapabilityID:    req.GetCapabilityId(),
		CorrelationID:   req.GetCorrelationId(),
	}
}

func normalizeActionTypeForSelector(actionType string) string {
	normalized, _, err := normalizeAction(actionType)
	if err != nil {
		return actionType
	}
	return normalized
}

func (s RuntimeMapSelector) Valid() bool {
	return s.RuntimeActionID != "" &&
		s.IdempotencyKey != "" &&
		s.AdapterID != "" &&
		s.ActionType != "" &&
		s.TargetScope != "" &&
		s.TargetKey != "" &&
		s.CapabilityID != ""
}

func (entry RuntimeMapEntry) MatchesSelector(selector RuntimeMapSelector) bool {
	return entry.RuntimeActionID == selector.RuntimeActionID &&
		entry.IdempotencyKey == selector.IdempotencyKey &&
		entry.AdapterID == selector.AdapterID &&
		entry.ActionType == selector.ActionType &&
		entry.TargetScope == selector.TargetScope &&
		entry.TargetKey == selector.TargetKey &&
		entry.CapabilityID == selector.CapabilityID
}

func entryFromSelector(selector RuntimeMapSelector, status string, now time.Time) RuntimeMapEntry {
	_, mapName, _ := normalizeAction(selector.ActionType)
	return RuntimeMapEntry{
		RuntimeActionID: selector.RuntimeActionID,
		IdempotencyKey:  selector.IdempotencyKey,
		AdapterID:       selector.AdapterID,
		ActionType:      selector.ActionType,
		TargetScope:     selector.TargetScope,
		TargetKey:       selector.TargetKey,
		CapabilityID:    selector.CapabilityID,
		CorrelationID:   selector.CorrelationID,
		MapName:         mapName,
		Status:          status,
		UpdatedAt:       now.UTC(),
	}
}

func inputEvidence(operation, message string) *adapterv1.Evidence {
	payload, _ := json.Marshal(map[string]string{
		"operation": operation,
		"message":   message,
	})
	return &adapterv1.Evidence{
		Id:         "klshield.evidence." + shortHash(operation+"."+message),
		Type:       "klshield.input",
		Subject:    operation,
		Freshness:  "immediate",
		Confidence: "controlled_substitute",
		Payload:    payload,
	}
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}
