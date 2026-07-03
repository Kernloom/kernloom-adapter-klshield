// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapter

import (
	"context"
	"testing"
	"time"

	contractv1 "github.com/kernloom/kernloom-protocol/contract/adapter/v1"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
)

func TestAdapterPassesServiceContract(t *testing.T) {
	contractv1.RunServiceContract(t, New())
}

func TestExecuteRuntimeActionRateLimitAndReadback(t *testing.T) {
	ctx := context.Background()
	adapter := New()
	req := validExecuteRequest("runtime_action.rate_limit_source", "source-1", "idem-rate-limit")

	resp, err := adapter.ExecuteRuntimeAction(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != statusActive {
		t.Fatalf("expected active status, got %q", resp.GetStatus())
	}
	assertEvidenceType(t, resp.GetEvidence(), "klshield.map_write")
	assertEvidenceType(t, resp.GetEvidence(), "klshield.map_readback")

	state, err := adapter.GetRuntimeActionState(ctx, stateRequestFor(req))
	if err != nil {
		t.Fatal(err)
	}
	if state.GetStatus() != statusActive {
		t.Fatalf("expected active readback, got %q", state.GetStatus())
	}
	assertEvidenceType(t, state.GetEvidence(), "klshield.map_readback")
}

func TestExecuteRuntimeActionDenyTemporarily(t *testing.T) {
	ctx := context.Background()
	adapter := New()
	resp, err := adapter.ExecuteRuntimeAction(ctx, validExecuteRequest("runtime_action.deny_temporarily_source", "source-2", "idem-deny"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != statusActive {
		t.Fatalf("expected active status, got %q", resp.GetStatus())
	}
	assertEvidenceType(t, resp.GetEvidence(), "klshield.map_write")
}

func TestExecuteRuntimeActionDuplicateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	adapter := New()
	first := validExecuteRequest("runtime_action.rate_limit_source", "source-dup", "idem-dup")
	if _, err := adapter.ExecuteRuntimeAction(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := validExecuteRequest("runtime_action.rate_limit_source", "source-dup", "idem-dup")
	second.Ttl = "10m"
	resp, err := adapter.ExecuteRuntimeAction(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != statusActive {
		t.Fatalf("expected active duplicate status, got %q", resp.GetStatus())
	}
	assertEvidenceType(t, resp.GetEvidence(), "klshield.map_readback")
	entry, ok, err := adapter.store.Get(ctx, selectorFor(first))
	if err != nil {
		t.Fatal(err)
	}
	if !ok || entry.TTL != first.GetTtl() {
		t.Fatalf("expected duplicate not to extend ttl, got ok=%t entry=%#v", ok, entry)
	}
}

func TestRevokeRuntimeActionProducesTTLCleanupEvidence(t *testing.T) {
	ctx := context.Background()
	adapter := New()
	req := validExecuteRequest("runtime_action.deny_temporarily_source", "source-cleanup", "idem-cleanup")
	if _, err := adapter.ExecuteRuntimeAction(ctx, req); err != nil {
		t.Fatal(err)
	}
	resp, err := adapter.RevokeRuntimeAction(ctx, revokeRequestFor(req, "ttl expired", "audit.cleanup"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != statusExpired {
		t.Fatalf("expected expired status, got %q", resp.GetStatus())
	}
	assertEvidenceType(t, resp.GetEvidence(), "klshield.ttl_cleanup")
	state, err := adapter.GetRuntimeActionState(ctx, stateRequestFor(req))
	if err != nil {
		t.Fatal(err)
	}
	if state.GetStatus() != statusExpired {
		t.Fatalf("expected expired readback, got %q", state.GetStatus())
	}
}

func TestRuntimeActionRejectsUnsupportedAction(t *testing.T) {
	adapter := New()
	req := validExecuteRequest("runtime_action.unsupported", "source-3", "idem-unsupported")
	if _, err := adapter.ExecuteRuntimeAction(context.Background(), req); err == nil {
		t.Fatal("expected unsupported action to be rejected")
	}
}

func TestRuntimeActionRejectsMissingSignedBundle(t *testing.T) {
	adapter := New()
	req := validExecuteRequest("runtime_action.rate_limit_source", "source-no-bundle", "idem-no-bundle")
	req.SignedBundle = nil
	if _, err := adapter.ExecuteRuntimeAction(context.Background(), req); err == nil {
		t.Fatal("expected missing signed_bundle to be rejected")
	}
}

func TestSignalsAndConformanceEvidenceUseControlledStore(t *testing.T) {
	ctx := context.Background()
	adapter := New()
	if _, err := adapter.ExecuteRuntimeAction(ctx, validExecuteRequest("runtime_action.rate_limit_source", "source-signal", "idem-signal")); err != nil {
		t.Fatal(err)
	}
	signals, err := adapter.ReadSignals(ctx, &adapterv1.ReadSignalsRequest{Scope: "local_node"})
	if err != nil {
		t.Fatal(err)
	}
	if len(signals.GetSignals()) != 1 || signals.GetSignals()[0].GetType() != "klshield.runtime_action_counts" {
		t.Fatalf("expected runtime action count signal, got %#v", signals.GetSignals())
	}
	evidence, err := adapter.ProvideConformanceEvidence(ctx, &adapterv1.ProvideConformanceEvidenceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidenceType(t, evidence.GetEvidence(), "klshield.map_readback")
}

func validExecuteRequest(actionType, targetKey, idempotencyKey string) *adapterv1.ExecuteRuntimeActionRequest {
	return &adapterv1.ExecuteRuntimeActionRequest{
		RuntimeActionId:   "runtime_action.test",
		IdempotencyKey:    idempotencyKey,
		AdapterId:         adapterID,
		ActionType:        actionType,
		TargetScope:       "source",
		TargetKey:         targetKey,
		CapabilityId:      "klshield.runtime.source_mitigation",
		CorrelationId:     "correlation.test",
		Ttl:               (5 * time.Minute).String(),
		Reason:            "test runtime action",
		AuditId:           "audit.test",
		SourceCommit:      "abc123",
		CapabilityGrantId: "grant.test",
		SignedBundle:      []byte(`{"kind":"SignedEnvelope"}`),
	}
}

func stateRequestFor(req *adapterv1.ExecuteRuntimeActionRequest) *adapterv1.GetRuntimeActionStateRequest {
	selector := selectorFor(req)
	return &adapterv1.GetRuntimeActionStateRequest{
		RuntimeActionId: selector.RuntimeActionID,
		IdempotencyKey:  selector.IdempotencyKey,
		AdapterId:       selector.AdapterID,
		ActionType:      selector.ActionType,
		TargetScope:     selector.TargetScope,
		TargetKey:       selector.TargetKey,
		CapabilityId:    selector.CapabilityID,
		CorrelationId:   selector.CorrelationID,
	}
}

func revokeRequestFor(req *adapterv1.ExecuteRuntimeActionRequest, reason, auditID string) *adapterv1.RevokeRuntimeActionRequest {
	selector := selectorFor(req)
	return &adapterv1.RevokeRuntimeActionRequest{
		RuntimeActionId:   selector.RuntimeActionID,
		IdempotencyKey:    selector.IdempotencyKey,
		AdapterId:         selector.AdapterID,
		ActionType:        selector.ActionType,
		TargetScope:       selector.TargetScope,
		TargetKey:         selector.TargetKey,
		CapabilityId:      selector.CapabilityID,
		SourceCommit:      req.GetSourceCommit(),
		CapabilityGrantId: req.GetCapabilityGrantId(),
		CorrelationId:     selector.CorrelationID,
		Reason:            reason,
		AuditId:           auditID,
	}
}

func selectorFor(req *adapterv1.ExecuteRuntimeActionRequest) RuntimeMapSelector {
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

func assertEvidenceType(t *testing.T, evidence []*adapterv1.Evidence, evidenceType string) {
	t.Helper()
	for _, item := range evidence {
		if item.GetType() == evidenceType {
			return
		}
	}
	t.Fatalf("expected evidence type %q, got %#v", evidenceType, evidence)
}
