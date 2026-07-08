// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/kernloom/kernloom-protocol/contract/adapter/v1"
	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
)

func TestAdapterPassesServiceContract(t *testing.T) {
	contractv1.RunServiceContract(t, New())
}

func TestDescriptorReportsManifestDigest(t *testing.T) {
	adapter := NewWithStoreAuthorityAndManifestDigest(nil, DevInsecureRuntimeAuthorityVerifier{}, " sha256:test-manifest ")
	desc, err := adapter.Descriptor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if desc.GetManifestDigest() != "sha256:test-manifest" {
		t.Fatalf("expected manifest digest to be reported, got %q", desc.GetManifestDigest())
	}
}

func TestExecuteRuntimeActionRateLimitAndReadback(t *testing.T) {
	ctx := context.Background()
	adapter, signer := newTestAdapter(t)
	req := validSignedExecuteRequest(t, signer, "runtime_action.rate_limit_source", "source-1", "idem-rate-limit")

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
	adapter, signer := newTestAdapter(t)
	resp, err := adapter.ExecuteRuntimeAction(ctx, validSignedExecuteRequest(t, signer, "runtime_action.deny_temporarily_source", "source-2", "idem-deny"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != statusActive {
		t.Fatalf("expected active status, got %q", resp.GetStatus())
	}
	assertEvidenceType(t, resp.GetEvidence(), "klshield.map_write")
}

func TestExecuteRuntimeActionRateLimitRequiresSignedParameters(t *testing.T) {
	adapter, signer := newTestAdapter(t)
	req := validExecuteRequest("runtime_action.rate_limit_source", "source-missing-rate-params", "idem-missing-rate-params")
	signer.attachSignedBundleWithRateLimitParameters(t, req, time.Now().Add(time.Hour), false)
	if _, err := adapter.ExecuteRuntimeAction(context.Background(), req); err == nil || !strings.Contains(err.Error(), "rate_limit.rate_pps") {
		t.Fatalf("expected missing signed rate limit parameters to be rejected, got %v", err)
	}
}

func TestExecuteRuntimeActionDuplicateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	adapter, signer := newTestAdapter(t)
	first := validSignedExecuteRequest(t, signer, "runtime_action.rate_limit_source", "source-dup", "idem-dup")
	if _, err := adapter.ExecuteRuntimeAction(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := validSignedExecuteRequest(t, signer, "runtime_action.rate_limit_source", "source-dup", "idem-dup")
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
	adapter, signer := newTestAdapter(t)
	req := validSignedExecuteRequest(t, signer, "runtime_action.deny_temporarily_source", "source-cleanup", "idem-cleanup")
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
	adapter, _ := newTestAdapter(t)
	req := validExecuteRequest("runtime_action.unsupported", "source-3", "idem-unsupported")
	if _, err := adapter.ExecuteRuntimeAction(context.Background(), req); err == nil {
		t.Fatal("expected unsupported action to be rejected")
	}
}

func TestRuntimeActionRejectsMissingSignedBundle(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	req := validExecuteRequest("runtime_action.rate_limit_source", "source-no-bundle", "idem-no-bundle")
	req.SignedBundle = nil
	if _, err := adapter.ExecuteRuntimeAction(context.Background(), req); err == nil {
		t.Fatal("expected missing signed_bundle to be rejected")
	}
}

func TestRuntimeActionRejectsInvalidSignedBundle(t *testing.T) {
	adapter, signer := newTestAdapter(t)
	req := validSignedExecuteRequest(t, signer, "runtime_action.rate_limit_source", "source-invalid-signature", "idem-invalid-signature")
	var envelope signedEnvelope
	if err := json.Unmarshal(req.SignedBundle, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signature[0] ^= 1
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	req.SignedBundle = data
	if _, err := adapter.ExecuteRuntimeAction(context.Background(), req); err == nil {
		t.Fatal("expected invalid signed runtime authority to be rejected")
	}
}

func TestRuntimeActionRejectsExpiredSignedBundle(t *testing.T) {
	adapter, signer := newTestAdapter(t)
	req := validExecuteRequest("runtime_action.rate_limit_source", "source-expired-signature", "idem-expired-signature")
	signer.attachSignedBundle(t, req, time.Now().Add(-time.Second))
	if _, err := adapter.ExecuteRuntimeAction(context.Background(), req); err == nil {
		t.Fatal("expected expired signed runtime authority to be rejected")
	}
}

func TestRuntimeActionRejectsCapabilityGrantScopeMismatch(t *testing.T) {
	adapter, signer := newTestAdapter(t)
	req := validExecuteRequest("runtime_action.rate_limit_source", "source-grant-scope", "idem-grant-scope")
	signer.attachSignedBundleWithScope(t, req, "application", time.Now().Add(time.Hour))
	if _, err := adapter.ExecuteRuntimeAction(context.Background(), req); err == nil {
		t.Fatal("expected capability grant scope mismatch to be rejected")
	}
}

func TestSignalsAndConformanceEvidenceUseControlledStore(t *testing.T) {
	ctx := context.Background()
	adapter, signer := newTestAdapter(t)
	if _, err := adapter.ExecuteRuntimeAction(ctx, validSignedExecuteRequest(t, signer, "runtime_action.rate_limit_source", "source-signal", "idem-signal")); err != nil {
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
	grantID := "grant.test." + strings.TrimPrefix(strings.TrimPrefix(actionType, "runtime_action."), "runtime.action.")
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
		CapabilityGrantId: grantID,
	}
}

func validSignedExecuteRequest(t *testing.T, signer testAuthoritySigner, actionType, targetKey, idempotencyKey string) *adapterv1.ExecuteRuntimeActionRequest {
	t.Helper()
	req := validExecuteRequest(actionType, targetKey, idempotencyKey)
	signer.attachSignedBundle(t, req, time.Now().Add(time.Hour))
	return req
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

type testAuthoritySigner struct {
	keyID      string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func newTestAdapter(t *testing.T) (*Adapter, testAuthoritySigner) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := testAuthoritySigner{
		keyID:      "runtime-authority.test",
		publicKey:  publicKey,
		privateKey: privateKey,
	}
	verifier, err := NewStaticRuntimeAuthorityVerifier(signer.keyID, signer.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return NewWithStoreAndAuthority(NewMemoryRuntimeMapStore(), verifier), signer
}

func (s testAuthoritySigner) attachSignedBundle(t *testing.T, req *adapterv1.ExecuteRuntimeActionRequest, expiresAt time.Time) {
	t.Helper()
	s.attachSignedBundleWithScopeAndRateLimitParameters(t, req, req.GetTargetScope(), expiresAt, true)
}

func (s testAuthoritySigner) attachSignedBundleWithScope(t *testing.T, req *adapterv1.ExecuteRuntimeActionRequest, grantScope string, expiresAt time.Time) {
	t.Helper()
	s.attachSignedBundleWithScopeAndRateLimitParameters(t, req, grantScope, expiresAt, true)
}

func (s testAuthoritySigner) attachSignedBundleWithRateLimitParameters(t *testing.T, req *adapterv1.ExecuteRuntimeActionRequest, expiresAt time.Time, includeRateLimit bool) {
	t.Helper()
	s.attachSignedBundleWithScopeAndRateLimitParameters(t, req, req.GetTargetScope(), expiresAt, includeRateLimit)
}

func (s testAuthoritySigner) attachSignedBundleWithScopeAndRateLimitParameters(t *testing.T, req *adapterv1.ExecuteRuntimeActionRequest, grantScope string, expiresAt time.Time, includeRateLimit bool) {
	t.Helper()
	actionType, _, err := normalizeAction(req.GetActionType())
	if err != nil {
		t.Fatal(err)
	}
	grant := map[string]any{
		"capability_grant_id":   req.GetCapabilityGrantId(),
		"adapter_id":            req.GetAdapterId(),
		"capability_id":         req.GetCapabilityId(),
		"action_type":           actionType,
		"allowed_target_scopes": []string{grantScope},
		"max_ttl":               "10m",
	}
	if actionType == actionRateLimitSource && includeRateLimit {
		grant["rate_limit"] = map[string]any{
			"rate_pps": uint64(1000),
			"burst":    uint64(2000),
		}
	}
	payload, err := json.Marshal(map[string]any{
		"kind": "RuntimeBundle",
		"metadata": map[string]any{
			"id":            "runtime_bundle.test",
			"policy_id":     "policy.runtime",
			"source_commit": req.GetSourceCommit(),
		},
		"spec": map[string]any{
			"policy_id":       "policy.runtime",
			"runtime_allowed": true,
			"runtime_actions": []map[string]string{{
				"label":        actionType,
				"canonical_id": actionType,
			}},
			"capability_grants": []map[string]any{grant},
			"max_ttl":           "10m",
			"max_scope":         req.GetTargetScope(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	envelope := signedEnvelope{
		Kind:          "SignedEnvelope",
		KeyID:         s.keyID,
		Algorithm:     "Ed25519",
		PayloadType:   "application/vnd.kernloom.artifact+json",
		Payload:       payload,
		PayloadSHA256: "sha256:" + hex.EncodeToString(sum[:]),
		SignedAt:      time.Now().UTC(),
		ExpiresAt:     &expiresAt,
		SourceCommit:  req.GetSourceCommit(),
		PolicyID:      "policy.runtime",
	}
	input, err := runtimeAuthoritySigningInput(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = ed25519.Sign(s.privateKey, input)
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	req.SignedBundle = data
}
