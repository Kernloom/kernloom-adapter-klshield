// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapter

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
)

type RuntimeAuthorityVerifier interface {
	VerifyRuntimeAuthority(req *adapterv1.ExecuteRuntimeActionRequest, normalizedAction string, now time.Time) error
}

type RejectingRuntimeAuthorityVerifier struct{}

func (RejectingRuntimeAuthorityVerifier) VerifyRuntimeAuthority(*adapterv1.ExecuteRuntimeActionRequest, string, time.Time) error {
	return fmt.Errorf("runtime authority verifier is not configured")
}

type DevInsecureRuntimeAuthorityVerifier struct{}

func (DevInsecureRuntimeAuthorityVerifier) VerifyRuntimeAuthority(*adapterv1.ExecuteRuntimeActionRequest, string, time.Time) error {
	return nil
}

type StaticRuntimeAuthorityVerifier struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

func NewStaticRuntimeAuthorityVerifier(keyID string, publicKey []byte) (StaticRuntimeAuthorityVerifier, error) {
	if strings.TrimSpace(keyID) == "" {
		return StaticRuntimeAuthorityVerifier{}, fmt.Errorf("runtime authority key_id is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return StaticRuntimeAuthorityVerifier{}, fmt.Errorf("runtime authority public key must be Ed25519")
	}
	return StaticRuntimeAuthorityVerifier{KeyID: strings.TrimSpace(keyID), PublicKey: ed25519.PublicKey(publicKey)}, nil
}

func (v StaticRuntimeAuthorityVerifier) VerifyRuntimeAuthority(req *adapterv1.ExecuteRuntimeActionRequest, normalizedAction string, now time.Time) error {
	if req == nil {
		return fmt.Errorf("runtime action request is required")
	}
	var envelope signedEnvelope
	if err := json.Unmarshal(req.GetSignedBundle(), &envelope); err != nil {
		return fmt.Errorf("signed_bundle is not a signed envelope: %w", err)
	}
	if err := v.verifyEnvelope(envelope, now); err != nil {
		return err
	}
	var runtimeBundle runtimeAuthorityBundle
	if err := json.Unmarshal(envelope.Payload, &runtimeBundle); err != nil {
		return fmt.Errorf("signed runtime authority payload is invalid: %w", err)
	}
	if runtimeBundle.Kind != "RuntimeBundle" {
		return fmt.Errorf("signed runtime authority kind %q is not RuntimeBundle", runtimeBundle.Kind)
	}
	if !runtimeBundle.Spec.RuntimeAllowed {
		return fmt.Errorf("runtime authority does not allow runtime actions")
	}
	if envelope.SourceCommit != "" && envelope.SourceCommit != req.GetSourceCommit() {
		return fmt.Errorf("runtime authority source_commit %q does not match request source_commit %q", envelope.SourceCommit, req.GetSourceCommit())
	}
	if runtimeBundle.Metadata.SourceCommit != "" && runtimeBundle.Metadata.SourceCommit != req.GetSourceCommit() {
		return fmt.Errorf("runtime bundle source_commit %q does not match request source_commit %q", runtimeBundle.Metadata.SourceCommit, req.GetSourceCommit())
	}
	if !runtimeAuthorityAllowsAction(runtimeBundle, normalizedAction) {
		return fmt.Errorf("runtime action %q is not allowed by signed runtime authority", normalizedAction)
	}
	if runtimeBundle.Spec.MaxScope != "" && req.GetTargetScope() != runtimeBundle.Spec.MaxScope {
		return fmt.Errorf("target scope %q does not match signed runtime authority max_scope %q", req.GetTargetScope(), runtimeBundle.Spec.MaxScope)
	}
	ttl, err := time.ParseDuration(req.GetTtl())
	if err != nil {
		return fmt.Errorf("ttl %q is invalid: %w", req.GetTtl(), err)
	}
	if runtimeBundle.Spec.MaxTTL != "" {
		maxTTL, err := time.ParseDuration(runtimeBundle.Spec.MaxTTL)
		if err != nil {
			return fmt.Errorf("signed runtime authority max_ttl %q is invalid: %w", runtimeBundle.Spec.MaxTTL, err)
		}
		if ttl > maxTTL {
			return fmt.Errorf("ttl %s exceeds signed runtime authority max_ttl %s", ttl, maxTTL)
		}
	}
	return validateRuntimeAuthorityGrant(runtimeBundle, req, normalizedAction, ttl, now)
}

func (v StaticRuntimeAuthorityVerifier) verifyEnvelope(envelope signedEnvelope, now time.Time) error {
	if envelope.Kind != "SignedEnvelope" {
		return fmt.Errorf("signed_bundle kind %q is not SignedEnvelope", envelope.Kind)
	}
	if envelope.Algorithm != "Ed25519" {
		return fmt.Errorf("unsupported signed_bundle algorithm %q", envelope.Algorithm)
	}
	if envelope.KeyID != v.KeyID {
		return fmt.Errorf("signed_bundle key_id %q does not match runtime authority key %q", envelope.KeyID, v.KeyID)
	}
	if len(v.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("runtime authority verifier requires an Ed25519 public key")
	}
	if envelope.ExpiresAt != nil && !now.UTC().Before(envelope.ExpiresAt.UTC()) {
		return fmt.Errorf("signed runtime authority is expired")
	}
	sum := sha256.Sum256(envelope.Payload)
	payloadSHA256 := "sha256:" + hex.EncodeToString(sum[:])
	if envelope.PayloadSHA256 != payloadSHA256 {
		return fmt.Errorf("signed runtime authority payload hash mismatch")
	}
	input, err := runtimeAuthoritySigningInput(envelope)
	if err != nil {
		return err
	}
	if !ed25519.Verify(v.PublicKey, input, envelope.Signature) {
		return fmt.Errorf("signed runtime authority signature verification failed")
	}
	return nil
}

func validateRuntimeAuthorityGrant(runtimeBundle runtimeAuthorityBundle, req *adapterv1.ExecuteRuntimeActionRequest, normalizedAction string, ttl time.Duration, now time.Time) error {
	var grant runtimeAuthorityCapabilityGrant
	found := false
	for _, candidate := range runtimeBundle.Spec.CapabilityGrants {
		if candidate.ID == req.GetCapabilityGrantId() {
			grant = candidate
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("capability grant %q is not present in signed runtime authority", req.GetCapabilityGrantId())
	}
	if grant.AdapterID != req.GetAdapterId() {
		return fmt.Errorf("capability grant %q adapter_id %q does not match request adapter_id %q", grant.ID, grant.AdapterID, req.GetAdapterId())
	}
	if grant.CapabilityID != req.GetCapabilityId() {
		return fmt.Errorf("capability grant %q capability_id %q does not match request capability_id %q", grant.ID, grant.CapabilityID, req.GetCapabilityId())
	}
	if grant.ActionType != normalizedAction {
		return fmt.Errorf("capability grant %q action_type %q does not match request action_type %q", grant.ID, grant.ActionType, normalizedAction)
	}
	if !runtimeAuthorityGrantAllowsScope(grant, req.GetTargetScope()) {
		return fmt.Errorf("target scope %q is not allowed by capability grant %q", req.GetTargetScope(), grant.ID)
	}
	if grant.MaxTTL != "" {
		maxTTL, err := time.ParseDuration(grant.MaxTTL)
		if err != nil {
			return fmt.Errorf("capability grant %q max_ttl %q is invalid: %w", grant.ID, grant.MaxTTL, err)
		}
		if ttl > maxTTL {
			return fmt.Errorf("ttl %s exceeds capability grant %q max_ttl %s", ttl, grant.ID, maxTTL)
		}
	}
	if strings.TrimSpace(grant.ExpiresAt) != "" {
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(grant.ExpiresAt))
		if err != nil {
			return fmt.Errorf("capability grant %q expires_at is invalid: %w", grant.ID, err)
		}
		if !now.UTC().Before(expiresAt.UTC()) {
			return fmt.Errorf("capability grant %q is expired", grant.ID)
		}
	}
	return nil
}

func runtimeAuthorityGrantAllowsScope(grant runtimeAuthorityCapabilityGrant, scope string) bool {
	for _, candidate := range grant.AllowedTargetScopes {
		if strings.TrimSpace(candidate) == scope {
			return true
		}
	}
	return false
}

func runtimeAuthorityAllowsAction(runtimeBundle runtimeAuthorityBundle, actionType string) bool {
	for _, action := range runtimeBundle.Spec.RuntimeActions {
		if action.CanonicalID == actionType || action.Label == actionType {
			return true
		}
	}
	return false
}

func runtimeAuthoritySigningInput(envelope signedEnvelope) ([]byte, error) {
	return json.Marshal(protectedHeader{
		Kind:          envelope.Kind,
		KeyID:         envelope.KeyID,
		Algorithm:     envelope.Algorithm,
		PayloadType:   envelope.PayloadType,
		PayloadSHA256: envelope.PayloadSHA256,
		SignedAt:      envelope.SignedAt,
		ExpiresAt:     envelope.ExpiresAt,
		SourceCommit:  envelope.SourceCommit,
		PolicyID:      envelope.PolicyID,
	})
}

type signedEnvelope struct {
	Kind          string     `json:"kind"`
	KeyID         string     `json:"key_id"`
	Algorithm     string     `json:"algorithm"`
	PayloadType   string     `json:"payload_type"`
	Payload       []byte     `json:"payload"`
	PayloadSHA256 string     `json:"payload_sha256"`
	Signature     []byte     `json:"signature"`
	SignedAt      time.Time  `json:"signed_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	SourceCommit  string     `json:"source_commit,omitempty"`
	PolicyID      string     `json:"policy_id,omitempty"`
}

type protectedHeader struct {
	Kind          string     `json:"kind"`
	KeyID         string     `json:"key_id"`
	Algorithm     string     `json:"algorithm"`
	PayloadType   string     `json:"payload_type"`
	PayloadSHA256 string     `json:"payload_sha256"`
	SignedAt      time.Time  `json:"signed_at"`
	ExpiresAt     *time.Time `json:"expires_at"`
	SourceCommit  string     `json:"source_commit"`
	PolicyID      string     `json:"policy_id"`
}

type runtimeAuthorityBundle struct {
	Kind     string `json:"kind"`
	Metadata struct {
		ID           string `json:"id"`
		PolicyID     string `json:"policy_id"`
		SourceCommit string `json:"source_commit"`
	} `json:"metadata"`
	Spec struct {
		PolicyID         string                            `json:"policy_id"`
		RuntimeAllowed   bool                              `json:"runtime_allowed"`
		RuntimeActions   []runtimeAuthorityAction          `json:"runtime_actions"`
		CapabilityGrants []runtimeAuthorityCapabilityGrant `json:"capability_grants"`
		MaxTTL           string                            `json:"max_ttl"`
		MaxScope         string                            `json:"max_scope"`
		MaxScopeSource   string                            `json:"max_scope_source"`
		MaxTTLSource     string                            `json:"max_ttl_source"`
	} `json:"spec"`
}

type runtimeAuthorityAction struct {
	Label       string `json:"label"`
	CanonicalID string `json:"canonical_id"`
}

type runtimeAuthorityCapabilityGrant struct {
	ID                  string   `json:"capability_grant_id"`
	AdapterID           string   `json:"adapter_id"`
	CapabilityID        string   `json:"capability_id"`
	ActionType          string   `json:"action_type"`
	AllowedTargetScopes []string `json:"allowed_target_scopes"`
	MaxTTL              string   `json:"max_ttl"`
	ExpiresAt           string   `json:"expires_at,omitempty"`
}
