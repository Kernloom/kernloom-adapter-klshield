// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapter

import (
	"context"

	adapterv1 "github.com/kernloom/kernloom-protocol/sdk/go/adapter/v1"
)

type Adapter struct{}

func New() *Adapter {
	return &Adapter{}
}

func (a *Adapter) Describe(context.Context) (*adapterv1.AdapterDescriptor, error) {
	return &adapterv1.AdapterDescriptor{
		AdapterId:       "kernloom.adapter.klshield",
		Name:            "Kernloom KLShield Adapter",
		ProtocolVersion: adapterv1.ProtocolVersion,
		Capabilities: []*adapterv1.CapabilityDescriptor{
			{
				Id:             "klshield.runtime.source_mitigation",
				DisplayName:    "Apply temporary source mitigations",
				Kind:           "runtime_executor",
				RuntimeActions: []string{"rate_limit_source", "deny_temporarily_source"},
			},
			{
				Id:          "klshield.signals.read",
				DisplayName: "Read KLShield packet, flow, drop and rate signals",
				Kind:        "signal_provider",
				Actions:     []string{"read_packet_stats", "read_flow_stats", "read_drop_stats", "read_rate_stats"},
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
	}, nil
}

func (a *Adapter) Health(context.Context) (*adapterv1.HealthResponse, error) {
	return &adapterv1.HealthResponse{
		Status:  adapterv1.HealthServing,
		Message: "klshield adapter bootstrap is serving",
	}, nil
}
