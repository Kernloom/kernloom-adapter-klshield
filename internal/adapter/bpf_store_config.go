// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapter

const (
	DefaultBPFFSRoot      = "/sys/fs/bpf"
	DefaultRuntimeRatePPS = uint64(1000)
	DefaultRuntimeBurst   = uint64(2000)
)

type BPFMapRuntimeStoreConfig struct {
	BPFFSRoot      string
	DefaultRatePPS uint64
	DefaultBurst   uint64
}
