// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

//go:build !linux

package adapter

import "fmt"

type BPFMapRuntimeStore struct{}

func NewBPFMapRuntimeStore(BPFMapRuntimeStoreConfig) (*BPFMapRuntimeStore, error) {
	return nil, fmt.Errorf("klshield bpf runtime store is only supported on Linux")
}

func (s *BPFMapRuntimeStore) Kind() string {
	return "bpf"
}
