// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapter

import (
	"testing"

	contractv1 "github.com/kernloom/kernloom-protocol/contract/adapter/v1"
)

func TestAdapterPassesMinimalContract(t *testing.T) {
	contractv1.RunMinimalContract(t, New())
}
