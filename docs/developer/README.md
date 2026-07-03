# Developer Guide

The adapter must be idempotent by idempotency key and return evidence for map writes, read-back and cleanup.

Runtime store rules:

- `MemoryRuntimeMapStore` is for unit tests, contract tests and local substitute
  runs.
- `BPFMapRuntimeStore` is Linux-only and writes pinned KLShield maps via
  `github.com/cilium/ebpf`.
- Do not put TTL metadata into KLShield BPF values. KLIQ owns leases,
  expiration and reconciliation.
- New runtime actions must declare the exact map ABI, write path, readback path
  and revoke path before being marked implemented.
