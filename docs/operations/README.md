# Operations Guide

Monitor adapter health, KLShield map write evidence, cleanup evidence and stale runtime-action state. Unknown action state is not conformant.

Use `--runtime-store bpf` only on Linux hosts with loaded KLShield maps:

```sh
sudo ./bin/kernloom-adapter-klshield serve --runtime-store bpf --bpffs-root /sys/fs/bpf
```

The adapter keeps an in-process idempotency index so it can map Kernloom runtime
action IDs back to KLShield IP-keyed maps. KLIQ remains the durable owner of
leases and TTL. If the adapter restarts, KLIQ reconciliation should either
re-apply active actions or mark state unknown until a fresh execute/readback is
available.
