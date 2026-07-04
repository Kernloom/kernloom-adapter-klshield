# Operations Guide

Monitor adapter health, KLShield map write evidence, cleanup evidence and stale runtime-action state. Unknown action state is not conformant.

Use `--runtime-store bpf` only on Linux hosts with loaded KLShield maps:

```sh
sudo ./bin/kernloom-adapter-klshield serve \
  --runtime-store bpf \
  --bpffs-root /sys/fs/bpf \
  --tls-cert /etc/kernloom/adapter/server.crt \
  --tls-key /etc/kernloom/adapter/server.key \
  --client-ca /etc/kernloom/adapter/client-ca.pem \
  --authority-public-key /etc/kernloom/trust/runtime-authority.public.json
```

Production mode requires adapter mTLS and signed runtime authority
verification. `--dev-insecure-transport` and
`--dev-insecure-skip-authority-verification` are local smoke-test flags only.

The adapter keeps an in-process idempotency index so it can map Kernloom runtime
action IDs back to KLShield IP-keyed maps. KLIQ remains the durable owner of
leases and TTL. If the adapter restarts, KLIQ reconciliation should either
re-apply active actions or mark state unknown until a fresh execute/readback is
available.
