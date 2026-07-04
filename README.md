# kernloom-adapter-klshield

`kernloom-adapter-klshield` controls the KLShield PEP/Data Plane by writing concrete BPF maps and reading evidence state. KLIQ owns policy decisions, leases, TTL and reconciliation.

## Build

```sh
make build
```

## Test

```sh
make test
```

## Run

```sh
./bin/kernloom-adapter-klshield serve \
  --addr 127.0.0.1:18082 \
  --tls-cert /etc/kernloom/adapter/server.crt \
  --tls-key /etc/kernloom/adapter/server.key \
  --client-ca /etc/kernloom/adapter/client-ca.pem \
  --authority-public-key /etc/kernloom/trust/runtime-authority.public.json
```

The default runtime store is the in-memory substitute used by tests and local
development. To write real KLShield pinned BPF maps, start the adapter on a
Linux host where `kernloom-shield` has loaded and pinned its maps:

```sh
sudo ./bin/kernloom-adapter-klshield serve \
  --addr 127.0.0.1:18082 \
  --tls-cert /etc/kernloom/adapter/server.crt \
  --tls-key /etc/kernloom/adapter/server.key \
  --client-ca /etc/kernloom/adapter/client-ca.pem \
  --authority-public-key /etc/kernloom/trust/runtime-authority.public.json \
  --runtime-store bpf \
  --bpffs-root /sys/fs/bpf \
  --default-rate-pps 1000 \
  --default-burst 2000
```

Local plaintext smoke tests are explicit dev mode:

```sh
./bin/kernloom-adapter-klshield serve \
  --addr 127.0.0.1:18082 \
  --dev-insecure-transport \
  --dev-insecure-skip-authority-verification
```

For local inspection, running the binary without arguments prints the adapter descriptor as JSON.

## Runtime Actions

Slice 5.6 implements `ExecuteRuntimeAction`, `GetRuntimeActionState`, `RevokeRuntimeAction`, `ReadSignals`, `StreamSignals` and `ProvideConformanceEvidence` against either the controlled in-memory substitute or real KLShield BPF maps.

Supported runtime actions:

```text
runtime_action.rate_limit_source       -> kernloom_rl_policy4
runtime_action.deny_temporarily_source -> kernloom_deny4_hash
```

The BPF backend accepts IPv4 source `target_key` values only. IPv6, tuple-level
and L7/session mitigations are not implemented by this adapter capability yet.
It writes
`runtime_action.rate_limit_source` using the adapter server defaults
`--default-rate-pps` and `--default-burst`, writes
`runtime_action.deny_temporarily_source` as a deny-map value of `1`, reads back
the pinned map after execute/state checks, and deletes the map key during
revoke. KLIQ remains the lease and TTL owner.

Before enforcement, the adapter verifies the signed RuntimeBundle authority
against the configured Ed25519 public key. The signature, source commit,
runtime action allowlist, max scope, max TTL and CapabilityGrant scope must
match the request.

Execute duplicate detection uses `idempotency_key`. State read-back and revoke
require the full runtime action selector: `runtime_action_id`,
`idempotency_key`, `adapter_id`, `capability_id`, `action_type`,
`target_scope` and `target_key`. The adapter returns `klshield.map_write` and
`klshield.map_readback` evidence after execute, and `klshield.ttl_cleanup`
evidence after revoke.

## Release

Release pipelines must run protocol compatibility checks, contract tests, unit tests, KLShield lab integration tests, packaging and signing.

## Dependencies

The adapter uses `go 1.26` with `toolchain go1.26.4` and imports `github.com/kernloom/kernloom-protocol`. Local development uses a `replace` directive to the sibling protocol repo.

## Related Repos

KLIQ lives in `kernloom-core`. Protocol definitions and contract tests live in `kernloom-protocol`. The KLShield PEP/Data Plane lives in `kernloom-shield`; this adapter should remain the Kernloom contract bridge, not the packet enforcement implementation.
