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
./bin/kernloom-adapter-klshield serve --addr 127.0.0.1:18082
```

For local inspection, running the binary without arguments prints the adapter descriptor as JSON.

## Release

Release pipelines must run protocol compatibility checks, contract tests, unit tests, KLShield lab integration tests, packaging and signing.

## Dependencies

The adapter uses `go 1.26` with `toolchain go1.26.4` and imports `github.com/kernloom/kernloom-protocol`. Local development uses a `replace` directive to the sibling protocol repo.

## Related Repos

KLIQ lives in `kernloom-core`. Protocol definitions and contract tests live in `kernloom-protocol`.
