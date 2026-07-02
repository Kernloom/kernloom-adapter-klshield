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

## Release

Release pipelines must run protocol compatibility checks, contract tests, unit tests, KLShield lab integration tests, packaging and signing.

## Dependencies

The adapter uses Go 1.26.4 and imports `github.com/kernloom/kernloom-protocol`. Local development uses a `replace` directive to the sibling protocol repo.

## Related Repos

KLIQ lives in `kernloom-core`. Protocol definitions and contract tests live in `kernloom-protocol`.
