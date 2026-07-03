# User Guide

Use this adapter for approved, TTL-bound KLShield runtime actions such as `rate_limit_source` and `deny_temporarily_source`.

For normal local development, start it with the default memory runtime store.
For end-to-end KLShield enforcement, start it with `--runtime-store bpf` on the
same Linux host where `kernloom-shield` has pinned its maps under `/sys/fs/bpf`.

The BPF backend currently accepts IPv4 source `target_key` values. IPv6,
tuple-level and L7/session mitigations remain unsupported in this capability.
KLIQ owns the runtime action lease and calls revoke when the action expires; the
adapter only writes, reads back and deletes the effective KLShield map entry.
