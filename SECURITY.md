# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/B0yko/pgwarden/security/advisories/new)
for this repository, not as a public issue. We aim to acknowledge a report within a
few days.

## Scope and known limitations

pgwarden's threat model is in [docs/threat-model.md](docs/threat-model.md) and its
limitations are listed in the README. In particular: a compromised gateway host
holds the role secret and can act as any mapped person; a database superuser can
rewrite the audit log (export the head hash `pgwarden audit verify` prints);
disclosure of data a person may read, planner-statistics leakage through `EXPLAIN`,
and exfiltration through a model's final answer are documented residual risks, not
bugs.

## Supported versions

v0.1.x receives security fixes.
