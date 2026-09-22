# Security policy

## Reporting

Report vulnerabilities through the maintainer's private security contact. Do not open a public
issue containing credentials, tenant data, private hostnames, raw responses, cookies, HAR files,
or screenshots with customer information.

Include the affected version, sanitized reproduction steps, expected impact, and confirmation that
the report contains no live secrets or tenant payloads.

## Operational expectations

- Prefer `ANVILOGIC_API_KEY` over command-line arguments or local persistence.
- Keep TLS verification enabled and use HTTPS endpoints.
- Treat API responses and exported payloads as sensitive.
- Inspect every mutation preview before adding `--apply`.
- Revoke an API key immediately if it may have appeared in logs, shell history, or version control.

## Release checks

Before publishing, run `python3 scripts/quality_gate.py` and `python3
scripts/check_secret_scan.py`, build privately in a clean environment, inspect both distribution
archives, and audit the exact constrained dependency set for known vulnerabilities. Public
releases contain source only and must not attach the private verification wheel or sdist.

The public tree must not contain caller-supplied model exports, compiled model catalogs, raw
captures, tenant response data, workstation paths, or private Git history. Secret-scan exceptions
must be narrow entries in `security/secret-scan-allowlist.json` with a path, finding label, line
fragment, and human review reason. Scanner output reports only location and finding class; it must
never echo the candidate value.
