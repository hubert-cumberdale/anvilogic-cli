# Anvilogic CLI

[![CI](https://github.com/hubert-cumberdale/anvilogic-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/hubert-cumberdale/anvilogic-cli/actions/workflows/ci.yml)

A security-focused, independent command-line client for the Anvilogic API.

Current release: `0.3.2` (Alpha; not production-qualified).

The public release provides generic API calls, a reviewed operation fact registry, and the
apply-gated threat-scenario exporter. It is a source-only release: GitHub prereleases have no
package assets, the project is not published to PyPI, and users install from a source checkout.

## Public data boundary

No Anvilogic model export is bundled. The historical supplied model corpus and its compiled
derivative remain only in the private repository history through `v0.3.1`. Model discovery and
explicit request or response validation require a file supplied locally by the operator through
`--models-path` or `ANVILOGIC_MODELS_PATH`.

The bundled operation registry contains only reviewed facts: IDs, methods, normalized paths,
query names, request-body presence, and per-entry risk, confidence, evidence class, and
last-verified date. It contains no raw traffic, tenant values, observation counts, response
samples, statuses, or model-validation claims. Private traffic is named only as the evidence
provenance for distilled facts.

See [docs/PROVENANCE.md](docs/PROVENANCE.md),
[docs/OPERATION_COVERAGE.md](docs/OPERATION_COVERAGE.md), and
[docs/PUBLIC_RELEASE.md](docs/PUBLIC_RELEASE.md) for the complete publication boundary.

## Install from source

Python 3.10 or newer is required.

```bash
git clone https://github.com/hubert-cumberdale/anvilogic-cli.git
cd anvilogic-cli
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -c constraints.txt -e '.[dev]'
anvilogic --help
```

Both `anvilogic` and `avl` entry points are installed.

## Configure

Environment variables take precedence over stored configuration and are recommended for
automation:

```bash
export ANVILOGIC_BASE_URL='https://secure.anvilogic.com'
export ANVILOGIC_API_KEY='<api-key>'
export ANVILOGIC_AUTH_SCHEME='bearer'
anvilogic config validate
```

Supported authentication modes are `bearer` (default), `x-api-key`, `token`, and `none`.
Confirm the correct scheme for the endpoint and tenant you use. To store non-secret settings and
an API key locally:

```bash
anvilogic config set --base-url 'https://secure.anvilogic.com' --auth-scheme bearer
anvilogic auth set
```

The configuration directory and file use restrictive permissions where POSIX permissions are
available. `anvilogic config show` masks the stored key.

## Use a local model catalog

Pass an operator-controlled Markdown export or OpenAPI JSON document before the command group:

```bash
anvilogic --models-path /secure/path/model-export.json models stats
anvilogic --models-path /secure/path/model-export.json models list --search comment
anvilogic --models-path /secure/path/model-export.json models show AddCommentRequest
anvilogic --models-path /secure/path/model-export.json models sample AddCommentRequest
anvilogic --models-path /secure/path/model-export.json \
  models validate AddCommentRequest --data '{"comment":"investigating"}'
```

The environment variable is equivalent:

```bash
export ANVILOGIC_MODELS_PATH=/secure/path/model-export.json
anvilogic models stats
```

If desired, compile a Markdown export into a deterministic local JSON catalog. Keep both files
outside public repositories and package build directories:

```bash
python3 scripts/compile_models.py \
  --input /secure/path/model-export.md \
  --output /secure/path/model-catalog.json
```

All `models` commands and every explicit `--request-model` or `--response-model` validation fail
with exit code 6 when no local catalog is supplied.

## Explore reviewed operations

```bash
anvilogic operations stats
anvilogic operations list --search alert --output-format names
anvilogic operations show get.api.info.user
anvilogic invoke get.api.info.user --dry-run
```

`invoke` restricts query names to the registry and encodes path parameters as single URL
segments. The registry is provisional evidence, not an official or complete API specification.
It deliberately does not bind operations to models. Use the generic `call` command with an
explicit local catalog when model validation is needed.

Every POST operation remains preview-only until `--apply` is present, even when evidence suggests
a read or search workflow:

```bash
anvilogic invoke post.services.triage.alert.search --data-file request.json
anvilogic invoke post.services.triage.alert.search --data-file request.json --apply
```

## Call the API

Read-only methods (`GET`, `HEAD`, and `OPTIONS`) send unless `--dry-run` is used. POST, PUT, PATCH,
and DELETE remain local previews unless `--apply` is supplied:

```bash
anvilogic call GET /api/example --query page=1
anvilogic call POST /api/comments --data '{"comment":"investigating"}'
anvilogic call POST /api/comments --data-file request.json --apply
```

Explicit validation uses the local catalog:

```bash
anvilogic --models-path /secure/path/model-export.json call POST /api/comments \
  --request-model AddCommentRequest \
  --data-file request.json \
  --apply
```

Dry-run output recursively redacts secret-shaped fields. Managed authentication, `Accept`, and
`User-Agent` headers cannot be overridden. Absolute request URLs and credential-bearing redirects
are disabled. TLS verification and bounded timeouts remain enabled by default. Response files use
user-only permissions and are never replaced without `--force`.

## Export threat-scenario coverage

The reviewed exporter collects all visible scenarios, preserves ordered stage and identifier
membership, validates completeness, and writes normalized private artifacts:

```bash
anvilogic threat-scenarios export \
  --scope all-visible \
  --page-size 100 \
  --output-dir /secure/path/anvilogic-run \
  --apply
```

Without `--apply`, it prints a local preview and sends nothing. The two POST reads are never
retried. The exporter verifies pagination metadata, descending ordering, stable totals, unique
IDs, stage membership, and exact cardinality; it restarts once on drift and otherwise fails
closed. Output directories use `0700` and files use `0600` where supported.

Artifacts are `threat_scenarios.jsonl`, `threat_scenario_identifiers.csv`,
`collection_manifest.json`, and `collection_findings.json`. They omit raw envelopes, headers,
credentials, owners, and rule logic. Treat every export as sensitive tenant data and keep it
outside source control.

The exact released v1 JSONL schema remains immutable and is available offline:

```bash
anvilogic threat-scenarios schema
```

Its ID remains `urn:anvilogic-cli:threat-scenario-record:1`. Every record is validated before any
run artifact is written, and collection manifests bind to the exact schema bytes.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `ANVILOGIC_BASE_URL` | API base URL |
| `ANVILOGIC_API_KEY` | API key; preferred over local storage |
| `ANVILOGIC_AUTH_SCHEME` | `bearer`, `x-api-key`, `token`, or `none` |
| `ANVILOGIC_CONFIG_DIR` | Override the user configuration directory |
| `ANVILOGIC_MODELS_PATH` | Required local model catalog for model features |

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success or preview completed |
| 1 | General application error |
| 2 | Invalid command usage |
| 3 | Missing or invalid configuration |
| 4 | Network/transport failure |
| 5 | HTTP error response |
| 6 | Model catalog or payload validation failure |

## Development and release

```bash
python3 scripts/quality_gate.py
```

The gate runs dependency alignment, the release contract, immutable schema check, package-data
boundary, independent secret scanner, tracked-file and wheel public-safety scan, Ruff, mypy, and
pytest. CI runs it on Python 3.10 through 3.13.

Public releases are sanitized one-commit source snapshots of a tagged private commit. The public
prerelease contains no wheel or sdist assets and is not published to PyPI. This project is an
independent client and is not an official Anvilogic product.

The provenance and registry design was informed by the public MIT-licensed
[`grandcamel/anvilogic-as`](https://github.com/grandcamel/anvilogic-as) project; no endpoint facts
or source code were copied from it.
