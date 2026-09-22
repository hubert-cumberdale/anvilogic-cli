# Architecture

## Purpose and boundary

The CLI provides secure generic HTTP access, local opt-in model tooling, reviewed operation facts,
and one bounded threat-scenario exporter. The public package contains no model corpus and no raw
endpoint evidence.

```text
operator
   |
   v
cli.py ----------> config.py ----------> local config / environment
   |                    |
   |                    v
   +--------------> client.py ---------> Anvilogic API
   |                    |
   |                    v
   |                   io.py -----------> stdout / private output file
   |
   +--------------> schemas.py ---------> caller-supplied model file
   |
   +--------------> operations.py ------> bundled distilled fact registry
   |
   +--------------> cli_threat_scenarios.py
                           |
                           v
                    threat_scenarios.py -> immutable bundled v1 record schema
                           |
                           +-------------> private normalized run artifacts

tagged private commit
   |
   v
create_public_mirror.py -> safety scan -> validation wheel -> manifest
   |
   v
one-commit public main + lightweight version tag
```

- `cli.py` owns command parsing, explicit local-model requirements, apply gating, and stable exits.
- `config.py` validates configuration, resolves environment precedence, and persists atomically
  with restrictive permissions.
- `client.py` builds relative URLs, manages authentication, redacts previews, disables redirects,
  and retries only safe methods.
- `schemas.py` loads only caller-supplied Markdown/OpenAPI files and provides search, reference
  expansion, samples, and JSON Schema validation.
- `operations.py` validates the bundled v2 fact registry, resolves path parameters, and restricts
  named invocation to reviewed query names.
- `io.py` handles repeatable arguments, deterministic response formatting, and private file writes.
- `threat_scenarios.py` owns fail-closed collection, normalization, v1 record validation, findings,
  hashes, and private artifact output.
- `check_secret_scan.py` reports secret-shaped findings without reproducing candidate values.
- `check_public_safety.py` scans tracked source and a built wheel for forbidden artifacts, raw
  capture formats, private paths/hosts, and secret patterns.
- `create_public_mirror.py` exports a clean tag outside the private repository, verifies the public
  boundary, builds a validation-only wheel, writes a deterministic manifest, and initializes a
  one-commit `main` repository.

## Request flow

1. Resolve and validate effective configuration.
2. If request or response model validation is explicitly requested, require and load the caller's
   model catalog.
3. Parse query, header, and body input and reject ambiguous or unsafe forms.
4. Validate a request body when requested.
5. Build one request plan with managed authentication headers.
6. Stop at a redacted preview for `--dry-run` or any non-safe method lacking `--apply`.
7. Send with TLS verification, timeout, redirect suppression, and safe-method retries.
8. Validate a response when requested, then emit deterministic JSON or raw bytes.

Named `invoke` adds fact-registry lookup and path/query allowlisting before this flow. Registry
entries have no model bindings. Every POST remains apply-gated and non-retried because evidence of
a search-like request does not prove absence of server-side effects.

## Threat-scenario exporter

The exporter remains limited to three reviewed operations. Scenario list pages must reconcile the
requested page and size, current count, page count, total results, sort, hit IDs, descending ranges,
and unique count. Each scenario's full detail is submitted once for group membership; unique stage
membership and exact totals are required. A collection may restart once on drift. All normalized
records validate before the output directory is created, and the manifest binds the output to the
immutable v1 schema bytes.

## Public mirror integrity

The private repository is authoritative. The mirror manifest records the private source ref and
commit, commit time, package version, deterministic tree digest, history policy, and distribution
policy. The digest covers each path and file digest in lexical order and excludes only the manifest
itself and `.git/`. The public repository begins with one synthetic release commit, so no private
parent, branch, tag, or deleted artifact is reachable.
