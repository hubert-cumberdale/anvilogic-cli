# Changelog

## Unreleased

## 0.3.2 - 2026-09-22

- Publish the first source-only public Alpha snapshot through a deterministic one-commit mirror,
  with a provenance manifest and no private Git history or attached package assets.
- Remove the supplied model export and compiled catalog from the release tree and package. Require
  `--models-path` or `ANVILOGIC_MODELS_PATH` for model commands and explicit payload validation.
- Replace traffic-derived counts, statuses, samples, and model bindings with a distilled operation
  fact registry carrying risk, confidence, evidence class, and last-verified metadata.
- Add provenance and operation-coverage ledgers, independent secret scanning, tracked-source and
  wheel public-safety checks, and public-mirror generation tests.
- Preserve POST apply gates, the threat-scenario CLI, and the exact v1 record schema bytes.

## 0.3.1 - 2026-09-22

- Repair the threat-scenario collector to use the verified scenario-list and full-detail stage
  membership contracts, and fail closed on inconsistent pagination, sorting, hit identity,
  ordering, membership totals, duplicate entries, malformed membership, and unverified response
  envelopes. Only validated group results supply stage membership. The immutable v1 record schema
  and CLI interface are unchanged.

## 0.3.0 - 2026-09-14

- Add an apply-gated all-visible threat-scenario export with stable pagination, one drift restart,
  ordered stage and identifier normalization, private JSONL/CSV output, findings, and hashed
  completeness manifests.
- Formalize each JSONL record as an immutable strict v1 JSON Schema contract, add deterministic
  offline schema discovery and pre-write validation, and bind manifests to the schema digest.
- Add release alignment and package-data checks while retaining Alpha status and private GitHub
  prerelease distribution.

## 0.2.0 - 2026-09-03

- Reconcile sanitized browser traffic into 74 observed operations covering 120 exchanges.
- Add operation discovery and governed named invocation with path/query allowlisting.
- Bind 11 operations to exported models where every captured sample validated.
- Confirm Bearer authentication for observed traffic while preserving configurable auth.
- Exclude the authentication handshake and retain no raw captured values.

## 0.1.0 - 2026-09-02

- Add the initial schema-aware Anvilogic CLI.
- Compile all 809 supplied OpenAPI model fragments into a deterministic bundled catalog.
- Add generic API calls with configurable authentication, TLS verification, timeouts, safe-method
  retries, redirect suppression, request/response model validation, redacted previews, and
  mutation apply gating.
- Add secure configuration/output persistence, stable exit codes, tests, CI, and governance docs.
