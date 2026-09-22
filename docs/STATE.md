# Project state

Last updated: 2026-09-22

- Version: `0.3.2`.
- Lifecycle: Alpha; not production-qualified.
- Release channel: private authority repository plus a source-only public GitHub prerelease mirror;
  no attached public package assets and no PyPI publication.
- Model source: no model corpus is distributed. All model commands and explicit request/response
  validation require `--models-path` or `ANVILOGIC_MODELS_PATH` pointing to an operator-supplied
  Markdown export or OpenAPI JSON document.
- Operation source: 74 reviewed fact entries distilled from private traffic evidence. The public
  registry retains IDs, methods, normalized paths, query names, request-body presence, risk,
  confidence, evidence class, and last-verified date. It retains no raw capture, tenant values,
  counts, response samples, statuses, or model bindings.
- Implemented: configuration and environment precedence, configurable API-key schemes, generic
  calls, reviewed operation lookup and named invocation, path/query allowlisting, redacted
  previews, method-based apply gating, bounded safe-read retries, deterministic output, private
  response files, opt-in local model search/show/sample/validation, and the apply-gated all-visible
  threat-scenario export.
- Threat-scenario contract: the verified `hits`/`searchMetadata` list flow, complete detail stage
  membership request, fail-closed pagination/order/membership/count checks, one drift restart,
  normalized private artifacts, findings, hashes, and the immutable strict v1 JSONL schema remain
  unchanged from `v0.3.1`.
- Public release controls: provenance ledger, operation coverage matrix, independent sanitized
  secret scanner, tracked-source and wheel boundary scan, distribution inspection, and a
  deterministic one-commit mirror manifest tied to the private source commit.
- Deliberately absent: bundled model data, raw evidence, private Git history, authentication-flow
  replay, inferred required parameters, automatic pagination outside the reviewed exporter,
  resource-specific mutations, mutation retries, attached public packages, and PyPI distribution.
- Next contract needed: an authoritative public OpenAPI paths document to confirm methods,
  authentication, required parameters, pagination, response envelopes, and mutation semantics.
