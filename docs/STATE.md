# Project state

Last updated: 2026-09-23

- Version: `0.3.5`.
- Lifecycle: Alpha; not production-qualified.
- Release channel: private authority repository plus a source-only public GitHub prerelease mirror;
  no attached public package assets and no PyPI publication.
- Model source: no model corpus is distributed. Manual model commands and generic `call` model
  validation accept an operator-supplied Markdown export or JSON/YAML schema catalog. Named
  operation validation requires a full local OpenAPI 3.0.x JSON/YAML document. Both use
  `--models-path` or `ANVILOGIC_MODELS_PATH`; URI-valued paths are rejected.
- Operation source: 344 reviewed fact entries: all 317 operations from the pinned public OpenAPI
  3.0 document and 27 provisional private-evidence-only compatibility operations. The 47 overlaps
  preserve their existing IDs and record both evidence classes. The registry retains no complete
  OpenAPI document, schemas, raw capture, tenant values, counts, samples, statuses, or bindings.
  Registry v4 records 94 required, 58 optional, and 12 private-unknown request bodies, plus 180
  bodyless operations.
- Implemented: configuration and environment precedence, configurable API-key schemes, generic
  calls, reviewed operation lookup and named invocation, path/query allowlisting, redacted
  previews, method-based apply gating, bounded safe-read retries, deterministic output, private
  response files, opt-in local model search/show/sample/validation, and the apply-gated all-visible
  threat-scenario export. Named invocation can opt into request and response validation by exact
  method/path resolution from a caller-controlled full OpenAPI document, entirely offline. Model
  and contract JSON/YAML use one strict loader; invocation orchestration is separate from CLI
  parsing and rendering. OpenAPI 3.0 validation covers recursive local references, composition,
  nullable values, directional properties, and supported constraints while unknown validation
  semantics fail closed.
- Adoption evidence: `adoption assess` validates versioned, sanitized request/response fixtures
  entirely offline against reviewed operation IDs and a caller-controlled contract. It reports
  only aggregate outcomes and has no transport, output-path, or payload-retention capability.
- Threat-scenario contract: the verified `hits`/`searchMetadata` list flow, complete detail stage
  membership request, fail-closed pagination/order/membership/count checks, one drift restart,
  normalized private artifacts, findings, hashes, and the immutable strict v1 JSONL schema remain
  unchanged from `v0.3.1`.
- Public release controls: deterministic checksum-pinned registry generation, provenance ledger,
  operation coverage matrix, independently pinned private seed, sanitized secret scanner,
  tracked-source and complete wheel/sdist boundary scans, distribution inspection, and a
  one-commit mirror manifest tied to the tagged private authority-branch tip.
- Work tracking: the public `v0.3.5 — Hardening and Adoption` milestone contains six release
  blockers. Nine separately labeled post-v0.3.5 issues cover authentication, parameter
  requiredness, envelopes, pagination, stability, idempotency, mutation semantics, bounded v0.4
  workflow selection, and adoption/distribution maturity.
- Deliberately absent: bundled model data, raw evidence, private Git history, authentication-flow
  replay, inferred required parameters, automatic pagination outside the reviewed exporter,
  resource-specific mutations, mutation retries, attached public packages, and PyPI distribution.
- Still unproven: authentication scope, required parameters beyond retained path/query facts,
  pagination, response envelopes, endpoint stability, idempotency, and mutation semantics outside
  the reviewed exporter.
