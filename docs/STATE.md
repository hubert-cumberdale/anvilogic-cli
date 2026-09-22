# Project state

Last updated: 2026-09-22

- Version: `0.3.3`.
- Lifecycle: Alpha; not production-qualified.
- Release channel: private authority repository plus a source-only public GitHub prerelease mirror;
  no attached public package assets and no PyPI publication.
- Model source: no model corpus is distributed. All model commands and explicit request/response
  validation require `--models-path` or `ANVILOGIC_MODELS_PATH` pointing to an operator-supplied
  Markdown export or local OpenAPI JSON/YAML document. YAML aliases, duplicate keys, and
  non-JSON-compatible values are rejected; URI-valued paths are rejected.
- Operation source: 344 reviewed fact entries: all 317 operations from the pinned public OpenAPI
  3.0 document and 27 provisional private-evidence-only compatibility operations. The 47 overlaps
  preserve their existing IDs and record both evidence classes. The registry retains no complete
  OpenAPI document, schemas, raw capture, tenant values, counts, samples, statuses, or bindings.
- Implemented: configuration and environment precedence, configurable API-key schemes, generic
  calls, reviewed operation lookup and named invocation, path/query allowlisting, redacted
  previews, method-based apply gating, bounded safe-read retries, deterministic output, private
  response files, opt-in local model search/show/sample/validation, and the apply-gated all-visible
  threat-scenario export.
- Threat-scenario contract: the verified `hits`/`searchMetadata` list flow, complete detail stage
  membership request, fail-closed pagination/order/membership/count checks, one drift restart,
  normalized private artifacts, findings, hashes, and the immutable strict v1 JSONL schema remain
  unchanged from `v0.3.1`.
- Public release controls: deterministic checksum-pinned registry generation, provenance ledger,
  operation coverage matrix, independently pinned private seed, sanitized secret scanner,
  tracked-source and complete wheel/sdist boundary scans, distribution inspection, and a
  one-commit mirror manifest tied to the tagged private authority-branch tip.
- Deliberately absent: bundled model data, raw evidence, private Git history, authentication-flow
  replay, inferred required parameters, automatic pagination outside the reviewed exporter,
  resource-specific mutations, mutation retries, attached public packages, and PyPI distribution.
- Still unproven: authentication scope, required parameters beyond retained path/query facts,
  pagination, response envelopes, endpoint stability, idempotency, and mutation semantics outside
  the reviewed exporter.
