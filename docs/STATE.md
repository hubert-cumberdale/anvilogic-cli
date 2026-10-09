# Project state

Last updated: 2026-10-09

- Version: `0.3.6`.
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
- Threat-scenario contract: the verified `hits`/`searchMetadata` list flow now requires two complete
  sweeps with valid stable metadata, exact unique counts, and identical scenario ID/modification
  time mappings. Source range ordering is recorded rather than trusted, and the verified snapshot
  is ordered locally. Every listed item is detail-classified before group lookup, and non-scenario
  items are recorded in private findings and aggregate source counts. Detail stages resolve through
  explicit group references before exact identifier-membership checks. Group-proven identifiers
  with unavailable 403/404 details retain placeholder membership and private findings; other HTTP
  errors remain fatal. Exact canonical ATT&CK tokens are extracted from dedicated fields and the
  allowlisted identifier description without name inference. One drift restart, normalized private
  artifacts, findings, hashes, and the immutable strict v1 JSONL schema remain in place.
- Collection issue fix: v0.3.6 addresses
  [public issue #1](https://github.com/hubert-cumberdale/anvilogic-cli/issues/1), covering false
  failures from cross-page ordering, distinct stage/group IDs, and non-scenario list items. The
  generic restart error remains for actual collection drift or incomplete membership.
- Downstream interoperability: the normalized v1 JSONL remains the approved handoff to offline
  consumers. This repository owns the export contract and a public-safe integration summary; the
  central platform team owns cross-tool sequencing, compatible refs, approvals, recovery, and
  acceptance in its private handbook. Exact ATT&CK-plus-platform matches remain reviewable
  candidates, missing ATT&CK metadata remains source remediation, and the handoff authorizes no
  model call, upload, assessment apply, new Anvilogic endpoint, or v0.4 workflow.
- Daybreak calibration: a repository-only preparation script validates the private collection and
  reconciliation hash chains, both AttackIQ catalogs, terminal states, packet relationships, and
  permissions before producing an atomic 12-gap/12-control review package. Selection uses fixed
  platform quotas, occurrence/ATT&CK/stable-ID ranking, distinct identifiers, and same-platform
  covered controls. Fingerprint-bound reviewer decisions stop on a failed positive control and
  deterministically replenish false gaps. The AttackIQ reconciler now maps its Linux-distribution
  runtime keys to Linux and `osx` to macOS, and the refreshed private plan has covered mappings for
  Windows, Linux, and macOS. Pilot preparation still fails closed before output because containers,
  IaaS, network devices, and SaaS lack same-platform covered controls. Model access, data sharing,
  submission, upload, and assessment application remain unapproved.
- Public release controls: deterministic checksum-pinned registry generation, provenance ledger,
  operation coverage matrix, independently pinned private seed, sanitized secret scanner,
  tracked-source and complete wheel/sdist boundary scans, distribution inspection, and a
  one-commit mirror manifest tied to the tagged private authority-branch tip.
- Work tracking: the public `v0.3.5 — Hardening and Adoption` milestone closed with all six release
  blockers complete. The post-v0.3.5 evidence campaign retains only aggregate assessment counts by
  candidate workflow and addresses authentication, envelopes, pagination, stability, and relevant
  parameter requiredness in that order. No operator reports are retained, and the public evidence
  audit left the first authentication gate insufficient, so no v0.4 workflow or implementation
  milestone is selected. Mutation evidence and adoption/distribution maturity remain separately
  gated.
- Deliberately absent: bundled model data, raw evidence, private Git history, authentication-flow
  replay, inferred required parameters, automatic pagination outside the reviewed exporter,
  resource-specific mutations, mutation retries, attached public packages, and PyPI distribution.
- Still unproven: authentication scope, required parameters beyond retained path/query facts,
  pagination, response envelopes, endpoint stability, idempotency, and mutation semantics outside
  the reviewed exporter.
