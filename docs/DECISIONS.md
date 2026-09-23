# Decisions

## 2026-09-02: Start from a schema catalog and generic client

- Context: the supplied export has 809 complete component schemas but no endpoint paths or
  operation IDs.
- Decision: expose model discovery/validation and a generic method/path client; do not invent
  named API resources.
- Consequence: operators can work immediately while endpoint-specific ergonomics wait for an
  authoritative contract.

## 2026-09-02: Keep API-key authentication configurable

- Context: public documentation confirms API-key generation, while the exported fragments do not
  define a security scheme or header.
- Decision: support bearer, X-API-Key, token, and unauthenticated modes with bearer as the explicit
  documented default.
- Consequence: tenant-specific integration is possible without hard-coding an unverified wire
  contract.

## 2026-09-02: Apply-gate generic mutations

- Context: generic endpoint calls cannot encode endpoint-specific mutation safety.
- Decision: POST, PUT, PATCH, and DELETE only render a redacted plan unless `--apply` is passed.
- Consequence: scripts must opt in clearly to state changes; safe read methods remain convenient.

## 2026-09-03: Treat captured traffic as a provisional operation contract

- Context: a user-supplied Burp project contains authenticated browser traffic but is not an
  authoritative API specification and includes sensitive tenant material.
- Decision: retain only normalized methods, paths, query names, status codes, counts, and validated
  model bindings. Exclude the authentication handshake and never copy raw capture content into the
  repository.
- Consequence: `operations` and `invoke` provide useful endpoint ergonomics while clearly labeling
  their provenance and keeping `call` as the escape hatch for contract drift.

## 2026-09-03: Preserve method-based apply gating for observed operations

- Context: several captured POST routes appear to perform searches or aggregations, but observation
  alone cannot prove server-side effect semantics or idempotency.
- Decision: all POST operations remain preview-only without `--apply` and are never retried. Bind a
  model only when every parsed sample for that direction validates against the export.
- Consequence: captured convenience does not weaken the original safety boundary, and incomplete
  schema matches do not reject traffic that the browser demonstrably sends.

## 2026-09-03: Add a bounded all-visible threat-scenario export

- Context: cross-product validation requires complete scenario, stage, identifier, ATT&CK, and
  platform mappings, while the reviewed endpoints use both GET and POST reads.
- Decision: add one named exporter over the three sanitized observed operations. Keep POST reads
  apply-gated and non-retried, sort stably, reconcile every page against `totalResults`, restart
  once on drift, and retain only allowlisted normalized fields in private artifacts.
- Consequence: operators can prove collection completeness and feed an offline reconciler without
  committing raw tenant payloads or weakening generic mutation safeguards.

## 2026-09-14: Freeze the threat-scenario JSONL v1 contract

- Context: downstream reconciliation needs a stable machine-readable record contract and a way to
  identify the precise schema used by an export.
- Decision: bundle strict JSON Schema 2020-12 under stable ID
  `urn:anvilogic-cli:threat-scenario-record:1`, expose its exact bytes offline, validate every
  normalized record before creating artifacts, and bind manifests to the schema digest.
- Consequence: released v1 schema bytes cannot change. Field or semantic changes require a new
  schema version, while shape-preserving exporter corrections remain compatible with v1.

## 2026-09-22: Separate model inputs from the public release

- Context: the supplied model export and its compiled derivative are not approved public source
  artifacts.
- Decision: retain them only in private history through `v0.3.1`; require an explicit local path
  for model discovery and request/response validation from `v0.3.2` onward.
- Consequence: generic calls and the reviewed exporter remain available without models, while
  model-aware use is opt-in and controlled by the operator.

## 2026-09-22: Publish distilled facts through a no-history mirror

- Context: endpoint ergonomics remain useful publicly, but raw evidence, tenant-derived values,
  and private repository history are outside the publication boundary.
- Decision: publish only reviewed operation facts with risk, confidence, evidence class, and
  last-verified metadata. Export tagged source into a newly initialized one-commit repository and
  bind it to the private source commit through `PUBLICATION_MANIFEST.json`.
- Consequence: public users can inspect provenance and gaps without receiving raw captures,
  observation counts, samples, model bindings, or private history. Public releases are source-only
  prereleases with no package assets and no PyPI publication.

## 2026-09-22: Adopt the pinned public OpenAPI document as wire evidence

- Context: Anvilogic publishes an OpenAPI 3.0 document with 317 operations and 820 schemas, but the
  mutable GitBook URL declares no explicit redistribution license.
- Decision: verify a maintainer-controlled local copy by URL metadata, title, version, SHA-256,
  and operation totals; publish only a deterministic factual distillation. Merge 47 overlaps with
  the prior registry, retain 27 private-only compatibility facts, and never bundle or fetch the
  complete YAML at runtime.
- Consequence: documented wire facts are authoritative and reproducible without republishing the
  upstream expression. Semantic safety, support, stability, model bindings, and idempotency remain
  unclaimed; all non-safe methods stay apply-gated and non-retried.

## 2026-09-23: Resolve opt-in contracts from an operator-controlled OpenAPI document

- Context: the distilled registry can govern named operations and body presence without legally or
  operationally bundling the upstream schemas, while manual model names cannot safely establish an
  operation's request and response contracts.
- Decision: record public request-body requiredness in registry v4 and add explicit
  `invoke --validate-request` and `--validate-response` modes. Resolve exact method/path contracts
  only from a caller-controlled full OpenAPI 3.0.x JSON/YAML document, allow only local JSON
  Pointer references, and perform no runtime fetching.
- Consequence: operation validation is fail-closed and remains opt-in. Optional bodies may be
  omitted, private-only body requiredness remains conservatively unknown, response validation is
  incompatible with previews, and no operation gains a bundled or automatic model binding.

## 2026-09-23: Keep alias expansion outside the runtime trust boundary

- Context: the authoritative upstream YAML uses aliases, while runtime model and contract loading
  deliberately rejects shared YAML object graphs and cycles.
- Decision: keep alias rejection in the shared structured-document loader and provide an explicit
  trusted offline YAML-to-JSON workflow. Do not make the CLI expand, convert, copy, or retain an
  operator document.
- Consequence: alias-bearing YAML fails with actionable remediation, while JSON and alias-free
  YAML share one strict loader and the established Markdown model workflow remains unchanged.

## 2026-09-23: Gather adoption evidence without gathering tenant payloads

- Context: endpoint selection needs real contract-fit evidence, but retaining request/response
  examples or enabling a network path would expand the public and security boundary.
- Decision: add a versioned offline adoption harness over reviewed operation IDs and sanitized
  fixtures. Reduce every result in memory to aggregate valid, invalid, or unusable counts and
  expose neither output-file nor transport capability.
- Consequence: maintainers can compare contract conformance before choosing a bounded v0.4 read
  workflow without receiving payloads, per-operation results, or new endpoint claims.
