# Governance

## Scope control

- Define the operator workflow and acceptance criteria before adding a command family.
- The public OpenAPI document is authoritative only for documented wire facts after title,
  version, and SHA-256 verification. It does not prove endpoint stability or semantic safety.
  Private-only compatibility entries and local model exports remain provisional inputs.
- Add named resource commands only from an authoritative endpoint contract or sanitized,
  reviewable tenant evidence.
- Treat production mutations, high-volume reads, tenant-data retention, and authentication-flow
  changes as separately reviewed work.
- The threat-scenario export is the approved high-volume read workflow. Its scope is all visible
  scenarios. Completeness requires two full list sweeps with valid, stable page metadata, an exact
  unique-count match in each sweep, and identical scenario-ID-to-modification-time mappings across
  sweeps. Source page ranges need not be globally ordered; the verified snapshot is ordered
  locally and source range ordering is recorded in the manifest. Ordered stages must resolve
  through explicit detail group references to complete, unique, exact-count memberships.
- Every stable list item must be detail-inspected. A detail without a `threatScenario` object is
  classified as a non-scenario, excluded before group lookup, recorded in private findings, and
  included in aggregate manifest source counts. A malformed present object fails closed.
- A group-proven identifier whose detail alone returns HTTP 403 or 404 retains its membership as an
  un-enriched placeholder with a private finding. Other HTTP failures, scenario details, group
  responses, membership, and completeness checks remain fatal.
- Normalize ATT&CK IDs only from explicit canonical technique tokens in dedicated MITRE fields or
  the allowlisted identifier description. Do not infer IDs from technique names; retain unmapped
  identifiers with private findings.

## Safety rules

- Never commit tokens, cookies, authorization headers, raw tenant responses, private hostnames,
  HAR files, or connector secrets.
- TLS verification, bounded timeouts, no credential-bearing redirects, and redacted diagnostics
  remain default invariants.
- Mutations require `--apply`; a command without it must remain local and preview-only.
- Read retries are bounded. Mutation retries require endpoint-specific idempotency evidence and
  are not allowed in the generic client.
- Output paths must not be overwritten implicitly. Files containing API output use 0600
  permissions where supported.
- Multi-artifact coverage exports use a 0700 run directory, normalized allowlisted fields, and
  hashes. They must not retain raw API envelopes, headers, owners, rule logic, or credentials.
- Cross-product reconciliation uses private offline artifacts only. Require a stable repeated
  AttackIQ catalog before planning, treat exact tag/platform matches as reviewable candidates, and
  keep Daybreak packets pending and untransmitted until model access, data sharing, and human review
  are separately approved. Coverage acceptance never authorizes model calls, scenario uploads, or
  assessment application.
- Daybreak calibration uses a deterministic 12-gap, 12-control private pilot with fixed platform
  quotas. Every positive control must be covered on the same platform and human-confirmed as
  semantically equivalent; every gap must be confirmed missing or removed and deterministically
  replenished. Any failed positive control stops calibration. Pilot acceptance leaves
  `submission_authorized` false and does not authorize model requests or product mutations.

## Model provenance

- Model exports, full OpenAPI documents, and compiled model catalogs are operator-controlled local
  inputs and are forbidden from the public tree, wheel, and sdist.
- `--models-path` or `ANVILOGIC_MODELS_PATH` is required for every model command and any explicit
  request or response model validation.
- Local model inputs may be Markdown, JSON, YAML, or YML. YAML parsing must use the safe loader,
  retain YAML 1.2 scalar behavior, reject aliases and duplicate keys, and produce an acyclic
  JSON-compatible tree. URI-valued model paths are forbidden; the CLI does not fetch schemas at
  runtime.
- `scripts/compile_models.py` may compile a local Markdown export only with explicit input and
  output paths. Its output must remain outside the repository.
- The private repository history through `v0.3.1` is the only retained location for the originally
  supplied corpus and compiled derivative.

## Operation fact provenance

- `operations.json` contains reviewed facts only: stable ID, method, normalized path, query names,
  request-body presence and requiredness, risk, confidence, evidence classes, and last-verified
  date.
- `scripts/generate_operations.py` accepts only a local YAML input and the independently
  checksum-pinned `v0.3.3` registry seed. It must verify both inputs, public URL metadata, title,
  version, operation totals, and collision-free IDs before replacing the distilled registry. The
  seed and output paths must differ.
- Private traffic may be named as the provenance class, but capture filenames, raw messages,
  tenant values, observation counts, response samples, statuses, and model-validation claims are
  forbidden.
- `docs/PROVENANCE.md` records source and license boundaries.
- `docs/OPERATION_COVERAGE.md` distinguishes fact capture from semantic implementation and tests.

## Export contract

- Every `threat_scenarios.jsonl` record must validate against the bundled JSON Schema before a run
  directory is created or any artifact is written.
- The released bytes for schema ID `urn:anvilogic-cli:threat-scenario-record:1` are immutable.
  Adding, removing, retyping, or changing the meaning of a field requires a new schema version and
  ID. Implementation fixes that preserve the contract remain on v1.
- The collection manifest must record the schema ID, integer version, and SHA-256 of the exact
  bundled schema bytes. A sanitized golden v1 record protects consumer compatibility.
- Schema discovery must be deterministic, offline, and emit the exact packaged resource.

## Change discipline

- Keep the CLI layer thin and test transport/configuration/model behavior independently.
- Add tests with sanitized example domains and placeholder credentials.
- Update public docs whenever flags, outputs, exit codes, environment variables, or safety gates
  change.
- Every pull request must state whether commands, artifacts, schemas, safety gates, or workflow
  states affect a central cross-tool playbook. Link the corresponding private playbook pull request
  or record `No cross-tool playbook impact` with a reason.
- Run `python3 scripts/quality_gate.py` before review.
- Run the independent secret scanner and public-safety scanner on every candidate. Allowlist
  entries require a narrow match and written review reason.

## Release discipline

- `pyproject.toml`, `src/anvilogic_cli/__init__.py`, `CHANGELOG.md`, and `docs/STATE.md` must agree
  on the release version and lifecycle status.
- Refresh and vulnerability-audit constraints in a clean environment before a release.
- A release requires the Python 3.10-3.13 CI matrix, dependency alignment, vulnerability audit,
  secret scan, public-safety source and wheel scan, lint, type checking, tests, and clean private
  package builds.
- Build release archives without isolation from a clean checkout with the exact tools in
  `release-requirements.txt`, verify the immutable schema bytes and full-content public-safety
  scan of both archives, and smoke-test the wheel with and without an operator-supplied model
  export.
- Before release, resolve the documentation-impact item for every changed command, artifact,
  schema, safety gate, or workflow state. Affected cross-tool behavior must link an approved
  central-playbook change; otherwise record why there is no playbook impact.
- The private repository remains release authority. A public release is created only from a
  lightweight tag that exactly matches the merged private authority branch tip, as verified by
  `scripts/create_public_mirror.py`.
- The public repository has a single sanitized commit on `main`, a lightweight matching version
  tag, and `PUBLICATION_MANIFEST.json` binding it to the private commit and source-tree digest.
- Public and private GitHub releases remain Alpha prereleases. Public releases are source-only:
  attach no wheel or sdist. PyPI publication is not approved.
