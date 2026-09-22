# Governance

## Scope control

- Define the operator workflow and acceptance criteria before adding a command family.
- The generic endpoint surface and reviewed operation registry are provisional; neither a local
  model export nor distilled traffic facts constitute an authoritative paths contract.
- Add named resource commands only from an authoritative endpoint contract or sanitized,
  reviewable tenant evidence.
- Treat production mutations, high-volume reads, tenant-data retention, and authentication-flow
  changes as separately reviewed work.
- The threat-scenario export is the approved high-volume read workflow. Its scope is all visible
  scenarios, and completeness requires stable page metadata plus an exact unique-count match.

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

## Model provenance

- Model exports and compiled model catalogs are operator-controlled local inputs and are forbidden
  from the public tree, wheel, and sdist.
- `--models-path` or `ANVILOGIC_MODELS_PATH` is required for every model command and any explicit
  request or response model validation.
- `scripts/compile_models.py` may compile a local Markdown export only with explicit input and
  output paths. Its output must remain outside the repository.
- The private repository history through `v0.3.1` is the only retained location for the originally
  supplied corpus and compiled derivative.

## Operation fact provenance

- `operations.json` contains reviewed facts only: stable ID, method, normalized path, query names,
  request-body presence, risk, confidence, evidence class, and last-verified date.
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
- Build release archives from a clean checkout with the exact tools in
  `release-requirements.txt`, verify the immutable schema bytes and absence of model catalogs in
  both archives, and smoke-test the wheel with and without an operator-supplied model export.
- The private repository remains release authority. A public release is created only from the
  merged, tagged private commit by `scripts/create_public_mirror.py`.
- The public repository has a single sanitized commit on `main`, a lightweight matching version
  tag, and `PUBLICATION_MANIFEST.json` binding it to the private commit and source-tree digest.
- Public and private GitHub releases remain Alpha prereleases. Public releases are source-only:
  attach no wheel or sdist. PyPI publication is not approved.
