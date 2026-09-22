# Private-evidence reconciliation

## Public result

Private browser traffic was reviewed to establish a provisional operation surface. The public
release does not include the capture, capture filenames, request or response values, tenant data,
headers, cookies, authentication exchanges, samples, or counts.

The distilled registry contains 74 entries. Each entry is limited to:

- stable reviewed ID;
- HTTP method and normalized relative path;
- query parameter names and request-body presence;
- conservative risk classification;
- confidence, evidence class, and last-verified date.

Paths that contained variable segments were normalized to named placeholders before review. Query
values were discarded; only names remain. Model bindings and response status observations were
removed for `v0.3.2` because they would assert validation conclusions derived from the excluded
model corpus and private response evidence.

## Interpretation

`confidence: confirmed` means the retained wire fact was directly present in reviewed private
evidence. It does not mean the endpoint is publicly documented, stable, complete, supported, or
semantically safe. `evidence_class: distilled-private-traffic` identifies the provenance class
without identifying a capture file or tenant.

Risk is an operator safeguard, not a server-semantics claim:

- `read` is used for GET/HEAD/OPTIONS facts;
- `write` is used conservatively for POST/PUT/PATCH/DELETE facts;
- `bulk` identifies the two POST reads used by the reviewed all-visible exporter;
- `destructive` is reserved for a future explicitly reviewed destructive operation.

All POST operations are preview-only without `--apply` and are never retried. The fact registry
does not relax generic client safeguards.

## Reviewed named workflow

Only three operations have a resource-specific implementation: the threat-scenario list, detail,
and stage-membership operations used by `threat-scenarios export`. Their request and response
handling is enforced in exporter code and sanitized test fixtures. The remaining entries are
available only through generic named invocation; no endpoint-specific semantic contract is claimed.

See [OPERATION_COVERAGE.md](OPERATION_COVERAGE.md) for status and
[PROVENANCE.md](PROVENANCE.md) for the evidence and license boundary.
