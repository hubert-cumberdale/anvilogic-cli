# Operation coverage matrix

The v2 registry contains 74 public fact entries: 51 GET and 23 POST. “Captured” below means the
listed fact fields were distilled and reviewed; it does not mean an official contract exists.
“Implemented” distinguishes generic invocation from endpoint-specific semantics. “Tested” means
offline behavior, never a live tenant call.

| Surface | Captured | Implemented | Tested | Documented | Publicly releasable |
| --- | --- | --- | --- | --- | --- |
| All 74 registry facts | Yes | Generic `invoke` resolution | Metadata, uniqueness, path, query, and body validation | Registry, provenance, and reconciliation docs | Yes |
| 51 GET facts | Yes | Generic invocation; safe-method send behavior | Representative request planning plus all-entry registry validation | Generic call/invoke docs | Yes |
| 21 ordinary POST facts | Yes | Generic invocation, always apply-gated | Apply-gate regression plus all-entry registry validation | Generic call/invoke docs | Yes |
| `post.api.search.scenario-list-view` | Yes | Threat-scenario list and generic invocation | Pagination, ordering, totals, drift, apply gate | Exporter contract | Yes |
| `get.api.analytic.use-case` | Yes | Threat-scenario detail and generic invocation | Detail normalization and malformed-response cases | Exporter contract | Yes |
| `post.api.search.scenario-group-query` | Yes | Stage membership and generic invocation | Membership, cardinality, duplicate, conflict, apply gate | Exporter contract | Yes |
| Endpoint-specific semantics outside the exporter | Fact only | No | No live or semantic endpoint tests | Limitation documented | Registry facts only |
| Authentication-flow replay | No | No | No | Explicitly excluded | No |
| Mutation retry/idempotency contracts | No | No | No | Explicitly excluded | No |
| Model bindings | Removed | Explicit local validation only | Caller-supplied model tests | Local model workflow | No binding claims |

## Status rules

- Every registry entry must have `risk`, `confidence`, `evidence_class`, and `last_verified`.
- Every method/path pair is resolvable by ID and every named query is allowlisted.
- POST never becomes an implicit read: it remains preview-only without `--apply` and is never
  retried.
- Public releasability applies to the distilled fact row, not to private supporting evidence.
- Only the three named exporter rows claim endpoint-specific implementation and tests.

The canonical per-operation list is
[`src/anvilogic_cli/operations.json`](../src/anvilogic_cli/operations.json); duplicating all 74 rows
here would create a second registry. `OperationCatalog` validates every entry on load, and tests
assert that the three exporter IDs resolve from the same canonical data.
