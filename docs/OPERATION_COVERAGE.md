# Operation coverage matrix

The v3 registry contains 344 fact entries: 317 from the public OpenAPI document plus 27
private-evidence-only compatibility entries. Totals are 155 GET, 144 POST, 18 DELETE, 17 PATCH,
and 10 PUT. “Documented” below means a wire fact appears in the pinned public document; it does not
establish support or semantic safety. Tests are offline and never make live tenant calls.

| Surface | Captured | Implemented | Tested | Documented | Publicly releasable |
| --- | --- | --- | --- | --- | --- |
| All 344 registry facts | Yes | Generic `invoke` resolution | Metadata, uniqueness, path, query, body, totals, and ID generation | Registry and provenance docs | Yes |
| 317 public OpenAPI facts | Publicly documented | Generic invocation | Deterministic generation and exact method totals | Public source metadata recorded | Distilled facts only |
| 47 public/private overlaps | Both evidence classes | Generic invocation with stable prior IDs | ID preservation and 11 merged query allowlists | Mixed provenance explicit | Yes |
| 27 private-only facts | Provisional compatibility facts | Generic invocation | Stable IDs and evidence metadata | Limitation explicit | Facts only |
| 155 GET facts | Mixed evidence | Generic invocation; safe-method send behavior | Path/query and request planning | Generic call/invoke docs | Yes |
| 189 non-safe facts | Mixed evidence | Generic invocation, always apply-gated | Apply gates and no mutation retry | Generic call/invoke docs | Yes |
| `post.api.search.scenario-list-view` | Yes | Threat-scenario list and generic invocation | Pagination, ordering, totals, drift, apply gate | Exporter contract | Yes |
| `get.api.analytic.use-case` | Yes | Threat-scenario detail and generic invocation | Detail normalization and malformed-response cases | Exporter contract | Yes |
| `post.api.search.scenario-group-query` | Yes | Stage membership and generic invocation | Membership, cardinality, duplicate, conflict, apply gate | Exporter contract | Yes |
| Endpoint-specific semantics outside the exporter | Fact only | No | No live or semantic endpoint tests | Limitation documented | Registry facts only |
| Authentication-flow replay | No | No | No | Explicitly excluded | No |
| Mutation retry/idempotency contracts | No | No | No | Explicitly excluded | No |
| Model bindings | Removed | Explicit local validation only | Caller-supplied model tests | Local model workflow | No binding claims |

## Status rules

- Every registry entry must have `risk`, `confidence`, non-empty `evidence`, and `last_verified`.
- Every method/path pair is resolvable by ID and every named query is allowlisted.
- POST, PUT, PATCH, and DELETE never become implicit reads: they remain preview-only without
  `--apply` and are never retried.
- Public releasability applies to the distilled fact row, not to private supporting evidence.
- Only the three named exporter rows claim endpoint-specific implementation and tests.

The canonical per-operation list is
[`src/anvilogic_cli/operations.json`](../src/anvilogic_cli/operations.json); duplicating all 344 rows
here would create a second registry. `OperationCatalog` validates every entry on load, and tests
assert that the three exporter IDs resolve from the same canonical data.
