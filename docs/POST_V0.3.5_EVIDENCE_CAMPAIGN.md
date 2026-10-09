# Post-v0.3.5 evidence campaign

Status: collecting evidence. No v0.4 workflow is selected, and no v0.4 implementation milestone
exists.

The campaign uses the v0.3.5 offline adoption harness to compare demand and contract fit without
collecting tenant material. The 344-operation registry is a discovery aid, not evidence that an
endpoint is supported, stable, complete, or suitable for a named workflow.

## Non-negotiable boundary

- Operators keep contracts and sanitized fixtures on systems they control and run every assessment
  offline.
- Maintainers retain only aggregate outcome counts grouped by a public, non-tenant-specific
  candidate workflow name.
- Do not submit or commit contracts, fixtures, request or response payloads, credentials, cookies,
  headers, tenant or user identifiers, private hosts, raw responses, logs, screenshots, HAR files,
  or per-operation results.
- Public documentation may be cited. Authorized private evidence may be reviewed, but only the
  minimum distilled fact and its evidence class may enter the public record.
- Assessment results establish contract fit only. They do not establish authentication behavior,
  pagination completeness, endpoint support, or semantic safety.
- Automatic pagination, resource mutations, and mutation retries remain out of scope. Alpha,
  source-only GitHub prereleases, zero release assets, and no PyPI publication remain in force.

If an input cannot be sanitized without losing the behavior under review, do not submit it and
mark the corresponding evidence gate insufficient.

## Operator assessment

Use the v0.3.5 release and place both inputs outside the repository. A fixture document must use
format version 1 and reviewed operation IDs as documented in the README. Disconnect the assessment
environment from the network if that is part of the operator's evidence procedure; the command
itself has no host, credential, transport, or output-file capability.

```bash
anvilogic adoption assess \
  --contract /secure/operator/path/trusted-openapi.json \
  --fixtures /secure/operator/path/sanitized-fixtures.json
```

Before reporting a result:

1. Confirm every value is synthetic or irreversibly sanitized and contains no tenant-specific
   identifiers or private hostnames.
2. Run the same assessment twice offline and confirm the aggregate JSON is identical.
3. Confirm `evaluated = valid + invalid + unusable` for `request`, `response`, and `total`, and
   confirm the request and response counts sum to the total counts.
4. Keep the contract and fixture document outside the repository and operator-controlled. Do not
   attach either input or a command transcript to an issue.
5. Report only the aggregate fields below. A maintainer adds them to the workflow rollup; the
   submitted inputs are never requested or retained.

```json
{
  "candidate_workflow": "public non-tenant-specific name",
  "assessment_runs": 1,
  "request": {"evaluated": 0, "valid": 0, "invalid": 0, "unusable": 0},
  "response": {"evaluated": 0, "valid": 0, "invalid": 0, "unusable": 0},
  "total": {"evaluated": 0, "valid": 0, "invalid": 0, "unusable": 0}
}
```

All numeric fields are non-negative integers. `assessment_runs` is demand evidence, not a count of
unique tenants or organizations. Maintainers sum matching fields by candidate workflow and retain
no submitter or environment breakdown. Empty placeholder reports are not evidence.

## Ordered evidence gates

Evidence is reviewed in this order. A later gate cannot compensate for an insufficient earlier
gate. Record each gate as `satisfied`, `not applicable` with authoritative justification, or
`insufficient`; do not use partial confidence to select a workflow.

1. [#13 authentication scope and tenant
   behavior](https://github.com/hubert-cumberdale/avl-cli/issues/13) must establish the supported
   scheme, credential scope, tenant boundary, and sanitized failure behavior without authentication
   replay or credential retention.
2. [#15 response envelopes](https://github.com/hubert-cumberdale/avl-cli/issues/15) must establish
   the exact success and documented error statuses, media types, and envelope schema for every
   operation in the candidate. Aggregate adoption results must show whether sanitized request and
   response fixtures can be evaluated by the authoritative contract.
3. [#16 pagination and completeness](https://github.com/hubert-cumberdale/avl-cli/issues/16) must
   establish page inputs, bounds, stable metadata, deterministic ordering, termination,
   deduplication, drift behavior, and a completeness invariant. A non-paginated workflow may use
   `not applicable` only when authoritative evidence proves the response is complete.
4. [#17 endpoint stability and support](https://github.com/hubert-cumberdale/avl-cli/issues/17)
   must establish an authoritative support and lifecycle statement for every endpoint in the
   workflow. A documented wire shape or registry entry is not enough.
5. [#14 documented parameter requiredness](https://github.com/hubert-cumberdale/avl-cli/issues/14)
   must cover every path, query, header, and body parameter needed by the candidate. Requiredness
   may not be inferred from observed traffic, names, examples, or common behavior. Record this gate
   as `not applicable` only when the authoritative contract proves the candidate has no such
   unresolved parameter facts.

Authoritative evidence means a versioned vendor contract or explicit vendor support statement
whose provenance can be reviewed. Sanitized observations can test that evidence, but cannot replace
it. Each gate issue holds only citations, distilled conclusions, aggregate counts where relevant,
and an explicit disposition; it must not hold caller-supplied documents or payloads.

Current gate: #13 is `insufficient`. Vendor-authored [connection setup][api-key-setup] explains how
an administrator generates an API key for the Anvilogic Splunk integration, and the
[Splunk architecture][splunk-architecture] states that integration traffic uses REST over
HTTPS/TLS. Neither source establishes the API authentication header or scheme, credential scope,
candidate-read tenant boundary, cross-tenant behavior, or missing, invalid, expired, unauthorized,
and wrong-tenant credential behavior. The remaining gates have not been dispositioned because the
first gate has not passed.

## Selection record

Issue [#20](https://github.com/hubert-cumberdale/avl-cli/issues/20) is the only selection record.
For each candidate it records the aggregate assessment rollup, relative demand, the disposition of
the ordered gates, and one of `eligible`, `ineligible`, or `insufficient evidence`.

Select exactly one candidate only when all applicable gates are satisfied and its bounded scope can
be stated without unresolved endpoint assumptions. Eligibility also requires authoritative contract
evidence and nonempty aggregate outcomes from sanitized fixtures that remained operator-controlled.
Demand ranks otherwise eligible candidates; it does not waive a gate. If no candidate qualifies,
record that v0.4 is deferred and leave endpoint behavior unchanged. Do not select a workflow merely
because it exists in `operations.json`.

Current result: no aggregate operator reports are retained and gate #13 is insufficient, so v0.4
is deferred. Issue #20 remains open for the campaign; this is not a workflow selection.

## Work allowed after selection

Only after issue #20 names exactly one eligible workflow may maintainers create a bounded v0.4
implementation milestone. Its test plan must cover:

- supported and failed authentication without exposing credentials;
- all documented request requirements;
- success and error response envelopes;
- pagination termination, deduplication, completeness, and drift, or the reviewed non-pagination
  invariant;
- missing, mismatched, and unsupported contract behavior that fails closed;
- bounded safe-read retries, TLS verification, explicit timeouts, and redirect suppression; and
- the unchanged mutation apply gates, absence of mutation retries, private output handling, secret
  scan, and complete public-safety checks.

The milestone must contain only that workflow, its contract-focused tests, documentation, and
release verification. Other reads, automatic pagination without #16, resource mutations, mutation
retries, Beta status, release assets, and PyPI remain separate decisions.

[api-key-setup]: https://public-docs.anvilogic.com/get-started/onboarding-guide/select-your-data-repository-and-get-data-in/integrate-splunk-as-your-data-repository/connect-to-the-anvilogic-platform
[splunk-architecture]: https://public-docs.anvilogic.com/get-started/reference-architectures/anvilogic-on-splunk-architecture
