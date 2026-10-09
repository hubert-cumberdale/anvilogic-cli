# AttackIQ integration summary

The end-to-end Anvilogic-to-AttackIQ coverage procedure is owned by the central platform team in
the private security-platform handbook. Operators with access must use its canonical playbook for
sequencing, compatible tool refs, approvals, evidence, gap dispositions, recovery, and cross-tool
acceptance.

This public-safe summary defines only the `avl-cli` side of the handoff. The command reference,
schema, collection invariants, and safety behavior remain authoritative in this repository.

## Export contract

`anvilogic threat-scenarios export` is the approved producer. Preview without `--apply`; the
preview sends no request and writes no artifact. The explicit `--apply` flag authorizes the
reviewed high-volume POST-based reads and creation of a new private output directory. It does not
authorize a downstream model call or product mutation.

The consumer handoff consists of:

| Artifact | Contract |
| --- | --- |
| `threat_scenarios.jsonl` | Records conform to immutable schema ID `urn:anvilogic-cli:threat-scenario-record:1`. |
| `collection_manifest.json` | Records completeness, schema identity, aggregate source counts, artifact hashes, and permission expectations. |
| `collection_findings.json` | Records private metadata and enrichment limitations requiring operator review. |
| `threat_scenario_identifiers.csv` | Provides a private flattened analyst view; it is not the canonical machine handoff. |

Every record validates before a run directory is created. The collector requires two stable list
sweeps, exact unique counts, ordered stage-to-group resolution, and exact group membership. A
group-proven identifier whose detail alone returns HTTP 403 or 404 remains as an un-enriched
placeholder with a finding; other HTTP failures remain fatal. Only explicit canonical ATT&CK IDs
are normalized. Technique names are never converted into IDs.

The exact schema remains available offline:

```bash
anvilogic threat-scenarios schema
```

## Consumer boundary

A downstream reconciler must reject an incomplete manifest, invalid schema identity, mismatched
hash, malformed record, or unreviewed source limitation. Treat every artifact as restricted tenant
data: keep run directories outside Git with `0700` permissions and files with `0600` permissions,
and never retain raw API envelopes, headers, credentials, owners, or rule logic.

Exact ATT&CK-and-platform correlation can identify review candidates; it cannot prove semantic
equivalence or complete visibility in another product. Missing ATT&CK metadata is source
remediation, not a content gap. This handoff grants no authority to invoke a model, generate or
upload content, apply an assessment, set a target or schedule, or execute an assessment.

See the [README](../README.md#export-threat-scenario-coverage),
[architecture](ARCHITECTURE.md#threat-scenario-exporter), and
[governance](GOVERNANCE.md#export-contract) for the authoritative `avl-cli` behavior.
