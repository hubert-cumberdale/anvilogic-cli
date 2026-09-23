# Provenance ledger

This ledger describes every source class represented in the public `v0.3.4` tree. Facts are
distinguished from copied expressive content, and excluded inputs remain excluded from source and
package artifacts.

| Source class | Access and license boundary | Public use | Included material |
| --- | --- | --- | --- |
| Project implementation and documentation | Authored for this project; released under the repository MIT license | Direct source publication | Python source, tests, scripts, and project documentation |
| Historical supplied Anvilogic model export | Private supplied material; redistribution not approved | Excluded; retained only in private Git history through `v0.3.1` | None |
| Historical compiled model catalog | Deterministic derivative of the excluded supplied export | Excluded from source, wheel, and sdist | None |
| Operator-supplied model catalog | User-controlled local input; its license and sensitivity are the operator's responsibility | Loaded at runtime only through an explicit path | No bytes copied into the project or release |
| Public Anvilogic OpenAPI 3.0 document | Publicly accessible at the recorded GitBook URL; no explicit redistribution license was found, and copyright remains with its publisher | Checksum-pinned factual distillation and attribution only | Method, normalized path, query names, request-body presence and requiredness, source metadata, and verification date; no YAML or schemas |
| Reviewed private traffic evidence | Private evidence; raw messages and tenant material are not redistributed | Facts were distilled through human review | Operation ID, method, normalized path, query names, body presence, conservative unknown requiredness, and review metadata only |
| Threat-scenario v1 output contract | Authored for this project and already released; bytes frozen | Bundled verbatim | JSON Schema and synthetic compatibility fixtures |
| Synthetic tests | Authored for this project; no tenant or live response material | Bundled in source only | Minimal model and response shapes needed for offline tests |
| Other public Anvilogic documentation | Publicly accessible; copyright remains with its publisher | Facts summarized without verbatim republication | Product/authentication context only |
| `grandcamel/anvilogic-as` | Public MIT-licensed project | Design reference and attribution only | Provenance ledger, coverage matrix, and registry metadata concepts; no endpoint facts or code copied |
| `hubert-cumberdale/attackiq-cli` | Maintainer's public source project; package metadata declares MIT | Release-process reference | One-commit mirror, manifest, and validation-wheel pattern adapted for this repository |
| Python dependencies | Third-party packages under their respective licenses | Referenced by constrained dependencies; not vendored | Package names and versions only |

## Distillation rules

- Facts must be necessary for documented CLI behavior and independently reviewable in the public
  registry.
- Raw captures, headers, cookies, tokens, host-specific tenant values, bodies, response samples,
  observation counts, and private capture paths are never copied.
- Public operations are marked `publicly-documented`; private-only facts remain `confirmed` and
  provisional. Confidence does not establish support, stability, or semantic safety.
- Risk is conservative. Any method outside GET/HEAD/OPTIONS remains apply-gated regardless of
  apparent read semantics.
- Model-validation conclusions derived from excluded evidence or the excluded model corpus are not
  public facts and were removed.
- The mutable GitBook URL is never fetched at runtime. Maintainers control a local copy and the
  generator accepts it only when its SHA-256, title, version, and operation totals match the
  reviewed source.

## Publication chain

The private repository remains authoritative. A merged private commit is tagged, exported with
`git archive`, scanned, built into a validation-only wheel, and recorded in
`PUBLICATION_MANIFEST.json`. A new repository is then initialized with exactly one commit on
`main`; the matching lightweight tag points to that same commit. Private Git parents and removed
files are therefore not reachable from the public repository.

The public prerelease attaches no package assets. Private wheel and sdist builds exist only to
validate packaging and installation, and no release is published to PyPI.

## Credit

The per-entry risk, confidence, evidence, verification metadata, source ledger, and coverage design
were informed by [`grandcamel/anvilogic-as`](https://github.com/grandcamel/anvilogic-as). That
project's public registry intentionally contains public-source evidence; this project does not copy
its endpoint facts and separately labels distilled private evidence.
