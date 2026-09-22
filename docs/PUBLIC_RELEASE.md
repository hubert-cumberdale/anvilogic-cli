# Public release process

## Policy

The private repository is the release authority. Public releases are Alpha, source-only, and
published to `hubert-cumberdale/anvilogic-cli` as sanitized one-commit snapshots. They do not
include private Git history, model catalogs, raw evidence, build products, attached wheel/sdist
assets, or a PyPI release.

## Private candidate

1. Create `release/vX.Y.Z`, update version and lifecycle documents, and open a reviewable pull
   request.
2. Run `python3 scripts/quality_gate.py` on Python 3.10 through 3.13.
3. Verify dependency constraints and audit them with `pip-audit`.
4. Build a wheel and sdist privately, then run `python3 scripts/verify_distributions.py dist`.
5. Smoke-test a clean wheel install. Confirm ordinary commands work without a model catalog,
   model features fail clearly without one, and succeed with a synthetic caller-supplied export.
6. Compare the threat-scenario v1 schema bytes to `v0.3.1`.
7. Merge the reviewed pull request and create a lightweight private `vX.Y.Z` tag on the merge.

## Mirror creation

From the clean tagged private checkout:

```bash
python3 scripts/create_public_mirror.py \
  --ref v0.3.2 \
  --output-dir /tmp/anvilogic-cli-v032-public
```

The generator exports the tag with `git archive`, rejects forbidden model/capture files, runs the
source and secret scans, builds and inspects a validation-only wheel, writes a deterministic
`PUBLICATION_MANIFEST.json`, initializes `main`, commits the entire snapshot once, and adds a
lightweight matching tag.

The manifest records the private source ref/commit/commit time, package version, tree digest,
history policy, and distribution policy. Its digest excludes only itself and `.git/`.

## Publication and verification

1. Create the public repository as public if it does not already exist.
2. Add it as the mirror export's `origin` and atomically push `main` and the matching tag.
3. Verify visibility, default branch, one-commit count, branch/tag commit equality, CI success, and
   the manifest digest against the public checkout.
4. Create matching public and private GitHub prereleases with zero attached assets.
5. Confirm no PyPI version exists.

Never mirror the private repository directly and never force-push a public repository before
verifying the exact local target and obtaining the authorization required by repository policy.
