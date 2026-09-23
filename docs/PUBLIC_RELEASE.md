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
4. Install `release-requirements.txt`, run `python3 -m build --no-isolation`, then run
   `python3 scripts/verify_distributions.py dist`. The exact pinned setuptools and wheel versions
   are part of the release toolchain.
5. Smoke-test a clean wheel install. Confirm ordinary commands work without a model catalog,
   model features fail clearly without one, and succeed with synthetic caller-supplied JSON and
   YAML documents.
6. Compare the threat-scenario v1 schema bytes to `v0.3.1`.
7. Confirm wheel and sdist contain neither model catalogs nor the complete upstream OpenAPI YAML.
8. Merge the reviewed pull request and create a lightweight private `vX.Y.Z` tag on the merge.

## Mirror creation

From the clean tagged private checkout:

```bash
python3 scripts/create_public_mirror.py \
  --ref v0.3.4 \
  --authority-ref master \
  --output-dir /tmp/anvilogic-cli-v034-public
```

The generator first verifies that the named tag is lightweight and points to the exact authority
branch tip. It exports the tag with `git archive`, rejects forbidden model/capture files, runs the
source and secret scans, builds and inspects a validation-only wheel, writes a deterministic
`PUBLICATION_MANIFEST.json`, initializes `main`, commits the snapshot once, and adds a lightweight
matching tag.

The manifest records the private source ref/commit/commit time, package version, tree digest,
history policy, and distribution policy. Its digest excludes only itself and `.git/`.

## Publication and verification

1. Create the public repository as public if it does not already exist.
2. Resolve the exact current public `main`, then atomically replace it with an exact
   `--force-with-lease`. Retain prior release tags and their disconnected snapshots, and push the
   new lightweight tag pointing to the new one-commit `main`.
3. Verify visibility, default branch, one-commit count, branch/tag commit equality, CI success, and
   the manifest digest against the public checkout.
4. Create matching public and private GitHub prereleases with zero attached assets.
5. Confirm no PyPI version exists.

Never mirror the private repository directly and never force-push a public repository before
verifying the exact local target and obtaining the authorization required by repository policy.
