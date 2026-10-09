# Contributing

Create a Python 3.10+ virtual environment, install with constrained development dependencies, and
run the quality gate:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -c constraints.txt -e '.[dev]'
python3 scripts/quality_gate.py
```

Keep changes focused and add tests for new behavior. Update the README and state/architecture docs
when user-visible behavior changes. Model exports are local operator inputs: never add a model
export or compiled model catalog to the repository. The optional compiler requires explicit
`--input` and `--output` paths, which should remain outside the checkout.

Pull requests should include a summary, explicit security/compatibility impact, checks run, and any
known gaps. Never include real API keys, tenant payloads, internal hosts, raw captures, private
filesystem paths, or live-response evidence.
