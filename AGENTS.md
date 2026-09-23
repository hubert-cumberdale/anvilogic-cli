# Repository Guidelines

## Structure

- `src/anvilogic_cli/`: CLI, configuration, client, model catalog, and output code.
- `src/anvilogic_cli/operations.json`: reviewed, distilled operation fact registry.
- `tests/`: focused pytest tests named `test_*.py`.
- `scripts/`: model compilation, public-safety checks, and the local quality gate.
- `docs/`: governance, architecture, decisions, and current-state documents.

## Development commands

- `python3 -m venv .venv`: create a virtual environment.
- `python -m pip install -c constraints.txt -e '.[dev]'`: install for development.
- `python3 scripts/quality_gate.py`: run all repository checks.
- `python3 scripts/check_public_safety.py`: scan tracked source and a validation wheel.
- `anvilogic --help`: inspect the installed command tree.

## Code and tests

- Support Python 3.10 and later; use four spaces and a 100-character line limit.
- Use `snake_case` for modules and functions and `PascalCase` for classes.
- Keep CLI parsing, network transport, configuration, model handling, and output separate.
- Add focused tests for behavior changes. Never make live tenant calls from unit tests.

## Secure defaults

- Never commit, log, echo, or include real secrets, tenant payloads, cookies, or private hosts in
  fixtures.
- Keep TLS verification on, use explicit timeouts, and do not follow redirects carrying auth.
- Redact authentication and secret-shaped fields in request previews and errors.
- Keep mutation commands preview-only unless the operator passes an explicit apply flag.
- Treat response files as sensitive and write them with user-only permissions.

## Change governance

- Start with `docs/GOVERNANCE.md` and preserve the scope boundaries in `docs/STATE.md`.
- Update README and architecture/state docs when public behavior changes.
- Never commit caller-supplied model exports or compiled model catalogs.
- Keep commits small and imperative. PRs must describe scope, security impact, and checks run.
