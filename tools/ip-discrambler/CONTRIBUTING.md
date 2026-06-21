# Contributing to IP-Discrambler

Thank you for your interest in contributing. This document covers local setup, coding standards, and the pull request workflow.

## Development setup

```bash
git clone https://github.com/dmang69/IP-Discrambler.git
cd IP-Discrambler
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
pre-commit install
```

When working inside the IntentKernel monorepo, the package lives at `tools/ip-discrambler/`.

## Running tests

```bash
pytest tests/
ruff check src tests
mypy src/ip_discrambler
```

## Coding standards

- Python 3.9+ compatible syntax and type hints where practical
- Keep provider backends pluggable under `src/ip_discrambler/providers/`
- Prefer async I/O in the client; expose sync wrappers for CLI and scripting
- Add tests for new behavior; mock external HTTP calls in unit tests
- Run `ruff check` before opening a PR

## Commit messages

Use clear, imperative subjects:

- `feat: add Greynoise threat provider`
- `fix: handle IPv6 link-local in subnet audit`
- `docs: document REST policy-check endpoint`

## Pull request checklist

- [ ] Tests pass locally (`pytest tests/`)
- [ ] Lint passes (`ruff check src tests`)
- [ ] README or OpenAPI updated if behavior changed
- [ ] No secrets or API keys committed

## Architecture notes

| Layer | Location |
|-------|----------|
| CLI | `src/ip_discrambler/cli.py` |
| Client | `src/ip_discrambler/client.py` |
| REST server | `src/ip_discrambler/serve.py` |
| Providers | `src/ip_discrambler/providers/` |
| IntentOS bridge | `src/ip_discrambler/bridge.py` |

IntentKernel integration (monorepo only):

- `rust/crates/intentos-utilities/src/ip_discrambler.rs`
- `rust/crates/intentos-kernel/src/ip_policy.rs`
- IntentOS shell command: `ipdis`

## Questions

Open an issue at [github.com/dmang69/IP-Discrambler/issues](https://github.com/dmang69/IP-Discrambler/issues).