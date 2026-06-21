# Publishing IP-Discrambler to GitHub

The canonical development copy lives in the IntentKernel monorepo at `tools/ip-discrambler/`.
The public repository is [github.com/dmang69/IP-Discrambler](https://github.com/dmang69/IP-Discrambler).

## Mirror from monorepo (Windows)

```powershell
cd C:\Users\Dizzle\rust
.\scripts\publish-ip-discrambler.ps1
```

Output defaults to `IP-Discrambler-mirror/` at the repo root with:

- Python package source
- `Dockerfile`, `CONTRIBUTING.md`, `openapi.yaml`
- Standalone `.github/workflows/ci.yml` (repo-root paths)

## Push to GitHub

```powershell
.\scripts\publish-ip-discrambler.ps1 -Push
```

Requires `git` credentials with write access to `dmang69/IP-Discrambler`.

Manual alternative:

```powershell
.\scripts\publish-ip-discrambler.ps1 -Destination C:\src\IP-Discrambler
cd C:\src\IP-Discrambler
git remote add origin https://github.com/dmang69/IP-Discrambler.git
git push -u origin main
```

## Monorepo CI

Changes under `tools/ip-discrambler/` also run via `.github/workflows/ip-discrambler.yml` in the IntentKernel repo.

## PyPI (planned)

```bash
cd tools/ip-discrambler
pip install build twine
python -m build
twine upload dist/*
```