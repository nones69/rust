# Mirror tools/ip-discrambler to a standalone GitHub-ready directory.
# Usage:
#   .\scripts\publish-ip-discrambler.ps1
#   .\scripts\publish-ip-discrambler.ps1 -Destination C:\src\IP-Discrambler -Push

param(
    [string]$Destination = (Join-Path $PSScriptRoot "..\IP-Discrambler-mirror"),
    [switch]$Push,
    [string]$Remote = "https://github.com/dmang69/IP-Discrambler.git"
)

$ErrorActionPreference = "Stop"
$Source = Resolve-Path (Join-Path $PSScriptRoot "..\tools\ip-discrambler")

Write-Host "Source:      $Source"
Write-Host "Destination: $Destination"

if (Test-Path $Destination) {
    Remove-Item -Recurse -Force $Destination
}
New-Item -ItemType Directory -Path $Destination | Out-Null

$excludeDirs = @("__pycache__", ".pytest_cache", ".venv", ".ruff_cache", "dist", "build", "*.egg-info")
$robocopyArgs = @(
    $Source, $Destination,
    "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS",
    "/XD", "__pycache__", ".pytest_cache", ".venv", ".ruff_cache", "dist", "build"
)
$null = robocopy @robocopyArgs
if ($LASTEXITCODE -ge 8) {
    throw "robocopy failed with exit code $LASTEXITCODE"
}

# Standalone repo uses workflows at repo root (not tools/ip-discrambler prefix).
$standaloneCi = Join-Path $Destination ".github\workflows\ci.yml"
if (-not (Test-Path (Split-Path $standaloneCi))) {
    New-Item -ItemType Directory -Path (Split-Path $standaloneCi) -Force | Out-Null
}
@'
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.9", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev]"
      - run: ruff check src tests
      - run: pytest tests/
'@ | Set-Content -Path $standaloneCi -Encoding utf8

Push-Location $Destination
try {
    if (-not (Test-Path ".git")) {
        git init
        git branch -M main
    }
    git add -A
    $status = git status --porcelain
    if ($status) {
        git commit -m "sync: mirror from IntentKernel monorepo tools/ip-discrambler"
    } else {
        Write-Host "No changes to commit."
    }

    if ($Push) {
        $remotes = git remote
        if ($remotes -notcontains "origin") {
            git remote add origin $Remote
        } else {
            git remote set-url origin $Remote
        }
        git push -u origin main
        Write-Host "Pushed to $Remote"
    } else {
        Write-Host ""
        Write-Host "Mirror ready. To publish:"
        Write-Host "  cd `"$Destination`""
        Write-Host "  git remote add origin $Remote"
        Write-Host "  git push -u origin main"
        Write-Host ""
        Write-Host "Or re-run: .\scripts\publish-ip-discrambler.ps1 -Push"
    }
} finally {
    Pop-Location
}