# pre-commit stability (Windows)

- Shell: PowerShell + venv; `python -m pre_commit`
- Setup: `pre-commit install && pre-commit autoupdate`
- Flow: `pre-commit run --all-files` → `git add -A` → commit
- EOL: `git config core.autocrlf false`; rely on EOL check in CI
- Conflict: if stash/auto-fix conflicts, use `--no-verify` as exception; CI will re-run hooks