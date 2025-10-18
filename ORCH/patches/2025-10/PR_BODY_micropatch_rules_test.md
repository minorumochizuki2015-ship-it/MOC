# Micropatch: DIFF_GUARD + Secret Scan unit test (≤50 lines)

- Purpose: minimal DIFF_GUARD and safe unit test using runtime strings
- Changes: .trae/rules/DIFF_GUARD.yaml, tests/unit/test_secret_patterns.py
- Budget: total additions ≤50 lines (compressed)
- Verify locally: `pre-commit run --all-files` and `pytest -q tests/unit/test_secret_patterns.py`
- Impact: rules + tests only; no production code
- Compare: https://github.com/minorumochizuki2015-ship-it/MOC/compare/master...work/micropatch-rules-test