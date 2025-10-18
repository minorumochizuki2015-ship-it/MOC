from pathlib import Path

BASE = Path("data/validation/benchmarks/trae_credit_bench_20251009")
SUBS = ["raw", "normalized", "summaries", "reports"]


def ensure_dirs():
    created = []
    for s in SUBS:
        p = BASE / s
        p.mkdir(parents=True, exist_ok=True)
        created.append(str(p))
    return created


if __name__ == "__main__":
    dirs = ensure_dirs()
    print("Prepared validation directories:")
    for d in dirs:
        print(" -", d)
