# Benchmarks

This directory contains simple benchmark scripts to validate performance SLO gates.

Included:
- python_bench.py: Measures p95 latency and error rate for dashboard endpoints.

Recommended usage:
```
python bench/python_bench.py --iterations 100 --delay 0.05
```

SLO gates (from project_rules.yaml):
- p95 <= 0.2s
- error rate <= 0.5%