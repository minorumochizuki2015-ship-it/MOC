"""
Simple SBOM generator (PoC)

Reads requirements.txt and outputs a minimal SBOM JSON with components.
This is a fallback for environments where cyclonedx-bom CLI is unavailable.

Usage:
  python scripts/sbom/generate_sbom.py --requirements requirements.txt --out observability/sbom/sbom.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_requirements(req_path: Path) -> list[dict]:
    components = []
    for line in req_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # naive parse: split on first comparison operator or '=='
        name = line
        version = "unknown"
        for sep in ["==", ">=", "<=", ">", "<", "~=", "!="]:
            if sep in line:
                parts = line.split(sep, 1)
                name = parts[0].strip()
                version = sep + parts[1].strip()
                break
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}",
            }
        )
    return components


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate minimal SBOM JSON from requirements.txt")
    parser.add_argument("--requirements", required=True, help="Path to requirements.txt")
    parser.add_argument("--out", required=True, help="Path to output SBOM JSON")
    args = parser.parse_args()

    req_path = Path(args.requirements)
    out_path = Path(args.out)
    components = parse_requirements(req_path)

    sbom = {
        "bomFormat": "CycloneDX-poC",
        "specVersion": "0.0",
        "serialNumber": "urn:uuid:placeholder",
        "version": 1,
        "components": components,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(f"SBOM generated: {out_path} (components={len(components)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
