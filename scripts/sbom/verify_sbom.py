"""
SBOM signature verification PoC script

Verifies a Base64 RSA-PSS(SHA256) signature for the CycloneDX SBOM JSON file.

Usage:
  python scripts/sbom/verify_sbom.py --sbom observability/sbom/sbom.json \
    --sig observability/sbom/sbom.sig --keys-dir observability/sbom/keys
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def verify_signature(sbom_path: Path, sig_path: Path, public_key_path: Path) -> bool:
    data = sbom_path.read_bytes()
    signature = base64.b64decode(sig_path.read_text().encode("utf-8"))

    public_key = serialization.load_pem_public_key(
        public_key_path.read_bytes(), backend=default_backend()
    )
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify SBOM signature using RSA-PSS (SHA256)")
    parser.add_argument("--sbom", required=True, help="Path to SBOM JSON file")
    parser.add_argument("--sig", required=True, help="Path to signature (Base64)")
    parser.add_argument("--keys-dir", required=True, help="Directory containing RSA public key")
    args = parser.parse_args()

    sbom_path = Path(args.sbom)
    sig_path = Path(args.sig)
    keys_dir = Path(args.keys_dir)
    public_key_path = keys_dir / "public.pem"

    if not sbom_path.exists():
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")
    if not sig_path.exists():
        raise FileNotFoundError(f"Signature file not found: {sig_path}")
    if not public_key_path.exists():
        raise FileNotFoundError(f"Public key not found: {public_key_path}")

    ok = verify_signature(sbom_path, sig_path, public_key_path)
    if ok:
        print("SBOM signature verification: OK")
        return 0
    else:
        print("SBOM signature verification: FAILED")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
