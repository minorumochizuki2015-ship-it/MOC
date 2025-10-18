"""
SBOM signing PoC script

Signs a CycloneDX SBOM JSON file using RSA-PSS (SHA256) and writes a Base64 signature.

Usage:
  python scripts/sbom/sign_sbom.py --sbom observability/sbom/sbom.json \
    --out observability/sbom/sbom.sig --keys-dir observability/sbom/keys
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def ensure_keys(keys_dir: Path) -> tuple[Path, Path]:
    private_path = keys_dir / "private.pem"
    public_path = keys_dir / "public.pem"

    if not keys_dir.exists():
        keys_dir.mkdir(parents=True, exist_ok=True)

    if not private_path.exists() or not public_path.exists():
        # Generate ephemeral RSA key pair for PoC
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        private_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_path.write_bytes(private_bytes)
        public_path.write_bytes(public_bytes)

    return private_path, public_path


def sign_file(sbom_path: Path, private_key_path: Path) -> bytes:
    data = sbom_path.read_bytes()

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None, backend=default_backend()
    )
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign SBOM JSON using RSA-PSS (SHA256)")
    parser.add_argument("--sbom", required=True, help="Path to SBOM JSON file")
    parser.add_argument("--out", required=True, help="Path to write signature (Base64)")
    parser.add_argument("--keys-dir", required=True, help="Directory to store/read RSA keys")
    args = parser.parse_args()

    sbom_path = Path(args.sbom)
    out_path = Path(args.out)
    keys_dir = Path(args.keys_dir)

    if not sbom_path.exists():
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")

    private_key_path, public_key_path = ensure_keys(keys_dir)
    signature = sign_file(sbom_path, private_key_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(base64.b64encode(signature).decode("utf-8"))

    print("SBOM signed successfully")
    print(f"SBOM: {sbom_path}")
    print(f"Signature: {out_path}")
    print(f"Public Key: {public_key_path}")
    # Security hygiene: remove private key after signing (PoC ephemeral key policy)
    try:
        if private_key_path.exists():
            private_key_path.unlink()
            print(f"Private Key removed: {private_key_path}")
    except Exception as e:
        print(f"Warning: could not remove private key: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
