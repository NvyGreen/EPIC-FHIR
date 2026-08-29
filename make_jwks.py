"""
Convert keys/public_key.pem into a JWKS document for Epic's "JWK Set URL" field.

Epic's backend app form has no public-key file upload — it asks for a URL where
your public key is published in JWKS (JSON Web Key Set) format. This script
writes that file; you host it, then paste its URL into the form.

    python make_jwks.py

Writes keys/jwks.json and prints the `kid` (key ID). The kid is an RFC 7638
thumbprint — a fingerprint derived from the key itself, so it changes only if
the key changes. epic_fhir_backend.py reads it from jwks.json automatically and
puts it in the JWT header so Epic knows which key in the set to verify against.

HOSTING IT (any public HTTPS URL works; no auth, no redirects)
  Easiest is GitHub Pages:
    1. Make a public repo, e.g. `epic-jwks`.
    2. Commit jwks.json to it. NOTE: publishing the *public* key is fine and
       expected — that's the whole point. Never commit private_key.pem.
    3. Settings -> Pages -> deploy from the main branch, root.
    4. Your URL is https://<user>.github.io/epic-jwks/jwks.json
    5. Open it in a browser first. If it doesn't render raw JSON, Epic can't
       read it either.
"""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization

PUBLIC_KEY_PATH = os.path.join("keys", "public_key.pem")
JWKS_PATH = os.path.join("keys", "jwks.json")


def b64url(raw: bytes) -> str:
    """Base64url with padding stripped, as JOSE requires."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def int_to_b64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return b64url(value.to_bytes(length, "big"))


def thumbprint(jwk_n: str, jwk_e: str) -> str:
    """RFC 7638 key thumbprint: SHA-256 over the canonical required members.

    Canonical means exactly these keys, lexicographically ordered, no spaces.
    """
    canonical = json.dumps(
        {"e": jwk_e, "kty": "RSA", "n": jwk_n}, separators=(",", ":"), sort_keys=True
    )
    return b64url(hashlib.sha256(canonical.encode()).digest())


def main():
    if not os.path.exists(PUBLIC_KEY_PATH):
        raise SystemExit(
            f"{PUBLIC_KEY_PATH} not found. Run: python generate_keypair.py"
        )

    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    numbers = public_key.public_numbers()
    jwk_n = int_to_b64url(numbers.n)
    jwk_e = int_to_b64url(numbers.e)
    kid = thumbprint(jwk_n, jwk_e)

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS384",  # must match how epic_fhir_backend.py signs
                "n": jwk_n,
                "e": jwk_e,
            }
        ]
    }

    with open(JWKS_PATH, "w", encoding="utf-8") as f:
        json.dump(jwks, f, indent=2)

    print(f"Wrote {JWKS_PATH}")
    print(f"kid: {kid}")
    print()
    print("Host this file at a public HTTPS URL, then paste that URL into")
    print("'Non-Production JWK Set URL' on the Epic Build Apps form.")
    print()
    print(json.dumps(jwks, indent=2))


if __name__ == "__main__":
    main()
