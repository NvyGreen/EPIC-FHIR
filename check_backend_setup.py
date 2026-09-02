"""
Diagnose an `invalid_client` from Epic's backend-services token endpoint.

Checks, in the order they're worth checking:
  1. Does keys/private_key.pem match keys/public_key.pem?
  2. Does the local jwks.json describe that same key?
  3. Is the published JWK Set URL reachable, raw JSON, redirect-free, and does
     it serve the same key as the local jwks.json?
  4. Does the assertion the script actually signs verify against that key,
     and does its `kid` appear in the published set?

Usage:
    python check_backend_setup.py https://<user>.github.io/<repo>/jwks.json

The URL argument is optional; without it, checks 1, 2 and 4 still run.
"""

import base64
import hashlib
import json
import os
import sys

import requests
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import epic_fhir_backend as app  # noqa: E402

PRIVATE_KEY_PATH = app.PRIVATE_KEY_PATH
PUBLIC_KEY_PATH = os.path.join("keys", "public_key.pem")
JWKS_PATH = app.JWKS_PATH

OK, BAD, WARN = "  [ok]  ", "  [BAD] ", "  [??]  "


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def int_to_b64url(value: int) -> str:
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def jwk_from_public_numbers(numbers):
    n, e = int_to_b64url(numbers.n), int_to_b64url(numbers.e)
    canonical = json.dumps(
        {"e": e, "kty": "RSA", "n": n}, separators=(",", ":"), sort_keys=True
    )
    return {"n": n, "e": e, "kid": b64url(hashlib.sha256(canonical.encode()).digest())}


def head(title):
    print(f"\n{title}\n{'-' * len(title)}")


def check_local_keys():
    """1 + 2: private key vs public key vs the jwks.json we'd publish."""
    head("1. Local key material")

    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    priv_jwk = jwk_from_public_numbers(priv.public_key().public_numbers())
    print(f"{OK}private_key.pem  kid={priv_jwk['kid']}")

    if os.path.exists(PUBLIC_KEY_PATH):
        with open(PUBLIC_KEY_PATH, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        pub_jwk = jwk_from_public_numbers(pub.public_numbers())
        match = pub_jwk["kid"] == priv_jwk["kid"]
        print(f"{OK if match else BAD}public_key.pem   kid={pub_jwk['kid']}")
        if not match:
            print("        public_key.pem is NOT the pair of private_key.pem.")

    head("2. Local jwks.json vs private_key.pem")
    if not os.path.exists(JWKS_PATH):
        print(f"{BAD}{JWKS_PATH} does not exist. Run: python make_jwks.py")
        return priv_jwk, None

    with open(JWKS_PATH, encoding="utf-8") as f:
        local_jwks = json.load(f)
    keys = local_jwks.get("keys", [])
    print(f"        {JWKS_PATH} holds {len(keys)} key(s)")

    hit = next((k for k in keys if k.get("n") == priv_jwk["n"]), None)
    if hit:
        print(f"{OK}jwks.json contains the public half of private_key.pem")
        if hit.get("kid") != priv_jwk["kid"]:
            print(f"{WARN}but its kid is {hit.get('kid')}, not the RFC 7638"
                  " thumbprint. Harmless if Epic has the same file.")
        if hit.get("alg") not in (None, "RS384"):
            print(f"{BAD}alg is {hit.get('alg')}; the script signs with RS384.")
    else:
        print(f"{BAD}jwks.json does NOT contain private_key.pem's public key.")
        for k in keys:
            print(f"        published kid: {k.get('kid')}")
        print("        --> Epic is verifying against the wrong key.")
        print("        --> Fix: python make_jwks.py, then re-publish jwks.json.")

    return priv_jwk, local_jwks


def check_published(url, priv_jwk, local_jwks):
    """3: is the JWK Set URL something Epic's server can actually consume?"""
    head("3. Published JWK Set URL")
    if not url:
        print(f"{WARN}No URL given. Re-run with your Non-Production JWK Set URL")
        print("        as the argument to check this.")
        return

    print(f"        {url}")
    if not url.startswith("https://"):
        print(f"{BAD}Not HTTPS. Epic will not fetch it.")

    try:
        resp = requests.get(url, timeout=30, allow_redirects=True)
    except requests.RequestException as e:
        print(f"{BAD}Could not fetch: {e}")
        return

    if resp.history:
        print(f"{BAD}Redirected {len(resp.history)}x "
              f"({' -> '.join(str(r.status_code) for r in resp.history)}). "
              "Epic does not follow redirects; register the final URL.")
    if resp.status_code != 200:
        print(f"{BAD}HTTP {resp.status_code}. Body starts: {resp.text[:120]!r}")
        return
    print(f"{OK}HTTP 200")

    ctype = resp.headers.get("Content-Type", "")
    if "json" not in ctype and "text/plain" not in ctype:
        print(f"{WARN}Content-Type is {ctype!r}. Epic wants raw JSON; an HTML"
              " page (a GitHub blob view instead of raw/Pages) fails here.")
    else:
        print(f"{OK}Content-Type: {ctype}")

    try:
        remote = resp.json()
    except ValueError:
        print(f"{BAD}Body is not JSON. First 200 chars:\n{resp.text[:200]}")
        return

    remote_keys = remote.get("keys")
    if not isinstance(remote_keys, list) or not remote_keys:
        print(f"{BAD}No non-empty top-level \"keys\" array.")
        return
    print(f"{OK}Valid JWKS with {len(remote_keys)} key(s)")

    if any(k.get("n") == priv_jwk["n"] for k in remote_keys):
        print(f"{OK}Published set contains private_key.pem's public key")
    else:
        print(f"{BAD}Published set does NOT contain private_key.pem's key.")
        for k in remote_keys:
            print(f"        published kid: {k.get('kid')}")
        print("        --> This alone causes invalid_client.")

    if local_jwks and remote != local_jwks:
        print(f"{WARN}Published JSON differs from local {JWKS_PATH} "
              "(may just be formatting).")


def check_assertion(priv_jwk, local_jwks):
    """4: verify the exact JWT the app sends, the way Epic would."""
    head("4. The assertion epic_fhir_backend.py actually sends")

    import jwt

    token = app.build_client_assertion()
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})

    print(f"        alg={header.get('alg')}  kid={header.get('kid')}")
    if header.get("alg") != "RS384":
        print(f"{BAD}Epic requires RS384.")
    if not header.get("kid"):
        print(f"{WARN}No kid in the header. Fine for a one-key set, but Epic"
              " is stricter when your published set has several.")
    elif local_jwks and not any(
        k.get("kid") == header["kid"] for k in local_jwks.get("keys", [])
    ):
        print(f"{BAD}kid is not in {JWKS_PATH}.")

    print(f"        iss={claims['iss']}")
    print(f"        sub={claims['sub']}")
    print(f"        aud={claims['aud']}")
    if claims["iss"] != claims["sub"]:
        print(f"{BAD}iss and sub must both be the client ID.")
    if claims["aud"] != app.TOKEN_URL:
        print(f"{BAD}aud must be exactly {app.TOKEN_URL}")
    lifetime = claims["exp"] - claims["iat"]
    print(f"{OK if lifetime <= 300 else BAD}lifetime {lifetime}s (Epic caps at 300)")

    with open(PRIVATE_KEY_PATH, "rb") as f:
        pub_pem = (
            serialization.load_pem_private_key(f.read(), password=None)
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    try:
        jwt.decode(token, pub_pem, algorithms=["RS384"], audience=app.TOKEN_URL)
        print(f"{OK}Signature verifies against private_key.pem's public half")
    except Exception as e:  # noqa: BLE001 - diagnostic, report anything
        print(f"{BAD}Self-verification failed: {e}")


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EPIC_JWKS_URL")
    priv_jwk, local_jwks = check_local_keys()
    check_published(url, priv_jwk, local_jwks)
    check_assertion(priv_jwk, local_jwks)

    head("5. Not checkable from here")
    print("        - Read APIs selected on the app (Epic portal only)")
    print("        - Application Audience = Backend Systems (portal only)")
    print("        - Whether Epic has finished syncing your last save")


if __name__ == "__main__":
    main()
