"""
Generate the RSA key pair used to authenticate to Epic as a backend service.

Writes into keys/:
    private_key.pem    <- stays on your machine, never share it
    public_key.pem     <- plain SubjectPublicKeyInfo public key
    public_cert.pem    <- self-signed base64 X.509 certificate

Epic's docs say "public keys should be exported to a base64 encoded X.509
certificate before being uploaded," but the portal's upload control has also
accepted a plain public key. Both are generated from the same key pair, so
upload whichever one the form accepts — either verifies the same signatures.

Re-running is safe: an existing private_key.pem is reused, not replaced, so
the public key you already uploaded to Epic stays valid.

    pip install cryptography
    python generate_keypair.py
"""

import datetime
import os
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

KEY_DIR = "keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")
PUBLIC_CERT_PATH = os.path.join(KEY_DIR, "public_cert.pem")

# Epic requires at least 2048 bits; 3072 is a comfortable margin.
KEY_SIZE = 3072

# Nothing verifies this name — the certificate is just a wrapper around the
# public key, and Epic trusts it because you uploaded it, not because of a CA.
CERT_SUBJECT = "epic-fhir-backend-client"
CERT_VALID_DAYS = 365 * 5


def load_or_create_private_key():
    if os.path.exists(PRIVATE_KEY_PATH):
        print(f"Reusing existing {PRIVATE_KEY_PATH}")
        with open(PRIVATE_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    print(f"Generating a new {KEY_SIZE}-bit RSA key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)

    # Best-effort lockdown (owner read/write only).
    try:
        os.chmod(PRIVATE_KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # Windows ACLs don't map cleanly; .gitignore is the real guard

    print(f"Wrote {PRIVATE_KEY_PATH}  (keep private)")
    return private_key


def build_self_signed_cert(private_key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERT_SUBJECT)])
    now = datetime.datetime.now(datetime.timezone.utc)

    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: subject == issuer
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))  # clock-skew slack
        .not_valid_after(now + datetime.timedelta(days=CERT_VALID_DAYS))
        .sign(private_key, hashes.SHA384())
    )


def main():
    os.makedirs(KEY_DIR, exist_ok=True)

    private_key = load_or_create_private_key()

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)
    print(f"Wrote {PUBLIC_KEY_PATH}   (plain public key)")

    cert = build_self_signed_cert(private_key)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(PUBLIC_CERT_PATH, "wb") as f:
        f.write(cert_pem)
    print(f"Wrote {PUBLIC_CERT_PATH}  (base64 X.509 certificate — try this first)")

    print()
    print("Upload one of these to fhir.epic.com. Epic's docs ask for the")
    print("certificate; the plain public key also works on the current portal.")
    print()
    print(cert_pem.decode())


if __name__ == "__main__":
    main()
