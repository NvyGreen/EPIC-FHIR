"""
Pull a FHIR dataset from Epic with NO browser and NO user login, using
SMART on FHIR "Backend Services" (OAuth2 client_credentials + signed JWT).

HOW THIS DIFFERS FROM epic_fhir_pull.py
  epic_fhir_pull.py  -> authorization_code grant. A human logs in, approves the
                        app, and Epic tells you which patient they are.
  this script        -> client_credentials grant. The app proves its identity by
                        signing a JWT with its own private key. No human, no
                        browser, no consent screen. Runs fine from cron, a
                        service, or a container.

THE TRADE-OFF
  Because nobody logs in, there is no "current patient". The token response has
  no `patient` field. You must tell the script which patients to pull — either
  by FHIR ID or by name search (see the CONFIG section).

BEFORE RUNNING (see SETUP_BACKEND.md for the click-by-click version)
  1. python generate_keypair.py
  2. Register a NEW app at https://fhir.epic.com with:
       Application Audience = Backend Systems
       system/*.read scopes (Patient, Condition, Observation, ...)
       upload keys/public_key.pem as the public key
     Your existing SMART-on-FHIR client ID will NOT work here.
  3. Put the new Non-Production Client ID in CLIENT_ID below.
  4. Wait ~60 minutes. Epic syncs new backend keys to the sandbox on a timer;
     until then you get "invalid client" no matter what you do.

    pip install requests pyjwt cryptography
    python epic_fhir_backend.py
"""

import json
import os
import time
import uuid

import jwt
import requests

# ---------------------------------------------------------------------------
# CONFIG — edit this section
# ---------------------------------------------------------------------------

# The Non-Production Client ID of your *Backend Systems* app (not the one in
# epic_fhir_pull.py). Can also be supplied via the EPIC_CLIENT_ID env var.
CLIENT_ID = os.environ.get("EPIC_CLIENT_ID", "816f074f-5143-4271-98ed-00d35641d55f")

PRIVATE_KEY_PATH = os.environ.get("EPIC_PRIVATE_KEY", "keys/private_key.pem")

# Written by make_jwks.py. Used only to read back the `kid`, which must appear
# in the JWT header so Epic can pick the right key out of your published JWKS.
# Lives outside keys/ because it's the one file here that gets published.
JWKS_PATH = "jwks.json"

# Epic's public non-production (sandbox) endpoints.
TOKEN_URL = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token"
FHIR_BASE_URL = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"

# Which patients to pull. Two ways, use either or both:
#
#   PATIENT_IDS   — exact Epic FHIR IDs, fastest and most reliable.
#   PATIENT_NAMES — (family, given) pairs; the script searches for the ID first.
#
# The IDs below are Epic's long-standing public sandbox test patients. If one
# 404s, Epic reshuffled it — fall back to PATIENT_NAMES, or check the current
# list under Documentation -> Sandbox on fhir.epic.com.
PATIENT_IDS = [
    "erXuFYUfucBZaryVksYEcMg3",  # Camila Lopez
    "eq081-VQEgP8drUUqCWzHfw3",  # Derrick Lin
]

PATIENT_NAMES = [
    # ("Lopez", "Camila"),
    # ("Lin", "Derrick"),
]

RESOURCE_TYPES = [
    "Condition",
    "Observation",
    "MedicationRequest",
    "AllergyIntolerance",
    "Immunization",
]

# Epic requires a category or code on some searches rather than returning
# everything; these keep the common ones from erroring out.
SEARCH_DEFAULTS = {
    "Observation": {"category": "laboratory,vital-signs,social-history"},
}

OUTPUT_DIR = "fhir_data_backend"

# Epic caps the assertion lifetime at 5 minutes.
ASSERTION_LIFETIME_SECONDS = 240


# ---------------------------------------------------------------------------
# Authentication — this is the part that replaces the browser login
# ---------------------------------------------------------------------------
def read_kid():
    """Read the key ID from the JWKS we published, if there is one.

    Epic fetches your JWK Set URL and needs to know which key in the set signed
    the assertion. That's the `kid`, and it goes in the JWT *header*, not the
    claims. Without it Epic may reject the assertion even though the signature
    is perfectly valid.
    """
    if not os.path.exists(JWKS_PATH):
        return None
    with open(JWKS_PATH, encoding="utf-8") as f:
        keys = json.load(f).get("keys", [])
    return keys[0].get("kid") if keys else None


def build_client_assertion():
    """Build and sign the JWT that proves we are CLIENT_ID.

    Epic verifies the signature against the public key it fetched from your
    JWK Set URL. That's how the app authenticates with no secret and no human.
    """
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = f.read()

    now = int(time.time())
    claims = {
        "iss": CLIENT_ID,                 # who is asserting
        "sub": CLIENT_ID,                 # who the assertion is about (same app)
        "aud": TOKEN_URL,                 # must match Epic's token endpoint exactly
        "jti": str(uuid.uuid4()),         # unique per request; Epic rejects replays
        "iat": now,
        "nbf": now,
        "exp": now + ASSERTION_LIFETIME_SECONDS,
    }

    kid = read_kid()
    headers = {"kid": kid} if kid else None

    # RS384 is what the SMART Backend Services spec mandates.
    return jwt.encode(claims, private_key, algorithm="RS384", headers=headers)


def get_access_token():
    assertion = build_client_assertion()
    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    resp = requests.post(
        TOKEN_URL,
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=30,
    )

    if resp.status_code != 200:
        raise RuntimeError(
            f"Token request failed ({resp.status_code}): {resp.text}\n\n"
            "Common causes:\n"
            "  - Less than ~60 min since you saved the app. Epic syncs app\n"
            "    changes to the sandbox on a timer.\n"
            "  - CLIENT_ID is the Production one. Use the NON-Production one.\n"
            "  - Epic can't reach your JWK Set URL, or it doesn't return raw\n"
            "    JSON. Open the URL in a private browser window to check.\n"
            "  - The published jwks.json doesn't match keys/private_key.pem.\n"
            "    Re-run make_jwks.py and re-publish.\n"
            "  - The app has no Read APIs selected."
        )

    payload = resp.json()
    print(f"Got access token, valid {payload.get('expires_in', '?')}s.")
    return payload["access_token"]


# ---------------------------------------------------------------------------
# FHIR calls
# ---------------------------------------------------------------------------
def fhir_get(access_token, url, params=None):
    resp = requests.get(
        url,
        params=params,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/fhir+json",
        },
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_bundle(access_token, resource_type, patient_id):
    """Fetch a search bundle, following `next` links so we get every page."""
    params = {"patient": patient_id}
    params.update(SEARCH_DEFAULTS.get(resource_type, {}))

    bundle = fhir_get(access_token, f"{FHIR_BASE_URL}/{resource_type}", params)
    entries = bundle.get("entry", [])

    next_url = _next_link(bundle)
    while next_url:
        page = fhir_get(access_token, next_url)
        entries.extend(page.get("entry", []))
        next_url = _next_link(page)

    bundle["entry"] = entries
    bundle["total"] = len(entries)
    bundle.pop("link", None)  # paging links are meaningless once merged
    return bundle


def _next_link(bundle):
    for link in bundle.get("link", []):
        if link.get("relation") == "next":
            return link.get("url")
    return None


def find_patient_id(access_token, family, given):
    bundle = fhir_get(
        access_token, f"{FHIR_BASE_URL}/Patient", {"family": family, "given": given}
    )
    entries = bundle.get("entry", [])
    if not entries:
        raise RuntimeError(f"No patient found for {given} {family}")
    return entries[0]["resource"]["id"]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def save(obj, *path_parts):
    path = os.path.join(OUTPUT_DIR, *path_parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    return path


def pull_patient(access_token, patient_id):
    print(f"\nPatient {patient_id}")

    patient = fhir_get(access_token, f"{FHIR_BASE_URL}/Patient/{patient_id}")
    save(patient, patient_id, "Patient.json")
    name = patient.get("name", [{}])[0].get("text", "(no name)")
    print(f"  Patient.json — {name}")

    for rtype in RESOURCE_TYPES:
        try:
            bundle = fetch_bundle(access_token, rtype, patient_id)
            save(bundle, patient_id, f"{rtype}.json")
            print(f"  {rtype}.json — {bundle['total']} entries")
        except requests.HTTPError as e:
            print(f"  {rtype} skipped: {e}")


def main():
    if "PASTE_YOUR" in CLIENT_ID:
        raise SystemExit(
            "Set CLIENT_ID (or the EPIC_CLIENT_ID env var) to the Non-Production "
            "Client ID of your Backend Systems app. See SETUP_BACKEND.md."
        )
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise SystemExit(
            f"{PRIVATE_KEY_PATH} not found. Run: python generate_keypair.py"
        )

    access_token = get_access_token()

    patient_ids = list(PATIENT_IDS)
    for family, given in PATIENT_NAMES:
        try:
            found = find_patient_id(access_token, family, given)
            print(f"Resolved {given} {family} -> {found}")
            patient_ids.append(found)
        except (requests.HTTPError, RuntimeError) as e:
            print(f"Could not resolve {given} {family}: {e}")

    if not patient_ids:
        raise SystemExit(
            "No patients configured. Fill in PATIENT_IDS or PATIENT_NAMES."
        )

    for patient_id in dict.fromkeys(patient_ids):  # de-dupe, keep order
        try:
            pull_patient(access_token, patient_id)
        except requests.HTTPError as e:
            print(f"\nPatient {patient_id} failed: {e}")

    print(f"\nDone. Data saved under ./{OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
