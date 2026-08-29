# How `epic_fhir_pull.py` Works

This walks through the script function by function, with extra focus on OAuth2 since that's the part doing the "magic" when your browser popped up asking for a MyChart login.

---

## Part 1: What OAuth2 actually is (no code yet)

Before touching the script, the concept. OAuth2 answers one question:

> "How does a third-party app (this Python script) get permission to read a patient's medical data from Epic, **without the patient ever handing their MyChart password to the script**?"

Four players are involved:

| Role | Who it is here |
|---|---|
| **Resource Owner** | The patient (e.g. Derrick Lin) — the person who owns the data and can grant access to it |
| **Client** | `epic_fhir_pull.py` — the app requesting access |
| **Authorization Server** | Epic's login page (`fhir.epic.com/.../oauth2/authorize`) — checks who you are and what you're allowing |
| **Resource Server** | Epic's FHIR API (`fhir.epic.com/.../api/FHIR/R4`) — actually holds the data |

The trick: the password is only ever typed into the **Authorization Server's** page (Epic's own login screen, in your browser). The script never sees it. Instead, the script gets handed a temporary, revocable **token** it can use to make API calls on the patient's behalf.

This script uses the **Authorization Code flow with PKCE** — the standard pattern for apps that open a browser and can't safely keep a secret (since anyone could read this Python source). Roughly:

```
 You (browser)                epic_fhir_pull.py              Epic
 --------------                -----------------              ----
 1. Script starts a tiny local web server (localhost:8080)
 2. Script opens your browser to Epic's login page ------------>
 3. You log in as a test patient on Epic's page (never touches the script)
 4. Epic redirects your browser back to localhost:8080/callback?code=XYZ&state=...
 5. Local server grabs `code` from that redirect
 6. Script exchanges `code` (+ proof it's the same script that started this) for an access_token  ------------> Epic
 7. Epic returns access_token  <------------------------------
 8. Script calls the FHIR API with "Authorization: Bearer <access_token>" ------------> Epic
 9. Epic returns the patient's data (JSON)
```

Two safety mechanisms worth understanding since they show up directly in the code:

- **`state`** — a random string the script generates before opening the browser, and checks again when Epic redirects back. If they don't match, someone might be trying to trick the script into accepting a code that wasn't meant for it (CSRF attack). See `_make_handler`.
- **PKCE (Proof Key for Code Exchange)** — because this is a "public" client (no secret password baked into the app that only the script knows), Epic needs another way to confirm that whoever is redeeming the authorization code is the same party who started the login. The script generates a random `verifier`, sends a hashed version of it (`challenge`) when starting the login, then sends the original `verifier` when exchanging the code. Epic checks the hash matches. This stops an attacker who intercepts the `code` mid-flight from being able to use it. See `make_pkce_pair`.

With that mental model, the code below will make more sense.

---

## Part 2: Imports and config

```python
import base64
import hashlib
import http.server
import json
import os
import secrets
import threading
import urllib.parse
import webbrowser

import requests
```

- `http.server` + `threading` — used to spin up a tiny local web server that catches Epic's redirect.
- `secrets` — cryptographically secure random values, used for `state` and the PKCE verifier.
- `hashlib` / `base64` — used to build the PKCE `code_challenge` (a SHA-256 hash of the verifier, base64-encoded).
- `webbrowser` — opens your default browser to Epic's login page.
- `requests` — the only non-stdlib dependency; used for the two direct HTTP calls to Epic's API (token exchange, FHIR data fetch).

```python
CLIENT_ID = "4604a817-98fc-4c1d-bcc8-cab1937568e6"
REDIRECT_URI = "http://localhost:8080/callback"

AUTHORIZE_URL = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize"
TOKEN_URL = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token"
FHIR_BASE_URL = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"
```

- `CLIENT_ID` — identifies *this app* to Epic (assigned when you registered the app on fhir.epic.com). Not secret — it's fine for it to be visible in source code.
- `REDIRECT_URI` — where Epic is allowed to send the browser back to after login. Epic checks this against what you registered; they must match exactly, which is why SETUP.md is strict about it.
- `AUTHORIZE_URL` — the login page (step 2 in the diagram above).
- `TOKEN_URL` — the API endpoint used to trade a `code` for an `access_token` (step 6).
- `FHIR_BASE_URL` — the actual data API (step 8).

```python
SCOPES = (
    "openid fhirUser "
    "patient/Patient.read "
    "patient/Condition.read "
    "patient/Observation.read "
    "patient/AllergyIntolerance.read "
    "patient/Immunization.read"
)
```

**Scopes** are how OAuth2 expresses "what exactly is being requested" — least-privilege by design. SMART on FHIR's scope format is `<compartment>/<Resource>.<permission>`:
- `patient/Condition.read` = "read access to Condition resources, scoped to whichever patient is logged in."
- `openid` and `fhirUser` are identity scopes (not data) — they're what makes Epic return `id_token`/user identity info alongside the access token.

This is also exactly why you got 403s earlier: the app registered on fhir.epic.com needs each of these APIs explicitly enabled in its own settings — listing a scope here in the script is a *request*, not a guarantee it will be granted.

```python
RESOURCE_TYPES = ["Condition", "Observation", "AllergyIntolerance", "Immunization"]
OUTPUT_DIR = "fhir_data"
```

Just a list the script loops over later to know which resources to fetch and save.

---

## Part 3: PKCE helper

```python
def make_pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(40)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge
```

- `verifier`: 40 random bytes, base64-encoded into a URL-safe string. This is the "secret" only this script run knows.
- `challenge`: SHA-256 hash of the verifier, also base64-encoded. This is sent to Epic *up front* (Epic can't reverse a hash back into the verifier).
- Later, when exchanging the code, the script sends the raw `verifier`. Epic hashes it itself and checks it matches the `challenge` it was given earlier. This proves "the thing exchanging the code is the same thing that started the login" without ever needing a pre-shared client secret.

---

## Part 4: The local callback server

```python
class _CallbackResult:
    code = None
    error = None
```
A simple shared "mailbox" — the web server writes into this, and the main thread reads from it afterward.

```python
def _make_handler(state_expected):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            params = urllib.parse.parse_qs(parsed.query)
            if params.get("state", [None])[0] != state_expected:
                _CallbackResult.error = "State mismatch — possible CSRF, aborting."
            elif "code" in params:
                _CallbackResult.code = params["code"][0]
            else:
                _CallbackResult.error = params.get("error_description", ["Unknown error"])[0]
            ...
    return Handler
```

This defines a tiny web server request handler. When Epic redirects your browser to `http://localhost:8080/callback?code=XYZ&state=abc123`, this is what receives that request:

1. Confirms the path is `/callback` (anything else → 404).
2. Parses the query string parameters (`code`, `state`, possibly `error_description`).
3. **Checks `state` matches** what the script generated before opening the browser — this is the CSRF check described in Part 1. If it doesn't match, the response is rejected even if a valid-looking `code` is present.
4. If everything checks out, stores the `code` for the main thread to pick up.
5. Writes a simple HTML page back to your browser tab ("Login complete — you can close this tab").

`log_message` is overridden to do nothing — just suppresses noisy default request logging in your terminal.

```python
def get_authorization_code():
    state = secrets.token_urlsafe(16)
    verifier, challenge = make_pkce_pair()

    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "aud": FHIR_BASE_URL,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{AUTHORIZE_URL}?{urllib.parse.urlencode(auth_params)}"

    server = http.server.HTTPServer(("localhost", 8080), _make_handler(state))
    thread = threading.Thread(target=server.handle_request)
    thread.start()

    print("Opening browser for Epic sandbox login...")
    webbrowser.open(auth_url)

    thread.join(timeout=300)
    server.server_close()

    if _CallbackResult.error:
        raise RuntimeError(_CallbackResult.error)
    if not _CallbackResult.code:
        raise RuntimeError("Timed out waiting for login/redirect.")

    return _CallbackResult.code, verifier
```

This is the orchestrator for steps 1–5 of the OAuth flow:

1. Generates the random `state` and the PKCE `verifier`/`challenge` pair.
2. Builds the full authorization URL — this is the exact URL that turned into the MyChart login page you saw. Every field here maps back to the OAuth flow: `client_id` says who's asking, `redirect_uri` says where to send the answer, `scope` says what's being requested, `code_challenge` is the PKCE hash, `aud` tells Epic which FHIR server this token is meant for (required by SMART on FHIR).
3. Starts the local server in a background thread — `handle_request()` (not `serve_forever()`) means it processes **exactly one** incoming request, then stops. That one request will be Epic's redirect.
4. `webbrowser.open(auth_url)` — this is the line that actually popped the login page open on your machine.
5. `thread.join(timeout=300)` blocks the main script for up to 5 minutes waiting for that one request to come in (i.e., waiting for you to finish logging in).
6. Once the server has handled the redirect, checks whether it captured an error or a valid `code`, and returns the `code` plus the `verifier` (needed for the next step).

---

## Part 5: Exchanging the code for a token

```python
def exchange_code_for_token(code, verifier):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    }
    resp = requests.post(TOKEN_URL, data=data, headers={"Accept": "application/json"})
    resp.raise_for_status()
    return resp.json()
```

This is step 6 in the diagram — a direct, server-to-server POST (no browser involved) from the script straight to Epic's token endpoint. It sends:
- the `code` obtained from the callback,
- the same `redirect_uri` (Epic checks it matches, as an anti-tampering measure),
- `client_id` (who's asking),
- `code_verifier` — the *original*, un-hashed PKCE secret. Epic hashes it and compares to the `code_challenge` sent earlier. Match → proceeds. Mismatch → rejected.

`resp.raise_for_status()` throws an exception if Epic responds with an HTTP error (4xx/5xx) — e.g. this is exactly the kind of call that would surface a 403.

The JSON response includes things like `access_token`, `expires_in`, `scope` (what was *actually* granted — can be narrower than what you asked for), and for patient-facing SMART launches, a `patient` field with the FHIR ID of the logged-in patient.

---

## Part 6: Calling the FHIR API

```python
def fetch_resource(access_token, resource_type, patient_id):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json",
    }
    if resource_type == "Patient":
        url = f"{FHIR_BASE_URL}/Patient/{patient_id}"
    else:
        url = f"{FHIR_BASE_URL}/{resource_type}?patient={patient_id}"

    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()
```

This is step 8 — using the access token to actually read data. The `Authorization: Bearer <token>` header is the standard way an OAuth access token is presented on every API call; it's effectively "here's my temporary pass, let me in."

- `Patient` is fetched by ID directly (`/Patient/{id}`).
- Everything else is fetched via a **search** with a `patient=` filter (`/Condition?patient={id}`), which is the FHIR convention for "give me all resources of this type belonging to this patient."

---

## Part 7: `main()` — tying it together

```python
def main():
    if "PASTE_YOUR" in CLIENT_ID:
        raise SystemExit(...)

    code, verifier = get_authorization_code()
    token_response = exchange_code_for_token(code, verifier)

    access_token = token_response["access_token"]
    patient_id = token_response.get("patient")
    if not patient_id:
        raise RuntimeError(...)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    patient = fetch_resource(access_token, "Patient", patient_id)
    with open(os.path.join(OUTPUT_DIR, "Patient.json"), "w") as f:
        json.dump(patient, f, indent=2)

    for rtype in RESOURCE_TYPES:
        try:
            bundle = fetch_resource(access_token, rtype, patient_id)
            with open(os.path.join(OUTPUT_DIR, f"{rtype}.json"), "w") as f:
                json.dump(bundle, f, indent=2)
            count = bundle.get("total", len(bundle.get("entry", [])))
            print(f"Saved {rtype}.json ({count} entries)")
        except requests.HTTPError as e:
            print(f"Skipped {rtype}: {e}")
```

Sequence:
1. Guard clause: refuses to run if you never set a real `CLIENT_ID`.
2. Runs the full OAuth dance (`get_authorization_code` → `exchange_code_for_token`) to get an `access_token`.
3. Pulls the `patient` FHIR ID out of the token response — this is SMART on FHIR telling the app "here's who logged in and consented," so the script doesn't have to ask separately.
4. Creates `./fhir_data/` if it doesn't exist.
5. Fetches and saves `Patient.json` first (fetched outside the loop since it uses a different URL shape).
6. Loops over `RESOURCE_TYPES`, fetching and saving each as `<ResourceType>.json`. Each one is wrapped in its own `try/except` — **this is why a 403 on `Condition` doesn't stop `Observation` from being attempted** — one failure is logged and skipped rather than crashing the whole run.

---

## Quick recap: why the browser popup was expected

Every time you run this script, `get_authorization_code()` calls `webbrowser.open(auth_url)` — that's a deliberate, necessary part of OAuth2's Authorization Code flow, because only *you*, in your own browser, on Epic's own domain, are allowed to enter credentials. The script is designed to never see or handle a password directly — that's the entire point of using OAuth2 instead of, say, asking you to type your MyChart password into the Python script.

# Issues/challenges Faced:
## Login Failed at oAUTH
Non Prod client ID vs client _id - sandbox should use non prod client id only, client id is for prod only
versions: USCIDv1 vs v3 - read whats the difference, what will happen if i chose v3 over v1
Incoming APIS should have selected all the API scope matching between .PY file and EPIC app.
SMART version R4 vs DSTU and STU - read about it why you chose R4
http vs https - call back - i had only https local host but incoming localhost should be http. added both to EPIC App

## After login - test application user id/password
go to epic --> documentation --> sandbox test data: get derrice lin or camila lopex user id/pwd 
use the user_id and pwd to get their data into local folder as a JSON file
