# Pulling FHIR Data from Epic With No Login (Backend Services)

This is the server-to-server version of `SETUP.md`. Nothing opens a browser,
nobody logs in, no consent screen appears. You run one command and get JSON.

## Why the other script needs a login and this one doesn't

`epic_fhir_pull.py` uses the **authorization_code** grant. That flow exists to
let a *human* prove who they are and approve your app's access to *their* chart.
The browser and the login screen aren't incidental — they are the whole point of
that grant. You cannot remove them from it.

`epic_fhir_backend.py` uses the **client_credentials** grant with a signed JWT
(the SMART on FHIR "Backend Services" profile). Here the *app itself* is the
authenticated party. It proves identity by signing a short-lived token with a
private key only it holds; Epic checks that signature against the public key you
registered. No user is involved because no user's consent is being asked for —
the access was granted once, at registration time.

The consequence: there is no "logged-in patient," so the token response has no
`patient` field. You say which patients you want.

## 1. Generate your key pair

```bash
pip install requests pyjwt cryptography
python generate_keypair.py
```

Creates in `keys/`:

| File | Purpose |
|---|---|
| `private_key.pem` | Secret. Signs your JWTs. Never leaves your machine. |
| `public_key.pem` | Plain public key — input to `make_jwks.py`. |
| `public_cert.pem` | X.509 form of the same key. Not needed for the JWKS flow; kept in case you hit an Epic form that wants a certificate. |

Re-running is safe: it reuses an existing private key rather than replacing
it, so a key you've already published stays valid.

## 2. Register a **new** app on fhir.epic.com

Your existing client ID will not work — app type is fixed at registration.

1. https://fhir.epic.com → **Build Apps** → **Create**.
2. **Application Audience**: **Backend Systems**. (This is the setting that
   matters. It's what SETUP.md told you *not* to pick.)
3. **Incoming APIs**: move the R4 `.Read` and `.Search` entries you need into
   the *Selected* box. You don't pick a `system/` prefix anywhere — setting
   Application Audience to Backend Systems is what makes these system-level
   scopes. Make sure **`Patient.Read (R4)`**, **`Patient.Search (R4)`**, and
   **`Observation.Read (R4)`** are in *Selected*; it's easy to scroll past them
   and the script fails on the first patient without them.
4. **Public key**: there is **no file-upload control** on this form. Epic's
   current portal takes a **Non-Production JWK Set URL** instead — a public
   HTTPS URL where you publish your key in JWKS format. See step 3 below for
   how to create and host that file. Leave *Production JWK Set URL* blank.

   There's no redirect URI field either; backend apps have no redirect.
5. **SMART on FHIR Version**: R4. **SMART Scope Version**: SMART v1 is fine.
6. Save, and copy the **Non-Production Client ID** — *not* the plain "Client
   ID" field above it, which is the production one and won't work in sandbox.

To change the key or scopes later, reopen the app from **Build Apps**. Each
save restarts the sync wait in step 5.

## 3. Publish your key as a JWKS

```bash
python make_jwks.py
```

That writes **`jwks.json` in the project root** — deliberately *not* inside
`keys/`. The rule is: everything in `keys/` is secret and gitignored; `jwks.json`
is the one artifact meant to be published, so it sits outside that boundary.

Now put it at a public HTTPS URL. GitHub Pages is the least-effort option:

1. Create a **public** repo, e.g. `epic-jwks`.
2. Commit `jwks.json` into it. Publishing the *public* key is the entire point
   — it's safe and intended. Never commit `private_key.pem`.
3. **Settings → Pages →** deploy from `main`, root folder.
4. Your URL is `https://<username>.github.io/epic-jwks/jwks.json`.
5. Open it in a private browser window before pasting it into Epic. If it
   doesn't show raw JSON there, Epic's server can't read it either. The URL
   must need no login and issue no redirect.

Paste that URL into **Non-Production JWK Set URL** on the Build Apps form.

The `kid` printed by the script is a fingerprint of the key. `epic_fhir_backend.py`
reads it out of `jwks.json` and puts it in the JWT header automatically, so Epic
knows which key in the set to verify against — keep `jwks.json` next to the
script, and re-run `make_jwks.py` if you ever change keys.

## 4. Configure the script

Either edit `CLIENT_ID` at the top of `epic_fhir_backend.py`, or keep it out of
the file entirely:

```powershell
$env:EPIC_CLIENT_ID = "your-backend-client-id"
```

## 5. Wait about an hour

**This is the step everyone trips on.** Epic syncs new and edited apps to the
sandbox on a periodic job: per their docs, changes "may take up to 1 hour to
sync with the Sandbox." Until it runs you get a blunt `invalid_client` error
and nothing you change will fix it. This applies to *every* edit, not just the
first save — so if you swap the key later, wait again. Register, then go do
something else.

## 6. Run it

```bash
python epic_fhir_backend.py
```

Output lands in `./fhir_data_backend/<patient-id>/*.json`, one folder per
patient, same FHIR R4 resource shapes as before. Search results are fully
paginated, so `Observation.json` has every page merged rather than just the
first 50.

## Choosing patients

Edit either list near the top of the script:

```python
PATIENT_IDS = ["erXuFYUfucBZaryVksYEcMg3"]   # exact FHIR IDs, most reliable
PATIENT_NAMES = [("Lopez", "Camila")]        # resolved via Patient search
```

The two IDs shipped in the file are Epic's long-standing public sandbox
patients. If one 404s, Epic reshuffled the sandbox — switch to `PATIENT_NAMES`,
or get the current list from **Documentation → Sandbox** on fhir.epic.com.

## Running it unattended

There is nothing interactive left, so this drops straight into a scheduled task:

```powershell
schtasks /create /tn "EpicFHIRPull" /tr "python C:\DATA\EPIC-FHIR\epic_fhir_backend.py" /sc daily /st 02:00
```

Tokens last about an hour and the script fetches a fresh one each run, so
there's no refresh-token bookkeeping to maintain.

## Security notes for your writeup

- `keys/private_key.pem` is the credential. Anyone with it can pull data as
  your app, with no second factor. It's gitignored; keep it that way, and in a
  real deployment it belongs in a secrets manager, not on disk.
- The signed assertion is deliberately short-lived (4 minutes) and carries a
  unique `jti`, so a captured token can't be replayed.
- Backend apps are the right pattern for population-level work — analytics,
  registries, nightly ETL. They're the *wrong* pattern for anything acting on
  behalf of one identified user, because they bypass user consent by design.
- Going to production is a different matter: sandbox backend access is
  self-serve, but a production backend app must be reviewed by Epic *and*
  separately enabled by each hospital organization whose data you want.
