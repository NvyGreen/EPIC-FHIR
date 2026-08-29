# Pulling a FHIR Dataset from Epic (Sandbox) — Setup Guide

This gets you real FHIR-formatted data (fake patients, real data shapes) out of
Epic's free public sandbox, using OAuth2, for a school project. No hospital
account or approval needed — the sandbox is open to anyone.

## 1. Register a free app on Epic on FHIR

1. Go to https://fhir.epic.com and create an account (top right, "Log in" →
   sign up). This is Epic's developer portal, separate from any hospital login.
2. Once logged in, go to **Build Apps** → **Create**.
3. Fill out the app form:
   - **Application Audience**: choose *Clinicians* or *Patients* (either is
     fine for a standalone-launch demo — patient-facing is simplest).
   - **Application Type**: *SMART on FHIR* (not Backend Systems — that's a
     separate, server-to-server flow with no user login).
   - **Redirect URI**: enter exactly `http://localhost:8080/callback`
     (must match what's in the script).
   - **FHIR APIs / scopes**: select R4 versions of Patient.Read,
     Observation.Read, Condition.Read, MedicationRequest.Read,
     AllergyIntolerance.Read, Immunization.Read (or just select all — you can
     narrow later).
4. Save. Epic immediately issues a **Non-Production Client ID** — this works
   right away, no waiting period (only *production* access requires Epic's
   review).
5. Copy that Non-Production Client ID into `CLIENT_ID` at the top of
   `epic_fhir_pull.py`.

## 2. Sandbox test patient logins

Epic's sandbox comes preloaded with fake patients you log in as (there's no
real PHI involved). The current list of usernames/passwords is published on
fhir.epic.com under **Resources → Sandbox Patients** (or similar — Epic
occasionally reshuffles the page, so check there for the live list rather than
relying on any hardcoded credentials). Commonly referenced test patients
include names like "Camila Lopez" and "Derrick Lin" with sandbox-only
passwords shown right on that page — use whichever one you're given.

## 3. Run it

```bash
pip install requests --break-system-packages
python3 epic_fhir_pull.py
```

This will:
- Open your browser to Epic's sandbox login.
- You log in with a test patient's credentials from step 2.
- The script catches the redirect, exchanges the code for a token, and pulls
  the patient's Condition, Observation, MedicationRequest,
  AllergyIntolerance, and Immunization resources.
- Everything is saved as JSON (standard FHIR R4 Bundles) into `./fhir_data/`.

## Notes for your writeup

- This uses the SMART on FHIR **standalone launch** pattern: Authorization
  Code grant + PKCE, which is the standard OAuth2 flow real EHR-connected apps
  use (e.g. Apple Health, patient portals).
- The token response includes a `patient` field — Epic's way of telling the
  app which FHIR patient ID the logged-in user's data is scoped to.
- Everything returned is standard FHIR R4 — the same resource shapes
  (Patient, Observation, Condition, etc.) any real Epic-connected system uses.
- If you need write access, different scopes, or a backend (no-login)
  service-to-service flow, that's a separate registration path ("Backend
  Systems" app type using JWT-signed client assertions) — let me know if your
  project needs that instead.
