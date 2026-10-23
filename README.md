# Dekho Hatke

Android video-link downloader/streamer (Kotlin + Jetpack Compose) backed by a FastAPI proxy that
gates access with a license key, talks to the `xapiverse.com` resolver API, and comes with a web
admin panel. Built from the spec in `prompt.txt` and the reference screenshots you supplied.

```
dekhohatke/
├── backend/                  FastAPI app — deploy this to Render
│   ├── main.py
│   ├── requirements.txt
│   ├── generate_keys.py      run once locally, never commit its output
│   └── admin/                admin panel (served at /admin by the same app)
├── android/                  Android Studio project
│   └── app/src/main/java/drdev/hamza/dekhohatke/
└── Build_DekhoHatke_APK.ipynb   Colab notebook that builds & signs the release APK
```

## 1. Backend (Render + Firebase)

1. **Firebase**: create a Realtime Database (any region), generate a service-account JSON
   (Project settings → Service accounts → Generate new private key).
2. **Keys**: run `python backend/generate_keys.py` locally. It prints:
   - `RSA_PRIVATE_KEY_B64`, `SESSION_SECRET`, `ADMIN_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`
     → paste these into Render's **Environment** tab.
   - A `-----BEGIN PUBLIC KEY-----` PEM → this goes into the **Android app**, not the server
     (step 3 of the Colab notebook, or `android/app/src/main/res/raw/pubkey.pem` directly).
3. **Render**: new Web Service → point at `backend/` → build command
   `pip install -r requirements.txt` → start command
   `uvicorn main:app --host 0.0.0.0 --port $PORT`.
4. **Environment variables** to set on Render:

   | Variable | What it is |
   |---|---|
   | `FIREBASE_CREDENTIALS_JSON` | the whole service-account JSON, as one line |
   | `FIREBASE_DB_URL` | `https://<project>-default-rtdb.<region>.firebasedatabase.app` |
   | `RSA_PRIVATE_KEY_B64`, `SESSION_SECRET`, `ADMIN_SECRET` | from `generate_keys.py` |
   | `ADMIN_USERNAME`, `ADMIN_PASSWORD` | admin panel login |
   | `LICENSE_VERIFY_URL` | your `dekhohatke.onrender.com`-style license verify endpoint |
   | `LICENSE_API_KEY` | that service's API key |
   | `XAPI_URL` | `https://xapiverse.com/api/app` (or your resolver) |
   | `XAPI_KEY` | your xAPIverse key |
   | `APK_CERT_SHA256` | comma-separated SHA-256(s) of your release signing cert (see below) |
   | `APK_DEX_HASHES` | optional, comma-separated SHA-256(s) of the APK's classes, pinned per release |

   Leaving `APK_CERT_SHA256` / `APK_DEX_HASHES` empty disables that particular tamper check
   (useful while you're still testing) — fill them in before shipping to real users.

5. Visit `https://<your-render-app>.onrender.com/admin` and log in with `ADMIN_USERNAME`
   / `ADMIN_PASSWORD` to edit the Maintenance banner, force-update dialog, and the
   About/Privacy/Contact/Share HTML shown inside the app.

## 2. Android app

Open `android/` in Android Studio, or build headlessly with the included
**`Build_DekhoHatke_APK.ipynb`** Colab notebook — it installs the SDK/Gradle, drops in your
public key and backend URL, generates (or reuses) a signing keystore, and hands you back a
signed release `.apk`. Keep the generated `.jks` + passwords; every future update must be signed
with the same one.

Before building:
- Put the public key from `generate_keys.py` into `app/src/main/res/raw/pubkey.pem`.
- Set `BACKEND_URL` (via `gradle.properties` or the Colab form) to your Render URL.
- Replace the two placeholder `sha256/...` pins in `crypto/ApiClient.kt` with your Render TLS
  cert's real pin (the comment above them has the exact `openssl` command).
- After your first real signed build, run
  `keytool -list -v -keystore release.jks` (or `-printcert` on the APK) to get the cert's
  SHA-256, and put it in Render's `APK_CERT_SHA256` so the backend starts enforcing it.

## 3. How the anti-reverse-engineering protection actually works

I want to be straightforward about what's realistic here rather than oversell it:

**What's genuinely strong (server-side, can't be bypassed by decompiling the APK):**
- Every API call is RSA‑OAEP + AES‑256‑GCM encrypted and HMAC‑signed with a per‑launch session
  key — a decompiled APK reveals the *protocol*, not a way to forge valid requests without
  breaking RSA‑2048/AES‑256 directly.
- Replay protection (nonce + 60s window) and rate limiting live on the server.
- License checks fail **closed**: any upstream error denies access, never grants it.
- A modified/re-signed APK (wrong cert hash or dex hash) gets silently **shadow-banned** —
  it looks like it's working but every license check reports "not found" and every fetch
  reports "failed," rather than returning an error that tips off whoever patched it.
- 3 wrong license attempts blocks the device for an hour; admin can block a user and ban their
  device(s) from the panel.

**What's a speed bump, not a wall (client-side):**
- Root/emulator/Frida‑Xposed/debugger detection, signing-cert and dex-hash reporting, ProGuard/R8
  obfuscation and string stripping. These raise the cost of tampering and feed the server's
  shadow-ban decision, but anything that ships inside an APK can eventually be read or patched
  by someone sufficiently motivated — there's no client-side trick that changes that. The real
  boundary is the server-side encryption + shadow-ban logic above, which is why the bulk of the
  protection lives there instead of in the app.

If you need stronger client tamper-resistance than stock R8 (native-code checks, string
encryption, control-flow obfuscation), that's normally a commercial tool like DexGuard — happy
to point you at what that would involve if you want to go further.

## 4. What's left to wire up on your end

- Your real `LICENSE_VERIFY_URL` request/response shape — `main.py`'s `check_license()` assumes
  `{"success": true, "license": {...}}` / `{"code": "...", "message": "..."}`; adjust the field
  names to match your actual license service.
- Your real `xapiverse.com` response shape — `op_fetch()` assumes
  `{"status": "success", "list": [{...}]}` with `fast_stream_url` as a quality→URL map; adjust to
  match what that API actually returns for your account.
- Play Store listing / Rate Us link once you publish (`SettingsScreen.kt` already builds the
  Play Store URL from your `applicationId`).
