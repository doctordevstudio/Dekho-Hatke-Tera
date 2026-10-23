"""Dekho Hatke backend: encrypted proxy + license gate + admin panel (FastAPI).

Security model (server side is the real protection, the APK is only a client):
  * /v1/hs   : app encrypts a random client key with the RSA public key, server returns a fresh
               per-launch session key (AES-GCM sealed with the client key).
  * /v1/x/*  : every payload is AES-256-GCM encrypted + HMAC-SHA256 signed with the session key,
               bound to op + timestamp + nonce (replay protection, 60s window, one-time nonce).
  * Modified APK / hooked / rooted devices get a silent shadow-ban: valid looking, useless answers.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

import anyio
import firebase_admin
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from firebase_admin import credentials, db

log = logging.getLogger("dh")
logging.basicConfig(level=logging.INFO)


def env(k, d=""):
    return os.environ.get(k, d)


# ----------------------------------------------------------------------------- config
FB_ROOT = "dekhohatketera"
LICENSE_URL = env("LICENSE_VERIFY_URL")           # https://dekhohatke.onrender.com/api/v1/app_xxx/verify
LICENSE_API_KEY = env("LICENSE_API_KEY")
XAPI_URL = env("XAPI_URL", "https://xapiverse.com/api/app")
XAPI_KEY = env("XAPI_KEY")
CERTS = {x.strip().lower().replace(":", "") for x in env("APK_CERT_SHA256").split(",") if x.strip()}
DEXES = {x.strip().lower() for x in env("APK_DEX_HASHES").split(",") if x.strip()}
SESSION_TTL = 6 * 3600
DID_RE = re.compile(r"^[0-9a-f]{64}$")
LK_RE = re.compile(r"^[A-Za-z0-9]{18}$")
ADMIN_USER, ADMIN_PASS = env("ADMIN_USERNAME"), env("ADMIN_PASSWORD")
ADMIN_SECRET = (env("ADMIN_SECRET") or env("SESSION_SECRET")).encode()

firebase_admin.initialize_app(
    credentials.Certificate(json.loads(env("FIREBASE_CREDENTIALS_JSON"))),
    {"databaseURL": env("FIREBASE_DB_URL")},
)


def R(path=""):
    return db.reference(f"{FB_ROOT}/{path}".rstrip("/"))


http = requests.Session()
now = lambda: int(time.time())  # noqa: E731

# ----------------------------------------------------------------------------- crypto
_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_rsa = serialization.load_pem_private_key(base64.b64decode(env("RSA_PRIVATE_KEY_B64")), password=None)
_master = hashlib.sha256(env("SESSION_SECRET").encode()).digest()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def seal(key: bytes, obj, aad: bytes) -> dict:
    iv = os.urandom(12)
    pt = json.dumps(obj, separators=(",", ":")).encode()
    return {"iv": b64e(iv), "ct": b64e(AESGCM(key).encrypt(iv, pt, aad))}


def unseal(key: bytes, iv: str, ct: str, aad: bytes):
    return json.loads(AESGCM(key).decrypt(b64d(iv), b64d(ct), aad))


def make_token(sk: bytes, did: str, shadow: bool) -> str:
    iv = os.urandom(12)
    body = json.dumps({"k": b64e(sk), "d": did, "e": now() + SESSION_TTL, "s": 1 if shadow else 0}).encode()
    return base64.urlsafe_b64encode(iv + AESGCM(_master).encrypt(iv, body, b"tk")).decode()


def read_token(t: str) -> dict:
    raw = base64.urlsafe_b64decode(t)
    d = json.loads(AESGCM(_master).decrypt(raw[:12], raw[12:], b"tk"))
    if d["e"] < now():
        raise ValueError("expired")
    return d


# replay protection + rate limiting (in-memory; run a single worker)
_seen, _seen_lock, _seen_n = {}, threading.Lock(), [0]
_rl, _rl_lock = defaultdict(deque), threading.Lock()


def fresh_nonce(n: str) -> bool:
    t = time.time()
    with _seen_lock:
        _seen_n[0] += 1
        if _seen_n[0] % 200 == 0:
            for k in [k for k, v in _seen.items() if v < t]:
                del _seen[k]
        if n in _seen:
            return False
        _seen[n] = t + 130
    return True


def rate_ok(key: str, limit: int, window: int) -> bool:
    t = time.time()
    with _rl_lock:
        q = _rl[key]
        while q and q[0] <= t - window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(t)
    return True


# ----------------------------------------------------------------------------- settings / messages
DEFAULT_SETTINGS = {
    "maintenance": {"enabled": False, "message": "We are upgrading. Please try again soon.", "status_code": 503},
    "update": {"enabled": False, "force": False, "version_code": 0, "message": "A new version of Dekho Hatke is available.",
               "button_text": "Update Now", "url": ""},
    "min_version_code": 1,
    "telegram_url": "https://t.me/doctordevsupport",
}
DEFAULT_MESSAGES = {
    "privacy": {"html": "<h2>Privacy Policy</h2><p>We only store your license key, device identifier and the links you open in this app, to keep the service secure.</p>"},
    "about": {"html": "<p>This app is made by <b>Dr. Dev || Dr. Hamza</b>. I am currently a <b>NEET 1st year dropper</b>.</p><p>If you need <b>custom projects</b> or want to <b>modify existing projects</b>, message me on Telegram.</p>"},
    "contact": {"html": "<h2>Contact me</h2><p>If you have any doubt or want to hire me, contact me on mail.</p>"},
    "share": {"html": "Watch & download videos with Dekho Hatke!", "button_url": "https://t.me/doctordevsupport"},
}
_cache = {}


def cached(path, defaults, ttl=15):
    c = _cache.get(path)
    if c and time.time() - c[0] < ttl:
        return c[1]
    cur = R(path).get() or {}
    out = {}
    for k, v in defaults.items():
        out[k] = {**v, **(cur.get(k) or {})} if isinstance(v, dict) else cur.get(k, v)
    _cache[path] = (time.time(), out)
    return out


def settings():
    return cached("settings", DEFAULT_SETTINGS)


def messages():
    return cached("messages", DEFAULT_MESSAGES)


def drop_cache():
    _cache.clear()


def public_cfg(s):
    return {"tg": s.get("telegram_url", ""), "upd": s.get("update", {}), "minvc": s.get("min_version_code", 1)}


def deny(code, msg, **kw):
    return {"ok": False, "code": code, "msg": msg, **kw}


# ----------------------------------------------------------------------------- app
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.on_event("startup")
async def _startup():
    anyio.to_thread.current_default_thread_limiter().total_tokens = 64
    try:
        if R("settings").get() is None:
            R("settings").set(DEFAULT_SETTINGS)
        if R("messages").get() is None:
            R("messages").set(DEFAULT_MESSAGES)
    except Exception:
        log.exception("seed failed")


@app.exception_handler(RequestValidationError)
async def _bad(_, __):
    return JSONResponse({"e": "x"}, status_code=404)


@app.api_route("/", methods=["GET", "HEAD"])
@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {"ok": True}


def dev_get(did):
    return R(f"devices/{did}").get() or {}


# ----------------------------------------------------------------------------- handshake
@app.post("/v1/hs")
def handshake(body: dict = Body(...)):
    try:
        ck = _rsa.decrypt(b64d(body["ek"]), _OAEP)
        d = unseal(ck, body["iv"], body["ct"], b"hs")
        did = str(d["did"])
        if not DID_RE.match(did):
            raise ValueError
    except Exception:
        return JSONResponse({"e": "x"}, status_code=404)

    def out(o):
        return JSONResponse(seal(ck, o, b"hs-r"))

    s, dev = settings(), dev_get(did)
    if dev.get("banned"):
        return out(deny("DEVICE_BANNED", dev.get("ban_msg") or "Your device has been permanently banned."))
    vc = int(d.get("vc", 0))
    upd = s.get("update", {})
    if vc < int(s.get("min_version_code", 1)):
        return out(deny("OUTDATED", "This version is outdated. Please download the latest version.",
                        url=upd.get("url") or s.get("telegram_url", "")))
    tamper = bool((CERTS and str(d.get("cert", "")).lower() not in CERTS) or
                  (DEXES and str(d.get("dex", "")).lower() not in DEXES))
    flags = int(d.get("fl", 0))
    shadow = bool(dev.get("shadow")) or tamper or flags != 0
    info = {"last_hs": now(), "model": str(d.get("mdl", ""))[:40], "vc": vc, "fl": flags}
    if tamper:
        info.update(shadow=True, tamper_at=now())
    try:
        R(f"devices/{did}").update(info)
    except Exception:
        log.exception("dev update")
    m = s.get("maintenance", {})
    if m.get("enabled"):
        return out(deny("MAINTENANCE", m.get("message"), status=int(m.get("status_code", 503))))
    sk = os.urandom(32)
    return out({"ok": True, "sid": make_token(sk, did, shadow), "sk": b64e(sk), "st": now(), "cfg": public_cfg(s)})


# ----------------------------------------------------------------------------- api ops
def pre(did):
    dev = dev_get(did)
    if dev.get("banned"):
        return deny("DEVICE_BANNED", dev.get("ban_msg") or "Your device has been permanently banned.")
    bu = int(dev.get("blocked_until", 0))
    if bu > now():
        return deny("DEVICE_BLOCKED", f"Too many wrong attempts. Try again in {max(1, (bu - now() + 59) // 60)} minute(s).", until=bu)
    m = settings().get("maintenance", {})
    if m.get("enabled"):
        return deny("MAINTENANCE", m.get("message"), status=int(m.get("status_code", 503)))
    return None


MSG = {
    "LICENSE_EXPIRED": "Your license has expired. Please renew it from Telegram.",
    "LICENSE_REVOKED": "This license has been revoked.",
    "DEVICE_MISMATCH": "This license is already linked to another device. Contact support to reset it.",
    "APP_DISABLED": "This app is currently disabled.",
    "RATE_LIMITED": "Too many requests. Please wait a moment.",
}


def check_license(lk, did):
    """-> (True, license_dict) | (False, deny_dict). Never unlocks on network errors."""
    if not LK_RE.match(lk):
        return False, deny("LICENSE_NOT_FOUND", "Invalid license key.")
    j, st = {}, 0
    for attempt in (0, 1):
        try:
            r = http.post(LICENSE_URL, json={"license_key": lk, "device_id": did, "device_name": "Android", "app_version": "1.0.0"},
                          headers={"Content-Type": "application/json", "X-API-Key": LICENSE_API_KEY}, timeout=20)
            st = r.status_code
            try:
                j = r.json()
            except ValueError:
                j = {}
            break
        except requests.RequestException:
            if attempt:
                return False, deny("UPSTREAM", "Could not verify the license. Please try again.")
    if st == 200 and j.get("success") is True:
        return True, j.get("license") or {}
    if j.get("maintenance"):
        return False, deny("MAINTENANCE", j.get("message") or "Under maintenance.", status=st)
    code = j.get("code") or "UPSTREAM"
    if code == "INVALID_API_KEY":
        log.error("license API key rejected by upstream")
        return False, deny("UPSTREAM", "Service temporarily unavailable.")
    if code in ("LICENSE_NOT_FOUND",):
        return False, deny(code, "Invalid license key.")
    if code in MSG:
        return False, deny(code, MSG[code], retry_after=j.get("retry_after"))
    return False, deny("UPSTREAM", "Could not verify the license. Please try again.")


def upsert_user(lk, did, lic):
    ref = R(f"users/{lk}")
    u = ref.get() or {}
    upd = {"key": lk, "name": (lic.get("user") or {}).get("full_name") or u.get("name") or "User",
           "plan": lic.get("plan", ""), "expires_at": lic.get("expires_at") or 0, "last_seen": now(),
           "last_device": did, f"devices/{did}": True}
    if not u:
        upd["first_seen"] = now()
    ref.update(upd)
    return {**u, **upd}


def op_license(sess, p):
    did, lk = sess["d"], str(p.get("lk", "")).strip()
    err = pre(did)
    if err:
        return err
    if sess.get("s"):
        return deny("LICENSE_NOT_FOUND", "Invalid license key.")  # shadow: never succeeds
    ok, info = check_license(lk, did)
    if not ok:
        if info["code"] == "LICENSE_NOT_FOUND":
            dev = dev_get(did)
            f = int(dev.get("fails", 0)) + 1
            upd = {"fails": f, "fails_total": int(dev.get("fails_total", 0)) + 1, "last_tried": lk[:40], "last_fail": now()}
            if f >= 3:
                upd.update(blocked_until=now() + 3600, fails=0)
                R(f"devices/{did}").update(upd)
                return deny("DEVICE_BLOCKED", "Too many wrong attempts. This device is blocked for 1 hour.", until=now() + 3600)
            R(f"devices/{did}").update(upd)
            return deny("LICENSE_NOT_FOUND", f"Invalid license key. {3 - f} attempt(s) left.", left=3 - f)
        return info
    user = upsert_user(lk, did, info)
    R(f"devices/{did}").update({"fails": 0, "license": lk})
    if user.get("blocked"):
        return deny("USER_BLOCKED", user.get("block_msg") or "Your account has been blocked by the admin.")
    return {"ok": True, "name": user["name"], "plan": info.get("plan", ""), "exp": info.get("expires_at", 0),
            "rem": info.get("remaining_seconds", 0)}


def op_fetch(sess, p):
    did, lk, url = sess["d"], str(p.get("lk", "")).strip(), str(p.get("url", "")).strip()
    err = pre(did)
    if err:
        return err
    if sess.get("s"):
        return deny("FETCH_FAILED", "Unable to fetch this link right now. Please try again later.")
    if not rate_ok(f"f:{did}", 5, 60) or not rate_ok(f"fl:{lk}", 5, 60):
        return deny("RATE_LIMIT", "Maximum 5 fetches per minute. Please wait a little.")
    ok, info = check_license(lk, did)
    if not ok:
        return info
    user = upsert_user(lk, did, info)
    if user.get("blocked"):
        return deny("USER_BLOCKED", user.get("block_msg") or "Your account has been blocked by the admin.")
    if not re.match(r"^https?://[^\s]{4,2000}$", url):
        return deny("BAD_URL", "Please paste a valid link.")
    try:
        r = http.post(XAPI_URL, json={"url": url}, headers={"Content-Type": "application/json", "xAPIverse-Key": XAPI_KEY}, timeout=50)
        j = r.json()
    except (requests.RequestException, ValueError):
        return deny("FETCH_FAILED", "Could not fetch this link. Please try again.")
    if j.get("status") != "success" or not isinstance(j.get("list"), list):
        return deny("FETCH_FAILED", str(j.get("message") or "Could not fetch this link.")[:200])
    keep = ("name", "size", "type", "folder", "is_dir", "quality", "duration", "thumbnail", "stream_url", "normal_dlink",
            "subtitle_url", "size_formatted", "fast_stream_url")
    files = [{k: f.get(k) for k in keep if k in f} for f in j["list"] if isinstance(f, dict)][:100]
    return {"ok": True, "list": files, "total": len(files)}


def op_event(sess, p):
    did, lk = sess["d"], str(p.get("lk", "")).strip()
    if sess.get("s") or not LK_RE.match(lk) or p.get("t") not in ("watch", "download"):
        return {"ok": True}  # shadow / junk dropped silently
    if (R(f"users/{lk}/last_device").get() or "") != did:
        return {"ok": True}
    R(f"events/{lk}").push({"type": p["t"], "url": str(p.get("url", ""))[:3000], "src": str(p.get("src", ""))[:2000],
                            "name": str(p.get("name", ""))[:300], "ts": now()})
    return {"ok": True}


def op_msgs(sess, p):
    s = settings()
    return {"ok": True, "msgs": messages(), "cfg": public_cfg(s)}


OPS = {"l": op_license, "f": op_fetch, "e": op_event, "m": op_msgs}


@app.post("/v1/x/{op}")
def api(op: str, body: dict = Body(...)):
    try:
        token, ts, n = body["s"], int(body["ts"]), str(body["n"])
        iv, ct, h = body["iv"], body["ct"], body["h"]
        if abs(now() - ts) > 60 or len(n) > 40:
            raise ValueError
        sess = read_token(token)
        sk = b64d(sess["k"])
        calc = b64e(hmac.new(sk, f"{token}.{ts}.{n}.{iv}.{ct}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(calc, h):
            raise ValueError
        p = unseal(sk, iv, ct, f"{op}|{ts}|{n}".encode())
    except Exception:
        return JSONResponse({"e": "S"}, status_code=401)
    if not fresh_nonce(n) or op not in OPS:
        return JSONResponse({"e": "S"}, status_code=401)
    try:
        out = OPS[op](sess, p)
    except Exception:
        log.exception("op %s failed", op)
        out = deny("ERR", "Something went wrong. Please try again.")
    return JSONResponse(seal(sk, out, f"r|{ts}|{n}".encode()))


# ----------------------------------------------------------------------------- admin
def _sig(exp: str) -> str:
    return hmac.new(ADMIN_SECRET, exp.encode(), hashlib.sha256).hexdigest()


def admin_required(request: Request):
    try:
        exp, sig = request.cookies.get("dh_admin", "").split(".")
        if not (hmac.compare_digest(sig, _sig(exp)) and int(exp) > now()):
            raise ValueError
    except Exception:
        raise HTTPException(401)
    if request.method != "GET" and request.headers.get("x-requested-with") != "dh":
        raise HTTPException(403)


@app.post("/admin/api/login")
def a_login(request: Request, body: dict = Body(...)):
    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "x").split(",")[0]
    if not rate_ok(f"adm:{ip}", 6, 300):
        raise HTTPException(429, "Too many attempts")
    ok = ADMIN_USER and ADMIN_PASS and hmac.compare_digest(str(body.get("u", "")), ADMIN_USER) \
        and hmac.compare_digest(str(body.get("p", "")), ADMIN_PASS)
    if not ok:
        raise HTTPException(401, "Wrong credentials")
    exp = str(now() + 12 * 3600)
    resp = JSONResponse({"ok": True})
    resp.set_cookie("dh_admin", f"{exp}.{_sig(exp)}", max_age=12 * 3600, httponly=True, samesite="strict", secure=True)
    return resp


@app.post("/admin/api/logout")
def a_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("dh_admin")
    return resp


def _vk(lk):
    if not re.match(r"^[A-Za-z0-9]{6,64}$", lk):
        raise HTTPException(400)


@app.get("/admin/api/users", dependencies=[Depends(admin_required)])
def a_users(q: str = ""):
    q = q.strip().lower()
    rows = []
    for k, u in (R("users").get() or {}).items():
        if q and q not in k.lower() and q not in str(u.get("name", "")).lower():
            continue
        rows.append({"key": k, "name": u.get("name"), "plan": u.get("plan"), "expires_at": u.get("expires_at"),
                     "last_seen": u.get("last_seen", 0), "blocked": bool(u.get("blocked")),
                     "devices": len(u.get("devices") or {})})
    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    return rows[:500]


@app.get("/admin/api/user/{lk}", dependencies=[Depends(admin_required)])
def a_user(lk: str):
    _vk(lk)
    u = R(f"users/{lk}").get()
    if not u:
        raise HTTPException(404)
    ev = R(f"events/{lk}").order_by_key().limit_to_last(500).get() or {}
    events = sorted(ev.values(), key=lambda e: e.get("ts", 0), reverse=True)
    devs = {d: {k: v for k, v in (dev_get(d) or {}).items() if k in ("banned", "shadow", "model", "last_hs", "ban_msg")}
            for d in (u.get("devices") or {})}
    return {"user": u, "events": events, "devices": devs}


@app.post("/admin/api/user/{lk}/block", dependencies=[Depends(admin_required)])
def a_block(lk: str, body: dict = Body(...)):
    _vk(lk)
    u = R(f"users/{lk}").get()
    if not u:
        raise HTTPException(404)
    msg = str(body.get("message") or "Your account has been blocked by the admin.")[:300]
    R(f"users/{lk}").update({"blocked": True, "block_msg": msg})
    if body.get("ban_device", True):
        for d in (u.get("devices") or {}):
            R(f"devices/{d}").update({"banned": True, "ban_msg": msg})
    return {"ok": True}


@app.post("/admin/api/user/{lk}/unblock", dependencies=[Depends(admin_required)])
def a_unblock(lk: str):
    _vk(lk)
    u = R(f"users/{lk}").get() or {}
    R(f"users/{lk}").update({"blocked": False, "block_msg": ""})
    for d in (u.get("devices") or {}):
        R(f"devices/{d}").update({"banned": False, "ban_msg": "", "blocked_until": 0, "fails": 0})
    return {"ok": True}


@app.get("/admin/api/devices", dependencies=[Depends(admin_required)])
def a_devices():
    t, rows = now(), []
    for d, v in (R("devices").get() or {}).items():
        if int(v.get("fails_total", 0)) or int(v.get("blocked_until", 0)) > t or v.get("banned") or v.get("shadow"):
            rows.append({"id": d, **{k: v.get(k) for k in ("fails", "fails_total", "blocked_until", "last_fail", "last_tried",
                                                          "banned", "ban_msg", "shadow", "model", "license")}})
    rows.sort(key=lambda r: r.get("last_fail") or 0, reverse=True)
    return rows[:300]


@app.post("/admin/api/device/{did}/release", dependencies=[Depends(admin_required)])
def a_release(did: str, body: dict = Body(default={})):
    if not DID_RE.match(did):
        raise HTTPException(400)
    upd = {"blocked_until": 0, "fails": 0}
    if body.get("unban"):
        upd.update(banned=False, ban_msg="", shadow=False)
    R(f"devices/{did}").update(upd)
    return {"ok": True}


@app.get("/admin/api/settings", dependencies=[Depends(admin_required)])
def a_get_settings():
    drop_cache()
    return {"settings": settings(), "messages": messages()}


@app.post("/admin/api/settings", dependencies=[Depends(admin_required)])
def a_set_settings(body: dict = Body(...)):
    s, m = body.get("settings"), body.get("messages")
    if isinstance(s, dict):
        R("settings").set({k: s[k] for k in DEFAULT_SETTINGS if k in s})
    if isinstance(m, dict):
        R("messages").set({k: m[k] for k in DEFAULT_MESSAGES if k in m})
    drop_cache()
    return {"ok": True}


@app.get("/admin")
def admin_page():
    return FileResponse(os.path.join(os.path.dirname(__file__), "admin", "index.html"),
                        headers={"X-Frame-Options": "DENY", "Cache-Control": "no-store"})


app.mount("/admin/assets", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "admin")), name="admin")
