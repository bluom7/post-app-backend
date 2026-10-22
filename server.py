import sys as _sys
import traceback as _tb

print('==> [DIAG] server.py starting load...', file=_sys.stderr, flush=True)

try:
    from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form, Query, Request, Header, WebSocket, WebSocketDisconnect
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from motor.motor_asyncio import AsyncIOMotorClient
    from dotenv import load_dotenv
    import os, uuid, random, secrets, logging, bcrypt, jwt, re, io, ipaddress, threading as _threading
    from pydantic import BaseModel, EmailStr, field_validator
    from typing import Optional, List
    from datetime import datetime, timezone, timedelta
    import base64, asyncio, urllib.request, urllib.parse, json as _json, tempfile
    import time as _time
    import hashlib as _hl, hmac as _hmac, os as _os
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, ECDSA, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_der_private_key
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from aiscreen import ai_router, auth_router, library_router
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    load_dotenv()

    MONGO_URL      = os.environ["MONGO_URL"].strip()
    DB_NAME        = os.environ.get("DB_NAME", "postapp")
    JWT_SECRET     = os.environ.get("JWT_SECRET", "change-me-in-production")

    # ── Cloudinary (video/photo hosting — enables smooth streaming) ──
    import cloudinary
    import cloudinary.uploader
    CLOUDINARY_URL        = os.environ.get("CLOUDINARY_URL", "").strip()
    CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME", "").strip()
    CLOUDINARY_API_KEY    = os.environ.get("CLOUDINARY_API_KEY", "").strip()
    CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET", "").strip()
    if CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET:
        cloudinary.config(
            cloud_name=CLOUDINARY_CLOUD_NAME,
            api_key=CLOUDINARY_API_KEY,
            api_secret=CLOUDINARY_API_SECRET,
            secure=True,
        )
    # else: falls back to CLOUDINARY_URL env var, which the SDK reads automatically on import

    def _b64ue(b):
        import base64 as _b64
        return _b64.urlsafe_b64encode(b).rstrip(b'=').decode()

    def _b64ud(s):
        import base64 as _b64
        s = s + '=' * (-len(s) % 4)
        return _b64.urlsafe_b64decode(s)

    _vapid_cache = {}
    async def get_vapid_keys():
        if _vapid_cache: return _vapid_cache.get('pub',''), _vapid_cache.get('priv','')
        existing = await db.settings.find_one({'key': 'vapid_keys'})
        if existing:
            _vapid_cache['pub'] = existing['public_key']
            _vapid_cache['priv'] = existing['private_key']
            return existing['public_key'], existing['private_key']
        try:
            priv_key = generate_private_key(SECP256R1())
            pub_bytes = priv_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            priv_bytes = priv_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
            pub = _b64ue(pub_bytes)
            priv = _b64ue(priv_bytes)
            await db.settings.insert_one({'key': 'vapid_keys', 'public_key': pub, 'private_key': priv, 'created_at': now().isoformat()})
            _vapid_cache['pub'] = pub
            _vapid_cache['priv'] = priv
            return pub, priv
        except Exception:
            return '', ''

    def _make_vapid_jwt(endpoint, priv_b64):
        try:
            from urllib.parse import urlparse
            priv_key = load_der_private_key(_b64ud(priv_b64), password=None)
            parsed = urlparse(endpoint)
            audience = parsed.scheme + '://' + parsed.netloc
            hdr = _b64ue(_json.dumps({"typ":"JWT","alg":"ES256"}).encode())
            claims = _b64ue(_json.dumps({"aud":audience,"exp":int(_time.time())+43200,"sub":"mailto:noreply@postapp.com"}).encode())
            signing_input = (hdr + '.' + claims).encode()
            sig = priv_key.sign(signing_input, ECDSA(SHA256()))
            r, s = decode_dss_signature(sig)
            raw = r.to_bytes(32,'big') + s.to_bytes(32,'big')
            return hdr + '.' + claims + '.' + _b64ue(raw)
        except Exception:
            return ''

    def _encrypt_push_payload(sub_info, data_bytes):
        try:
            sub_pub = _b64ud(sub_info['keys']['p256dh'])
            auth_secret = _b64ud(sub_info['keys']['auth'])
            # Generate sender ephemeral key
            sender_key = generate_private_key(SECP256R1())
            sender_pub = sender_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            # Import recipient public key
            from cryptography.hazmat.primitives.asymmetric.ec import ECDH, EllipticCurvePublicNumbers
            x = int.from_bytes(sub_pub[1:33],'big')
            y = int.from_bytes(sub_pub[33:65],'big')
            recv_pub = EllipticCurvePublicNumbers(x=x,y=y,curve=SECP256R1()).public_key()
            # ECDH shared secret
            # ECDH already imported at module level
            shared = sender_key.exchange(ECDH(), recv_pub)
            # HKDF pseudorandom key
            import hmac as _hmac2, hashlib
            # RFC 8291: two-step HKDF — Step1 PRK, Step2 IKM
            prk_key = _hmac2.new(auth_secret, shared, hashlib.sha256).digest()
            ikm = _hmac2.new(prk_key, b"WebPush: info\x00" + sub_pub + sender_pub + b"\x01", hashlib.sha256).digest()
            salt = os.urandom(16)
            # Content key and nonce via HKDF
            # HKDF-Expand: CEK + nonce from IKM
            cek = HKDF(algorithm=SHA256(),length=16,salt=salt,info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
            nonce = HKDF(algorithm=SHA256(),length=12,salt=salt,info=b"Content-Encoding: nonce\x00").derive(ikm)
            padded = data_bytes + b'\x02'   # RFC 8188 last-record delimiter
            ct = AESGCM(cek).encrypt(nonce, padded, None)
            # Build record: salt(16) + rs(4) + keylen(1) + sender_pub(65) + ciphertext
            import struct
            header = salt + struct.pack(">I", 4096) + bytes([len(sender_pub)]) + sender_pub
            return header + ct
        except Exception:
            return None

    async def send_push(user_id, title, body, notification_type=None):
        """Web-push to EVERY device the user subscribed on; dead subscriptions are removed."""
        try:
            subs = await db.push_subscriptions.find({'user_id': user_id}).to_list(10)
            if not subs: return
            pub, priv = await get_vapid_keys()
            if not pub or not priv: return
            payload_data = {'title': title, 'body': body}
            if notification_type:
                payload_data['type'] = notification_type
            payload = _json.dumps(payload_data).encode()
            loop = asyncio.get_event_loop()

            async def _one(sub_doc):
                sub = sub_doc.get('subscription', {}) or {}
                endpoint = sub.get('endpoint', '')
                if not endpoint: return
                jwt_tok = _make_vapid_jwt(endpoint, priv)
                if not jwt_tok: return
                enc_body = _encrypt_push_payload(sub, payload)
                def _req():
                    try:
                        import urllib.request as _ur, urllib.error as _ue
                        r = _ur.Request(endpoint, method='POST')
                        r.add_header('Authorization', 'vapid t=' + jwt_tok + ',k=' + pub)
                        r.add_header('TTL', '86400')
                        r.add_header('Urgency', 'high')
                        if enc_body:
                            r.data = enc_body
                            r.add_header('Content-Type', 'application/octet-stream')
                            r.add_header('Content-Encoding', 'aes128gcm')
                        with _ur.urlopen(r, timeout=10): pass
                        return 200
                    except Exception as e:
                        return getattr(e, 'code', 0) or 0
                code = await loop.run_in_executor(None, _req)
                if code in (404, 410):   # subscription expired / uninstalled
                    try: await db.push_subscriptions.delete_one({'_id': sub_doc['_id']})
                    except Exception: pass
            await asyncio.gather(*[_one(sd) for sd in subs], return_exceptions=True)
        except Exception:
            pass
    OFFICIAL_ACCOUNT_ID = os.environ.get("OFFICIAL_ACCOUNT_ID", "").strip()
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
    TWILIO_SID     = os.environ.get("TWILIO_SID", "").strip()
    TWILIO_TOKEN   = os.environ.get("TWILIO_TOKEN", "").strip()
    TWILIO_PHONE   = os.environ.get("TWILIO_PHONE", "").strip()
    # WhatsApp OTP (optional). Set TWILIO_WHATSAPP_FROM e.g. "+14155238886" (sandbox) or your approved WhatsApp sender.
    # TWILIO_WHATSAPP_CONTENT_SID = approved Authentication template SID (HX...) with variable {{1}} = code. Required for production.
    # Master switch: WhatsApp OTP stays OFF (hidden) unless WHATSAPP_OTP_ENABLED=1 is set.
    WHATSAPP_OTP_ENABLED        = os.environ.get("WHATSAPP_OTP_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on")
    TWILIO_WHATSAPP_FROM        = os.environ.get("TWILIO_WHATSAPP_FROM", "").strip()
    TWILIO_WHATSAPP_CONTENT_SID = os.environ.get("TWILIO_WHATSAPP_CONTENT_SID", "").strip()
    SMS_DEMO_MODE  = os.environ.get("SMS_DEMO_MODE", "").strip() == "1"   # dev only: return the OTP in the API response when SMS can't be sent
    NEWS_API_KEY   = (os.environ.get("NEWS_API_KEY") or os.environ.get("NEWSAPI_KEY") or os.environ.get("NEWSAPI_API_KEY") or os.environ.get("NEWS_KEY") or "").strip()

    DEMO_MODE = not bool(RESEND_API_KEY)

    DELETE_GRACE_DAYS    = 30
    ABUSE_WINDOW_DAYS    = 90
    ABUSE_MAX_DELETIONS  = 3
    ABUSE_COOLDOWN_DAYS  = 14

    client = AsyncIOMotorClient(
        MONGO_URL,
        maxPoolSize=20, minPoolSize=5,
        serverSelectionTimeoutMS=5000, connectTimeoutMS=5000,
    )
    db = client[DB_NAME]

    app    = FastAPI(title="POST App API")
    api    = APIRouter(prefix="/api")
    bearer = HTTPBearer(auto_error=False)

    app.add_middleware(GZipMiddleware, minimum_size=500)

    @app.get("/ping")
    async def ping():
        return {"status": "ok"}

    # Public lightweight health routes for Render/cron-job.org.
    # They intentionally do not touch MongoDB so wake-up checks stay reliable.
    @app.get("/")
    async def root_health():
        return {"status": "ok", "service": "post-app-backend"}

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "post-app-backend"}
    # Public app domain: change ONLY the FRONTEND_URL env var when the domain changes.
    # It is added to CORS automatically (plus www.). EXTRA_CORS_ORIGINS = comma-separated extras.
    PUBLIC_APP_URL = os.environ.get("FRONTEND_URL", "https://postbluom.online").strip().rstrip("/")
    _cors_origins = [
        "https://postbluom.online",
        "https://www.postbluom.online",
        "https://post-app-frontend-c0ai.onrender.com",
        PUBLIC_APP_URL,
    ]
    if PUBLIC_APP_URL.startswith("https://") and not PUBLIC_APP_URL.startswith("https://www."):
        _cors_origins.append("https://www." + PUBLIC_APP_URL[len("https://"):])
    _cors_origins += [o.strip().rstrip("/") for o in os.environ.get("EXTRA_CORS_ORIGINS", "").split(",") if o.strip()]
    _cors_origins = list(dict.fromkeys(_cors_origins))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    logging.basicConfig(level=logging.INFO)

    def now():
        return datetime.now(timezone.utc)

    # ── Password hashing (PBKDF2-HMAC-SHA256) ────────────────────
    _PBKDF2_ITER   = 32_000
    _PBKDF2_PREFIX = "$pbkdf2$"

    async def _run_sync(fn):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fn)

    async def run_in_bg(fn, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fn, *args)

    _PBKDF2_ITER_LEGACY = 260_000   # iterations used by all existing DB hashes

    def _pbkdf2_hash(password: str, salt: str, iters: int = _PBKDF2_ITER) -> str:
        return _hl.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iters).hex()

    async def hashpw(p: str, rounds=None) -> str:
        iters  = _PBKDF2_ITER
        salt   = _os.urandom(16).hex()
        digest = await _run_sync(lambda: _pbkdf2_hash(p, salt, iters))
        # New format: $pbkdf2$<iters>$<salt>$<digest>  (5 parts when split on "$")
        return f"{_PBKDF2_PREFIX}{iters}${salt}${digest}"

    async def verifypw(p: str, h: str) -> bool:
        if not h:
            return False
        if h.startswith(_PBKDF2_PREFIX):
            try:
                parts = h.split("$")
                if len(parts) == 5:
                    # New format: ["", "pbkdf2", iters, salt, digest]
                    iters = int(parts[2])
                    if not (10_000 <= iters <= 1_000_000):  # sanity-check iteration bounds
                        return False
                    salt, stored = parts[3], parts[4]
                elif len(parts) == 4:
                    # Legacy format: ["", "pbkdf2", salt, digest] — always 260k
                    iters  = _PBKDF2_ITER_LEGACY
                    salt, stored = parts[2], parts[3]
                else:
                    return False  # malformed — reject
                computed = await _run_sync(lambda: _pbkdf2_hash(p, salt, iters))
                return _hmac.compare_digest(computed, stored)
            except Exception:
                return False
        else:
            try:
                return await _run_sync(lambda: bcrypt.checkpw(p.encode(), h.encode()))
            except Exception:
                return False

    def _is_bcrypt(h: str) -> bool:
        return h.startswith("$2b$") or h.startswith("$2a$")

    def _email_q(email: str) -> dict:
        """Case-insensitive email lookup for MongoDB."""
        return {"email": {"$regex": f"^{re.escape(email.strip())}$", "$options": "i"}}

    def make_token(uid, session_id=None):
        payload = {"sub": uid, "exp": now() + timedelta(days=30)}
        if session_id:
            payload["sid"] = session_id
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    def _client_ip(request: Request | None = None) -> str:
        """Get the public client IP, including the proxy header used by Render."""
        if not request:
            return ""
        candidates = []
        candidates.extend(request.headers.get("x-forwarded-for", "").split(","))
        candidates.append(request.headers.get("x-real-ip", ""))
        candidates.append(request.headers.get("cf-connecting-ip", ""))
        candidates.append(request.client.host if request.client else "")
        for value in candidates:
            value = value.strip()
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not (address.is_private or address.is_loopback or address.is_reserved or address.is_link_local):
                return str(address)
        return ""

    def _lookup_ip_location(client_ip: str) -> dict:
        """Resolve a public IP to a city/region/country using short, keyless fallbacks."""
        if not client_ip:
            return {}
        encoded_ip = urllib.parse.quote(client_ip, safe="")
        providers = (
            (f"https://ipwho.is/{encoded_ip}", "ipwho"),
            (f"https://ipapi.co/{encoded_ip}/json/", "ipapi"),
        )
        for url, provider in providers:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "PostApp/1.0"})
                with urllib.request.urlopen(request, timeout=3) as response:
                    data = _json.loads(response.read().decode("utf-8"))
                if data.get("success") is False or data.get("error") is True:
                    continue
                if provider == "ipwho":
                    location = {
                        "city": str(data.get("city") or "").strip(),
                        "region": str(data.get("region") or "").strip(),
                        "country": str(data.get("country") or "").strip(),
                    }
                else:
                    location = {
                        "city": str(data.get("city") or "").strip(),
                        "region": str(data.get("region") or data.get("region_code") or "").strip(),
                        "country": str(data.get("country_name") or data.get("country") or "").strip(),
                    }
                if any(location.values()):
                    return location
            except Exception:
                continue
        return {}

    def _lookup_coordinate_location(client_location: dict | None) -> dict:
        """Reverse-geocode browser coordinates; coordinates are not persisted."""
        if not client_location:
            return {}
        try:
            latitude = float(client_location.get("latitude"))
            longitude = float(client_location.get("longitude"))
            if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                return {}
            query = urllib.parse.urlencode({
                "format": "json",
                "lat": latitude,
                "lon": longitude,
                "zoom": 10,
                "addressdetails": 1,
            })
            request = urllib.request.Request(
                f"https://nominatim.openstreetmap.org/reverse?{query}",
                headers={"User-Agent": "PostApp/1.0 (login location)"},
            )
            with urllib.request.urlopen(request, timeout=4) as response:
                data = _json.loads(response.read().decode("utf-8"))
            address = data.get("address") or {}
            return {
                "city": str(address.get("city") or address.get("town") or address.get("village") or address.get("municipality") or "").strip(),
                "region": str(address.get("state") or address.get("region") or "").strip(),
                "country": str(address.get("country") or "").strip(),
            }
        except Exception:
            return {}

    def _session_metadata(request: Request | None = None, client_location: dict | None = None) -> dict:
        """Capture device and city-level login location without storing credentials."""
        ua = request.headers.get("user-agent", "") if request else ""
        ua_lower = ua.lower()
        device_name = _parse_device_name(ua)
        client_model = (request.headers.get("sec-ch-ua-model", "") if request else "").strip().strip('"')
        if client_model: device_name = client_model.replace("_", " ")
        client_ip = _client_ip(request)
        coordinate_location = _lookup_coordinate_location(client_location)
        ip_location = coordinate_location or _lookup_ip_location(client_ip)
        city = ip_location.get("city") or (request.headers.get("x-city", "") if request else "").strip()
        region = ip_location.get("region") or (request.headers.get("x-region", "") if request else "").strip()
        country = ip_location.get("country") or (request.headers.get("x-country", "") if request else "").strip()
        location = ", ".join(part for part in (city, region, country) if part) or "Unknown location"
        return {
            "device_name": device_name,
            "device": device_name,
            "is_mobile": any(x in ua_lower for x in ("android", "iphone", "ipad", "mobile")),
            "location": location,
            "user_agent": ua[:500],
        }

    def _device_fp(device_name) -> str:
        """Stable, non-reversible fingerprint of a device label (e.g. 'Chrome on Android')."""
        return _hl.sha256((device_name or "unknown").strip().lower().encode()).hexdigest()[:16]

    def send_login_alert_email(email, name, device, location, when_text):
        if DEMO_MODE:
            logging.info(f"[DEMO] Login alert for {email}: {device} / {location} / {when_text}")
            return True
        try:
            import resend, html as _html
            resend.api_key = RESEND_API_KEY
            d, l, w = _html.escape(device or "Unknown device"), _html.escape(location or "Unknown location"), _html.escape(when_text)
            greet = _html.escape(name or "there")
            text = (f"Hi {name or 'there'},\n\nYour POST account was just logged in to from a new device.\n\n"
                    f"Device: {device}\nLocation: {location}\nTime: {when_text}\n\n"
                    "If this was you, you can ignore this email.\n"
                    "If it wasn't, open Settings > Security > Where you're logged in to log that device out, "
                    "then change your password.\n\n- POST App Team\npostbluom.online")
            html_body = (
                '<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#111">'
                '<h2 style="margin:0 0 12px">New login to your account</h2>'
                f'<p style="margin:0 0 16px;color:#444">Hi {greet}, your POST account was just logged in to from a new device.</p>'
                '<div style="background:#f5f6f7;border-radius:14px;padding:16px;margin:0 0 16px;line-height:1.7">'
                f'<b>Device:</b> {d}<br><b>Location:</b> {l}<br><b>Time:</b> {w}</div>'
                '<p style="margin:0 0 8px;color:#444">If this was you, you can ignore this email.</p>'
                '<p style="margin:0;color:#444">If it wasn\'t, go to <b>Settings &rsaquo; Security &rsaquo; Where you\'re logged in</b> '
                'to log that device out, then change your password.</p>'
                '<p style="margin:24px 0 0;color:#888;font-size:12px">POST App &middot; postbluom.online</p></div>')
            resend.Emails.send({
                "from": "POST App <otp@postbluom.online>",
                "to": [email],
                "subject": "New login to your POST account",
                "html": html_body, "text": text,
                "reply_to": "support@postbluom.online",
                "headers": {"X-Entity-Ref-ID": str(uuid.uuid4())},
            })
            return True
        except Exception as e:
            logging.warning(f"Login alert email failed: {e}")
            return False

    async def _login_alert(u: dict, metadata: dict):
        """Tell the owner when their account is opened from a device we haven't seen before."""
        try:
            uid = u["id"]
            fp = _device_fp(metadata.get("device_name"))
            known = u.get("known_devices")
            if known is None:
                # First time we track devices for this account: trust the devices that already have
                # a session, so nobody gets a flood of alerts right after this feature ships.
                rows = await db.sessions.find({"user_id": uid}, {"_id": 0, "device_name": 1}).to_list(50)
                seed = {fp} | {_device_fp(r.get("device_name")) for r in rows}
                await db.users.update_one({"id": uid, "known_devices": {"$exists": False}},
                                          {"$set": {"known_devices": sorted(seed)[:30]}})
                return
            if fp in known:
                return
            # Remember the device even when alerts are off, so turning alerts on later stays quiet for it.
            await db.users.update_one({"id": uid}, {"$push": {"known_devices": {"$each": [fp], "$slice": -30}}})
            if u.get("login_alerts_enabled") is False:
                return
            device = metadata.get("device_name") or "Unknown device"
            location = metadata.get("location") or "Unknown location"
            when_text = now().strftime("%d %b %Y, %H:%M UTC")
            _bg(_notify(uid, None, "system", title="New login to your account",
                        body=f"New login on {device} from {location}. If this wasn't you, log that device out in Settings > Security and change your password.",
                        push=("New login to your account", f"{device} · {location}")))
            if u.get("email"):
                await run_in_bg(send_login_alert_email, u["email"], u.get("name"), device, location, when_text)
        except Exception as e:
            logging.warning(f"Login alert failed for {u.get('id')}: {e}")

    async def issue_token(uid, request: Request | None = None, client_location: dict | None = None, notify_user: dict | None = None):
        """Create a revocable session record and bind the JWT to it."""
        session_id = str(uuid.uuid4())
        timestamp = now().isoformat()
        metadata = await asyncio.to_thread(_session_metadata, request, client_location)
        await db.sessions.insert_one({
            "id": session_id,
            "user_id": uid,
            "created_at": timestamp,
            "last_active": timestamp,
            **metadata,
        })
        if notify_user is not None:
            asyncio.create_task(_login_alert(notify_user, metadata))   # background: never slows login
        return make_token(uid, session_id)

    USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")

    # ── Translation cache (in-memory, TTL 1 h) — defined early so translate endpoint can use it
    _trans_cache: dict = {}
    _TRANS_TTL = 3600

    def _cache_get(key):
        entry = _trans_cache.get(key)
        if entry and (_time.monotonic() - entry[1]) < _TRANS_TTL:
            return entry[0]
        return None

    def _cache_set(key, value):
        if len(_trans_cache) > 2000:
            oldest = sorted(_trans_cache, key=lambda k: _trans_cache[k][1])[:500]
            for k in oldest:
                del _trans_cache[k]
        _trans_cache[key] = (value, _time.monotonic())

    def _safe_media_expr(value_expr):
        return {"$cond": [
            {"$eq": [{"$type": value_expr}, "string"]},
            {"$cond": [
                {"$regexMatch": {"input": value_expr, "regex": "^data:", "options": "i"}},
                None, value_expr,
            ]},
            value_expr,
        ]}

    def _safe_media_array_expr(array_expr):
        return {"$cond": [
            {"$isArray": array_expr},
            {"$filter": {
                "input": array_expr,
                "as": "media_item",
                "cond": {"$cond": [
                    {"$eq": [{"$type": "$$media_item"}, "string"]},
                    {"$not": [{"$regexMatch": {"input": "$$media_item", "regex": "^data:", "options": "i"}}]},
                    True,
                ]},
            }},
            array_expr,
        ]}

    def _safe_media_overlay_expr(array_expr):
        return {"$cond": [
            {"$isArray": array_expr},
            {"$filter": {
                "input": array_expr,
                "as": "overlay",
                "cond": {"$cond": [
                    {"$and": [
                        {"$eq": [{"$type": "$$overlay"}, "object"]},
                        {"$eq": [{"$type": "$$overlay.url"}, "string"]},
                    ]},
                    {"$not": [{"$regexMatch": {"input": "$$overlay.url", "regex": "^data:", "options": "i"}}]},
                    True,
                ]},
            }},
            array_expr,
        ]}

    def _safe_media_object_expr(object_expr):
        return {"$cond": [
            {"$eq": [{"$type": object_expr}, "object"]},
            {"$mergeObjects": [object_expr, {"avatar_photo": _safe_media_expr(object_expr + ".avatar_photo")}]},
            object_expr,
        ]}

    def _safe_media_object_array_expr(array_expr):
        return {"$cond": [
            {"$isArray": array_expr},
            {"$map": {"input": array_expr, "as": "embedded_user", "in": _safe_media_object_expr("$$embedded_user")}},
            array_expr,
        ]}

    def _safe_media_comments_expr(array_expr):
        replies = _safe_media_object_array_expr("$$comment.replies")
        safe_comment = {"$cond": [
            {"$eq": [{"$type": "$$comment"}, "object"]},
            {"$mergeObjects": [
                "$$comment",
                {"avatar_photo": _safe_media_expr("$$comment.avatar_photo"), "replies": replies},
            ]},
            "$$comment",
        ]}
        return {"$cond": [
            {"$isArray": array_expr},
            {"$map": {"input": array_expr, "as": "comment", "in": safe_comment}},
            array_expr,
        ]}

    def _safe_media_sanitize_stage(scalar_fields=(), array_fields=(), overlay_fields=(), comment_fields=()):
        updates = {}
        for field in scalar_fields:
            updates[field] = _safe_media_expr("$" + field)
        for field in array_fields:
            updates[field] = _safe_media_array_expr("$" + field)
        for field in overlay_fields:
            updates[field] = _safe_media_overlay_expr("$" + field)
        for field in comment_fields:
            updates[field] = _safe_media_comments_expr("$" + field)
        return {"$set": updates}

    async def _safe_media_find(collection, query, scalar_fields=(), array_fields=(), overlay_fields=(), comment_fields=(), projection=None, sort=None, skip=0, limit=100):
        pipeline = [{"$match": query}]
        if sort:
            pipeline.append({"$sort": sort})
        if skip:
            pipeline.append({"$skip": skip})
        if limit is not None:
            pipeline.append({"$limit": limit})
        pipeline.append(_safe_media_sanitize_stage(scalar_fields, array_fields, overlay_fields, comment_fields))
        if projection:
            pipeline.append({"$project": projection})
        rows = await collection.aggregate(pipeline).to_list(limit)
        if comment_fields:
            embedded_comments = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                for field in comment_fields:
                    values = row.get(field)
                    if isinstance(values, list):
                        embedded_comments.extend(
                            comment for comment in values if isinstance(comment, dict)
                        )
            await _hydrate_comment_profiles(embedded_comments)
        if getattr(collection, "name", None) in {"posts", "reels"} and "avatar_photo" in scalar_fields:
            await _hydrate_author_avatars(rows)
        return rows

    async def _safe_media_find_one(collection, query, **options):
        rows = await _safe_media_find(collection, query, limit=1, **options)
        return rows[0] if rows else None

    async def _migrate_legacy_user_profile_media(user):
        if not user:
            return None
        user_id = user.get("id")
        if user_id:
            safe_id = "".join(
                ch if ch.isalnum() or ch in "_-" else "_" for ch in str(user_id)
            )[:80] or uuid.uuid4().hex
            for field in ("avatar_photo", "cover_photo"):
                value = user.get(field)
                if not isinstance(value, str) or not value.lstrip().lower().startswith("data:image/"):
                    continue
                try:
                    hosted_url = await _cloudinaryize_inline_image(
                        value,
                        "post-app/profile-photos",
                        f"legacy_profile_{safe_id}_{field}",
                        overwrite=True,
                    )
                except Exception:
                    logging.exception(
                        "Legacy profile image migration failed for user %s field %s",
                        user_id, field,
                    )
                    hosted_url = None
                if not hosted_url:
                    continue
                try:
                    saved = await db.users.update_one(
                        {"id": user_id, field: value},
                        {"$set": {field: hosted_url}},
                    )
                except Exception:
                    logging.exception(
                        "Could not save migrated profile image for user %s field %s",
                        user_id, field,
                    )
                    user[field] = hosted_url
                    continue
                if saved.matched_count:
                    user[field] = hosted_url
                else:
                    latest = await db.users.find_one(
                        {"id": user_id}, {"_id": 0, field: 1}
                    )
                    user[field] = latest.get(field) if latest else None
        for field in ("avatar_photo", "cover_photo", "profile_video", "cover_video"):
            value = user.get(field)
            if isinstance(value, str) and value.lstrip().lower().startswith("data:"):
                user[field] = None
        return user

    async def _safe_user_find_one(query, projection=None):
        user = await db.users.find_one(
            query, projection or {"_id": 0, "password_hash": 0, "otp_hash": 0, "known_devices": 0}
        )
        return await _migrate_legacy_user_profile_media(user)

    async def _safe_user_find(query, projection=None, sort=None, skip=0, limit=100):
        profiles = await _safe_media_find(
            db.users, query,
            scalar_fields=("avatar_photo", "cover_photo", "profile_video", "cover_video"),
            projection=projection or {"_id": 0, "password_hash": 0, "otp_hash": 0, "known_devices": 0},
            sort=sort, skip=skip, limit=limit,
        )
        profile_ids = [profile.get("id") for profile in profiles if profile.get("id")]
        if not profile_ids:
            return profiles
        legacy_profiles = await db.users.find(
            {
                "id": {"$in": profile_ids},
                "$or": [
                    {"avatar_photo": {"$regex": "^data:", "$options": "i"}},
                    {"cover_photo": {"$regex": "^data:", "$options": "i"}},
                ],
            },
            {"_id": 0, "id": 1, "avatar_photo": 1, "cover_photo": 1},
        ).to_list(len(profile_ids))
        profiles_by_id = {str(profile["id"]): profile for profile in profiles}
        for offset in range(0, len(legacy_profiles), 8):
            migrated_batch = await asyncio.gather(*(
                _migrate_legacy_user_profile_media(profile)
                for profile in legacy_profiles[offset:offset + 8]
            ))
            for migrated in migrated_batch:
                target = profiles_by_id.get(str(migrated.get("id")))
                if not target:
                    continue
                for field in ("avatar_photo", "cover_photo"):
                    if field in target:
                        target[field] = migrated.get(field)
        return profiles

    async def _hydrate_author_avatars(rows):
        if not rows:
            return rows
        user_ids = list(dict.fromkeys(
            row.get("user_id") for row in rows
            if isinstance(row, dict) and row.get("user_id")
        ))
        if not user_ids:
            return rows
        authors = await _safe_user_find(
            {"id": {"$in": user_ids}},
            {"_id": 0, "id": 1, "avatar_photo": 1},
            limit=len(user_ids),
        )
        avatars = {
            str(author.get("id")): author.get("avatar_photo")
            for author in authors if author.get("avatar_photo")
        }
        for row in rows:
            photo = avatars.get(str(row.get("user_id")))
            if photo:
                row["avatar_photo"] = photo
        return rows

    async def _hydrate_comment_profiles(comments):
        """Fill embedded comment/reply identity from each author's current profile."""
        if not isinstance(comments, list) or not comments:
            return comments
        entries = []
        for comment in comments:
            if not isinstance(comment, dict):
                continue
            entries.append(comment)
            replies = comment.get("replies")
            if isinstance(replies, list):
                entries.extend(reply for reply in replies if isinstance(reply, dict))
        user_ids = list(dict.fromkeys(
            str(entry.get("user_id")).strip()
            for entry in entries
            if entry.get("user_id") is not None and str(entry.get("user_id")).strip()
        ))
        if not user_ids:
            return comments
        profile_map = {}
        profile_fields = {
            "_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
            "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1,
            "is_badge_verified": 1,
        }
        try:
            for offset in range(0, len(user_ids), 100):
                batch = user_ids[offset:offset + 100]
                profiles = await _safe_user_find(
                    {"id": {"$in": batch}}, profile_fields, limit=len(batch)
                )
                for profile in profiles:
                    if profile.get("id") is not None:
                        profile_map[str(profile["id"])] = profile
        except Exception:
            logging.exception("Comment profile hydration failed")
            return comments
        for entry in entries:
            profile = profile_map.get(str(entry.get("user_id")))
            if not profile:
                continue
            name = profile.get("name") or profile.get("username") or entry.get("user_name") or "User"
            entry["user_name"] = name
            if profile.get("handle"):
                entry["user_handle"] = profile["handle"]
            if profile.get("username"):
                entry["username"] = profile["username"]
            entry["avatar_photo"] = profile.get("avatar_photo")
            entry["avatar_bg"] = profile.get("avatar_bg") or entry.get("avatar_bg") or "#FFD600"
            entry["avatar_letter"] = profile.get("avatar_letter") or str(name)[0].upper()
            entry["is_badge_verified"] = bool(profile.get("is_badge_verified"))
        return comments

    # ── Auth helpers ─────────────────────────────────────────────
    async def raw_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
        if not creds:
            raise HTTPException(401, "Missing token")
        try:
            payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
            uid = payload["sub"]
            sid = payload.get("sid")
        except Exception:
            raise HTTPException(401, "Invalid token")
        u = await _safe_user_find_one({"id": uid})
        if not u:
            raise HTTPException(401, "User not found")
        if sid:
            session = await db.sessions.find_one({"id": sid, "user_id": uid}, {"_id": 0})
            if not session:
                raise HTTPException(401, "Session expired or revoked")
            await db.sessions.update_one(
                {"id": sid, "user_id": uid},
                {"$set": {"last_active": now().isoformat()}},
            )
            u["_current_session_id"] = sid
        return u

    async def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
        u = await raw_user(creds)
        return u

    # ── One-time reset: force old accounts to new theme/notification defaults ──
    async def _migrate_prefs_defaults(u: dict):
        if u.get("prefs_migrated"):
            return
        await db.users.update_one(
            {"id": u["id"]},
            {"$set": {
                "theme": "light",
                "notifications_prefs": {"likes": True, "comments": True, "friend_requests": True, "messages": True, "mentions": True, "tags": True},
                "prefs_migrated": True,
            }},
        )

    # ── Background hash migration helper ─────────────────────────
    async def _migrate_hash(uid: str, password: str):
        try:
            new_hash = await hashpw(password)
            await db.users.update_one({"id": uid}, {"$set": {"password_hash": new_hash}})
            logging.info(f"✅ Migrated password hash for {uid}")
        except Exception as e:
            logging.warning(f"Hash migration failed for {uid}: {e}")

    # ── Email / SMS senders ───────────────────────────────────────
    # ── Email brand assets (inline CID images → Gmail/Outlook me bina "load images" ke dikhte hain) ──
    _EMAIL_LOGO_B64 = "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"
    _EMAIL_WORDMARK_B64 = "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"
    _EMAIL_BADGE_B64 = "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"

    @app.get("/email-assets/{asset_name}")
    async def _email_asset(asset_name: str):
        """Public brand images for emails (served over HTTPS so Gmail loads them instantly and caches them)."""
        from fastapi.responses import Response as _Resp
        data = {"post-logo.png": _EMAIL_LOGO_B64, "post-badge.png": _EMAIL_BADGE_B64, "post-wordmark.png": _EMAIL_WORDMARK_B64}.get(asset_name)
        if not data:
            raise HTTPException(404, "Not found")
        return _Resp(content=base64.b64decode(data), media_type="image/png",
                     headers={"Cache-Control": "public, max-age=31536000, immutable"})

    def _email_asset_url(name):
        base = (os.environ.get("EMAIL_ASSET_BASE_URL") or os.environ.get("RENDER_EXTERNAL_URL") or PUBLIC_APP_URL or "").strip().rstrip("/")
        return f"{base}/email-assets/{name}?v=4"

    def _build_otp_email_html(code, email="", name=None):
        logo_url = _email_asset_url("post-logo.png")
        badge_url = _email_asset_url("post-badge.png")
        wordmark_url = _email_asset_url("post-wordmark.png")
        import html as _html
        email_safe = _html.escape(email or "you")
        _first = (str(name or "").strip().split() or [""])[0]
        greet_name = _html.escape(_first) if _first else "there"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your POST App verification code</title>
  <style>
    html, body {{ margin:0 !important; padding:0 !important; background:#FAF9F5 !important; width:100% !important; }}
    table {{ border-collapse:collapse; }}
    img {{ border:0; outline:none; text-decoration:none; }}
  </style>
</head>
<body bgcolor="#FAF9F5" style="margin:0;padding:0;background:#FAF9F5;width:100%;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#141413;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">Your POST App verification code is {code}. It expires in 10 minutes.</div>
  <table role="presentation" width="100%" bgcolor="#FAF9F5" cellpadding="0" cellspacing="0" style="background:#FAF9F5;width:100%;">
    <tr><td align="center" style="padding:0;background:#FAF9F5;">
      <table role="presentation" width="100%" bgcolor="#FAF9F5" cellpadding="0" cellspacing="0" style="width:100%;background:#FAF9F5;">

        <!-- Main cream block -->
        <tr><td style="background:#FAF9F5;padding:24px 24px 24px 24px;">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td style="vertical-align:middle;"><img src="{logo_url}" width="56" height="56" alt="POST" style="display:block;border:0;border-radius:28px;width:56px;height:56px;"></td>
            <td style="vertical-align:middle;padding-left:10px;">
              <img src="{wordmark_url}" width="115" height="30" alt="POST" style="vertical-align:middle;border:0;width:115px;height:30px;">
              <img src="{badge_url}" width="24" height="24" alt="Verified" style="vertical-align:middle;margin-left:6px;border:0;width:24px;height:24px;">
            </td>
          </tr></table>

          </td></tr>
        <tr><td height="1" bgcolor="#E3E0D4" style="height:1px;line-height:1px;font-size:0;background:#E3E0D4;padding:0;">&nbsp;</td></tr>
        <tr><td style="background:#FAF9F5;padding:28px 24px 40px 24px;">
          <p style="margin:0 0 0 0;font-size:22px;line-height:1.3;font-weight:600;color:#141413;">Hi {greet_name}! &#128155;</p>
          <p style="margin:6px 0 0 0;font-size:16px;line-height:1.5;color:#73726C;">We hope your day is going great today.</p>
          <h1 style="margin:22px 0 0 0;font-family:Georgia,'Times New Roman',serif;font-size:36px;line-height:1.15;font-weight:500;color:#141413;letter-spacing:-0.5px;">Verify your email, start posting</h1>
          <p style="margin:20px 0 0 0;font-size:17px;line-height:1.65;color:#3D3D3A;">We&#8217;re so happy to have you on POST. Enter this verification code in the app to confirm your email and finish creating your account.</p>

          <p style="margin:32px 0 0 0;text-align:center;font-family:Helvetica,Arial,sans-serif;font-size:26px;line-height:1.2;font-weight:600;letter-spacing:8px;color:#141413;">{code}</p>
          <p style="margin:18px 0 0 0;text-align:center;font-size:14px;color:#73726C;">This code expires in <strong style="color:#141413;">10 minutes</strong>.</p>
        </td></tr>

        <!-- Safety block -->
        <tr><td height="1" bgcolor="#E3E0D4" style="height:1px;line-height:1px;font-size:0;background:#E3E0D4;padding:0;">&nbsp;</td></tr>
        <tr><td style="background:#FAF9F5;padding:28px 24px 32px 24px;">
          <h2 style="margin:0 0 12px 0;font-family:Georgia,'Times New Roman',serif;font-size:24px;font-weight:500;color:#141413;">Keep your account safe</h2>
          <p style="margin:0;font-size:15px;line-height:1.65;color:#3D3D3A;">Never share this code with anyone. The POST team will never ask you for it, not by email, chat or phone.</p>
          <p style="margin:12px 0 0 0;font-size:15px;line-height:1.65;color:#3D3D3A;">Didn&#8217;t request this? You can safely ignore this email.</p>
        </td></tr>

        <!-- Footer -->
        <tr><td height="1" bgcolor="#E3E0D4" style="height:1px;line-height:1px;font-size:0;background:#E3E0D4;padding:0;">&nbsp;</td></tr>
        <tr><td style="background:#FAF9F5;padding:28px 24px 40px 24px;">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td style="vertical-align:middle;"><img src="{logo_url}" width="44" height="44" alt="POST" style="display:block;border:0;border-radius:22px;width:44px;height:44px;"></td>
            <td style="vertical-align:middle;padding-left:10px;"><img src="{wordmark_url}" width="92" height="24" alt="POST" style="display:block;border:0;width:92px;height:24px;"></td>
          </tr></table>
                    <p style="margin:18px 0 0 0;font-size:13px;line-height:1.7;color:#73726C;">&copy; 2025 POST App &middot; BluOm Group Pvt. Limited<br>Uttar Pradesh, India</p>
          <p style="margin:14px 0 0 0;font-size:13px;line-height:1.7;color:#73726C;">This email was sent to {email_safe} because a POST account was started with this address.<br><a href="https://postbluom.online" style="color:#141413;text-decoration:underline;">postbluom.online</a> &nbsp;&middot;&nbsp; <a href="mailto:support@postbluom.online" style="color:#141413;text-decoration:underline;">support@postbluom.online</a></p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    def send_otp_email(email, code, name=None):
        if DEMO_MODE:
            logging.info(f"[DEMO] Email OTP for {email}: {code}")
            return True
        try:
            import resend
            resend.api_key = RESEND_API_KEY

            plain_text = f"""POST App - Verify your email

Your POST App verification code is: {code}

This code expires in 10 minutes.
Never share this code with anyone.

If you did not request this code, you can safely ignore this email.

- POST App Team
postbluom.online"""

            resend.Emails.send({
                "from": "POST App <otp@postbluom.online>",
                "to": [email],
                "subject": "Your POST App verification code",
                "html": _build_otp_email_html(code, email, name),
                "text": plain_text,
                "reply_to": "support@postbluom.online",
                "headers": {"X-Entity-Ref-ID": str(uuid.uuid4())},
            })
            logging.info(f"✅ OTP email sent to {email}")
            return True
        except Exception as e:
            logging.warning(f"Email failed: {e}")
            return False

    def _send_otp_plain_sms(phone, code):
        if not TWILIO_SID or not TWILIO_TOKEN or not TWILIO_PHONE:
            missing = [k for k,v in {"TWILIO_SID": TWILIO_SID, "TWILIO_TOKEN": TWILIO_TOKEN, "TWILIO_PHONE": TWILIO_PHONE}.items() if not v]
            logging.warning(f"[SMS] Missing env vars: {missing}. OTP for {phone}: {code}")
            return None  # None = not configured
        try:
            from twilio.rest import Client
            twilio = Client(TWILIO_SID, TWILIO_TOKEN)
            twilio.messages.create(
                body=f"{code} is your POST verification code.\nValid for 10 minutes. Never share this code with anyone.\n\n- POST App (postbluom.online)",
                from_=TWILIO_PHONE,
                to=phone,
            )
            logging.info(f"[SMS] Sent to {phone}")
            return True
        except Exception as e:
            logging.error(f"[SMS] FAILED to {phone}: {e}")
            return str(e)  # Return error string so callers can surface it

    def send_otp_whatsapp(phone, code):
        """WhatsApp OTP via Twilio. Returns True on success, None if not configured, error string on failure."""
        if not (WHATSAPP_OTP_ENABLED and TWILIO_SID and TWILIO_TOKEN and TWILIO_WHATSAPP_FROM):
            return None
        try:
            import json as _json
            from twilio.rest import Client
            twilio = Client(TWILIO_SID, TWILIO_TOKEN)
            num = phone.strip()
            if not num.startswith("+"):
                num = "+" + num
            frm = TWILIO_WHATSAPP_FROM if TWILIO_WHATSAPP_FROM.startswith("whatsapp:") else f"whatsapp:{TWILIO_WHATSAPP_FROM}"
            kwargs = {"from_": frm, "to": f"whatsapp:{num}"}
            if TWILIO_WHATSAPP_CONTENT_SID:
                kwargs["content_sid"] = TWILIO_WHATSAPP_CONTENT_SID
                kwargs["content_variables"] = _json.dumps({"1": str(code)})
            else:
                kwargs["body"] = f"*{code}* is your POST verification code.\nValid for 10 minutes. Never share this code with anyone."
            twilio.messages.create(**kwargs)
            logging.info(f"[WhatsApp] Sent to {num}")
            return True
        except Exception as e:
            logging.error(f"[WhatsApp] FAILED to {phone}: {e}")
            return str(e)

    def send_otp_sms(phone, code):
        """Phone OTP: WhatsApp first (logo + verified business profile), automatic SMS fallback."""
        wa = send_otp_whatsapp(phone, code)
        if wa is True:
            return True
        if wa is not None:
            logging.warning(f"[OTP] WhatsApp failed, falling back to SMS: {wa}")
        return _send_otp_plain_sms(phone, code)

    # ── Misc helpers ──────────────────────────────────────────────
    async def ensure_username_unique(username: str, exclude_uid: Optional[str] = None):
        count = await db.users.count_documents({"username": username})
        if count > 0:
            if exclude_uid:
                user = await db.users.find_one({"username": username})
                if user["id"] != exclude_uid:
                    raise ValueError("Username already taken")
            else:
                raise ValueError("Username already taken")

    def _aware(dt):
        if dt and dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    async def permanently_delete_user(uid: str):
        await db.posts.delete_many({"user_id": uid})
        await db.messages.delete_many({"$or": [{"from_id": uid}, {"to_id": uid}]})
        await db.notifications.delete_many({"$or": [{"user_id": uid}, {"from_user_id": uid}]})
        await db.contact_books.delete_many({"user_id": uid})
        await db.friend_requests.delete_many({"$or": [{"from_id": uid}, {"to_id": uid}]})
        await db.users.update_many({}, {"$pull": {"followers": uid, "following": uid, "blocked_users": uid}})
        await db.users.delete_one({"id": uid})

    async def purge_expired_deleted_account(field: str, value: str):
        user = await db.users.find_one({field: value})
        if user and user.get("deleted_at"):
            deleted_at = _aware(user["deleted_at"])
            if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
                await permanently_delete_user(user["id"])
                return True
        return False

    async def check_delete_recreate_abuse(identifier: str):
        since = now() - timedelta(days=ABUSE_WINDOW_DAYS)
        count = await db.account_deletions.count_documents(
            {"identifier": identifier, "deleted_at": {"$gte": since}}
        )
        if count >= ABUSE_MAX_DELETIONS:
            last = await db.account_deletions.find(
                {"identifier": identifier}
            ).sort("deleted_at", -1).limit(1).to_list(1)
            if last:
                cooldown_until = _aware(last[0]["deleted_at"]) + timedelta(days=ABUSE_COOLDOWN_DAYS)
                if now() < cooldown_until:
                    raise HTTPException(
                        429,
                        f"Too many account deletions. Please try again after "
                        f"{cooldown_until.strftime('%d %b %Y')}.",
                    )

    # ── Pydantic models ───────────────────────────────────────────
    class SignupIn(BaseModel):
        email: EmailStr; password: str; name: str; username: str

        @field_validator("username")
        @classmethod
        def validate_username(cls, v):
            v = v.strip().lower()
            if not USERNAME_RE.match(v):
                raise ValueError("Username: 3-20 chars, only lowercase letters, numbers, underscore")
            return v

    class OtpIn(BaseModel):
        email: EmailStr; otp: str

    class ClientLocationIn(BaseModel):
        latitude: float
        longitude: float
        accuracy: Optional[float] = None

    class LoginIn(BaseModel):
        email: EmailStr; password: str
        client_location: Optional[ClientLocationIn] = None

    class PhoneInitIn(BaseModel):
        phone: str

    class PhoneVerifyIn(BaseModel):
        phone: str; otp: str

    class PhoneSignupIn(BaseModel):
        phone: str; name: str; password: str; username: str; dob: Optional[str] = None

        @field_validator("username")
        @classmethod
        def validate_username(cls, v):
            v = v.strip().lower()
            if not USERNAME_RE.match(v):
                raise ValueError("Username: 3-20 chars, only lowercase letters, numbers, underscore")
            return v

    class EmailInitIn(BaseModel):
        email: EmailStr

    class EmailVerifyIn(BaseModel):
        email: EmailStr; otp: str

    class EmailSignupIn(BaseModel):
        email: EmailStr; name: str; password: str; username: str; dob: Optional[str] = None

        @field_validator("username")
        @classmethod
        def validate_username(cls, v):
            v = v.strip().lower()
            if not USERNAME_RE.match(v):
                raise ValueError("Username: 3-20 chars, only lowercase letters, numbers, underscore")
            return v

    class PhoneLoginIn(BaseModel):
        phone: str; password: str
        client_location: Optional[ClientLocationIn] = None

    class ProfileUpdate(BaseModel):
        name: Optional[str] = None
        username: Optional[str] = None
        handle: Optional[str] = None
        location: Optional[str] = None
        about: Optional[str] = None
        website: Optional[str] = None
        avatar_bg: Optional[str] = None
        avatar_letter: Optional[str] = None
        avatar_photo: Optional[str] = None
        profile_video: Optional[str] = None
        cover_photo: Optional[str] = None
        cover_video: Optional[str] = None
        language: Optional[str] = None
        category: Optional[str] = None
        category_visible: Optional[bool] = None
        gender: Optional[str] = None
        dob: Optional[str] = None
        dob_month_day_visibility: Optional[str] = None
        dob_year_visibility: Optional[str] = None
        is_private: Optional[bool] = None
        theme: Optional[str] = None
        chat_translation_enabled: Optional[bool] = None
        account_type: Optional[str] = None
        is_badge_verified: Optional[bool] = None
        user_status: Optional[str] = None
        two_fa_enabled: Optional[bool] = None
        login_alerts_enabled: Optional[bool] = None
        who_can_message: Optional[str] = None
        who_can_follow: Optional[str] = None
        post_visibility: Optional[str] = None
        comment_control: Optional[str] = None
        sensitive_content_filter: Optional[bool] = None
        country: Optional[str] = None

        @field_validator("country")
        @classmethod
        def validate_country(cls, v):
            if v is None:
                return v
            v = " ".join(v.split())
            if not v or len(v) > 60:
                raise ValueError("Invalid country")
            return v

        @field_validator("username")
        @classmethod
        def validate_username(cls, v):
            if v is None:
                return v
            v = v.strip().lower()
            if not USERNAME_RE.match(v):
                raise ValueError("Username: 3-20 chars, only lowercase letters, numbers, underscore")
            return v

    class AddPhoneInitIn(BaseModel):
        phone: str

    class AddPhoneVerifyIn(BaseModel):
        phone: str; otp: str

    class ChangePhoneInitIn(BaseModel):
        phone: str
        password: Optional[str] = None

    class ChangePhoneVerifyIn(BaseModel):
        phone: str; otp: str

    class AddEmailInitIn(BaseModel):
        email: EmailStr

    class AddEmailVerifyIn(BaseModel):
        email: EmailStr; otp: str

    class NotificationsPrefsIn(BaseModel):
        likes: Optional[bool] = None
        comments: Optional[bool] = None
        friend_requests: Optional[bool] = None
        messages: Optional[bool] = None
        mentions: Optional[bool] = None
        tags: Optional[bool] = None

    class ThemeIn(BaseModel):
        theme: str

        @field_validator("theme")
        @classmethod
        def validate_theme(cls, v):
            v = v.strip().lower()
            if v not in {"light", "dark"}:
                raise ValueError("Theme must be light or dark")
            return v

    class ChangePasswordIn(BaseModel):
        current_password: str; new_password: str

    class PostIn(BaseModel):
        content: str; accent: str = "#FFD600"; location: Optional[str] = None
        photo_url: Optional[str] = None
        photo_urls: Optional[List[str]] = None  # up to 5 photos
        video_url: Optional[str] = None         # base64 data URI, max 30s (mutually exclusive with photos)
        video_duration: Optional[float] = None  # seconds, must be <= 30
        feeling: Optional[str] = None           # e.g. "😊 Happy"
        tagged_users: Optional[List[str]] = None  # list of @handles
        audience: Optional[str] = "public"       # public | followers
        comments_enabled: Optional[bool] = True  # False = comments turned off for this post
        photo_width: Optional[int] = None         # px width of first photo (from compressPhoto)
        photo_height: Optional[int] = None        # px height of first photo
        aspect_ratio: Optional[float] = None      # precomputed width/height
        music_title: Optional[str] = None             # iTunes track name
        music_artist: Optional[str] = None            # artist name
        music_artwork: Optional[str] = None           # 100x100 artwork URL
        music_preview_url: Optional[str] = None       # 30-sec preview URL from iTunes
        music_duration_ms: Optional[int] = None       # full track duration in ms
        music_start_ms: Optional[int] = None          # selected preview start in ms
        music_clip_duration_ms: Optional[int] = None # selected clip duration in ms (1-30000)
        alt_text: Optional[str] = None                # accessibility alt text for media
        gif_url: Optional[str] = None                  # Giphy GIF URL
        sticker_overlays: Optional[List[dict]] = None  # [{id, url, x, y}] Giphy stickers placed on media
        emoji_overlays: Optional[List[dict]] = None    # [{id, emoji, x, y, size}] emoji placed on video
        video_width: Optional[int] = None              # natural px width of video (captured at pick time from browser)
        video_height: Optional[int] = None             # natural px height of video
        video_text_overlays: Optional[List[dict]] = None  # [{id,text,x,y,color,size}] draggable text overlays baked during compose
        video_effect: Optional[str] = None                # VIDEO_EFFECTS id: none|vivid|warm|cool|bw|fade|vintage

    class CommentIn(BaseModel):
        text: str = ""
        gif_url: Optional[str] = None

    class LikeIn(BaseModel):
        color: Optional[str] = None

    class MessageIn(BaseModel):
        to_user_id: str; text: str = ""
        photo_url: Optional[str] = None; gif_url: Optional[str] = None
        mood_color: Optional[str] = None
        reply_to_id: Optional[str] = None
        shared_post_id: Optional[str] = None
        shared_reel_id: Optional[str] = None
        audio_url: Optional[str] = None
        audio_duration: Optional[int] = None
        file_url: Optional[str] = None
        file_name: Optional[str] = None
        file_size: Optional[int] = None
        file_type: Optional[str] = None

    class MessageEditIn(BaseModel):
        text: str = ""

    class TypingIn(BaseModel):
        to_user_id: str; is_typing: bool = True

    class FriendIn(BaseModel):
        target_user_id: str

    class ShareToFriendIn(BaseModel):
        friend_id: str

    class ForgotPasswordInitIn(BaseModel):
        identifier: str

    class ForgotPasswordVerifyIn(BaseModel):
        identifier: str; otp: str

    class ForgotPasswordResetIn(BaseModel):
        identifier: str; otp: str; new_password: str

    class VerificationRequestIn(BaseModel):
        full_name: str
        category: str          # Politician / Blogger / Journalist / Public Figure / Business / Other
        id_proof_url: Optional[str] = None
        social_links: Optional[str] = None

    class AdminGrantIn(BaseModel):
        user_id: str
        category: str

    class AdminRejectIn(BaseModel):
        reason: Optional[str] = "Does not meet verification criteria"

    # ── Auth Email ────────────────────────────────────────────────
    @api.post("/auth/signup")
    async def signup(p: SignupIn):
        existing = await db.users.find_one({"email": p.email})
        if existing and existing.get("is_verified"):
            raise HTTPException(400, "Email already registered")
        try:
            await ensure_username_unique(p.username, exclude_uid=existing["id"] if existing else None)
        except ValueError as e:
            raise HTTPException(400, str(e))
        code   = f"{secrets.randbelow(1000000):06d}"
        uid    = existing["id"] if existing else str(uuid.uuid4())
        colors = ["#FFD600", "#00C853", "#FF1744", "#29B6F6"]
        doc = {
            "id": uid, "email": p.email, "name": p.name, "username": p.username,
            "handle": f"@{p.username}",
            "password_hash": await hashpw(p.password), "is_verified": False,
            "otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10),
            "avatar_bg": random.choice(colors), "avatar_letter": p.name[0].upper(),
            "avatar_photo": None, "profile_video": None, "cover_photo": None, "cover_video": None,
            "website": "", "location": "", "about": "", "language": "en",
            "continent": "Asia", "created_at": now(), "is_seed": False, "deleted_at": None,
            "is_online": False, "last_seen": None, "is_private": False, "theme": "light",
            "chat_translation_enabled": True,
            "followers": [], "following": [], "blocked_users": [],
            "notifications_prefs": {"likes": True, "comments": True, "friend_requests": True, "messages": True, "mentions": True, "tags": True},
        }
        if existing:
            await db.users.update_one({"id": uid}, {"$set": doc})
        else:
            await db.users.insert_one(doc)
        asyncio.create_task(run_in_bg(send_otp_email, p.email, code, getattr(p, 'name', None)))
        return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

    @api.post("/auth/verify-otp")
    async def verify_otp(request: Request, p: OtpIn):
        u = await db.users.find_one({"email": p.email})
        if not u: raise HTTPException(400, "User not found")
        if u.get("is_verified"): raise HTTPException(400, "Already verified")
        exp = u["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "Code expired")
        if not await verifypw(p.otp, u["otp_hash"]): raise HTTPException(400, "Incorrect code")
        await db.users.update_one(
            {"id": u["id"]},
            {"$set": {"is_verified": True}, "$unset": {"otp_hash": "", "otp_expires_at": ""}},
        )
        return {"token": await issue_token(u["id"], request), "user_id": u["id"]}

    # ── Two-factor authentication (OTP to verified email / phone) ──────────
    TWOFA_TTL_MIN      = 10
    TWOFA_MAX_ATTEMPTS = 5
    TWOFA_MAX_SENDS    = 5
    TWOFA_RESEND_SECS  = 30

    class TwoFaPasswordIn(BaseModel):
        password: str

    class TwoFaOtpIn(BaseModel):
        otp: str

    class TwoFaLoginVerifyIn(BaseModel):
        challenge_id: str
        otp: str

    class TwoFaResendIn(BaseModel):
        challenge_id: str

    def _mask_email(e: str) -> str:
        try:
            name, dom = e.split("@", 1)
            return (name[:2] + "*" * max(1, len(name) - 2)) + "@" + dom
        except Exception:
            return "your email"

    def _mask_phone(ph: str) -> str:
        ph = (ph or "").strip()
        return (ph[:3] + "*" * max(2, len(ph) - 5) + ph[-2:]) if len(ph) > 6 else "your phone"

    def _twofa_target(u: dict):
        """Where the code is delivered: the account's email first, else its phone."""
        em = (u.get("email") or "").strip()
        if em:
            return "email", em
        ph = (u.get("phone") or "").strip()
        if ph:
            return "phone", ph
        return None, None

    async def _twofa_send(u: dict, purpose: str, client_location=None, cid=None, prior=None):
        kind, target = _twofa_target(u)
        if not kind:
            raise HTTPException(400, "Add a verified email or phone number first to use two-factor authentication")
        code  = f"{secrets.randbelow(1000000):06d}"
        cid   = cid or uuid.uuid4().hex
        sends = (prior.get("sends", 0) if prior else 0) + 1
        await db.twofa_challenges.update_one({"id": cid}, {"$set": {
            "id": cid, "user_id": u["id"], "purpose": purpose,
            "otp_hash": await hashpw(code),
            "expires_at": now() + timedelta(minutes=TWOFA_TTL_MIN),
            "sent_at": now(), "attempts": 0, "sends": sends,
            "client_location": client_location if client_location is not None else (prior or {}).get("client_location"),
        }}, upsert=True)
        if kind == "email":
            sent = bool(await run_in_bg(send_otp_email, target, code, u.get("name")))
        else:
            sent = (await run_in_bg(send_otp_sms, target, code)) is True
        if not sent:
            await db.twofa_challenges.delete_one({"id": cid})
            raise HTTPException(400, "Could not send the code right now. Please try again.")
        masked = _mask_email(target) if kind == "email" else _mask_phone(target)
        # The code is only echoed back in local/demo mode (no email provider configured).
        demo = code if (DEMO_MODE and kind == "email") else None
        return cid, masked, kind, demo

    async def _twofa_check(cid: str, otp: str, purpose: str, uid=None):
        """Validate a code. Counts every attempt atomically; the challenge is single-use."""
        from pymongo import ReturnDocument
        rec = await db.twofa_challenges.find_one_and_update(
            {"id": cid, "purpose": purpose}, {"$inc": {"attempts": 1}},
            return_document=ReturnDocument.AFTER)
        if not rec or (uid and rec.get("user_id") != uid):
            raise HTTPException(400, "Code expired. Please request a new one.")
        if now() > _aware(rec["expires_at"]):
            await db.twofa_challenges.delete_one({"id": cid})
            raise HTTPException(400, "Code expired. Please request a new one.")
        if rec.get("attempts", 0) > TWOFA_MAX_ATTEMPTS:
            await db.twofa_challenges.delete_one({"id": cid})
            raise HTTPException(429, "Too many wrong attempts. Please start again.")
        code = re.sub(r"\D", "", otp or "")
        if len(code) != 6 or not await verifypw(code, rec["otp_hash"]):
            raise HTTPException(400, "Incorrect code")
        await db.twofa_challenges.delete_one({"id": cid})
        return rec

    async def _twofa_login_gate(u: dict, client_location=None):
        """If the account has 2FA on, send a code and return the 'requires_2fa' payload (no token)."""
        if not u.get("two_fa_enabled"):
            return None
        kind, _t = _twofa_target(u)
        if not kind:
            logging.warning(f"2FA enabled but no contact on file for {u.get('id')} - allowing login")
            return None
        cid, masked, kind, demo = await _twofa_send(u, "login", client_location=client_location)
        return {"requires_2fa": True, "challenge_id": cid, "sent_to": masked, "method": kind,
                "expires_in": TWOFA_TTL_MIN * 60, "resend_in": TWOFA_RESEND_SECS, "demo_otp": demo}

    async def _complete_login(u: dict, request: Request, client_location=None):
        """Same response shape as /auth/login (used after the 2FA code is verified)."""
        resp = {}
        if u.get("deleted_at"):
            deleted_at = _aware(u["deleted_at"])
            if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
                asyncio.create_task(permanently_delete_user(u["id"]))
                raise HTTPException(400, "Invalid credentials")
            resp["pending_delete"] = True
            resp["restore_deadline"] = (deleted_at + timedelta(days=DELETE_GRACE_DAYS)).isoformat()
        asyncio.create_task(_migrate_prefs_defaults(u))
        token = await issue_token(u["id"], request, client_location, notify_user=u)
        user_profile = {k: v for k, v in u.items() if k not in ("_id", "password_hash", "otp_hash", "known_devices")}
        resp.update({"token": token, "user_id": u["id"], "user": user_profile})
        return resp

    @api.post("/auth/2fa/verify-login")
    async def twofa_verify_login(request: Request, p: TwoFaLoginVerifyIn):
        rec = await _twofa_check(p.challenge_id, p.otp, "login")
        u = await db.users.find_one({"id": rec["user_id"]})
        if not u or not u.get("is_verified"):
            raise HTTPException(400, "Account not available")
        return await _complete_login(u, request, rec.get("client_location"))

    @api.post("/auth/2fa/resend")
    async def twofa_resend_login(p: TwoFaResendIn):
        rec = await db.twofa_challenges.find_one({"id": p.challenge_id, "purpose": "login"})
        if not rec:
            raise HTTPException(400, "Session expired. Please log in again.")
        sent_at = _aware(rec.get("sent_at"))
        if sent_at and (now() - sent_at).total_seconds() < TWOFA_RESEND_SECS:
            raise HTTPException(429, f"Please wait {TWOFA_RESEND_SECS} seconds before requesting another code")
        if rec.get("sends", 0) >= TWOFA_MAX_SENDS:
            await db.twofa_challenges.delete_one({"id": p.challenge_id})
            raise HTTPException(429, "Too many codes requested. Please log in again.")
        u = await db.users.find_one({"id": rec["user_id"]})
        if not u:
            raise HTTPException(400, "Account not available")
        cid, masked, kind, demo = await _twofa_send(u, "login", cid=p.challenge_id, prior=rec)
        return {"challenge_id": cid, "sent_to": masked, "method": kind,
                "expires_in": TWOFA_TTL_MIN * 60, "resend_in": TWOFA_RESEND_SECS, "demo_otp": demo}

    # ── 2FA settings (enable needs password + OTP, disable needs password) ──
    @api.post("/security/2fa/enable-init")
    async def twofa_enable_init(p: TwoFaPasswordIn, u=Depends(current_user)):
        row = await db.users.find_one({"id": u["id"]}, {"_id": 0, "password_hash": 1})
        if not row or not await verifypw(p.password, row.get("password_hash", "")):
            raise HTTPException(400, "Password is incorrect")
        if u.get("two_fa_enabled"):
            raise HTTPException(400, "Two-factor authentication is already on")
        prior = await db.twofa_challenges.find_one({"user_id": u["id"], "purpose": "enable"})
        if prior:
            sent_at = _aware(prior.get("sent_at"))
            if sent_at and (now() - sent_at).total_seconds() < TWOFA_RESEND_SECS:
                raise HTTPException(429, f"Please wait {TWOFA_RESEND_SECS} seconds before requesting another code")
            if prior.get("sends", 0) >= TWOFA_MAX_SENDS:
                raise HTTPException(429, "Too many codes requested. Try again later.")
        cid, masked, kind, demo = await _twofa_send(u, "enable", cid=(prior or {}).get("id"), prior=prior)
        return {"challenge_id": cid, "sent_to": masked, "method": kind,
                "expires_in": TWOFA_TTL_MIN * 60, "resend_in": TWOFA_RESEND_SECS, "demo_otp": demo}

    @api.post("/security/2fa/enable-verify")
    async def twofa_enable_verify(p: TwoFaOtpIn, u=Depends(current_user)):
        rec = await db.twofa_challenges.find_one({"user_id": u["id"], "purpose": "enable"})
        if not rec:
            raise HTTPException(400, "Code expired. Please request a new one.")
        await _twofa_check(rec["id"], p.otp, "enable", uid=u["id"])
        await db.users.update_one({"id": u["id"]}, {"$set": {"two_fa_enabled": True}})
        return {"two_fa_enabled": True}

    @api.post("/security/2fa/disable")
    async def twofa_disable(p: TwoFaPasswordIn, u=Depends(current_user)):
        row = await db.users.find_one({"id": u["id"]}, {"_id": 0, "password_hash": 1})
        if not row or not await verifypw(p.password, row.get("password_hash", "")):
            raise HTTPException(400, "Password is incorrect")
        await db.users.update_one({"id": u["id"]}, {"$set": {"two_fa_enabled": False}})
        await db.twofa_challenges.delete_many({"user_id": u["id"]})
        return {"two_fa_enabled": False}

    @api.post("/auth/login")
    async def login(request: Request, p: LoginIn):
        u = await db.users.find_one(_email_q(p.email))          # case-insensitive lookup
        if not u: raise HTTPException(404, "User not found")
        if not u.get("is_verified"):                             # fast check BEFORE slow hash
            raise HTTPException(400, "Account not verified. Please check your email for the OTP verification code.")
        pw_hash = u.get("password_hash", "")
        if not await verifypw(p.password, pw_hash): raise HTTPException(401, "Wrong password")
        if _is_bcrypt(pw_hash) or (pw_hash.startswith(_PBKDF2_PREFIX) and len(pw_hash.split("$")) == 4):
            asyncio.create_task(_migrate_hash(u["id"], p.password))  # upgrade legacy 260k → 100k
        asyncio.create_task(_migrate_prefs_defaults(u))  # background — don't block login
        client_location = p.client_location.model_dump() if p.client_location else None
        _gate = await _twofa_login_gate(u, client_location)
        if _gate:
            return _gate
        token = await issue_token(u["id"], request, client_location, notify_user=u)
        user_profile = {k: v for k, v in u.items() if k not in ("_id", "password_hash", "otp_hash", "known_devices")}
        resp = {"token": token, "user_id": u["id"], "user": user_profile}
        if u.get("deleted_at"):
            deleted_at = _aware(u["deleted_at"])
            if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
                asyncio.create_task(permanently_delete_user(u["id"]))  # background delete
                raise HTTPException(400, "Invalid credentials")
            resp["pending_delete"] = True
            resp["restore_deadline"] = (deleted_at + timedelta(days=DELETE_GRACE_DAYS)).isoformat()
        return resp

    @api.post("/auth/resend-otp")
    async def resend_otp(body: dict):
        u = await db.users.find_one({"email": body.get("email")})
        if not u: raise HTTPException(400, "User not found")
        code = f"{secrets.randbelow(1000000):06d}"
        await db.users.update_one(
            {"id": u["id"]},
            {"$set": {"otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10)}},
        )
        asyncio.create_task(run_in_bg(send_otp_email, u["email"], code, u.get("name")))
        return {"message": "Resent", "demo_otp": code if DEMO_MODE else None}

    # ── Forgot Password ───────────────────────────────────────────
    @api.post("/auth/forgot-password-init")
    async def forgot_password_init(p: ForgotPasswordInitIn):
        identifier = p.identifier.strip()
        if "@" in identifier:
            user = await db.users.find_one(_email_q(identifier))   # case-insensitive, same as login
        else:
            _ph_v = [identifier]
            if identifier.startswith("+91") and len(identifier) == 13: _ph_v.append(identifier[3:])
            elif not identifier.startswith("+") and len(identifier) == 10: _ph_v.append("+91" + identifier)
            user = await db.users.find_one({"phone": {"$in": _ph_v}})
            # Do NOT change identifier — keep frontend-sent value so verify/reset calls match
        if not user or not user.get("is_verified"):
            raise HTTPException(400, "No account found with this email or phone number")
        is_email = "@" in identifier
        # Cooldown: if a valid OTP was already sent recently, don't invalidate it with a
        # fresh one — a slow-arriving email could otherwise be invalidated by an impatient resend.
        _existing = await db.reset_otps.find_one({"identifier": identifier})
        if _existing and _existing.get("otp_sent_at") and not _existing.get("verified"):
            _sa = _existing["otp_sent_at"]
            _sa = _sa if _sa.tzinfo else _sa.replace(tzinfo=timezone.utc)
            if (now() - _sa).total_seconds() < 45:
                return {
                    "message": "OTP recently sent",
                    "demo_otp": _existing.get("_plain"),
                    "method": "email" if is_email else "sms",
                }
        code = f"{secrets.randbelow(1000000):06d}"
        await db.reset_otps.update_one(
            {"identifier": identifier},
            {"$set": {
                "identifier": identifier, "user_id": user["id"],
                "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False,
                "otp_sent_at": now(), "attempts": 0, "_plain": code if DEMO_MODE else None,
            }, "$unset": {"verified_at": ""}},
            upsert=True,
        )
        if is_email:
            # Await send so we can detect and report failure; never leak OTP in response
            email_sent = await run_in_bg(send_otp_email, identifier, code)
            if not email_sent and not DEMO_MODE:
                raise HTTPException(503, "Failed to send verification email. Please try again in a moment.")
            return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None, "method": "email"}
        else:
            sms_result = await run_in_bg(send_otp_sms, identifier, code)
            if sms_result is not True:
                # Never hand the code back to the client when delivery fails — that would let
                # anyone who knows a phone number reset that account's password.
                logging.warning(f"[forgot-password] SMS delivery failed for {identifier}: {sms_result}")
                await db.reset_otps.delete_one({"identifier": identifier})
                raise HTTPException(400, "Could not send the code to this number right now. Try your email instead or try again later.")
            return {"message": "OTP sent", "demo_otp": None, "method": "sms"}

    @api.post("/auth/forgot-password-verify")
    async def forgot_password_verify(p: ForgotPasswordVerifyIn):
        from pymongo import ReturnDocument
        ident = p.identifier.strip()
        # Count every attempt atomically so the 6-digit code cannot be brute-forced.
        rec = await db.reset_otps.find_one_and_update(
            {"identifier": ident}, {"$inc": {"attempts": 1}}, return_document=ReturnDocument.AFTER)
        if not rec: raise HTTPException(400, "Request not found. Please start again.")
        exp = rec["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "OTP expired. Please request a new one.")
        if rec.get("attempts", 0) > 5:
            await db.reset_otps.delete_one({"identifier": ident})
            raise HTTPException(400, "Too many wrong attempts. Please request a new code.")
        if not await verifypw(re.sub(r"\D", "", p.otp or ""), rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
        await db.reset_otps.update_one({"identifier": ident}, {"$set": {"verified": True, "verified_at": now()}})
        return {"message": "OTP verified"}

    @api.post("/auth/forgot-password-reset")
    async def forgot_password_reset(p: ForgotPasswordResetIn):
        ident = p.identifier.strip()
        rec = await db.reset_otps.find_one({"identifier": ident, "verified": True})
        if not rec: raise HTTPException(400, "Not verified. Please verify OTP first.")
        # The verified step is only good for 15 minutes and must be bound to the same code.
        va = rec.get("verified_at")
        va = va if (va is None or va.tzinfo) else va.replace(tzinfo=timezone.utc)
        if not va or (now() - va).total_seconds() > 15 * 60:
            await db.reset_otps.delete_one({"identifier": ident})
            raise HTTPException(400, "Verification expired. Please start again.")
        if not await verifypw(re.sub(r"\D", "", p.otp or ""), rec["otp_hash"]):
            raise HTTPException(400, "Verification failed. Please start again.")
        if len(p.new_password) < 6: raise HTTPException(400, "Password must be at least 6 characters")
        await db.users.update_one(
            {"id": rec["user_id"]},
            {"$set": {"password_hash": await hashpw(p.new_password)}},
        )
        await db.reset_otps.delete_one({"identifier": ident})
        # Log the account out everywhere: anyone holding an old token (or the old password) is cut off.
        await db.sessions.delete_many({"user_id": rec["user_id"]})
        await db.twofa_challenges.delete_many({"user_id": rec["user_id"]})
        return {"message": "Password reset successfully! Please log in."}

    # ── Auth Email (OTP-first flow) ───────────────────────────────
    @api.post("/auth/email-signup-init")
    async def email_signup_init(p: EmailInitIn):
        await purge_expired_deleted_account("email", p.email)
        await check_delete_recreate_abuse(p.email)
        existing = await db.users.find_one({"email": p.email, "is_verified": True})
        if existing: raise HTTPException(400, "Email already registered")
        _r = await db.email_otps.find_one({"email": p.email})
        if _r and _r.get("otp_sent_at"):
            _sa = _r["otp_sent_at"]; _sa = _sa if _sa.tzinfo else _sa.replace(tzinfo=timezone.utc)
            if (now() - _sa).total_seconds() < 60:
                return {"message": "OTP recently sent", "demo_otp": _r.get("_plain")}
        code = f"{secrets.randbelow(1000000):06d}"
        await db.email_otps.update_one(
            {"email": p.email},
            {"$set": {
                "email": p.email, "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False,
                "otp_sent_at": now(), "_plain": code if DEMO_MODE else None,
            }},
            upsert=True,
        )
        asyncio.create_task(run_in_bg(send_otp_email, p.email, code, getattr(p, 'name', None)))
        return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

    @api.post("/auth/email-verify-init")
    async def email_verify_init(p: EmailVerifyIn):
        rec = await db.email_otps.find_one({"email": p.email})
        if not rec: raise HTTPException(400, "Email not found")
        exp = rec["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "OTP expired")
        if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
        await db.email_otps.update_one({"email": p.email}, {"$set": {"verified": True}, "$unset": {"_plain": ""}})
        return {"message": "Email verified"}

    @api.post("/auth/email-signup")
    async def email_signup(request: Request, p: EmailSignupIn):
        rec = await db.email_otps.find_one({"email": p.email, "verified": True})
        if not rec: raise HTTPException(400, "Email not verified")
        existing = await db.users.find_one({"email": p.email, "is_verified": True})
        if existing: raise HTTPException(400, "Email already registered")
        try:
            await ensure_username_unique(p.username)
        except ValueError as e:
            raise HTTPException(400, str(e))
        colors = ["#FFD600", "#00C853", "#FF1744", "#29B6F6"]
        uid = str(uuid.uuid4())
        doc = {
            "id": uid, "email": p.email, "name": p.name, "username": p.username,
            "handle": f"@{p.username}", "dob": p.dob,
            "password_hash": await hashpw(p.password), "is_verified": True,
            "signup_method": "email", "phone_verified": False, "phone": None,
            "avatar_bg": random.choice(colors), "avatar_letter": p.name[0].upper(),
            "avatar_photo": None, "profile_video": None, "cover_photo": None, "cover_video": None,
            "website": "", "location": "", "about": "", "language": "en",
            "continent": "Asia", "created_at": now(), "is_seed": False, "deleted_at": None,
            "is_online": False, "last_seen": None, "is_private": False, "theme": "light",
            "chat_translation_enabled": True,
            "followers": [], "following": [], "blocked_users": [],
            "notifications_prefs": {"likes": True, "comments": True, "friend_requests": True, "messages": True, "mentions": True, "tags": True},
        }
        await db.users.insert_one(doc)
        await db.email_otps.delete_one({"email": p.email})
        return {"token": await issue_token(uid, request), "user_id": uid, "requires_phone": True}

    # ── Auth Phone ────────────────────────────────────────────────
    @api.post("/auth/phone-signup-init")
    async def phone_signup_init(p: PhoneInitIn):
        await purge_expired_deleted_account("phone", p.phone)
        await check_delete_recreate_abuse(p.phone)
        _r = await db.phone_otps.find_one({"phone": p.phone})
        if _r and _r.get("otp_sent_at"):
            _sa = _r["otp_sent_at"]; _sa = _sa if _sa.tzinfo else _sa.replace(tzinfo=timezone.utc)
            if (now() - _sa).total_seconds() < 60:
                return {"message": "OTP recently sent", "demo_otp": _r.get("_plain")}
        code = f"{secrets.randbelow(1000000):06d}"
        await db.phone_otps.update_one(
            {"phone": p.phone},
            {"$set": {
                "phone": p.phone, "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False,
                "otp_sent_at": now(), "_plain": None,
            }},
            upsert=True,
        )
        sms_result = await run_in_bg(send_otp_sms, p.phone, code)
        sms_ok = sms_result is True
        sms_err = sms_result if isinstance(sms_result, str) else None
        demo = code if not sms_ok else None
        if demo: await db.phone_otps.update_one({"phone": p.phone}, {"$set": {"_plain": demo}})
        return {"message": "OTP sent", "demo_otp": demo, "sms_error": sms_err}

    @api.post("/auth/phone-verify-init")
    async def phone_verify_init(p: PhoneVerifyIn):
        rec = await db.phone_otps.find_one({"phone": p.phone})
        if not rec: raise HTTPException(400, "Phone not found")
        exp = rec["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "OTP expired")
        if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
        await db.phone_otps.update_one({"phone": p.phone}, {"$set": {"verified": True}, "$unset": {"_plain": ""}})
        return {"message": "Phone verified"}

    @api.post("/auth/phone-signup")
    async def phone_signup(request: Request, p: PhoneSignupIn):
        rec = await db.phone_otps.find_one({"phone": p.phone, "verified": True})
        if not rec: raise HTTPException(400, "Phone not verified")
        existing = await db.users.find_one({"phone": p.phone, "is_verified": True})
        if existing: raise HTTPException(400, "Phone already registered")
        try:
            await ensure_username_unique(p.username)
        except ValueError as e:
            raise HTTPException(400, str(e))
        colors = ["#FFD600", "#00C853", "#FF1744", "#29B6F6"]
        uid = str(uuid.uuid4())
        doc = {
            "id": uid, "phone": p.phone, "phone_key": _phone_key(p.phone), "discoverable_by_phone": True, "email": None,
            "name": p.name, "username": p.username, "handle": f"@{p.username}", "dob": p.dob,
            "password_hash": await hashpw(p.password), "is_verified": True,
            "signup_method": "phone", "email_verified": False,
            "avatar_bg": random.choice(colors), "avatar_letter": p.name[0].upper(),
            "avatar_photo": None, "profile_video": None, "cover_photo": None, "cover_video": None,
            "website": "", "location": "", "about": "", "language": "en",
            "continent": "Asia", "created_at": now(), "is_seed": False, "deleted_at": None,
            "is_online": False, "last_seen": None, "is_private": False, "theme": "light",
            "chat_translation_enabled": True,
            "followers": [], "following": [], "blocked_users": [],
            "notifications_prefs": {"likes": True, "comments": True, "friend_requests": True, "messages": True, "mentions": True, "tags": True},
        }
        await db.users.insert_one(doc)
        await db.phone_otps.delete_one({"phone": p.phone})
        asyncio.create_task(_on_phone_registered(uid, p.phone))  # tell friends who have this number saved
        return {"token": await issue_token(uid, request), "user_id": uid, "requires_email": True}

    @api.post("/auth/phone-login")
    async def phone_login(request: Request, p: PhoneLoginIn):
        # Flexible lookup: match +91XXXXXXXXXX or bare 10-digit, whichever is stored
        _ph = p.phone
        _ph_variants = [_ph]
        if _ph.startswith("+91") and len(_ph) == 13: _ph_variants.append(_ph[3:])
        elif not _ph.startswith("+") and len(_ph) == 10: _ph_variants.append("+91" + _ph)
        u = await db.users.find_one({"phone": {"$in": _ph_variants}})
        if not u: raise HTTPException(400, "No account found with this phone number")
        pw_hash_p = u.get("password_hash", "")
        if not await verifypw(p.password, pw_hash_p):
            raise HTTPException(401, "Wrong password")
        if u and (_is_bcrypt(pw_hash_p) or (pw_hash_p.startswith(_PBKDF2_PREFIX) and len(pw_hash_p.split("$")) == 4)):
            asyncio.create_task(_migrate_hash(u["id"], p.password))  # upgrade legacy 260k → 100k
        if not u.get("is_verified"): raise HTTPException(400, "Account not verified")
        asyncio.create_task(_migrate_prefs_defaults(u))  # background — don't block login
        client_location = p.client_location.model_dump() if p.client_location else None
        _gate = await _twofa_login_gate(u, client_location)
        if _gate:
            return _gate
        token = await issue_token(u["id"], request, client_location, notify_user=u)
        user_profile = {k: v for k, v in u.items() if k not in ("_id", "password_hash", "otp_hash", "known_devices")}
        resp = {"token": token, "user_id": u["id"], "user": user_profile}
        if u.get("deleted_at"):
            deleted_at = _aware(u["deleted_at"])
            if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
                asyncio.create_task(permanently_delete_user(u["id"]))  # background delete
                raise HTTPException(400, "Invalid phone or password")
            resp["pending_delete"] = True
            resp["restore_deadline"] = (deleted_at + timedelta(days=DELETE_GRACE_DAYS)).isoformat()
        return resp

    @api.get("/auth/me")
    async def me(u=Depends(current_user)):
        return u

    # ── Add Secondary Contact ─────────────────────────────────────
    @api.post("/auth/add-phone-init")
    async def add_phone_init(p: AddPhoneInitIn, u=Depends(raw_user)):
        if u.get("signup_method") != "email": raise HTTPException(403, "Only for email-registered accounts")
        if u.get("phone_verified"): raise HTTPException(400, "Phone already verified")
        existing = await db.users.find_one({"phone": p.phone, "is_verified": True, "id": {"$ne": u["id"]}})
        if existing: raise HTTPException(400, "This phone is already registered to another account")
        _r = await db.phone_otps.find_one({"phone": p.phone, "user_id": u["id"]})
        if _r and _r.get("otp_sent_at"):
            _sa = _r["otp_sent_at"]; _sa = _sa if _sa.tzinfo else _sa.replace(tzinfo=timezone.utc)
            if (now() - _sa).total_seconds() < 60:
                return {"message": "OTP recently sent", "demo_otp": _r.get("_plain")}
        code = f"{secrets.randbelow(1000000):06d}"
        await db.phone_otps.update_one(
            {"phone": p.phone},
            {"$set": {
                "phone": p.phone, "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False, "user_id": u["id"],
                "otp_sent_at": now(), "_plain": None,
            }},
            upsert=True,
        )
        sms_result = await run_in_bg(send_otp_sms, p.phone, code)
        if sms_result is not True:
            logging.error(f"[SMS] add-phone OTP not delivered to {p.phone}: {sms_result}")
            if not SMS_DEMO_MODE:
                # never hand the code to the client: it would let anyone "verify" a number they don't own
                await db.phone_otps.delete_one({"phone": p.phone})
                raise HTTPException(503, "We couldn't send the SMS right now. Please try again in a few minutes.")
            await db.phone_otps.update_one({"phone": p.phone}, {"$set": {"_plain": code}})
            return {"message": "OTP sent", "demo_otp": code, "sms_error": sms_result if isinstance(sms_result, str) else None}
        return {"message": "OTP sent", "demo_otp": None, "sms_error": None}

    @api.post("/auth/add-phone-verify")
    async def add_phone_verify(request: Request, p: AddPhoneVerifyIn, u=Depends(raw_user)):
        if u.get("signup_method") != "email": raise HTTPException(403, "Only for email-registered accounts")
        if u.get("phone_verified"): raise HTTPException(400, "Phone already verified")
        rec = await db.phone_otps.find_one({"phone": p.phone, "user_id": u["id"]})
        if not rec: raise HTTPException(400, "OTP not found. Please request a new one.")
        exp = rec["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "OTP expired. Please request a new one.")
        if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
        await db.users.update_one({"id": u["id"]}, {"$set": {"phone": p.phone, "phone_verified": True, "phone_key": _phone_key(p.phone)}})
        await db.phone_otps.delete_one({"phone": p.phone})
        asyncio.create_task(_on_phone_registered(u["id"], p.phone))  # tell friends who have this number saved
        return {"message": "Phone verified successfully", "token": await issue_token(u["id"], request)}

    # ── Change an already-verified phone number (OTP to the NEW number + password) ──
    @api.post("/auth/change-phone-init")
    async def change_phone_init(p: ChangePhoneInitIn, u=Depends(raw_user)):
        if not u.get("phone"): raise HTTPException(400, "No phone number on this account yet. Please add one first.")
        new_phone = (p.phone or "").strip()
        if not re.fullmatch(r"\+\d{8,15}", new_phone): raise HTTPException(400, "Enter a valid mobile number with country code")
        if new_phone == u.get("phone"): raise HTTPException(400, "This is already your current number")
        creds_doc = await db.users.find_one({"id": u["id"]}, {"_id": 0, "password_hash": 1})
        pw_hash = (creds_doc or {}).get("password_hash") or ""
        if pw_hash:
            if not p.password: raise HTTPException(400, "Enter your password to change your number")
            if not await verifypw(p.password, pw_hash): raise HTTPException(400, "Incorrect password")
        existing = await db.users.find_one({"phone": new_phone, "is_verified": True, "id": {"$ne": u["id"]}})
        if existing: raise HTTPException(400, "This phone is already registered to another account")
        _r = await db.phone_otps.find_one({"phone": new_phone, "user_id": u["id"]})
        if _r and _r.get("otp_sent_at"):
            _sa = _r["otp_sent_at"]; _sa = _sa if _sa.tzinfo else _sa.replace(tzinfo=timezone.utc)
            if (now() - _sa).total_seconds() < 60:
                return {"message": "OTP recently sent", "demo_otp": _r.get("_plain")}
        code = f"{secrets.randbelow(1000000):06d}"
        await db.phone_otps.update_one(
            {"phone": new_phone},
            {"$set": {
                "phone": new_phone, "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False, "user_id": u["id"],
                "otp_sent_at": now(), "_plain": None, "purpose": "change_phone",
            }},
            upsert=True,
        )
        sms_result = await run_in_bg(send_otp_sms, new_phone, code)
        if sms_result is not True:
            logging.error(f"[SMS] change-phone OTP not delivered to {new_phone}: {sms_result}")
            if not SMS_DEMO_MODE:
                await db.phone_otps.delete_one({"phone": new_phone})
                raise HTTPException(503, "We couldn't send the SMS right now. Please try again in a few minutes.")
            await db.phone_otps.update_one({"phone": new_phone}, {"$set": {"_plain": code}})
            return {"message": "OTP sent", "demo_otp": code, "sms_error": sms_result if isinstance(sms_result, str) else None}
        return {"message": "OTP sent", "demo_otp": None, "sms_error": None}

    @api.post("/auth/change-phone-verify")
    async def change_phone_verify(request: Request, p: ChangePhoneVerifyIn, u=Depends(raw_user)):
        new_phone = (p.phone or "").strip()
        rec = await db.phone_otps.find_one({"phone": new_phone, "user_id": u["id"], "purpose": "change_phone"})
        if not rec: raise HTTPException(400, "OTP not found. Please request a new one.")
        exp = rec["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "OTP expired. Please request a new one.")
        if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
        taken = await db.users.find_one({"phone": new_phone, "is_verified": True, "id": {"$ne": u["id"]}})
        if taken: raise HTTPException(400, "This phone is already registered to another account")
        await db.users.update_one({"id": u["id"]}, {"$set": {"phone": new_phone, "phone_verified": True, "phone_key": _phone_key(new_phone)}})
        await db.phone_otps.delete_one({"phone": new_phone})
        asyncio.create_task(_on_phone_registered(u["id"], new_phone))
        return {"message": "Phone number updated successfully", "token": await issue_token(u["id"], request)}

    @api.post("/auth/add-email-init")
    async def add_email_init(p: AddEmailInitIn, u=Depends(raw_user)):
        if u.get("signup_method") != "phone": raise HTTPException(403, "Only for phone-registered accounts")
        if u.get("email_verified"): raise HTTPException(400, "Email already verified")
        existing = await db.users.find_one({"email": p.email, "is_verified": True, "id": {"$ne": u["id"]}})
        if existing: raise HTTPException(400, "This email is already registered to another account")
        _r = await db.email_otps.find_one({"email": p.email, "user_id": u["id"]})
        if _r and _r.get("otp_sent_at"):
            _sa = _r["otp_sent_at"]; _sa = _sa if _sa.tzinfo else _sa.replace(tzinfo=timezone.utc)
            if (now() - _sa).total_seconds() < 60:
                return {"message": "OTP recently sent", "demo_otp": _r.get("_plain")}
        code = f"{secrets.randbelow(1000000):06d}"
        await db.email_otps.update_one(
            {"email": p.email},
            {"$set": {
                "email": p.email, "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False, "user_id": u["id"],
                "otp_sent_at": now(), "_plain": code if DEMO_MODE else None,
            }},
            upsert=True,
        )
        asyncio.create_task(run_in_bg(send_otp_email, p.email, code, getattr(p, 'name', None)))
        return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

    @api.post("/auth/add-email-verify")
    async def add_email_verify(request: Request, p: AddEmailVerifyIn, u=Depends(raw_user)):
        if u.get("signup_method") != "phone": raise HTTPException(403, "Only for phone-registered accounts")
        if u.get("email_verified"): raise HTTPException(400, "Email already verified")
        rec = await db.email_otps.find_one({"email": p.email, "user_id": u["id"]})
        if not rec: raise HTTPException(400, "OTP not found. Please request a new one.")
        exp = rec["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "OTP expired. Please request a new one.")
        if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
        await db.users.update_one({"id": u["id"]}, {"$set": {"email": p.email, "email_verified": True}})
        await db.email_otps.delete_one({"email": p.email})
        return {"message": "Email verified successfully", "token": await issue_token(u["id"], request)}

    # ── Account deletion / restore ────────────────────────────────
    @api.post("/account/delete-request")
    async def request_account_delete(u=Depends(current_user)):
        if u.get("deleted_at"):
            raise HTTPException(400, "Account is already pending deletion")
        deleted_at = now()
        await db.users.update_one({"id": u["id"]}, {"$set": {"deleted_at": deleted_at}})
        identifier = u.get("phone") or u.get("email")
        await db.account_deletions.insert_one({
            "id": str(uuid.uuid4()), "user_id": u["id"],
            "identifier": identifier, "deleted_at": deleted_at,
        })
        restore_deadline = deleted_at + timedelta(days=DELETE_GRACE_DAYS)
        return {
            "message": f"Account will be permanently deleted in {DELETE_GRACE_DAYS} days unless you restore it.",
            "restore_deadline": restore_deadline.isoformat(),
        }

    @api.post("/account/restore")
    async def restore_account(u=Depends(current_user)):
        if not u.get("deleted_at"):
            raise HTTPException(400, "Account is not pending deletion")
        deleted_at = _aware(u["deleted_at"])
        if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
            raise HTTPException(400, "Restore window expired; account was permanently deleted")
        await db.users.update_one({"id": u["id"]}, {"$set": {"deleted_at": None}})
        await db.account_deletions.delete_many({"user_id": u["id"], "deleted_at": u["deleted_at"]})
        return {"message": "Account restored successfully"}

    @api.get("/account/deletion-status")
    async def deletion_status(u=Depends(current_user)):
        if not u.get("deleted_at"):
            return {"pending_delete": False}
        deleted_at = _aware(u["deleted_at"])
        deadline = deleted_at + timedelta(days=DELETE_GRACE_DAYS)
        return {
            "pending_delete": True,
            "restore_deadline": deadline.isoformat(),
            "days_left": max(0, (deadline - now()).days),
        }

    _DOB_VISIBILITY_OPTIONS = {"public", "followers", "following", "mutuals", "only_you"}

    def _dob_audience_allows(profile, viewer_id, audience, default):
        viewer = str(viewer_id or "")
        owner = str(profile.get("id") or "")
        if viewer and viewer == owner:
            return True
        if not viewer or not owner:
            return False
        audience = audience or default
        if audience not in _DOB_VISIBILITY_OPTIONS:
            return False
        followers = {str(value) for value in (profile.get("followers") or [])}
        following = {str(value) for value in (profile.get("following") or [])}
        if audience == "public":
            return True
        if audience == "followers":
            return viewer in followers
        if audience == "following":
            return viewer in following
        if audience == "mutuals":
            return viewer in followers and viewer in following
        return False

    def _apply_dob_visibility(profile, viewer_id):
        if not profile:
            return profile
        safe = dict(profile)
        raw_dob = profile.get("dob")
        is_self = str(profile.get("id") or "") == str(viewer_id or "")
        month_day_audience = profile.get("dob_month_day_visibility") or "mutuals"
        year_audience = profile.get("dob_year_visibility") or "only_you"
        for key in ("dob_month_day", "dob_year"):
            safe.pop(key, None)
        if is_self:
            safe["dob_month_day_visibility"] = month_day_audience if month_day_audience in _DOB_VISIBILITY_OPTIONS else "mutuals"
            safe["dob_year_visibility"] = year_audience if year_audience in _DOB_VISIBILITY_OPTIONS else "only_you"
        else:
            safe.pop("dob", None)
            safe.pop("dob_month_day_visibility", None)
            safe.pop("dob_year_visibility", None)
        if not raw_dob:
            return safe
        try:
            parsed_dob = datetime.strptime(str(raw_dob)[:10], "%Y-%m-%d")
        except (ValueError, TypeError):
            return safe
        can_see_month_day = _dob_audience_allows(profile, viewer_id, month_day_audience, "mutuals")
        can_see_year = _dob_audience_allows(profile, viewer_id, year_audience, "only_you")
        if is_self or can_see_month_day:
            safe["dob_month_day"] = parsed_dob.strftime("%m-%d")
        if is_self or can_see_year:
            safe["dob_year"] = parsed_dob.strftime("%Y")
        if not is_self and can_see_month_day and can_see_year:
            safe["dob"] = raw_dob
        return safe

    def _apply_presence_visibility(profile, viewer):
        if not profile:
            return profile
        safe = dict(profile)
        if safe.get("is_badge_verified") and not viewer.get("is_badge_verified"):
            safe.pop("is_online", None)
            safe.pop("last_seen", None)
        return safe

    def _apply_user_visibility(profile, viewer):
        return _apply_presence_visibility(_apply_dob_visibility(profile, viewer["id"]), viewer)

    # ── Profile ───────────────────────────────────────────────────
    @api.patch("/profile")
    async def update_profile(p: ProfileUpdate, u=Depends(current_user)):
        upd = {k: v for k, v in p.model_dump().items() if v is not None}
        upd.pop("two_fa_enabled", None)  # 2FA can only change via /security/2fa/* (password + OTP)
        for field in ("dob_month_day_visibility", "dob_year_visibility"):
            if field in upd and upd[field] not in _DOB_VISIBILITY_OPTIONS:
                raise HTTPException(400, "Invalid birthday visibility")
        if "username" in upd:
            if u.get("username_locked") and upd["username"] != u.get("username"):
                raise HTTPException(400, "Verified accounts cannot change their username")
            try:
                await ensure_username_unique(upd["username"], exclude_uid=u["id"])
            except ValueError as e:
                raise HTTPException(400, str(e))
            upd["handle"] = f"@{upd['username']}"
        if upd:
            for field in ("profile_video", "cover_video"):
                _reject_inline_data_uri(upd.get(field), field)
            for field in ("avatar_photo", "cover_photo"):
                if field in upd:
                    upd[field] = await _cloudinaryize_inline_image(
                        upd[field], "post-app/profile-photos",
                        f"profile_{u['id']}_{field}_{uuid.uuid4().hex}",
                    )
            await db.users.update_one({"id": u["id"]}, {"$set": upd})

            # Build denormalized updates and run them in the background
            # so the response returns immediately to the client
            post_upd = {}
            if "name" in upd: post_upd["user_name"] = upd["name"]
            if "handle" in upd: post_upd["user_handle"] = upd["handle"]
            if "avatar_bg" in upd: post_upd["avatar_bg"] = upd["avatar_bg"]
            if "avatar_letter" in upd: post_upd["avatar_letter"] = upd["avatar_letter"]
            if "avatar_photo" in upd: post_upd["avatar_photo"] = upd["avatar_photo"]

            comment_upd = {}
            if "name" in upd: comment_upd["comments.$[c].user_name"] = upd["name"]
            if "handle" in upd: comment_upd["comments.$[c].user_handle"] = upd["handle"]
            if "avatar_bg" in upd: comment_upd["comments.$[c].avatar_bg"] = upd["avatar_bg"]
            if "avatar_letter" in upd: comment_upd["comments.$[c].avatar_letter"] = upd["avatar_letter"]
            if "avatar_photo" in upd: comment_upd["comments.$[c].avatar_photo"] = upd["avatar_photo"]

            msg_upd = {}
            if "name" in upd: msg_upd["from_name"] = upd["name"]
            if "avatar_bg" in upd: msg_upd["avatar_bg"] = upd["avatar_bg"]
            if "avatar_photo" in upd: msg_upd["avatar_photo"] = upd["avatar_photo"]

            uid = u["id"]
            async def _bg():
                try:
                    if post_upd:
                        await db.posts.update_many({"user_id": uid}, {"$set": post_upd})
                    if comment_upd:
                        await db.posts.update_many(
                            {"comments.user_id": uid},
                            {"$set": comment_upd},
                            array_filters=[{"c.user_id": uid}],
                        )
                    if msg_upd:
                        await db.messages.update_many({"from_id": uid}, {"$set": msg_upd})
                except Exception:
                    pass
            asyncio.create_task(_bg())

        return await _safe_user_find_one({"id": u["id"]})


    @api.get("/data/activity-log")
    async def get_activity_log(u=Depends(current_user)):
        """Return the signed-in user's recent posts and comments with safe display metadata."""
        def public_profile(profile):
            if not profile: return None
            return {"id":profile.get("id"),"name":profile.get("name"),"handle":profile.get("handle"),"username":profile.get("username"),"avatar_photo":profile.get("avatar_photo"),"avatar_bg":profile.get("avatar_bg"),"avatar_letter":profile.get("avatar_letter"),"is_badge_verified":bool(profile.get("is_badge_verified"))}
        actor = public_profile(u)
        posts = []
        owned_posts = await _safe_media_find(db.posts, {"user_id": u["id"]}, scalar_fields=("photo_url", "video_url"), array_fields=("photo_urls",), projection={"_id": 0, "id": 1, "content": 1, "created_at": 1, "photo_url": 1, "photo_urls": 1, "video_url": 1}, sort={"created_at": -1}, limit=50)
        for post in owned_posts:
            posts.append({"id":post.get("id"),"type":"post","content":post.get("content") or "(media post)","created_at":post.get("created_at"),"author":actor,"has_media":bool(post.get("photo_url") or post.get("photo_urls") or post.get("video_url")),"media_url":(post.get("photo_urls") or [post.get("photo_url")])[0] if (post.get("photo_urls") or post.get("photo_url")) else None})
        comments=[]; owner_ids=set()
        commented_posts = await _safe_media_find(db.posts, {"comments.user_id": u["id"]}, scalar_fields=("photo_url",), array_fields=("photo_urls",), comment_fields=("comments",), projection={"_id": 0, "id": 1, "content": 1, "created_at": 1, "user_id": 1, "comments": 1, "photo_url": 1, "photo_urls": 1}, limit=200)
        for post in commented_posts:
            owner_id=post.get("user_id")
            if owner_id: owner_ids.add(owner_id)
            for comment in post.get("comments",[]):
                if comment.get("user_id")==u["id"]:
                    comments.append({"id":comment.get("id"),"type":"comment","comment":comment.get("text", ""),"created_at":comment.get("created_at"),"actor":actor,"target_type":"post","target_id":post.get("id"),"target_content":post.get("content") or "(media post)","target_created_at":post.get("created_at"),"target_user_id":owner_id,"target_media_url":(post.get("photo_urls") or [post.get("photo_url")])[0] if (post.get("photo_urls") or post.get("photo_url")) else None})
        commented_reels = await _safe_media_find(db.reels, {"comments.user_id": u["id"]}, scalar_fields=("photo_url",), comment_fields=("comments",), projection={"_id": 0, "id": 1, "caption": 1, "created_at": 1, "user_id": 1, "comments": 1, "photo_url": 1}, limit=200)
        for reel in commented_reels:
            owner_id=reel.get("user_id")
            if owner_id: owner_ids.add(owner_id)
            for comment in reel.get("comments",[]):
                if comment.get("user_id")==u["id"]:
                    comments.append({"id":comment.get("id"),"type":"comment","comment":comment.get("text", ""),"created_at":comment.get("created_at"),"actor":actor,"target_type":"reel","target_id":reel.get("id"),"target_content":reel.get("caption") or "(reel)","target_created_at":reel.get("created_at"),"target_user_id":owner_id,"target_media_url":reel.get("photo_url")})
        like_items=[]
        liked_posts = await _safe_media_find(db.posts, {"likes.user_id": u["id"]}, scalar_fields=("photo_url",), array_fields=("photo_urls",), projection={"_id": 0, "id": 1, "content": 1, "created_at": 1, "user_id": 1, "photo_url": 1, "photo_urls": 1}, limit=200)
        for post in liked_posts:
            owner_id=post.get("user_id")
            if owner_id: owner_ids.add(owner_id)
            like_items.append({"id":"post:"+post.get("id"),"type":"like","actor":actor,"target_type":"post","target_id":post.get("id"),"target_content":post.get("content") or "(media post)","target_created_at":post.get("created_at"),"target_user_id":owner_id,"target_media_url":(post.get("photo_urls") or [post.get("photo_url")])[0] if (post.get("photo_urls") or post.get("photo_url")) else None})
        liked_reels = await _safe_media_find(db.reels, {"likes": u["id"]}, scalar_fields=("photo_url",), projection={"_id": 0, "id": 1, "caption": 1, "created_at": 1, "user_id": 1, "photo_url": 1}, limit=200)
        for reel in liked_reels:
            owner_id=reel.get("user_id")
            if owner_id: owner_ids.add(owner_id)
            like_items.append({"id":"reel:"+reel.get("id"),"type":"like","actor":actor,"target_type":"reel","target_id":reel.get("id"),"target_content":reel.get("caption") or "(reel)","target_created_at":reel.get("created_at"),"target_user_id":owner_id,"target_media_url":reel.get("photo_url")})
        owners=await _safe_user_find({"id":{"$in":list(owner_ids)}},{"_id":0,"id":1,"name":1,"handle":1,"username":1,"avatar_photo":1,"avatar_bg":1,"avatar_letter":1,"is_badge_verified":1},limit=len(owner_ids)) if owner_ids else []
        owner_map={profile.get("id"):public_profile(profile) for profile in owners}
        for item in comments: item["target_author"]=owner_map.get(item.get("target_user_id"))
        comments.sort(key=lambda item:item.get("created_at") or "",reverse=True)
        for item in like_items: item["target_author"]=owner_map.get(item.get("target_user_id"))
        like_items.sort(key=lambda item:item.get("target_created_at") or "",reverse=True)
        return {"actor":actor,"posts":posts,"comments":comments[:50],"likes":like_items[:50]}

    @api.delete("/data/activity-log/{activity_type}/{activity_id}")
    async def delete_activity_log_item(activity_type: str, activity_id: str, u=Depends(current_user)):
        """Permanently delete one of the signed-in user's posts or comments."""
        if activity_type == "like":
            if ":" not in activity_id:
                raise HTTPException(400, "Invalid like activity")
            target_type, target_id = activity_id.split(":", 1)
            if target_type == "post":
                result = await db.posts.update_one({"id": target_id}, {"$pull": {"likes": {"user_id": u["id"]}}})
            elif target_type == "reel":
                result = await db.reels.update_one({"id": target_id}, {"$pull": {"likes": u["id"]}})
            else:
                raise HTTPException(400, "Unsupported like target")
            if not result.modified_count:
                raise HTTPException(404, "Activity not found")
            return {"ok": True, "deleted": "like"}
        if activity_type == "post":
            result = await db.posts.delete_one({"id": activity_id, "user_id": u["id"]})
            if not result.deleted_count:
                raise HTTPException(404, "Activity not found")
            return {"ok": True, "deleted": "post"}
        if activity_type != "comment":
            raise HTTPException(400, "Unsupported activity type")
        post_result = await db.posts.update_one(
            {"comments": {"$elemMatch": {"id": activity_id, "user_id": u["id"]}}},
            {"$pull": {"comments": {"id": activity_id, "user_id": u["id"]}}},
        )
        if post_result.modified_count:
            await db.posts.update_many(
                {"comments": {"$exists": True}},
                [{"$set": {"comment_count": {"$size": {"$ifNull": ["$comments", []]}}}}],
            )
            return {"ok": True, "deleted": "comment"}
        reel_result = await db.reels.update_one(
            {"comments": {"$elemMatch": {"id": activity_id, "user_id": u["id"]}}},
            {"$pull": {"comments": {"id": activity_id, "user_id": u["id"]}}},
        )
        if reel_result.modified_count:
            await db.reels.update_one(
                {"comments": {"$exists": True}},
                [{"$set": {"comment_count": {"$size": {"$ifNull": ["$comments", []]}}}}],
            )
            return {"ok": True, "deleted": "comment"}
        raise HTTPException(404, "Activity not found")
    @api.patch("/profile/online")
    async def update_online_status(body: dict, u=Depends(current_user)):
        is_online = body.get("is_online", True)
        await db.users.update_one(
            {"id": u["id"]},
            {"$set": {"is_online": is_online, "last_seen": now().isoformat()}},
        )
        return {"ok": True}

    # ── Users ─────────────────────────────────────────────────────
    @api.get("/users/me/blocked")
    async def get_blocked_users(u=Depends(current_user)):
        ids = u.get("blocked_users", [])
        if not ids: return []
        users = await _safe_user_find(
            {"id": {"$in": ids}}, {"_id": 0, "password_hash": 0, "otp_hash": 0, "known_devices": 0}, limit=len(ids)
        )
        return [_apply_user_visibility(profile, u) for profile in users]

    @api.get("/users/me/follow-requests")
    async def my_follow_requests(u=Depends(current_user)):
        pending = await db.follow_requests.find(
            {"to_id": u["id"], "status": "pending"}, {"_id": 0}
        ).to_list(500)
        from_ids = [r["from_id"] for r in pending]
        PUBLIC = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
                  "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1, "location": 1, "about": 1}
        users_list = await _safe_user_find({"id": {"$in": from_ids}}, PUBLIC, limit=500) if from_ids else []
        users_map  = {u2["id"]: u2 for u2 in users_list}
        for r in pending:
            r["from_user"] = users_map.get(r["from_id"], {})
        outgoing = await db.follow_requests.find(
            {"from_id": u["id"], "status": "pending"}, {"_id": 0}
        ).to_list(500)
        return {"incoming": pending, "outgoing": outgoing}

    @api.get("/users/me/remove-follower/{follower_id}")
    async def remove_follower_get(follower_id: str, u=Depends(current_user)):
        raise HTTPException(405, "Use POST")

    @api.post("/users/me/remove-follower/{follower_id}")
    async def remove_follower(follower_id: str, u=Depends(current_user)):
        await db.users.update_one({"id": u["id"]}, {"$pull": {"followers": follower_id}})
        await db.users.update_one({"id": follower_id}, {"$pull": {"following": u["id"]}})
        return {"ok": True}

    @api.get("/users")
    async def list_users(
        continent: Optional[str] = None, q: Optional[str] = Query(None, max_length=100),
        skip: int = Query(0, ge=0, le=10000), limit: int = Query(50, ge=1, le=100), u=Depends(current_user),
    ):
        excluded_ids = list(set([u["id"]] + (u.get("following") or [])))
        query: dict = {"id": {"$nin": excluded_ids}, "is_verified": True, "deleted_at": None}
        if continent and continent != "All":
            query["continent"] = continent
        if q:
            query["$or"] = [
                {"name": {"$regex": q, "$options": "i"}},
                {"handle": {"$regex": q, "$options": "i"}},
                {"username": {"$regex": q, "$options": "i"}},
                {"location": {"$regex": q, "$options": "i"}},
            ]
        users = await _safe_user_find(
            query, {"_id": 0, "password_hash": 0, "otp_hash": 0, "known_devices": 0}, skip=skip, limit=limit
        )
        total = await db.users.count_documents(query)
        return {"users": [_apply_user_visibility(profile, u) for profile in users], "total": total, "skip": skip, "limit": limit}

    # ── Search tab: verified people + search history ─────────────────────────
    class SearchHistoryIn(BaseModel):
        kind: str
        q: Optional[str] = None
        target_id: Optional[str] = None
        scope: Optional[str] = None          # which search bar: "people" (Search tab, default), "reels", "chats", "notifications", …

    class SearchHistoryClearIn(BaseModel):
        timeframe: str = "all"
        scope: Optional[str] = None

    _SEARCH_HISTORY_CAP = 200
    _SEARCH_SCOPE_RE = re.compile(r"^[a-z0-9_\-]{1,40}$")

    def _history_scope(raw):
        """Every search bar in the app has its own history ('scope'). The original Search tab = 'people' (also matches old rows without a scope)."""
        sc = (raw or "people").strip().lower()
        if not _SEARCH_SCOPE_RE.match(sc):
            raise HTTPException(400, "Invalid search scope")
        return sc

    def _scope_filter(uid, scope):
        if scope == "people":
            return {"user_id": uid, "$or": [{"scope": "people"}, {"scope": None}]}      # None also matches rows saved before scopes existed
        return {"user_id": uid, "scope": scope}
    _SEARCH_HISTORY_RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "4w": timedelta(weeks=4)}
    _DISCOVER_FIELDS = {
        "_id": 0, "id": 1, "name": 1, "username": 1, "handle": 1,
        "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1, "cover_photo": 1,
        "about": 1, "category": 1, "category_visible": 1, "verified_category": 1,
        "is_badge_verified": 1, "is_private": 1, "blocked_users": 1,
    }

    def _discover_card(p, followers_count=0, following=False, requested=False):
        # bio = "about", profession = "category" (only when the owner has not hidden it)
        cat = p.get("category") if p.get("category_visible", True) is not False else None
        return {
            "id": p.get("id"), "name": p.get("name"), "username": p.get("username"), "handle": p.get("handle"),
            "avatar_bg": p.get("avatar_bg"), "avatar_letter": p.get("avatar_letter"),
            "avatar_photo": p.get("avatar_photo"), "cover_photo": p.get("cover_photo"),
            "about": (p.get("about") or "").strip()[:200],
            "category": (cat or "").strip() or None,
            "verified_category": p.get("verified_category"),
            "is_badge_verified": bool(p.get("is_badge_verified")),
            "is_private": bool(p.get("is_private")),
            "followers_count": int(followers_count or 0),
            "following": bool(following), "requested": bool(requested),
        }

    @api.get("/discover/people")
    async def discover_people(
        skip: int = Query(0, ge=0, le=5000), limit: int = Query(20, ge=1, le=50), u=Depends(current_user),
    ):
        """People you may know (Search tab), ranked: mutual connections, people who follow you, same profession,
        popularity (followers) and verified badge. Only accounts the viewer does not follow yet."""
        import math as _math
        blocked = list(set(u.get("blocked_users") or []))
        my_following = list(set(u.get("following") or []))
        excluded = list(set([u["id"]] + my_following + blocked))
        match = {"is_verified": True, "deleted_at": None, "id": {"$nin": excluded}}
        _fol = {"$cond": [{"$isArray": "$followers"}, "$followers", []]}
        _fng = {"$cond": [{"$isArray": "$following"}, "$following", []]}
        pool = await db.users.aggregate([
            {"$match": match},
            {"$project": {"_id": 0, "id": 1, "cat": "$category",
                          "vb": {"$cond": [{"$eq": ["$is_badge_verified", True]}, 1, 0]},
                          "fc": {"$size": _fol},
                          "mutual": {"$size": {"$setIntersection": [_fol, my_following]}},
                          "follows_me": {"$in": [u["id"], _fng]}}},
            {"$sort": {"vb": -1, "fc": -1, "id": 1}},
            {"$limit": 300},
        ]).to_list(300)
        my_cat = str(u.get("category") or "").strip().lower()

        def _pymk(row):
            same_cat = bool(my_cat) and str(row.get("cat") or "").strip().lower() == my_cat
            return (0.35 * min(1.0, int(row.get("mutual") or 0) / 5.0)
                    + 0.25 * (1.0 if row.get("follows_me") else 0.0)
                    + 0.20 * min(1.0, _math.log1p(int(row.get("fc") or 0)) / _math.log1p(10000))
                    + 0.12 * (1.0 if row.get("vb") else 0.0)
                    + 0.08 * (1.0 if same_cat else 0.0))
        ranked_pool = sorted(pool, key=_pymk, reverse=True)
        rows = ranked_pool[skip: skip + limit]
        total = await db.users.count_documents(match)
        ids = [r["id"] for r in rows]
        if not ids:
            return {"users": [], "total": total, "skip": skip, "limit": limit}
        profiles = {p["id"]: p for p in await _safe_user_find({"id": {"$in": ids}}, _DISCOVER_FIELDS, limit=len(ids) + 1)}
        reqs = await db.follow_requests.find(
            {"from_id": u["id"], "to_id": {"$in": ids}, "status": "pending"}, {"_id": 0, "to_id": 1}
        ).to_list(length=len(ids) + 1)
        pending = {r["to_id"] for r in reqs}
        out = []
        for r in rows:
            p = profiles.get(r["id"])
            if not p or u["id"] in (p.get("blocked_users") or []):
                continue
            out.append(_discover_card(p, r.get("fc"), False, r["id"] in pending))
        return {"users": out, "total": total, "skip": skip, "limit": limit}

    @api.get("/search-history")
    async def search_history_list(scope: Optional[str] = Query(None), u=Depends(current_user)):
        scope = _history_scope(scope)
        rows = await db.search_history.find(_scope_filter(u["id"], scope), {"_id": 0}).sort("created_at", -1).to_list(_SEARCH_HISTORY_CAP)
        target_ids = list({r["target_id"] for r in rows if r.get("kind") == "visit" and r.get("target_id")})
        profiles = {}
        if target_ids:
            plist = await _safe_user_find(
                {"id": {"$in": target_ids}, "deleted_at": None}, _DISCOVER_FIELDS, limit=len(target_ids) + 1
            )
            profiles = {p["id"]: p for p in plist}
        items, stale = [], []
        for r in rows:
            if r.get("kind") == "search":
                items.append({"id": r["id"], "kind": "search", "q": r.get("q") or "", "created_at": r.get("created_at")})
                continue
            p = profiles.get(r.get("target_id"))
            if not p or u["id"] in (p.get("blocked_users") or []):
                stale.append(r["id"])      # account deleted / blocked you -> drop it quietly
                continue
            card = _discover_card(p)
            card.pop("cover_photo", None)
            items.append({"id": r["id"], "kind": "visit", "created_at": r.get("created_at"), "user": card})
        if stale:
            await db.search_history.delete_many({"user_id": u["id"], "id": {"$in": stale}})
        return {"items": items, "scope": scope}

    @api.post("/search-history")
    async def search_history_add(p: SearchHistoryIn, u=Depends(current_user)):
        kind = (p.kind or "").strip().lower()
        scope = _history_scope(p.scope)
        ts = now().isoformat()
        if kind == "search":
            q = " ".join((p.q or "").split())[:100]
            if not q:
                raise HTTPException(400, "Empty search")
            key = {"user_id": u["id"], "kind": "search", "q_key": q.lower()}
            fields = {"q": q, "created_at": ts}
        elif kind == "visit":
            if scope != "people":
                raise HTTPException(400, "Visits are only kept for the Search tab")
            tid = (p.target_id or "").strip()
            if not tid or tid == u["id"]:
                return {"ok": True}
            if not await db.users.find_one({"id": tid, "deleted_at": None}, {"_id": 0, "id": 1}):
                raise HTTPException(404, "User not found")
            key = {"user_id": u["id"], "kind": "visit", "target_id": tid}
            fields = {"created_at": ts}
        else:
            raise HTTPException(400, "Invalid history type")
        if scope == "people":
            key["$or"] = [{"scope": "people"}, {"scope": None}]
            fields["scope"] = "people"
        else:
            key["scope"] = scope
        await db.search_history.update_one(key, {"$set": fields, "$setOnInsert": {"id": str(uuid.uuid4())}}, upsert=True)
        total = await db.search_history.count_documents(_scope_filter(u["id"], scope))
        if total > _SEARCH_HISTORY_CAP:
            extra = await db.search_history.find(_scope_filter(u["id"], scope), {"_id": 0, "id": 1}).sort("created_at", 1).to_list(total - _SEARCH_HISTORY_CAP)
            await db.search_history.delete_many({"user_id": u["id"], "id": {"$in": [x["id"] for x in extra]}})
        return {"ok": True}

    @api.delete("/search-history/{item_id}")
    async def search_history_delete_one(item_id: str, u=Depends(current_user)):
        await db.search_history.delete_one({"user_id": u["id"], "id": item_id})
        return {"ok": True}

    @api.post("/search-history/clear")
    async def search_history_clear(p: SearchHistoryClearIn, u=Depends(current_user)):
        tf = (p.timeframe or "all").strip().lower()
        flt = _scope_filter(u["id"], _history_scope(p.scope))
        if tf == "all":
            res = await db.search_history.delete_many(flt)
        elif tf in _SEARCH_HISTORY_RANGES:
            cutoff = (now() - _SEARCH_HISTORY_RANGES[tf]).isoformat()
            res = await db.search_history.delete_many({**flt, "created_at": {"$gte": cutoff}})
        else:
            raise HTTPException(400, "Invalid time frame")
        return {"ok": True, "deleted": res.deleted_count}

    @app.on_event("startup")
    async def setup_search_history_index():
        try:
            await db.search_history.create_index([("user_id", 1), ("created_at", -1)])
            await db.search_history.create_index([("user_id", 1), ("kind", 1), ("q_key", 1)])
            await db.search_history.create_index([("user_id", 1), ("kind", 1), ("target_id", 1)])
            await db.search_history.create_index([("user_id", 1), ("scope", 1), ("created_at", -1)])
        except Exception:
            logging.exception("search history index setup failed")

    @api.get("/users/{user_id}")
    async def get_user(user_id: str, u=Depends(current_user)):
        user = await _safe_user_find_one({"id": user_id})
        if not user: raise HTTPException(404, "User not found")
        is_self      = user_id == u["id"]
        is_follower  = u["id"] in user.get("followers", [])
        is_private   = user.get("is_private", False)
        is_private_locked = is_private and not is_follower and not is_self
        pending_req  = None
        posts_count_task = db.posts.count_documents({"user_id": user_id})
        reels_count_task = db.reels.count_documents({"user_id": user_id})
        follow_req_task  = (
            db.follow_requests.find_one({"from_id": u["id"], "to_id": user_id, "status": "pending"})
            if is_private_locked else None
        )
        if follow_req_task is not None:
            posts_count, reels_count, pending_req = await asyncio.gather(
                posts_count_task, reels_count_task, follow_req_task
            )
        else:
            posts_count, reels_count = await asyncio.gather(
                posts_count_task, reels_count_task
            )
        posts_count += reels_count
        is_mutual        = user_id in u.get("following", []) and u["id"] in (user.get("following") or [])
        is_following_you = u["id"] in user.get("following", [])
        followers_count  = len(user.get("followers", []))
        following_count  = len(user.get("following", []))
        base = {
            "id": user["id"], "name": user.get("name"), "handle": user.get("handle"),
            "username": user.get("username"), "avatar_bg": user.get("avatar_bg"),
            "avatar_letter": user.get("avatar_letter"), "avatar_photo": user.get("avatar_photo"),
            "is_private": is_private, "account_type": user.get("account_type"),
            "is_badge_verified": user.get("is_badge_verified"), "category": user.get("category"),
            "category_visible": user.get("category_visible", True),
            "is_official": bool(OFFICIAL_ACCOUNT_ID and user_id == OFFICIAL_ACCOUNT_ID),
            "is_mutual": is_mutual, "is_following_you": is_following_you,
            "is_private_locked": is_private_locked, "has_pending_request": bool(pending_req),
            "stats": {"posts": posts_count, "followers": followers_count, "following": following_count},
        }
        if is_private_locked:
            return base
        safe_user = _apply_user_visibility(user, u)
        return {
            **safe_user, "is_official": bool(OFFICIAL_ACCOUNT_ID and user_id == OFFICIAL_ACCOUNT_ID),
            "is_mutual": is_mutual, "is_following_you": is_following_you,
            "is_private_locked": False, "has_pending_request": False,
            "stats": {"posts": posts_count, "followers": followers_count, "following": following_count},
        }

    # ── Follow / Unfollow ─────────────────────────────────────────
    # ── Central notification pipeline ─────────────────────────────
    # Every notification in the app goes through _notify():
    #   1) saved in db.notifications (de-duplicated where it makes sense)
    #   2) pushed LIVE to the user's open app over /ws-live (no waiting for the 15s poll)
    #   3) sent as web-push to all the user's devices
    #   The six Settings toggles (see _NOTIFY_PUSH_PREF) gate ALL three steps: toggle OFF = nothing is created for that type.
    _notify_tasks: set = set()
    _NOTIFY_PUSH_PREF = {
        "like": "likes", "repost": "likes", "reel_repost": "likes",
        "comment": "comments", "reply": "comments",
        "follow": "friend_requests", "follow_request": "friend_requests", "follow_accept": "friend_requests",
        "friend_request": "friend_requests", "friend_accept": "friend_requests", "contact_joined": "friend_requests",
        "group_add": "friend_requests", "message": "messages", "group_message": "messages",
        "mention": "mentions", "reel_mention": "mentions", "tag": "tags",
        "world_like": "likes", "world_comment": "comments",
    }
    _NOTIFY_KEEP_ONE = {"like", "follow", "follow_request", "friend_request", "repost", "reel_repost", "reel_mention",
                        "tag", "mention", "follow_accept", "friend_accept", "contact_joined", "group_add"}
    _NOTIFY_RESURFACE = {"message", "group_message"}          # one row per sender, refreshed by each new message
    _NOTIFY_SELF_OK = {"system", "verification_approved", "verification_rejected", "verification_revoked"}
    _NOTIFY_PUSH_TYPE = {"message": "message", "group_message": "message", "contact_joined": "contact_joined", "system": "security"}

    def _bg(coro):
        task = asyncio.create_task(coro)
        _notify_tasks.add(task)
        task.add_done_callback(_notify_tasks.discard)
        return task

    async def _live_send(key, text):
        client = _live_clients.get(key)
        if not client: return
        try:
            await asyncio.wait_for(client["ws"].send_text(text), timeout=3)
        except Exception:
            _live_drop(key)

    def _live_push_user(user_id, payload):
        """Instant delivery to every open app/tab of this user."""
        try:
            text = _json.dumps(payload)
            for key, client in list(_live_clients.items()):
                if client.get("uid") == user_id:
                    _bg(_live_send(key, text))
        except Exception:
            logging.exception("live notification push failed")

    async def _notify(recipient_id, actor, ntype, *, push=None, **extra):
        try:
            if not recipient_id: return None
            actor = actor or {}
            actor_id = actor.get("id")
            if actor_id and actor_id == recipient_id and ntype not in _NOTIFY_SELF_OK: return None
            rec = await db.users.find_one({"id": recipient_id}, {"_id": 0, "notifications_prefs": 1, "blocked_users": 1, "deleted_at": 1, "notif_muted_types": 1, "notif_muted_posts": 1})
            if not rec or rec.get("deleted_at"): return None
            if actor_id and actor_id in (rec.get("blocked_users") or []): return None
            extra = dict(extra)
            if extra.get("reel_id"):                      # reel notifications open through the same post_id path
                extra["is_reel"] = True
                extra.setdefault("post_id", extra["reel_id"])
            ts = now().isoformat()
            # "Turn off … notifications" from the notification menu: nothing is saved / pushed for a muted type or post
            if ntype not in _NOTIFY_SELF_OK:
                if ntype in (rec.get("notif_muted_types") or []): return None
                _mp = extra.get("post_id") or extra.get("reel_id")
                if _mp and str(_mp) in (rec.get("notif_muted_posts") or []): return None
            # Settings > Notifications toggles (likes / comments / follow requests / messages / mentions / tags):
            # when the recipient switched a toggle OFF, that kind of notification is not saved, not shown live and not pushed.
            _pref_key = _NOTIFY_PUSH_PREF.get(ntype)
            if _pref_key and ntype not in _NOTIFY_SELF_OK and (rec.get("notifications_prefs") or {}).get(_pref_key, True) is False:
                return None
            doc = {"id": str(uuid.uuid4()), "user_id": recipient_id, "type": ntype, "created_at": ts, "read": False}
            if actor_id:
                doc.update({
                    "from_user_id": actor_id, "from_user_name": actor.get("name", ""),
                    "from_user_avatar": actor.get("avatar_photo"), "from_user_bg": actor.get("avatar_bg"),
                    "from_user_letter": actor.get("avatar_letter"),
                    "from_user_is_verified": bool(actor.get("is_badge_verified")),
                })
            doc.update(extra)
            if ntype in _NOTIFY_KEEP_ONE or ntype in _NOTIFY_RESURFACE:
                flt = {"user_id": recipient_id, "type": ntype}
                if actor_id: flt["from_user_id"] = actor_id
                for k in ("post_id", "reel_id", "comment_id", "reply_id", "group_id"):
                    flt[k] = extra.get(k)
                if ntype in _NOTIFY_RESURFACE: flt["read"] = False
                existing = await db.notifications.find_one(flt, {"_id": 0})
                if existing:
                    if ntype not in _NOTIFY_RESURFACE: return None      # already told them (like→unlike→like must not spam)
                    upd = {k: v for k, v in doc.items() if k not in ("id", "user_id")}
                    await db.notifications.update_one({"id": existing["id"]}, {"$set": upd})
                    doc = {**existing, **upd}
                else:
                    await db.notifications.insert_one(doc.copy())
            else:
                await db.notifications.insert_one(doc.copy())
            _live_push_user(recipient_id, {"type": "notification", "notification": doc})
            if push:
                pref_key = _NOTIFY_PUSH_PREF.get(ntype)
                prefs = rec.get("notifications_prefs") or {}
                chat_open = ntype == "message" and recipient_id in _ws_connections
                if (pref_key is None or prefs.get(pref_key, True) is not False) and not chat_open:
                    _bg(send_push(recipient_id, push[0], push[1], _NOTIFY_PUSH_TYPE.get(ntype)))
            return doc
        except Exception:
            logging.exception("notify failed (%s)", ntype)
            return None

    def _default_push(ntype, actor, extra):
        n = (actor or {}).get("name") or "Someone"
        what = "comment" if extra.get("comment_id") else ("reel" if extra.get("reel_id") else "post")
        if ntype == "like": return ("New like ♥️", f"{n} liked your {what}")
        if ntype == "comment": return ("New comment 💬", f"{n} commented on your {what}")
        if ntype == "reply": return ("New reply 💬", f"{n} replied to your comment")
        if ntype == "message": return (n, extra.get("message") or "Sent you a message")
        if ntype == "group_message": return (extra.get("group_name") or "Group", f"{n}: {extra.get('message') or 'New message'}")
        return None

    async def _purge_notifs(flt):
        try:
            await db.notifications.delete_many(flt)
        except Exception:
            logging.exception("notification cleanup failed")

    async def _unnotify(recipient_id, actor_id, ntype, **match):
        """Undo a notification when the action is undone (un-like): it disappears from the recipient's list, like Instagram.
        A comment-level match (comment_id) never touches the post-level notification and vice-versa."""
        try:
            if not recipient_id or not actor_id: return
            flt = {"user_id": recipient_id, "from_user_id": actor_id, "type": ntype}
            for k in ("post_id", "reel_id", "comment_id"):
                if match.get(k): flt[k] = match[k]
            if not match.get("comment_id"): flt["comment_id"] = None     # None also matches "field missing"
            await db.notifications.delete_many(flt)
        except Exception:
            logging.exception("unnotify failed (%s)", ntype)

    async def _persist_user_activity_notification(recipient_id, actor, notification_type, **extra):
        # kept under the old name: every existing call site (reels, DMs, groups…) now gets live + push delivery
        _bg(_notify(recipient_id, actor, notification_type, push=_default_push(notification_type, actor, extra), **extra))

    _MENTION_RE = re.compile(r"(?<![\w@])@([A-Za-z0-9_]{3,20})")

    async def _notify_mentions(actor, text, *, exclude=(), where="post", **extra):
        """@username inside a caption / comment / reply → 'mention' notification."""
        try:
            names = list(dict.fromkeys(m.lower() for m in _MENTION_RE.findall(text or "")))[:10]
            if not names: return
            users = await db.users.find({"username": {"$in": names}}, {"_id": 0, "id": 1}).to_list(10)
            for tu in users:
                if tu["id"] in exclude or tu["id"] == actor.get("id"): continue
                await _notify(tu["id"], actor, "mention", push=("Mention 📢", f"{actor.get('name', 'Someone')} mentioned you in a {where}"), **extra)
        except Exception:
            logging.exception("mention notify failed")

    async def _notify_tags(actor, handles, **extra):
        """Tagged @handles → 'tag' notification. (Handles are stored as '@username'; the old lookup never matched.)"""
        ids = set()
        try:
            names = list(dict.fromkeys(str(h).strip().lstrip("@").lower() for h in (handles or []) if str(h).strip()))[:20]
            if not names: return ids
            users = await db.users.find(
                {"$or": [{"username": {"$in": names}}, {"handle": {"$in": names + ["@" + n for n in names]}}]},
                {"_id": 0, "id": 1}).to_list(40)
            kind = "reel" if extra.get("reel_id") else "post"
            for tu in users:
                if tu["id"] == actor.get("id"): continue
                ids.add(tu["id"])
                await _notify(tu["id"], actor, "tag", push=("Tag 🏷️", f"{actor.get('name', 'Someone')} tagged you in a {kind}"), **extra)
        except Exception:
            logging.exception("tag notify failed")
        return ids

    async def _notify_followers(actor, ntype, *, audience="public", push=None, **extra):
        """New post / reel → every follower gets a notification (capped; runs in the background)."""
        try:
            if audience in ("only_me", "only_show"): return
            followers = [f for f in dict.fromkeys(actor.get("followers") or []) if f != actor.get("id")][:500]
            for i in range(0, len(followers), 20):
                await asyncio.gather(*[_notify(fid, actor, ntype, push=push, **extra) for fid in followers[i:i + 20]], return_exceptions=True)
        except Exception:
            logging.exception("follower fan-out failed")

    @api.post("/users/{user_id}/follow")
    async def follow_user(user_id: str, u=Depends(current_user)):
        if user_id == u["id"]: raise HTTPException(400, "Can't follow yourself")
        target = await _safe_user_find_one({"id": user_id})
        if not target: raise HTTPException(404, "User not found")
        if u["id"] in target.get("blocked_users", []) or user_id in u.get("blocked_users", []): raise HTTPException(403, "Action not allowed")
        if target.get("is_private"):
            existing = await db.follow_requests.find_one({"from_id": u["id"], "to_id": user_id})
            if existing: return {"ok": True, "pending": True}
            await db.follow_requests.insert_one({"id": str(uuid.uuid4()), "from_id": u["id"], "to_id": user_id, "status": "pending", "created_at": now().isoformat()})
            _bg(_notify(user_id, u, "follow_request", push=("New follow request", u["name"] + " wants to follow you")))
            return {"ok": True, "pending": True}
        await asyncio.gather(db.users.update_one({"id": user_id}, {"$addToSet": {"followers": u["id"]}}), db.users.update_one({"id": u["id"]}, {"$addToSet": {"following": user_id}}))
        _bg(_notify(user_id, u, "follow", push=("New follower", u["name"] + " started following you")))
        return {"ok": True, "pending": False}

    @api.post("/users/{user_id}/unfollow")
    async def unfollow_user(user_id: str, u=Depends(current_user)):
        await asyncio.gather(db.users.update_one({"id": user_id}, {"$pull": {"followers": u["id"]}}), db.users.update_one({"id": u["id"]}, {"$pull": {"following": user_id}}), db.follow_requests.delete_many({"from_id": u["id"], "to_id": user_id}),
                             db.notifications.delete_many({"user_id": user_id, "from_user_id": u["id"], "type": {"$in": ["follow", "follow_request"]}}))
        return {"ok": True, "following": False, "pending": False}

    @api.get("/users/{user_id}/followers")
    async def get_followers(user_id: str, u=Depends(current_user)):
        user = await db.users.find_one({"id": user_id}, {"_id": 0, "followers": 1, "following": 1})
        if not user: raise HTTPException(404, "User not found")
        profiles = await _safe_user_find(
            {"id": {"$in": user.get("followers", [])}},
            {"_id": 0, "password_hash": 0, "otp_hash": 0, "known_devices": 0}, limit=500,
        )
        return [_apply_user_visibility(profile, u) for profile in profiles]

    @api.get("/users/{user_id}/following")
    async def get_following(user_id: str, u=Depends(current_user)):
        user = await db.users.find_one({"id": user_id}, {"_id": 0, "followers": 1, "following": 1})
        if not user: raise HTTPException(404, "User not found")
        profiles = await _safe_user_find(
            {"id": {"$in": user.get("following", [])}},
            {"_id": 0, "password_hash": 0, "otp_hash": 0, "known_devices": 0}, limit=500,
        )
        return [_apply_user_visibility(profile, u) for profile in profiles]

    # ── Follow Requests (private accounts) ───────────────────────
    @api.post("/users/{user_id}/follow-request/cancel")
    async def cancel_follow_request(user_id: str, u=Depends(current_user)):
        await db.follow_requests.delete_one({"from_id": u["id"], "to_id": user_id})
        await db.notifications.delete_many({"user_id": user_id, "from_user_id": u["id"], "type": "follow_request"})
        return {"ok": True}

    @api.post("/users/{user_id}/follow-request/accept")
    async def accept_follow_request(user_id: str, u=Depends(current_user)):
        req = await db.follow_requests.find_one({"from_id": user_id, "to_id": u["id"], "status": "pending"})
        if not req: raise HTTPException(404, "Follow request not found")
        await db.users.update_one({"id": u["id"]}, {"$addToSet": {"followers": user_id}})
        await db.users.update_one({"id": user_id}, {"$addToSet": {"following": u["id"]}})
        await db.follow_requests.delete_one({"from_id": user_id, "to_id": u["id"]})
        # Delete the follow_request notification so it never reappears
        await db.notifications.delete_one(
            {"user_id": u["id"], "from_user_id": user_id, "type": "follow_request"}
        )
        _bg(_notify(user_id, u, "follow_accept", push=("Follow accepted", u["name"] + " accepted your follow request")))
        return {"ok": True}

    @api.post("/users/{user_id}/follow-request/decline")
    async def decline_follow_request(user_id: str, u=Depends(current_user)):
        await db.follow_requests.delete_one({"from_id": user_id, "to_id": u["id"]})
        # Delete the follow_request notification so it never reappears
        await db.notifications.delete_one(
            {"user_id": u["id"], "from_user_id": user_id, "type": "follow_request"}
        )
        return {"ok": True}

    # ── Block / Unblock ───────────────────────────────────────────
    @api.post("/users/{user_id}/block")
    async def block_user(user_id: str, u=Depends(current_user)):
        if user_id == u["id"]: raise HTTPException(400, "Can't block yourself")
        await db.users.update_one({"id": u["id"]}, {"$addToSet": {"blocked_users": user_id}})
        return {"ok": True}

    @api.post("/users/{user_id}/unblock")
    async def unblock_user(user_id: str, u=Depends(current_user)):
        await db.users.update_one({"id": u["id"]}, {"$pull": {"blocked_users": user_id}})
        return {"ok": True}

    @api.post("/users/{user_id}/mute")
    async def mute_user(user_id: str, u=Depends(current_user)):
        if user_id == u["id"]: raise HTTPException(400, "Can't mute yourself")
        await db.users.update_one({"id": u["id"]}, {"$addToSet": {"muted_users": user_id}})
        return {"ok": True}

    @api.post("/users/{user_id}/unmute")
    async def unmute_user(user_id: str, u=Depends(current_user)):
        await db.users.update_one({"id": u["id"]}, {"$pull": {"muted_users": user_id}})
        return {"ok": True}

    @api.post("/posts/{pid}/not-interested")
    async def not_interested(pid: str, u=Depends(current_user)):
        await db.users.update_one({"id": u["id"]}, {"$addToSet": {"not_interested": pid}})
        return {"ok": True}


    # ── Posts ─────────────────────────────────────────────────────
    MAX_POST_VIDEO_SECONDS = 30
    MAX_UPLOAD_VIDEO_BYTES = 100 * 1024 * 1024  # 100MB raw file, uploaded straight to Cloudinary (no base64 inflation)

    def _measure_upload_size(file: UploadFile) -> int:
        """Measure and rewind the spooled upload without copying it into RAM."""
        stream = file.file
        stream.seek(0, _os.SEEK_END)
        size = stream.tell()
        stream.seek(0)
        return size

    async def _get_upload_size(file: UploadFile) -> int:
        # File seek/tell is blocking for disk-backed uploads; keep it off the event loop.
        return await asyncio.to_thread(_measure_upload_size, file)

    CLOUDINARY_UPLOAD_CHUNK_BYTES = 5 * 1024 * 1024
    _cloudinary_upload_semaphore = asyncio.Semaphore(1)

    async def _upload_large_to_cloudinary(file, **options):
        """Upload video/audio in bounded chunks and limit concurrent transfers."""
        async with _cloudinary_upload_semaphore:
            return await asyncio.to_thread(
                cloudinary.uploader.upload_large,
                file,
                chunk_size=CLOUDINARY_UPLOAD_CHUNK_BYTES,
                **options,
            )

    async def _cloudinaryize_inline_image(value, folder: str, public_id: str, overwrite: bool = False):
        """Replace a small legacy image data URI with a hosted URL before persistence."""
        if value is None or value == "":
            return value
        if not isinstance(value, str):
            raise HTTPException(400, "Invalid image value")
        value = value.strip()
        if not value.lower().startswith("data:"):
            return value
        metadata, separator, encoded = value.partition(",")
        if not separator or not metadata.lower().startswith("data:image/") or ";base64" not in metadata.lower() or not encoded:
            raise HTTPException(400, "Invalid image data. Please choose the image again.")
        max_encoded_chars = 4 * ((10 * 1024 * 1024 + 2) // 3)
        if len(encoded) > max_encoded_chars:
            raise HTTPException(413, "Image is too large. Max 10MB.")
        if not ((CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) or CLOUDINARY_URL):
            raise HTTPException(500, "Image hosting is not configured on the server")
        try:
            async with _cloudinary_upload_semaphore:
                result = await asyncio.to_thread(
                    cloudinary.uploader.upload, value, resource_type="image",
                    folder=folder, public_id=public_id, overwrite=overwrite,
                )
        except Exception:
            logging.exception("Cloudinary inline image upload failed")
            raise HTTPException(502, "Image upload failed. Please try again.")
        photo_url = result.get("secure_url") or result.get("url")
        if not photo_url:
            raise HTTPException(502, "Image upload did not return a URL")
        return photo_url

    def _reject_inline_data_uri(value, field_name: str):
        if isinstance(value, str) and value.lstrip().lower().startswith("data:"):
            raise HTTPException(400, f"{field_name} must be uploaded before saving; inline media is not stored.")

    def _clean_chat_file(file_url, file_name, file_size, file_type):
        """Validate/normalise a chat file attachment. Returns a dict of file_* fields."""
        if not file_url:
            return {"file_url": None, "file_name": None, "file_size": None, "file_type": None}
        _reject_inline_data_uri(file_url, "file_url")
        file_url = str(file_url).strip()
        if not (file_url.startswith("https://") or file_url.startswith("http://")):
            raise HTTPException(400, "Invalid file URL - please upload the file again")
        if len(file_url) > 2000:
            raise HTTPException(400, "Invalid file URL")
        name = _os.path.basename(str(file_name or "file").replace("\\", "/")).strip()[:120] or "file"
        try:
            size = max(0, int(file_size or 0))
        except (TypeError, ValueError):
            size = 0
        return {"file_url": file_url, "file_name": name, "file_size": size, "file_type": (str(file_type or "")[:100] or None)}

    def _validate_post_media(p: PostIn):
        for field_name, value in (("photo_url", p.photo_url), ("gif_url", p.gif_url),
                                  ("music_artwork", p.music_artwork), ("music_preview_url", p.music_preview_url)):
            _reject_inline_data_uri(value, field_name)
        for value in p.photo_urls or []:
            _reject_inline_data_uri(value, "photo_urls")
        for sticker in p.sticker_overlays or []:
            if isinstance(sticker, dict):
                _reject_inline_data_uri(sticker.get("url"), "sticker URL")

    def _validate_post_video(video_url: Optional[str], video_duration: Optional[float]):
        """Raises HTTPException if the given video URL is missing/invalid or too long.

        Videos are now hosted on Cloudinary (real files, streamed with HTTP range
        support) instead of being embedded as base64 data URIs — that's what used
        to make playback stall/buffer since a data URI can't be streamed or seeked.
        """
        if not video_url:
            return
        if not (video_url.startswith("https://") or video_url.startswith("http://")):
            raise HTTPException(400, "Invalid video URL — please upload the video again")
        if video_duration is not None and video_duration > MAX_POST_VIDEO_SECONDS + 0.5:
            raise HTTPException(400, f"Videos must be {MAX_POST_VIDEO_SECONDS} seconds or less")

    @api.post("/upload/photo")
    async def upload_photo(file: UploadFile = File(...), u=Depends(current_user)):
        """Upload any image to Cloudinary and return its URL."""
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) and not CLOUDINARY_URL:
            raise HTTPException(500, "Image hosting is not configured on the server")
        if not file.content_type or not file.content_type.startswith("image/"):
            raise HTTPException(400, "Please upload a valid image file")
        upload_size = await _get_upload_size(file)
        if upload_size > 10 * 1024 * 1024:
            raise HTTPException(400, "Image is too large. Max 10MB.")
        try:
            async with _cloudinary_upload_semaphore:
                result = await asyncio.to_thread(
                    cloudinary.uploader.upload,
                    file.file,
                    resource_type="image",
                    folder="post-app/photos",
                    public_id=f"{u['id']}_{uuid.uuid4().hex}",
                    overwrite=False,
                )
        except Exception:
            logging.exception("Cloudinary photo upload failed")
            raise HTTPException(502, "Image upload failed. Please try again.")
        return {"url": result.get("secure_url")}

    @api.post("/upload/audio")
    async def upload_audio(file: UploadFile = File(...), u=Depends(current_user)):
        """Upload a voice/audio recording to Cloudinary and return its URL."""
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) and not CLOUDINARY_URL:
            raise HTTPException(500, "Audio hosting is not configured on the server")
        ct = (file.content_type or "").split(";")[0].strip()
        if ct and not ct.startswith("audio/") and ct not in ("application/octet-stream",):
            raise HTTPException(400, "Please upload a valid audio file")
        upload_size = await _get_upload_size(file)
        if upload_size > 25 * 1024 * 1024:
            raise HTTPException(400, "Audio is too large. Max 25MB.")
        try:
            result = await _upload_large_to_cloudinary(
                file.file,
                resource_type="video",   # Cloudinary uses "video" resource_type for audio files
                folder="post-app/audio",
                public_id=f"{u['id']}_{uuid.uuid4().hex}",
                overwrite=False,
            )
        except Exception:
            logging.exception("Cloudinary audio upload failed")
            raise HTTPException(502, "Audio upload failed. Please try again.")
        return {"url": result.get("secure_url"), "duration": int(result.get("duration") or 0)}

    MAX_CHAT_FILE_BYTES = 25 * 1024 * 1024  # 25MB per shared file
    _BLOCKED_CHAT_FILE_EXTS = {
        ".exe", ".bat", ".cmd", ".com", ".scr", ".msi", ".dll", ".apk", ".jar", ".vbs",
        ".js", ".jse", ".wsf", ".ps1", ".sh", ".app", ".dmg", ".pif", ".lnk", ".html", ".htm", ".svg",
    }

    @api.post("/upload/file")
    async def upload_chat_file(file: UploadFile = File(...), u=Depends(current_user)):
        """Upload a document/file (pdf, doc, zip, ...) to Cloudinary for sharing in chats."""
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) and not CLOUDINARY_URL:
            raise HTTPException(500, "File hosting is not configured on the server")
        raw_name = _os.path.basename((file.filename or "file").replace("\\", "/")).strip() or "file"
        name = raw_name[:120]
        ext = _os.path.splitext(name)[1].lower()
        if ext in _BLOCKED_CHAT_FILE_EXTS:
            raise HTTPException(400, "This file type is not allowed")
        upload_size = await _get_upload_size(file)
        if upload_size <= 0:
            raise HTTPException(400, "File is empty")
        if upload_size > MAX_CHAT_FILE_BYTES:
            raise HTTPException(400, "File is too large. Max 25MB.")
        stem, ext2 = _os.path.splitext(name)
        safe_stem = re.sub(r"[^A-Za-z0-9_-]+", "_", stem).strip("_")[:80] or "file"
        safe_ext = re.sub(r"[^A-Za-z0-9.]", "", ext2.lower())[:10]
        safe_name = safe_stem + safe_ext  # keeps the real extension even for non-latin names
        try:
            result = await _upload_large_to_cloudinary(
                file.file,
                resource_type="raw",      # raw = any non-image/video file, keeps original bytes
                folder="post-app/files",
                public_id=f"{u['id']}_{uuid.uuid4().hex}_{safe_name}",  # extension stays in the URL
                overwrite=False,
            )
        except Exception:
            logging.exception("Cloudinary file upload failed")
            raise HTTPException(502, "File upload failed. Please try again.")
        url = result.get("secure_url") or result.get("url")
        if not url:
            raise HTTPException(502, "File upload did not return a URL")
        return {"url": url, "name": name, "size": upload_size, "type": (file.content_type or "application/octet-stream")[:100]}

    @api.post("/upload/video")
    async def upload_video(
        file: UploadFile = File(...),
        start_offset: Optional[float] = Form(None),
        end_offset: Optional[float] = Form(None),
        u=Depends(current_user),
    ):
        """Uploads a raw video file to Cloudinary and returns its streamable URL.

        Cloudinary serves videos over HTTP with byte-range support, so playback
        can start immediately and seek/buffer smoothly — unlike a base64 data URI,
        which forces the browser to download the entire clip up front before it
        can play anything. The original file is uploaded as-is, so quality is
        unchanged (no re-encoding/transcoding) unless a trim window is given.

        If start_offset/end_offset are given (seconds), the clip is cut down to
        that window during upload — this lets users pick up to a 1-minute video
        and trim it to the 30s max before it's ever stored, keeping the same
        resolution/bitrate (only the length changes).
        """
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) and not CLOUDINARY_URL:
            raise HTTPException(500, "Video hosting is not configured on the server")
        if not file.content_type or not file.content_type.startswith("video/"):
            raise HTTPException(400, "Please upload a valid video file")

        upload_size = await _get_upload_size(file)
        if upload_size > MAX_UPLOAD_VIDEO_BYTES:
            raise HTTPException(400, "Video is too large. Please choose a smaller clip.")

        upload_kwargs = dict(
            resource_type="video",
            folder="post-app/videos",
            public_id=f"{u['id']}_{uuid.uuid4().hex}",
            overwrite=False,
        )
        if start_offset is not None and end_offset is not None:
            if end_offset <= start_offset:
                raise HTTPException(400, "Invalid trim range")
            if end_offset - start_offset > MAX_POST_VIDEO_SECONDS + 0.5:
                raise HTTPException(400, f"Trimmed clip must be {MAX_POST_VIDEO_SECONDS} seconds or less")
            upload_kwargs["transformation"] = [{
                "start_offset": round(start_offset, 2),
                "end_offset": round(end_offset, 2),
            }]

        try:
            result = await _upload_large_to_cloudinary(file.file, **upload_kwargs)
        except Exception as e:
            # Log the full Cloudinary error server-side only — it can include
            # internal signing details ("String to sign - ...") that must never
            # be shown to end users.
            logging.exception("Cloudinary video upload failed")
            msg = str(e)
            if "Invalid Signature" in msg or "String to sign" in msg:
                raise HTTPException(500, "Video hosting is misconfigured on the server (invalid Cloudinary credentials). Please contact the app admin.")
            raise HTTPException(502, "Video upload failed. Please try again.")

        return {
            "url": result.get("secure_url"),
            "duration": result.get("duration"),
            "bytes": result.get("bytes"),
            "video_width": result.get("width"),    # natural video width (px) from Cloudinary
            "video_height": result.get("height"),  # natural video height (px) from Cloudinary
        }

    # ── One-time migration: move legacy inline photos/videos to Cloudinary ────
    # Legacy data URIs make feed responses enormous and prevent smooth video streaming.
    # This authenticated, repeatable endpoint migrates posts, reels, and profile media
    # one Mongo document at a time; it does not run during normal feed requests.
    MIGRATION_SECRET = os.environ.get("MIGRATION_SECRET", "").strip()

    def _decode_data_uri_video(data_uri: str):
        header, separator, b64data = data_uri.partition(",")
        if not separator or not header.lower().startswith("data:video/") or ";base64" not in header.lower():
            raise ValueError("Invalid video data URI")
        max_encoded_chars = 4 * ((MAX_UPLOAD_VIDEO_BYTES + 2) // 3)
        if len(b64data) > max_encoded_chars:
            raise ValueError("Legacy video exceeds the 100MB migration limit")
        stream = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b")
        try:
            chunk_chars = 4 * 1024 * 1024
            total_bytes = 0
            for offset in range(0, len(b64data), chunk_chars):
                decoded = base64.b64decode(b64data[offset:offset + chunk_chars], validate=True)
                total_bytes += len(decoded)
                if total_bytes > MAX_UPLOAD_VIDEO_BYTES:
                    raise ValueError("Legacy video exceeds the 100MB migration limit")
                stream.write(decoded)
            if total_bytes == 0:
                raise ValueError("Legacy video is empty")
            stream.seek(0)
            return stream
        except Exception:
            stream.close()
            raise

    async def _migrate_one_video(data_uri: str, public_id: str) -> Optional[str]:
        raw_stream = None
        try:
            raw_stream = await asyncio.to_thread(_decode_data_uri_video, data_uri)
            result = await _upload_large_to_cloudinary(
                raw_stream, resource_type="video", folder="post-app/videos-migrated",
                public_id=public_id, overwrite=True,
            )
            return result.get("secure_url")
        except Exception:
            logging.exception(f"Video migration failed for {public_id}")
            return None
        finally:
            if raw_stream is not None:
                raw_stream.close()

    async def _migrate_one_image(data_uri: str, folder: str, public_id: str) -> Optional[str]:
        try:
            return await _cloudinaryize_inline_image(data_uri, folder, public_id, overwrite=True)
        except Exception:
            logging.exception(f"Image migration failed for {public_id}")
            return None

    def _legacy_media_query(video_fields=(), image_fields=(), image_array_fields=(), overlay_fields=()):
        conditions = []
        for field in video_fields:
            conditions.append({field: {"$regex": "^data:video/", "$options": "i"}})
        for field in image_fields:
            conditions.append({field: {"$regex": "^data:image/", "$options": "i"}})
        for field in image_array_fields:
            conditions.append({field: {"$elemMatch": {"$regex": "^data:image/", "$options": "i"}}})
        for field in overlay_fields:
            conditions.append({field + ".url": {"$regex": "^data:image/", "$options": "i"}})
        return {"$or": conditions} if conditions else {"_id": {"$exists": False}}

    def _migration_value(doc, dotted_field):
        value = doc
        for part in dotted_field.split("."):
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    async def _migrate_collection_media(collection, video_fields=(), image_fields=(), image_array_fields=(), overlay_fields=(), max_documents=25, after_id=None):
        projection = {"_id": 0, "id": 1}
        for field in tuple(video_fields) + tuple(image_fields) + tuple(image_array_fields) + tuple(overlay_fields):
            projection[field] = 1
        result = {"documents_migrated": 0, "documents_failed": 0, "media_migrated": 0, "media_failed": 0, "batch_count": 0, "last_scanned_id": None, "has_more": False}
        query = _legacy_media_query(video_fields, image_fields, image_array_fields, overlay_fields)
        if after_id is not None:
            query = {"$and": [query, {"id": {"$gt": after_id}}]}
        cursor = collection.find(query, projection).sort("id", 1).batch_size(1).limit(max_documents)
        async for doc in cursor:
            doc_id = doc.get("id")
            result["batch_count"] += 1
            if doc_id is not None:
                result["last_scanned_id"] = str(doc_id)
            if doc_id is None:
                result["documents_failed"] += 1
                result["media_failed"] += 1
                continue
            safe_id = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in str(doc_id))[:80] or uuid.uuid4().hex
            updates = {}
            migrated = 0
            failed = 0
            video_cache = {}
            image_cache = {}

            for field in video_fields:
                value = _migration_value(doc, field)
                if isinstance(value, str) and value.lstrip().lower().startswith("data:video/"):
                    if value not in video_cache:
                        video_cache[value] = await _migrate_one_video(value, f"legacy_{safe_id}_{field}")
                    new_url = video_cache[value]
                    if new_url:
                        updates[field] = new_url
                        migrated += 1
                    else:
                        failed += 1

            async def migrate_image(value, public_id):
                if value not in image_cache:
                    image_cache[value] = await _migrate_one_image(
                        value, "post-app/photos-migrated", public_id
                    )
                return image_cache[value]

            for field in image_fields:
                value = _migration_value(doc, field)
                if isinstance(value, str) and value.lstrip().lower().startswith("data:image/"):
                    new_url = await migrate_image(value, f"legacy_{safe_id}_{field}")
                    if new_url:
                        updates[field] = new_url
                        migrated += 1
                    else:
                        failed += 1

            for field in image_array_fields:
                values = doc.get(field)
                if not isinstance(values, list):
                    continue
                new_values = list(values)
                changed = False
                for index, value in enumerate(values):
                    if isinstance(value, str) and value.lstrip().lower().startswith("data:image/"):
                        new_url = await migrate_image(value, f"legacy_{safe_id}_{field}_{index}")
                        if new_url:
                            new_values[index] = new_url
                            migrated += 1
                            changed = True
                        else:
                            failed += 1
                if changed:
                    updates[field] = new_values

            for field in overlay_fields:
                values = doc.get(field)
                if not isinstance(values, list):
                    continue
                new_values = list(values)
                changed = False
                for index, overlay in enumerate(values):
                    if not isinstance(overlay, dict):
                        continue
                    value = overlay.get("url")
                    if isinstance(value, str) and value.lstrip().lower().startswith("data:image/"):
                        new_url = await migrate_image(value, f"legacy_{safe_id}_{field}_{index}")
                        if new_url:
                            new_overlay = dict(overlay)
                            new_overlay["url"] = new_url
                            new_values[index] = new_overlay
                            migrated += 1
                            changed = True
                        else:
                            failed += 1
                if changed:
                    updates[field] = new_values

            if updates:
                try:
                    saved = await collection.update_one({"id": doc_id}, {"$set": updates})
                except Exception:
                    logging.exception(f"Legacy media database update failed for {safe_id}")
                    saved = None
                if saved and saved.matched_count:
                    result["documents_migrated"] += 1
                    result["media_migrated"] += migrated
                else:
                    result["documents_failed"] += 1
                    result["media_failed"] += migrated
            if failed:
                result["documents_failed"] += 1
                result["media_failed"] += failed
        if result["batch_count"] == max_documents and result["last_scanned_id"] is not None:
            more_query = _legacy_media_query(video_fields, image_fields, image_array_fields, overlay_fields)
            more_query = {"$and": [more_query, {"id": {"$gt": result["last_scanned_id"]}}]}
            result["has_more"] = bool(await collection.find_one(more_query, {"_id": 0, "id": 1}))
        return result

    _media_migration_lock = asyncio.Lock()

    @api.post("/admin/migrate-videos-to-cloudinary")
    @api.post("/admin/migrate-legacy-media-to-cloudinary")
    async def migrate_legacy_media_to_cloudinary(request: Request):
        if not MIGRATION_SECRET or request.headers.get("x-migration-key") != MIGRATION_SECRET:
            raise HTTPException(403, "Not authorized")
        if not ((CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) or CLOUDINARY_URL):
            raise HTTPException(500, "Media hosting is not configured on the server")
        if _media_migration_lock.locked():
            raise HTTPException(409, "A media migration is already running")
        try:
            cursor_payload = await request.json()
        except Exception:
            cursor_payload = {}
        after_ids = cursor_payload.get("after_ids", {}) if isinstance(cursor_payload, dict) else {}
        if not isinstance(after_ids, dict):
            after_ids = {}

        async with _media_migration_lock:
            specs = {
                "posts": (db.posts, {"video_fields": ("video_url",), "image_fields": ("photo_url", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"), "image_array_fields": ("photo_urls",), "overlay_fields": ("sticker_overlays",)}),
                "reels": (db.reels, {"video_fields": ("video_url",), "image_fields": ("photo_url", "music_artwork", "thumbnail_url"), "overlay_fields": ("sticker_overlays",)}),
                "users": (db.users, {"video_fields": ("profile_video", "cover_video"), "image_fields": ("avatar_photo", "cover_photo")}),
                "groups": (db.groups, {"image_fields": ("avatar_photo",)}),
                "messages": (db.messages, {"image_fields": ("photo_url", "gif_url", "audio_url", "from_avatar_photo", "shared_post.photo_url", "shared_post.avatar_photo", "shared_reel.video_url", "shared_reel.avatar_photo")}),
                "group_messages": (db.group_messages, {"image_fields": ("photo_url", "gif_url", "audio_url", "from_avatar_photo", "shared_post.photo_url", "shared_post.avatar_photo", "shared_reel.video_url", "shared_reel.avatar_photo")}),
                "reel_mentions": (db.reel_mentions, {"image_fields": ("source_user_avatar",)}),
            }
            results = {}
            for name, (collection, fields) in specs.items():
                results[name] = await _migrate_collection_media(collection, max_documents=25, after_id=after_ids.get(name), **fields)

        return {
            "ok": True,
            "batch_limit_per_collection": 25,
            "input_after_ids": after_ids,
            "collections": results,
            "posts_migrated": results["posts"]["documents_migrated"],
            "posts_failed": results["posts"]["documents_failed"],
            "reels_migrated": results["reels"]["documents_migrated"],
            "reels_failed": results["reels"]["documents_failed"],
            "users_migrated": results["users"]["documents_migrated"],
            "users_failed": results["users"]["documents_failed"],
            "media_migrated": sum(item["media_migrated"] for item in results.values()),
            "media_failed": sum(item["media_failed"] for item in results.values()),
        }

    async def _audit_media_field(collection, field, unwind_fields=()):
        pipeline = [{"$unwind": "$" + path} for path in unwind_fields]
        pipeline.append({"$facet": {
            "inline": [
                {"$match": {field: {"$regex": "^data:", "$options": "i"}}},
                {"$project": {
                    "kind": {"$cond": [
                        {"$regexMatch": {"input": "$" + field, "regex": "^data:video/", "options": "i"}}, "video",
                        {"$cond": [{"$regexMatch": {"input": "$" + field, "regex": "^data:audio/", "options": "i"}}, "audio", "image"]},
                    ]},
                    "bytes": {"$strLenBytes": "$" + field},
                }},
                {"$group": {"_id": "$kind", "references": {"$sum": 1}, "encoded_bytes": {"$sum": "$bytes"}}},
            ],
            "cloudinary": [
                {"$match": {field: {"$regex": r"^https?://res\.cloudinary\.com/", "$options": "i"}}},
                {"$group": {"_id": None, "references": {"$sum": 1}}},
            ],
        }})
        rows = await collection.aggregate(pipeline).to_list(1)
        facets = rows[0] if rows else {"inline": [], "cloudinary": []}
        inline = facets.get("inline", [])
        return {
            "inline_references": sum(row.get("references", 0) for row in inline),
            "inline_encoded_bytes": sum(row.get("encoded_bytes", 0) for row in inline),
            "inline_by_kind": {str(row.get("_id")): {"references": row.get("references", 0), "encoded_bytes": row.get("encoded_bytes", 0)} for row in inline},
            "cloudinary_url_references": facets.get("cloudinary", [{}])[0].get("references", 0) if facets.get("cloudinary") else 0,
        }

    @api.get("/admin/audit-media-storage")
    async def audit_media_storage(request: Request):
        if not MIGRATION_SECRET or request.headers.get("x-migration-key") != MIGRATION_SECRET:
            raise HTTPException(403, "Not authorized")
        specs = {
            "posts": (db.posts, {"video_url": (), "photo_url": (), "photo_urls": ("photo_urls",), "gif_url": (), "music_artwork": (), "music_preview_url": (), "thumbnail_url": (), "sticker_overlays.url": ("sticker_overlays",)}),
            "reels": (db.reels, {"video_url": (), "photo_url": (), "music_artwork": (), "thumbnail_url": (), "sticker_overlays.url": ("sticker_overlays",)}),
            "users": (db.users, {"avatar_photo": (), "cover_photo": (), "profile_video": (), "cover_video": ()}),
            "groups": (db.groups, {"avatar_photo": ()}),
            "messages": (db.messages, {"photo_url": (), "gif_url": (), "audio_url": (), "shared_post.photo_url": (), "shared_post.avatar_photo": (), "shared_reel.video_url": (), "shared_reel.avatar_photo": ()}),
            "group_messages": (db.group_messages, {"photo_url": (), "gif_url": (), "audio_url": (), "shared_post.photo_url": (), "shared_post.avatar_photo": (), "shared_reel.video_url": (), "shared_reel.avatar_photo": ()}),
            "reel_mentions": (db.reel_mentions, {"source_user_avatar": ()}),
        }
        report = {}
        for name, (collection, fields) in specs.items():
            report[name] = {}
            for field, unwind_fields in fields.items():
                report[name][field] = await _audit_media_field(collection, field, unwind_fields)
        return {
            "ok": True,
            "scope": "MongoDB media fields; Cloudinary counts are stored URL references, not provider-side asset verification",
            "collections": report,
            "inline_references": sum(item["inline_references"] for fields in report.values() for item in fields.values()),
            "inline_encoded_bytes": sum(item["inline_encoded_bytes"] for fields in report.values() for item in fields.values()),
            "cloudinary_url_references": sum(item["cloudinary_url_references"] for fields in report.values() for item in fields.values()),
        }

    @api.post("/posts")
    async def create_post(p: PostIn, u=Depends(current_user)):
        _validate_post_video(p.video_url, p.video_duration)
        _validate_post_media(p)
        # A post is either a photo carousel or a single video, never both
        has_video = bool(p.video_url)
        doc = {
            "id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"],
            "user_handle": u["handle"], "avatar_bg": u["avatar_bg"],
            "avatar_letter": u["avatar_letter"], "avatar_photo": u.get("avatar_photo"),
            "content": p.content, "accent": p.accent, "location": p.location or "",
            "photo_url": None if has_video else ((p.photo_urls[0] if p.photo_urls else None) or p.photo_url or None),
            "photo_urls": [] if has_video else (p.photo_urls or ([p.photo_url] if p.photo_url else [])),
            "video_url": p.video_url if has_video else None,
            "video_duration": min(p.video_duration, MAX_POST_VIDEO_SECONDS) if (has_video and p.video_duration is not None) else None,
            "user_location": u.get("location", ""),
            "feeling": p.feeling or None,
            "tagged_users": p.tagged_users or [],
            "audience": p.audience or "public",
            "comments_enabled": False if p.audience == "only_me" else (p.comments_enabled if p.comments_enabled is not None else True),
            "photo_width": p.photo_width or None,
            "photo_height": p.photo_height or None,
            "video_width": p.video_width or None,
            "video_height": p.video_height or None,
            "aspect_ratio": p.aspect_ratio or (
                round(p.video_width / p.video_height, 4) if (has_video and p.video_width and p.video_height) else
                round(p.photo_width / p.photo_height, 4) if (p.photo_width and p.photo_height) else None
            ),
            "is_badge_verified": bool(u.get("is_badge_verified")),
            "verified_category": u.get("verified_category") or None,
            "music_title": p.music_title or None,
            "music_artist": p.music_artist or None,
            "music_artwork": p.music_artwork or None,
            "music_preview_url": p.music_preview_url or None,
            "music_duration_ms": p.music_duration_ms or None,
            "music_start_ms": max(0, int(p.music_start_ms or 0)),
            "music_clip_duration_ms": max(1000, min(30000, int(p.music_clip_duration_ms or 30000))) if p.music_preview_url else None,
            "alt_text": (p.alt_text or "")[:1000] or None,
            "gif_url": (p.gif_url or "").strip() or None,
            "sticker_overlays": [{"id": s["id"], "url": s["url"], "x": float(s.get("x", 50)), "y": float(s.get("y", 50))} for s in (p.sticker_overlays or []) if s.get("url")][:10],
            "emoji_overlays": [{"id": e.get("id", ""), "emoji": str(e.get("emoji", ""))[:8], "x": float(e.get("x", 50)), "y": float(e.get("y", 50)), "size": max(24, min(int(e.get("size", 72)), 160))} for e in (p.emoji_overlays or []) if e.get("emoji")][:20],
            "video_text_overlays": [{"id": t.get("id",""), "text": (t.get("text") or "")[:200], "x": float(t.get("x", 50)), "y": float(t.get("y", 50)), "color": (t.get("color") or "#ffffff")[:20], "bgColor": (t.get("bgColor") or "transparent")[:20], "bgScale": float(t.get("bgScale") or 1), "size": int(t.get("size") or 22)} for t in (p.video_text_overlays or []) if t.get("text")][:10],
            "video_effect": (p.video_effect or "none")[:20] if p.video_effect else None,
            "likes": [], "comments": [], "views": [], "saves": [], "reposts": [],
            "created_at": now().isoformat(), "edited_at": None, "is_pinned": False,
        }
        await db.posts.insert_one(doc.copy())
        doc.pop("_id", None)
        # tag + @mention notifications (live + push)
        _tagged_ids = await _notify_tags(u, p.tagged_users, post_id=doc["id"])
        _bg(_notify_mentions(u, p.content, exclude=_tagged_ids, where="post", post_id=doc["id"]))
        _bg(_notify_followers(u, "new_post", audience=(p.audience or "public"), post_id=doc["id"], snippet=(p.content or "")[:60],
                              push=("New post", f"{u['name']} shared a new post")))
        return doc

    def _item_counts(item: dict) -> dict:
        """Single source of truth for every counter shown on a post/reel card.
        Home feed, Reels tab and Profile all read these same six fields."""
        def _n(v):
            try: return max(0, int(v or 0))
            except Exception: return 0
        def _len(v): return len(v) if isinstance(v, list) else 0
        views = item.get("views")
        views_n = len(set(v for v in views if isinstance(v, (str, int)))) if isinstance(views, list) else 0
        return {
            "like_count":    _len(item.get("likes")) or _n(item.get("like_count")),
            "comment_count": max(_len(item.get("comments")), _n(item.get("comment_count"))),
            "repost_count":  max(_len(item.get("reposts")), _n(item.get("repost_count"))),
            "share_count":   max(_len(item.get("shares")), _n(item.get("share_count"))),
            "view_count":    max(views_n, _n(item.get("view_count")), _n(item.get("views_count"))),
            "save_count":    max(_len(item.get("saves")), _n(item.get("save_count"))),
        }

    def _attach_counts(item):
        if isinstance(item, dict):
            counts = _item_counts(item)
            item.update(counts)
            item["views_count"] = counts["view_count"]
        return item

    def _reel_to_feed_item(r: dict, mentioned: bool = False, mentioned_by: Optional[dict] = None) -> dict:
        """Shapes a raw `reels` doc so it can sit alongside `posts` docs in the
        home feed / profile grid — same field names the frontend post card and
        PostMedia component already know how to render (video_url, content,
        likes as [{user_id,color}], etc). `is_reel` lets the frontend route
        interactions (like/comment/save/delete/open) to the /reels/* endpoints.
        """
        likes_ids = r.get("likes", [])
        views_raw = r.get("views", [])
        view_count = len(set(views_raw)) if isinstance(views_raw, list) else 0
        _feed_item = {
            "id": r["id"],
            "user_id": r["user_id"],
            "user_name": r.get("user_name"),
            "user_handle": r.get("user_handle"),
            "avatar_bg": r.get("avatar_bg"),
            "avatar_letter": r.get("avatar_letter"),
            "avatar_photo": r.get("avatar_photo"),
            "is_badge_verified": bool(r.get("is_badge_verified")),
            "verified_category": None,
            "content": r.get("caption") or "",
            # Keep the reel API contract intact for the full-screen Reels viewer.
            # The algorithm feed previously exposed this only as `content`, while
            # the viewer reads `caption`, hiding hashtags and prompts after posting.
            "caption": r.get("caption") or "",
            "accent": None,
            "location": None,
            # photo reels: pass photo_url so the home-feed card can render it.
            # video reels: keep photo_url null (video_url is the media).
            "photo_url":  (r.get("photo_url") if not r.get("video_url") else None),
            "photo_urls": ([r["photo_url"]] if r.get("photo_url") and not r.get("video_url") else None),
            "video_url": r.get("video_url"),
            "video_duration": r.get("duration"),
            "duration": r.get("duration"),
            "category": r.get("category"),
            "hashtags": r.get("hashtags") or [],
            "remix_of": r.get("remix_of"),
            "photo_width": None, "photo_height": None,
            # aspect_ratio: only meaningful for video reels (default 9/16).
            # For photo reels leave None — frontend uses natural img dimensions.
            "aspect_ratio": (
                r.get("aspect_ratio")
                or (
                    r.get("media_width") / r.get("media_height")
                    if r.get("video_url") and r.get("media_width") and r.get("media_height")
                    else (9 / 16 if r.get("video_url") else None)
                )
            ),
            "audience": "public",
            "comments_enabled": True,
            "likes": [{"user_id": uid, "color": "#FF3B30"} for uid in likes_ids],
            "comments": r.get("comments", []),
            # Keep raw viewer IDs out of the feed; expose the real aggregate count.
            "views": [],
            "views_count": view_count,
            "view_count": view_count,
            "saves": r.get("saves", []),
            "save_count": max(len(r.get("saves") or []), int(r.get("save_count") or 0)),
            "share_count": max(len(r.get("shares") or []), int(r.get("share_count") or 0)),
            "reposts": list(r.get("reposts") or []),
            "repost_count": len(r.get("reposts") or []),
            "created_at": r.get("created_at"),
            "edited_at": None,
            "is_pinned": False,
            "is_reel": True,
            # A mention is a reference to the original reel, never a copied
            # upload.  The frontend can therefore render the same URL and
            # preserve its natural media dimensions.
            "is_mentioned": mentioned,
            "mentioned_by": mentioned_by,
            "audio_label":      r.get("audio_label"),
            "music_url":        r.get("music_url"),
            "music_start_time": r.get("music_start_time") or 0,
            "music_clip_duration": r.get("music_clip_duration") or 15,
            "music_title":      r.get("music_title"),
            "music_artist":     r.get("music_artist"),
            "music_artwork":    r.get("music_artwork"),
            # Editing overlays — must be forwarded so the home-feed card renders
            # stickers, text, emoji and filter identically to the full-screen viewer.
            "sticker_overlays": r.get("sticker_overlays") or [],
            "text_overlays":    r.get("text_overlays")    or [],
            "emoji_overlays":   r.get("emoji_overlays")   or [],
            "video_effect":     r.get("video_effect"),
            "shares":           list(r.get("shares") or []),
            "comment_count":    r.get("comment_count") or 0,
        }
        return _attach_counts(_feed_item)

    @api.get("/posts")
    async def list_posts(
        q: Optional[str] = Query(None, max_length=200), user_id: Optional[str] = None,
        skip: int = Query(0, ge=0, le=500), limit: int = Query(20, ge=1, le=50), feed: bool = False,
        following_only: bool = False, track_views: bool = True,
        u=Depends(current_user),
    ):
        query: dict = {}
        filter_public_authors = False
        following_ids = u.get("following") or []
        feed_visible_user_ids = []
        excluded_user_ids = set(
            (u.get("blocked_users") or []) + (u.get("muted_users") or [])
        )

        async def _empty_list():
            return []
        if user_id and user_id != u["id"] and user_id in excluded_user_ids:
            return {"posts": [], "total": 0, "skip": skip, "limit": limit}

        if following_only:
            ids = list(set(following_ids + [u["id"]]))
            query["user_id"] = {"$in": ids} if ids else {"$in": [u["id"]]}
        elif user_id:
            target_user = await db.users.find_one({"id": user_id}, {"is_private": 1, "followers": 1})
            if target_user and target_user.get("is_private") and user_id != u["id"]:
                if u["id"] not in target_user.get("followers", []):
                    return {"posts": [], "total": 0, "skip": skip, "limit": limit, "private_locked": True}
            query["user_id"] = user_id
        elif feed:
            # Resolve public visibility in MongoDB; do not load every public user ID into RAM.
            # Followed private accounts and the viewer's own posts remain visible.
            feed_visible_user_ids = list(set(following_ids + [u["id"]]))
            filter_public_authors = True
        else:
            if q:
                query["$or"] = [
                    {"content": {"$regex": q, "$options": "i"}},
                    {"user_name": {"$regex": q, "$options": "i"}},
                    {"location": {"$regex": q, "$options": "i"}},
                ]
            filter_public_authors = True
        if q and user_id:
            query["$or"] = [
                {"content": {"$regex": q, "$options": "i"}},
                {"user_name": {"$regex": q, "$options": "i"}},
                {"location": {"$regex": q, "$options": "i"}},
            ]

        if excluded_user_ids:
            current_user_filter = query.get("user_id")
            if feed and isinstance(current_user_filter, dict) and "$in" in current_user_filter:
                current_user_filter["$in"] = [
                    item_id for item_id in current_user_filter["$in"]
                    if item_id not in excluded_user_ids
                ]
            elif not user_id:
                exclusion_filter = {"user_id": {"$nin": list(excluded_user_ids)}}
                query = {"$and": [query, exclusion_filter]} if query else exclusion_filter

        # Mongo strips legacy data URLs before documents reach Python or JSON.
        # Reels remain excluded from the normal mixed feed until their migration.
        legacy_media_filter = {"$nor": [
            {"video_url": {"$regex": "^data:"}},
            {"photo_url": {"$regex": "^data:"}},
            {"photo_urls": {"$elemMatch": {"$regex": "^data:"}}},
        ]}
        feed_user_filter = query.get("user_id")
        post_media_stage = _safe_media_sanitize_stage(
            scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"),
            array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",),
        )

        # Reels get merged into the home feed and profile grid (but not search).
        include_reels = (feed or bool(user_id)) and not q
        fetch_n = skip + limit
        repost_actor_ids = []
        if not q and feed:
            repost_actor_ids = [item_id for item_id in set(following_ids + [u["id"]]) if item_id not in excluded_user_ids]
        elif not q and following_only:
            repost_actor_ids = [item_id for item_id in set(following_ids + [u["id"]]) if item_id not in excluded_user_ids]
        elif not q and user_id and user_id not in excluded_user_ids:
            repost_actor_ids = [user_id]
        post_repost_rows = []
        reel_repost_rows = []
        if repost_actor_ids:
            post_repost_rows = await db.post_reposts.find(
                {"user_id": {"$in": repost_actor_ids}}, {"_id": 0}
            ).sort("created_at", -1).limit(fetch_n).to_list(fetch_n)
            reel_repost_rows = await db.reel_reposts.find(
                {"user_id": {"$in": repost_actor_ids}}, {"_id": 0}
            ).sort("created_at", -1).limit(fetch_n).to_list(fetch_n)
            legacy_reposts = await _safe_media_find(
                db.reel_mentions,
                {"source_user_id": {"$in": repost_actor_ids}, "$expr": {"$eq": ["$source_user_id", "$target_user_id"]}},
                scalar_fields=("source_user_avatar",),
                projection={"_id": 0, "id": 1, "reel_id": 1, "source_user_id": 1, "source_user_name": 1, "source_user_handle": 1, "source_user_avatar": 1, "source_user_bg": 1, "source_user_letter": 1, "created_at": 1},
                sort={"created_at": -1}, limit=fetch_n,
            )
            reel_repost_rows.extend({
                "id": row.get("id"), "reel_id": row.get("reel_id"),
                "user_id": row.get("source_user_id"), "user_name": row.get("source_user_name"),
                "user_handle": row.get("source_user_handle"), "avatar_photo": row.get("source_user_avatar"),
                "avatar_bg": row.get("source_user_bg"), "avatar_letter": row.get("source_user_letter"),
                "created_at": row.get("created_at"),
            } for row in legacy_reposts)
        if filter_public_authors:
            visible_author_filters = [
                {"user_id": u["id"]},
                {"_author.is_private": {"$ne": True}},
            ]
            if feed:
                visible_author_filters.insert(0, {"user_id": {"$in": feed_visible_user_ids}})
            posts_task = db.posts.aggregate([
                {"$match": query},
                {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "id", "as": "_author"}},
                {"$match": {"$or": visible_author_filters}},
                {"$sort": {"created_at": -1}},
                {"$limit": fetch_n},
                post_media_stage,
                {"$project": {"_id": 0, "_author": 0}},
            ]).to_list(fetch_n)
        else:
            posts_task = db.posts.aggregate([
                {"$match": query}, {"$sort": {"created_at": -1}}, {"$limit": fetch_n},
                post_media_stage, {"$project": {"_id": 0}},
            ]).to_list(fetch_n)
        if include_reels:
            # Mention visibility is private to the signed-in viewer, never the profile target.
            mention_target_id = u["id"]
            viewer_mentions = await _safe_media_find(
                db.reel_mentions, {"target_user_id": mention_target_id},
                scalar_fields=("source_user_avatar",),
                projection={"_id": 0, "reel_id": 1, "target_user_id": 1, "source_user_id": 1, "source_user_name": 1, "source_user_handle": 1, "source_user_avatar": 1, "source_user_bg": 1, "source_user_letter": 1, "created_at": 1},
                sort={"created_at": -1}, limit=fetch_n,
            )
            mentioned_ids = list(dict.fromkeys(
                doc["reel_id"] for doc in viewer_mentions + reel_repost_rows if doc.get("reel_id")
            ))

            async def _load_feed_reels():
                # Fetch normal feed reels and mentioned/reposted reels separately.
                # Applying limit() to one combined query can drop an old reel
                # before the mention/repost is merged into the Home feed.
                if feed:
                    reel_visibility = {"$or": [
                        {"user_id": u["id"]},
                        {"$and": [
                            {"$or": [{"audience": {"$exists": False}}, {"audience": "public"}]},
                            {"$or": [
                                {"_author.is_private": {"$ne": True}},
                                {"user_id": {"$in": feed_visible_user_ids}},
                            ]},
                        ]},
                        {"user_id": {"$in": following_ids}, "audience": "friends"},
                        {"audience": "only_show", "audience_users": u["id"]},
                    ]}
                    reel_safety = {"$and": [
                        {"user_id": {"$nin": list(excluded_user_ids)}},
                        {"moderation_status": {"$nin": ["flagged", "under_review", "removed"]}},
                    ]}

                    def _feed_reel_pipeline(base_query, result_limit):
                        return [
                            {"$match": base_query},
                            {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "id", "as": "_author"}},
                            {"$match": reel_visibility},
                            {"$sort": {"created_at": -1}},
                            {"$limit": result_limit},
                            _safe_media_sanitize_stage(
                                scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
                                overlay_fields=("sticker_overlays",), comment_fields=("comments",),
                            ),
                            {"$project": {"_id": 0, "_author": 0}},
                        ]

                    normal_query = {"$and": [legacy_media_filter, reel_safety]}
                    mentioned_query = {"$and": [
                        {"id": {"$in": mentioned_ids}}, legacy_media_filter, reel_safety,
                    ]}
                    normal_task = db.reels.aggregate(
                        _feed_reel_pipeline(normal_query, fetch_n)
                    ).to_list(fetch_n)
                    mentioned_task = (
                        db.reels.aggregate(
                            _feed_reel_pipeline(mentioned_query, len(mentioned_ids))
                        ).to_list(len(mentioned_ids))
                        if mentioned_ids else _empty_list()
                    )
                else:
                    normal_query = {"$and": [{"user_id": feed_user_filter}, legacy_media_filter]}
                    mentioned_query = {"$and": [{"id": {"$in": mentioned_ids}}, legacy_media_filter]}
                    reel_media_stage = _safe_media_sanitize_stage(
                        scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
                        overlay_fields=("sticker_overlays",), comment_fields=("comments",),
                    )
                    normal_task = db.reels.aggregate([
                        {"$match": normal_query}, {"$sort": {"created_at": -1}}, {"$limit": fetch_n},
                        reel_media_stage, {"$project": {"_id": 0}},
                    ]).to_list(fetch_n)
                    mentioned_task = (
                        db.reels.aggregate([
                            {"$match": mentioned_query}, {"$sort": {"created_at": -1}}, {"$limit": len(mentioned_ids)},
                            reel_media_stage, {"$project": {"_id": 0}},
                        ]).to_list(len(mentioned_ids))
                        if mentioned_ids else _empty_list()
                    )
                normal_reels, mentioned_reels = await asyncio.gather(normal_task, mentioned_task)
                merged_by_id = {}
                for item in normal_reels + mentioned_reels:
                    merged_by_id[item["id"]] = item
                return sorted(
                    merged_by_id.values(),
                    key=lambda item: item.get("created_at") or "",
                    reverse=True,
                )[:fetch_n]

            reels_task = _load_feed_reels()
        else:
            async def _no_reels(): return []
            reels_task = _no_reels()
        posts_raw, reels_raw = await asyncio.gather(posts_task, reels_task)
        if not q and (feed or following_only or user_id):
            legacy_clones = [item for item in posts_raw if item.get("repost_of")]
            source_ids = list(dict.fromkeys(
                [row.get("post_id") for row in post_repost_rows if row.get("post_id")]
                + [row.get("repost_of") for row in legacy_clones if row.get("repost_of")]
            ))
            source_posts = await _safe_media_find(
                db.posts, {"id": {"$in": source_ids}},
                scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"),
                array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",),
                projection={"_id": 0}, limit=len(source_ids),
            ) if source_ids else []
            source_by_id = {item.get("id"): item for item in source_posts if item.get("id")}
            source_author_ids = list(dict.fromkeys(item.get("user_id") for item in source_posts if item.get("user_id")))
            source_authors = await _safe_user_find(
                {"id": {"$in": source_author_ids}},
                {"_id": 0, "id": 1, "is_private": 1, "followers": 1}, limit=len(source_author_ids),
            ) if source_author_ids else []
            source_author_by_id = {item.get("id"): item for item in source_authors if item.get("id")}

            def _repost_source_is_visible(source):
                owner_id = source.get("user_id")
                if not owner_id or owner_id in excluded_user_ids:
                    return False
                if owner_id == u["id"] or owner_id in following_ids:
                    return True
                author = source_author_by_id.get(owner_id) or {}
                return not author.get("is_private")

            def _post_repost_projection(source, event):
                actor = {
                    "id": event.get("user_id"), "name": event.get("user_name"),
                    "handle": event.get("user_handle"), "avatar_photo": event.get("avatar_photo"),
                    "avatar_bg": event.get("avatar_bg"), "avatar_letter": event.get("avatar_letter"),
                }
                item = dict(source)
                item.update({
                    "repost_of": source.get("id"),
                    "repost_user_name": source.get("user_name"),
                    "repost_user_handle": source.get("user_handle"),
                    "reposted_by": actor,
                    "is_repost_event": True,
                    "is_reposted_by_viewer": u["id"] in (source.get("reposts") or []),
                    "feed_event_id": "post-repost:" + str(event.get("id") or actor.get("id") or source.get("id")),
                    "original_created_at": source.get("created_at"),
                    "created_at": event.get("created_at") or source.get("created_at"),
                })
                return item

            reposted_post_items = []
            for legacy in legacy_clones:
                source = source_by_id.get(legacy.get("repost_of"))
                if source and _repost_source_is_visible(source):
                    reposted_post_items.append(_post_repost_projection(source, legacy))
            for event in post_repost_rows:
                source = source_by_id.get(event.get("post_id"))
                if source and _repost_source_is_visible(source):
                    reposted_post_items.append(_post_repost_projection(source, event))

            posts_raw = [item for item in posts_raw if not item.get("repost_of")]
            if feed or following_only:
                by_source_id = {}
                for item in posts_raw + reposted_post_items:
                    source_id = item.get("repost_of") or item.get("id")
                    previous = by_source_id.get(source_id)
                    if previous is None or (
                        item.get("is_repost_event") and not previous.get("is_repost_event")
                    ) or (
                        item.get("is_repost_event") and previous.get("is_repost_event")
                        and (item.get("created_at") or "") > (previous.get("created_at") or "")
                    ):
                        by_source_id[source_id] = item
                posts_raw = list(by_source_id.values())
            else:
                posts_raw.extend(reposted_post_items)

        await _hydrate_author_avatars(posts_raw + reels_raw)
        # Mention visibility is private to the signed-in viewer, never the profile target.
        mention_docs = {}
        repost_docs = {}
        if include_reels:
            for doc in viewer_mentions:
                reel_key = doc.get("reel_id")
                previous = mention_docs.get(reel_key)
                if reel_key and (not previous or (doc.get("created_at") or "") > (previous.get("created_at") or "")):
                    mention_docs[reel_key] = doc
            for doc in reel_repost_rows:
                reel_key = doc.get("reel_id")
                previous = repost_docs.get(reel_key)
                if reel_key and (not previous or (doc.get("created_at") or "") > (previous.get("created_at") or "")):
                    repost_docs[reel_key] = doc
        repost_reel_author_ids = list(dict.fromkeys(
            reel.get("user_id") for reel in reels_raw
            if reel.get("id") in repost_docs and reel.get("user_id")
        ))
        repost_reel_authors = await _safe_user_find(
            {"id": {"$in": repost_reel_author_ids}},
            {"_id": 0, "id": 1, "is_private": 1, "followers": 1}, limit=len(repost_reel_author_ids),
        ) if repost_reel_author_ids and not feed else []
        repost_reel_author_by_id = {item.get("id"): item for item in repost_reel_authors if item.get("id")}
        merged_reels = []
        seen_reel_ids = set()
        for reel in reels_raw:
            if reel["id"] in seen_reel_ids:
                continue
            seen_reel_ids.add(reel["id"])
            mention = mention_docs.get(reel["id"])
            repost = repost_docs.get(reel["id"])
            mention_is_newer = bool(mention and (mention.get("created_at") or "") > ((repost or {}).get("created_at") or ""))
            if repost and not feed and reel.get("user_id") != u["id"] and reel.get("user_id") not in following_ids:
                source_author = repost_reel_author_by_id.get(reel.get("user_id")) or {}
                if source_author.get("is_private"):
                    continue
            use_repost = bool(repost and not mention_is_newer)
            actor = repost if use_repost else mention
            mentioned_by = (
                {"id": actor.get("user_id") if use_repost else actor.get("source_user_id"),
                 "name": actor.get("user_name") if use_repost else actor.get("source_user_name"),
                 "handle": actor.get("user_handle") if use_repost else actor.get("source_user_handle"),
                 "avatar_photo": actor.get("avatar_photo") if use_repost else actor.get("source_user_avatar"),
                 "avatar_bg": actor.get("avatar_bg") if use_repost else actor.get("source_user_bg"),
                 "avatar_letter": actor.get("avatar_letter") if use_repost else actor.get("source_user_letter")}
                if actor else None
            )
            feed_item = _reel_to_feed_item(reel, bool(mention or repost), mentioned_by)
            if use_repost:
                feed_item["is_repost_event"] = True
                feed_item["repost_of"] = reel["id"]
                feed_item["repost_user_name"] = reel.get("user_name")
                feed_item["repost_user_handle"] = reel.get("user_handle")
                feed_item["reposted_by"] = mentioned_by
                feed_item["is_reposted_by_viewer"] = repost.get("user_id") == u["id"]
                feed_item["feed_event_id"] = "reel-repost:" + str(repost.get("id") or reel["id"])
            if actor and actor.get("created_at"):
                feed_item["original_created_at"] = feed_item.get("created_at")
                feed_item["created_at"] = actor["created_at"]
            merged_reels.append(feed_item)
        merged = posts_raw + merged_reels
        merged.sort(key=lambda d: d.get("created_at") or "", reverse=True)
        posts = merged[skip:skip + limit]
        embedded_comments = []
        for item in posts:
            comments = item.get("comments") if isinstance(item, dict) else None
            if isinstance(comments, list):
                embedded_comments.extend(comment for comment in comments if isinstance(comment, dict))
        await _hydrate_comment_profiles(embedded_comments)
        unviewed_ids = [p["id"] for p in posts if not p.get("is_reel") and u["id"] not in p.get("views", [])] if track_views else []
        if unviewed_ids:
            # Fire-and-forget: don't block the response for view tracking
            async def _mark_viewed():
                try:
                    await db.posts.update_many(
                        {"id": {"$in": unviewed_ids}}, {"$addToSet": {"views": u["id"]}}
                    )
                except Exception:
                    pass
            asyncio.create_task(_mark_viewed())
        for _p in posts:
            if track_views and isinstance(_p, dict) and not _p.get("is_reel") and isinstance(_p.get("views"), list) and u["id"] not in _p["views"]:
                _p["views"] = _p["views"] + [u["id"]]
            _attach_counts(_p)
        return {"posts": posts, "has_more": len(posts) == limit, "skip": skip, "limit": limit}

    async def _viewer_can_access_item(item: Optional[dict], u: dict) -> bool:
        """Single visibility rule for a post OR a reel (needs user_id, audience, audience_users).

        True only when the viewer could actually see this item in the app:
          - owner always can
          - blocked either way -> no
          - private account -> only approved followers
          - audience: only_me -> owner only, friends/followers -> followers only,
            only_show -> only listed users, public -> everyone
        Used by share / open-by-link / share-to-friend so a guessed id never
        leaks or inflates a private item.
        """
        if not item:
            return False
        owner_id = item.get("user_id")
        if not owner_id:
            return False
        if owner_id == u["id"]:
            return True
        if owner_id in (u.get("blocked_users") or []):
            return False
        owner = await db.users.find_one(
            {"id": owner_id},
            {"_id": 0, "id": 1, "is_private": 1, "followers": 1, "blocked_users": 1},
        )
        if not owner or u["id"] in (owner.get("blocked_users") or []):
            return False
        is_follower = u["id"] in (owner.get("followers") or [])
        if owner.get("is_private") and not is_follower:
            return False
        audience = item.get("audience") or "public"
        if audience == "public":
            return True
        if audience in ("friends", "followers"):
            return is_follower
        if audience == "only_show":
            return u["id"] in (item.get("audience_users") or [])
        return False  # only_me or any unknown value -> deny

    _SHARE_ACCESS_FIELDS = {"user_id": 1, "audience": 1, "audience_users": 1}

    async def _record_share(coll, item_id: str, user_id: str):
        """One share counter for EVERYTHING: native share sheet (WhatsApp/Insta/FB/X/copy)
        AND in-app sends (DM / send-to-friend). Unique per user, pushed live to watchers.
        Returns the authoritative share_count, or None if it could not be recorded."""
        try:
            await coll.update_one(
                {"id": item_id, "shares": {"$ne": user_id}},
                {"$addToSet": {"shares": user_id}},
            )
            row = await coll.find_one({"id": item_id}, {"shares": 1, "share_count": 1, "_id": 0}) or {}
            _live_mark(item_id)
            return max(len(row.get("shares") or []), int(row.get("share_count") or 0))
        except Exception:
            logging.exception("Could not record share for %s", item_id)
            return None

    # ===================================================================
    # POSTS FEED ALGORITHM (Home "For You" + notification "keep scrolling")
    # ===================================================================
    # Same visibility rules as the old Home feed (it reuses list_posts), but the order is
    # ranked: people you follow and people you interact with, fresh posts, popular posts
    # (likes, comments, saves, shares, reposts), videos/reels, and posts that are taking off
    # right now. Posts you already saw sink, and one author / one media type never floods the screen.
    # ── Like rate limit (anti bot / engagement farming) ─────────────────────────────────────────────
    # Sliding window per user: generous for real people (a fast scroller likes a few items a minute),
    # but a script hammering likes gets HTTP 429 instead of pushing a post up the ranking.
    LIKE_RATE_MAX = 90            # like/unlike actions ...
    LIKE_RATE_WINDOW = 60.0       # ... per this many seconds
    _LIKE_RATE_LOG = {}

    def _like_rate_check(user_id):
        import time as _t
        from collections import deque as _dq
        t = _t.monotonic()
        q = _LIKE_RATE_LOG.get(user_id)
        if q is None:
            if len(_LIKE_RATE_LOG) > 5000:
                for k in [k for k, d in _LIKE_RATE_LOG.items() if not d or t - d[-1] > LIKE_RATE_WINDOW]:
                    _LIKE_RATE_LOG.pop(k, None)
            q = _LIKE_RATE_LOG[user_id] = _dq()
        while q and t - q[0] > LIKE_RATE_WINDOW:
            q.popleft()
        if len(q) >= LIKE_RATE_MAX:
            raise HTTPException(429, "You are liking too fast. Please slow down.")
        q.append(t)

    POSTS_RANK_POOL_PAGES = 4            # 4 x 50 = the 200 newest visible items are ranked
    POSTS_RANK_CACHE_TTL = 90            # seconds; keeps page 2, 3... consistent with page 1
    _POSTS_RANK_CACHE = {}
    _POSTS_RANK_WEIGHTS = {
        "home":  {"engagement": 0.24, "recency": 0.26, "velocity": 0.10, "relationship": 0.30, "media": 0.10},
        "notif": {"engagement": 0.38, "recency": 0.28, "velocity": 0.16, "relationship": 0.12, "media": 0.06},
    }

    def _posts_rank_age_hours(item):
        raw = item.get("original_created_at") or item.get("created_at")
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return max(0.0, (now() - dt).total_seconds() / 3600.0)
        except Exception:
            return 24.0 * 30

    def _posts_rank_diversify(ranked):
        out, waiting = [], list(ranked)
        def _is_video(x): return bool(x.get("is_reel") or x.get("video_url"))
        while waiting:
            pick = None
            for idx, cand in enumerate(waiting):
                last = out[-2:]
                same_author = len(last) == 2 and all(str(x.get("user_id")) == str(cand.get("user_id")) for x in last)
                last3 = out[-3:]
                video_run = len(last3) == 3 and all(_is_video(x) for x in last3) and _is_video(cand)
                if not same_author and not video_run:
                    pick = idx
                    break
            out.append(waiting.pop(pick if pick is not None else 0))
        return out

    async def _posts_rank_ordered(u, mode, force_refresh=False):
        import math as _math
        cache_key = (u["id"], mode)
        cached = _POSTS_RANK_CACHE.get(cache_key)
        if cached and not force_refresh and (now() - cached[0]).total_seconds() < POSTS_RANK_CACHE_TTL:
            return cached[1]

        pages = await asyncio.gather(*[
            list_posts(q=None, user_id=None, skip=50 * i, limit=50, feed=True, following_only=False, track_views=False, u=u)
            for i in range(POSTS_RANK_POOL_PAGES)
        ])
        pool, seen_ids = [], set()
        for page in pages:
            for item in (page or {}).get("posts", []):
                key = str(item.get("id") or "")
                if key and key not in seen_ids:
                    seen_ids.add(key)
                    pool.append(item)

        me = str(u["id"])
        following = set(str(x) for x in (u.get("following") or []))

        def _viewer_in(rows):
            for r in rows or []:
                rid = r.get("user_id") if isinstance(r, dict) else r
                if str(rid) == me:
                    return True
            return False

        # authors the viewer already interacts with (liked / commented / reposted their items)
        interacted = set()
        for item in pool:
            if _viewer_in(item.get("likes")) or _viewer_in(item.get("comments")) or _viewer_in(item.get("saves")) or me in [str(x) for x in (item.get("reposts") or []) if not isinstance(x, dict)]:
                interacted.add(str(item.get("user_id") or ""))
        interacted.discard(me)

        w = _POSTS_RANK_WEIGHTS[mode]

        # "Not interested" was stored on the user but never used. Now: those posts never come back, and an author
        # the viewer marked 2+ times is pushed down (same idea as the Reels not-interested / hidden-creator signal).
        ni_ids = [str(x) for x in (u.get("not_interested") or []) if x][-300:]
        ni_set = set(ni_ids)
        ni_author_counts = {}
        if ni_ids:
            pool = [it for it in pool if str(it.get("id")) not in ni_set and str(it.get("original_id") or "") not in ni_set]
            try:
                for row in await db.posts.find({"id": {"$in": ni_ids}}, {"_id": 0, "user_id": 1}).to_list(300):
                    a = str(row.get("user_id") or "")
                    if a:
                        ni_author_counts[a] = ni_author_counts.get(a, 0) + 1
            except Exception:
                logging.exception("posts rank: not-interested author lookup failed")

        def _score(item):
            c = _item_counts(item)
            points = c["like_count"] + c["comment_count"] * 3 + c["save_count"] * 4 + c["share_count"] * 5 + c["repost_count"] * 3
            views = c["view_count"]
            age = _posts_rank_age_hours(item)
            absolute = min(1.0, _math.log1p(points) / _math.log1p(150))
            rate = min(1.0, (points / (views + 25.0)) / 0.35)          # smoothed: 1 like on 1 view is not "viral"
            engagement = 0.6 * absolute + 0.4 * rate
            recency = _math.exp(-age / 36.0)
            velocity = min(1.0, (points / (age + 2.0)) / 4.0)
            author = str(item.get("user_id") or "")
            reposter = str((item.get("reposted_by") or {}).get("id") or "")
            if author in following:
                relationship = 1.0
            elif reposter and reposter in following:
                relationship = 0.8
            elif author in interacted:
                relationship = 0.7
            elif author == me:
                relationship = 0.3
            else:
                relationship = 0.1
            if item.get("is_reel") or item.get("video_url"):
                media = 1.0
            elif item.get("photo_url") or item.get("photo_urls"):
                media = 0.6
            else:
                media = 0.2
            score = (w["engagement"] * engagement + w["recency"] * recency + w["velocity"] * velocity
                     + w["relationship"] * relationship + w["media"] * media)
            if not item.get("is_reel") and _viewer_in(item.get("views")):
                score *= 0.55                                           # already seen -> fresh content rises
            if ni_author_counts.get(author, 0) >= 2 and author != me:
                score *= 0.6                                            # viewer keeps rejecting this author
            return score

        scored = sorted(pool, key=_score, reverse=True)
        for item in scored:
            item["rank_score"] = round(_score(item), 4)
        ordered = _posts_rank_diversify(scored)

        if len(_POSTS_RANK_CACHE) > 300:
            for old_key in sorted(_POSTS_RANK_CACHE, key=lambda k: _POSTS_RANK_CACHE[k][0])[:100]:
                _POSTS_RANK_CACHE.pop(old_key, None)
        _POSTS_RANK_CACHE[cache_key] = (now(), ordered)
        return ordered

    def _posts_rank_mark_viewed(items, u):
        ids = [p["id"] for p in items if not p.get("is_reel") and u["id"] not in (p.get("views") or [])]
        if not ids:
            return
        async def _mark():
            try:
                await db.posts.update_many({"id": {"$in": ids}}, {"$addToSet": {"views": u["id"]}})
            except Exception:
                pass
        asyncio.create_task(_mark())

    @api.get("/posts/home-feed")
    async def ranked_home_feed(
        skip: int = Query(0, ge=0, le=500), limit: int = Query(15, ge=1, le=30),
        u=Depends(current_user),
    ):
        """Home feed with the algorithm. Falls through to plain newest-first once the ranked pool is used up."""
        ordered = await _posts_rank_ordered(u, "home", force_refresh=(skip == 0))
        if skip < len(ordered):
            page_items = ordered[skip:skip + limit]
            for item in page_items:
                _attach_counts(item)
            _posts_rank_mark_viewed(page_items, u)
            more = skip + limit < len(ordered) or len(ordered) >= 50 * POSTS_RANK_POOL_PAGES - 20
            return {"posts": page_items, "skip": skip, "limit": limit, "has_more": more, "algorithm": "posts_home_v1"}
        # ranked pool exhausted -> continue with older posts, newest first
        tail_skip = 50 * POSTS_RANK_POOL_PAGES + (skip - len(ordered))
        if tail_skip > 500:
            return {"posts": [], "skip": skip, "limit": limit, "has_more": False, "algorithm": "posts_home_v1"}
        tail = await list_posts(q=None, user_id=None, skip=tail_skip, limit=limit, feed=True, following_only=False, track_views=True, u=u)
        have = {str(x.get("id")) for x in ordered}
        rows = [p for p in (tail or {}).get("posts", []) if str(p.get("id")) not in have]
        return {"posts": rows, "skip": skip, "limit": limit, "has_more": bool((tail or {}).get("has_more")), "algorithm": "posts_home_v1"}

    @api.get("/posts/ranked-feed")
    async def ranked_posts_feed(
        anchor_id: Optional[str] = Query(None, max_length=80),
        skip: int = Query(0, ge=0, le=400), limit: int = Query(10, ge=1, le=30),
        u=Depends(current_user),
    ):
        """'Keep scrolling' feed under a post/reel opened from a notification: popularity-heavy ranking.
        The opened item (anchor_id) is left out because the app already shows it first."""
        ordered = [p for p in await _posts_rank_ordered(u, "notif", force_refresh=(skip == 0))
                   if str(p.get("id")) != str(anchor_id or "")]
        page_items = ordered[skip:skip + limit]
        for item in page_items:
            _attach_counts(item)
        _posts_rank_mark_viewed(page_items, u)
        return {"posts": page_items, "skip": skip, "limit": limit,
                "has_more": skip + limit < len(ordered), "algorithm": "posts_notif_v1"}

    @api.get("/posts/{pid}")
    async def get_post(pid: str, u=Depends(current_user)):
        post = await _safe_media_find_one(db.posts, {"id": pid}, scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"), array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",), projection={"_id": 0})
        if not post: raise HTTPException(404, "Post not found")
        if not await _viewer_can_access_item(post, u):
            raise HTTPException(404, "Post not found")
        if u["id"] not in post.get("views", []):
            await db.posts.update_one({"id": pid}, {"$addToSet": {"views": u["id"]}})
            post["views"] = post.get("views", []) + [u["id"]]
        return _attach_counts(post)

    @api.delete("/posts/{pid}")
    async def delete_post(pid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid}, {"_id": 0, "user_id": 1})
        if not post: raise HTTPException(404, "Not found")
        if post["user_id"] != u["id"]: raise HTTPException(403, "Not your post")
        await db.posts.delete_one({"id": pid})
        _bg(_purge_notifs({"post_id": pid}))      # likes / comments / tags / mentions of a deleted post must not linger
        return {"ok": True}

    @api.patch("/posts/{pid}")
    async def edit_post(pid: str, p: PostIn, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid}, {"_id": 0, "user_id": 1, "tagged_users": 1})
        if not post: raise HTTPException(404, "Post not found")
        if post["user_id"] != u["id"]: raise HTTPException(403, "Not your post")
        _validate_post_video(p.video_url, p.video_duration)
        _validate_post_media(p)
        upd = {"content": p.content, "accent": p.accent, "location": p.location or "", "edited_at": now().isoformat()}
        if p.tagged_users is not None: upd["tagged_users"] = p.tagged_users
        if p.video_url is not None:
            # Switching to a video clears any existing photos, keeping the two mutually exclusive
            upd["video_url"] = p.video_url
            upd["video_duration"] = min(p.video_duration, MAX_POST_VIDEO_SECONDS) if p.video_duration is not None else None
            upd["photo_url"] = None
            upd["photo_urls"] = []
        elif p.photo_url is not None or p.photo_urls is not None:
            # Switching to photos clears any existing video
            upd["video_url"] = None
            upd["video_duration"] = None
            if p.photo_url is not None: upd["photo_url"] = p.photo_url
            if p.photo_urls is not None:
                upd["photo_urls"] = p.photo_urls
                upd["photo_url"] = p.photo_urls[0] if p.photo_urls else None
        await db.posts.update_one({"id": pid}, {"$set": upd})
        # Newly added tags / @mentions notify now (already-notified people are skipped by _notify's de-dupe);
        # people whose tag was removed lose that tag notification.
        _tagged_ids = await _notify_tags(u, p.tagged_users, post_id=pid) if p.tagged_users else set()
        _bg(_notify_mentions(u, p.content, exclude=_tagged_ids, where="post", post_id=pid))
        if p.tagged_users is not None:
            _old = {str(h).strip().lstrip("@").lower() for h in (post.get("tagged_users") or [])}
            _new = {str(h).strip().lstrip("@").lower() for h in p.tagged_users}
            _gone = list(_old - _new)
            if _gone:
                async def _drop_removed_tags():
                    try:
                        us = await db.users.find({"$or": [{"username": {"$in": _gone}}, {"handle": {"$in": _gone + ["@" + n for n in _gone]}}]}, {"_id": 0, "id": 1}).to_list(40)
                        for tu in us: await db.notifications.delete_many({"user_id": tu["id"], "from_user_id": u["id"], "type": "tag", "post_id": pid})
                    except Exception: logging.exception("tag cleanup failed")
                _bg(_drop_removed_tags())
        return await _safe_media_find_one(
            db.posts, {"id": pid},
            scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"),
            array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",),
            projection={"_id": 0},
        )

    @api.post("/posts/{pid}/like")
    async def like_post(pid: str, p: LikeIn, u=Depends(current_user)):
        _like_rate_check(u["id"])
        post = await db.posts.find_one({"id": pid}, {"_id": 0, "user_id": 1})
        if not post: raise HTTPException(404, "Not found")
        # Atomic: first remove any existing like from this user, then add new one if color given.
        # Avoids race condition where two simultaneous requests overwrite each other's likes.
        await db.posts.update_one({"id": pid}, {"$pull": {"likes": {"user_id": u["id"]}}})
        if p.color:
            new_like = {"user_id": u["id"], "color": p.color, "liked_at": now().isoformat()}
            await db.posts.update_one({"id": pid}, {"$push": {"likes": new_like}})
        updated = await db.posts.find_one({"id": pid}, {"_id": 0, "likes": 1})
        likes = updated.get("likes", []) if updated else []
        if p.color and post["user_id"] != u["id"]:
            _bg(_notify(post["user_id"], u, "like", post_id=pid, push=("New like ♥️", u["name"] + " liked your post")))
        elif not p.color and post["user_id"] != u["id"]:
            _bg(_unnotify(post["user_id"], u["id"], "like", post_id=pid))      # un-like → notification goes away
        return {"likes": likes, "total": len(likes), "like_count": len(likes)}

    @api.get("/posts/{pid}/comments")
    async def get_post_comments(pid: str, u=Depends(current_user)):
        post = await db.posts.find_one(
            {"id": pid},
            {"_id": 0, "user_id": 1, "audience": 1, "audience_users": 1},
        )
        if not post:
            raise HTTPException(404, "Post not found")
        owner_id = post.get("user_id")
        if owner_id and owner_id != u["id"]:
            excluded = set((u.get("blocked_users") or []) + (u.get("muted_users") or []))
            if owner_id in excluded:
                raise HTTPException(404, "Post not found")
            author = await db.users.find_one(
                {"id": owner_id},
                {"_id": 0, "is_private": 1, "followers": 1, "blocked_users": 1},
            )
            if not author or u["id"] in (author.get("blocked_users") or []):
                raise HTTPException(404, "Post not found")
            is_follower = u["id"] in (author.get("followers") or []) or owner_id in (u.get("following") or [])
            audience = post.get("audience") or "public"
            allowed_users = post.get("audience_users") or []
            if (author.get("is_private") and not is_follower) or audience == "only_me":
                raise HTTPException(403, "You can't view comments on this post")
            if audience == "only_show" and u["id"] not in allowed_users:
                raise HTTPException(403, "You can't view comments on this post")
            if audience == "followers" and not is_follower:
                raise HTTPException(403, "You can't view comments on this post")
        comment_post = await _safe_media_find_one(
            db.posts, {"id": pid}, comment_fields=("comments",),
            projection={"_id": 0, "comments": 1},
        )
        if not comment_post:
            raise HTTPException(404, "Post not found")
        return {"comments": comment_post.get("comments", []) or []}

    @api.post("/posts/{pid}/comments")
    async def add_comment(pid: str, p: CommentIn, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid}, {"_id": 0, "user_id": 1, "comments_enabled": 1})
        if not post: raise HTTPException(404, "Post not found")
        await get_post_comments(pid, u)
        if not post.get("comments_enabled", True):
            raise HTTPException(403, "Comments are turned off for this post")
        comment_text = (p.text or "").strip()
        gif_url = (p.gif_url or "").strip() or None
        _reject_inline_data_uri(gif_url, "gif_url")
        if not comment_text and not gif_url:
            raise HTTPException(400, "Empty comment")
        c = {
            "id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"],
            "user_handle": u["handle"], "avatar_bg": u["avatar_bg"],
            "avatar_letter": u["avatar_letter"], "avatar_photo": u.get("avatar_photo"),
            "is_badge_verified": bool(u.get("is_badge_verified")), "text": comment_text,
            "gif_url": gif_url, "likes": [], "replies": [],
            "created_at": now().isoformat(),
        }
        await _hydrate_comment_profiles([c])
        await db.posts.update_one({"id": pid}, {"$push": {"comments": c}})
        if post["user_id"] != u["id"]:
            _bg(_notify(post["user_id"], u, "comment", post_id=pid, comment_id=c["id"], snippet=(comment_text or "GIF")[:80],
                        push=("New comment 💬", u["name"] + " commented on your post")))
        _bg(_notify_mentions(u, comment_text, exclude={post["user_id"]}, where="comment", post_id=pid, comment_id=c["id"]))
        return c

    @api.delete("/posts/{pid}/comments/{cid}")
    async def delete_comment(pid: str, cid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid}, {"_id": 0, "user_id": 1, "comments.id": 1, "comments.user_id": 1})
        if not post: raise HTTPException(404, "Post not found")
        comment = next((c for c in post.get("comments", []) if c["id"] == cid), None)
        if not comment: raise HTTPException(404, "Comment not found")
        if comment["user_id"] != u["id"] and post["user_id"] != u["id"]:
            raise HTTPException(403, "Cannot delete")
        await db.posts.update_one({"id": pid}, {"$pull": {"comments": {"id": cid}}})
        _bg(_purge_notifs({"post_id": pid, "comment_id": cid}))   # comment / reply / mention / like notifications of this comment
        return {"ok": True}

    @api.post("/posts/{pid}/comments/{cid}/like")
    async def like_post_comment(pid: str, cid: str, body: dict = None, u=Depends(current_user)):
        _like_rate_check(u["id"])
        comments_result = await get_post_comments(pid, u)
        comment = next((c for c in comments_result.get("comments", []) if str(c.get("id")) == str(cid)), None)
        if not comment:
            raise HTTPException(404, "Comment not found")
        user_id = str(u["id"])
        existing_likes = [str(like_id) for like_id in (comment.get("likes") or [])]
        requested_state = body.get("liked") if isinstance(body, dict) else None
        if not isinstance(requested_state, bool):
            requested_state = user_id not in existing_likes
        update = {"$addToSet": {"comments.$.likes": user_id}} if requested_state else {"$pull": {"comments.$.likes": user_id}}
        await db.posts.update_one({"id": pid, "comments.id": cid}, update)
        updated_result = await get_post_comments(pid, u)
        updated_comment = next((c for c in updated_result.get("comments", []) if str(c.get("id")) == str(cid)), None)
        if not updated_comment:
            raise HTTPException(404, "Comment not found")
        authoritative_likes = [str(like_id) for like_id in (updated_comment.get("likes") or [])]
        if requested_state and comment.get("user_id") and comment.get("user_id") != u["id"]:
            _bg(_notify(comment["user_id"], u, "like", post_id=pid, comment_id=cid, push=("New like ♥️", u["name"] + " liked your comment")))
        elif not requested_state and comment.get("user_id") and comment.get("user_id") != u["id"]:
            _bg(_unnotify(comment["user_id"], u["id"], "like", post_id=pid, comment_id=cid))
        return {
            "liked": user_id in authoritative_likes,
            "like_count": len(authoritative_likes),
            "likes": authoritative_likes,
        }

    @api.post("/posts/{pid}/comments/{cid}/replies")
    async def add_post_comment_reply(pid: str, cid: str, body: dict, u=Depends(current_user)):
        comments_result = await get_post_comments(pid, u)
        parent_comment = next((c for c in comments_result.get("comments", []) if str(c.get("id")) == str(cid)), None)
        if not parent_comment:
            raise HTTPException(404, "Comment not found")
        post = await db.posts.find_one({"id": pid}, {"_id": 0, "user_id": 1, "comments_enabled": 1})
        if not post:
            raise HTTPException(404, "Post not found")
        if not post.get("comments_enabled", True):
            raise HTTPException(403, "Comments are turned off for this post")
        text = (body.get("text") or "").strip()
        gif_url = (body.get("gif_url") or "").strip() or None
        _reject_inline_data_uri(gif_url, "gif_url")
        if not text and not gif_url:
            raise HTTPException(400, "Empty reply")
        reply = {
            "id": str(uuid.uuid4()),
            "user_id": u["id"],
            "user_name": u["name"],
            "user_handle": u["handle"],
            "avatar_bg": u["avatar_bg"],
            "avatar_letter": u["avatar_letter"],
            "avatar_photo": u.get("avatar_photo"),
            "is_badge_verified": bool(u.get("is_badge_verified")),
            "text": text,
            "gif_url": gif_url,
            "created_at": now().isoformat(),
        }
        await _hydrate_comment_profiles([reply])
        await db.posts.update_one(
            {"id": pid, "comments.id": cid},
            {"$push": {"comments.$.replies": reply}}
        )
        if parent_comment.get("user_id") != u["id"]:
            _bg(_notify(parent_comment["user_id"], u, "reply", post_id=pid, comment_id=cid, snippet=(text or "GIF")[:80],
                        push=("New reply 💬", u["name"] + " replied to your comment")))
        _bg(_notify_mentions(u, text, exclude={parent_comment.get("user_id")}, where="comment", post_id=pid, comment_id=cid, reply_id=reply["id"]))
        return reply

    @api.post("/posts/{pid}/view")
    async def view_post(pid: str, u=Depends(current_user)):
        await db.posts.update_one({"id": pid}, {"$addToSet": {"views": u["id"]}})
        _row = await db.posts.find_one({"id": pid}, {"_id": 0, "views": 1})
        _views = (_row or {}).get("views")
        return {"ok": True, "view_count": len(set(_views)) if isinstance(_views, list) else 0}

    @api.post("/posts/{pid}/share")
    async def share_post(pid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid}, {"shares": 1, "share_count": 1, "_id": 0, **_SHARE_ACCESS_FIELDS})
        # Same answer for "missing" and "not allowed" so ids can't be probed.
        if not post or not await _viewer_can_access_item(post, u):
            raise HTTPException(404, "Post not found")
        result = await db.posts.update_one(
            {"id": pid, "shares": {"$ne": u["id"]}},
            {"$addToSet": {"shares": u["id"]}},
        )
        updated = await db.posts.find_one({"id": pid}, {"shares": 1, "share_count": 1, "_id": 0})
        shares = (updated or post).get("shares") or []
        share_count = max(len(shares), int((updated or post).get("share_count") or 0))
        return {"shared": result.modified_count > 0, "share_count": share_count}

    @api.post("/posts/{pid}/save")
    async def save_post(pid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid}, {"_id": 0, "saves": 1})
        if not post: raise HTTPException(404, "Post not found")
        if u["id"] in (post.get("saves") or []):
            await db.posts.update_one({"id": pid}, {"$pull": {"saves": u["id"]}})
            await db.saved_collections.update_many({"user_id": u["id"]}, {"$pull": {"items": {"item_id": pid, "item_type": "post"}}})
            return {"saved": False, "save_count": max(0, len(post.get("saves") or []) - 1)}
        await db.posts.update_one({"id": pid}, {"$addToSet": {"saves": u["id"]}})
        return {"saved": True, "save_count": len(post.get("saves") or []) + 1}

    @api.post("/posts/{pid}/repost")
    async def repost_post(pid: str, desired: Optional[bool] = Query(default=None), u=Depends(current_user)):
        post = await _safe_media_find_one(
            db.posts, {"id": pid},
            scalar_fields=("photo_url", "video_url", "avatar_photo"), array_fields=("photo_urls",),
            projection={"_id": 0, "id": 1, "user_id": 1, "user_name": 1, "user_handle": 1, "reposts": 1},
        )
        if not post:
            raise HTTPException(404, "Post not found")
        owner = await _safe_user_find_one({"id": post.get("user_id")})
        if not owner:
            raise HTTPException(404, "User not found")
        if post.get("user_id") in (u.get("blocked_users") or []) or u["id"] in (owner.get("blocked_users") or []):
            raise HTTPException(403, "Action not allowed")
        if owner.get("is_private") and owner.get("id") != u["id"] and u["id"] not in (owner.get("followers") or []):
            raise HTTPException(403, "This post is not available to you")

        relation_filter = {"post_id": pid, "user_id": u["id"]}
        relation, legacy = await asyncio.gather(
            db.post_reposts.find_one(relation_filter, {"_id": 0}),
            db.posts.find_one({"repost_of": pid, "user_id": u["id"]}, {"_id": 0, "id": 1}),
        )
        repost_ids = {str(value) for value in (post.get("reposts") or []) if value is not None}
        already_reposted = bool(relation or legacy or str(u["id"]) in repost_ids)
        should_repost = (not already_reposted) if desired is None else desired

        if not should_repost:
            if already_reposted:
                removal_tasks = [
                    db.post_reposts.delete_many(relation_filter),
                    db.posts.update_one({"id": pid}, {"$pull": {"reposts": u["id"]}}),
                ]
                if legacy and legacy.get("id"):
                    removal_tasks.append(db.posts.delete_one({"id": legacy["id"]}))
                await asyncio.gather(*removal_tasks)
                updated_post = await db.posts.find_one({"id": pid}, {"_id": 0, "reposts": 1})
                repost_ids = {str(value) for value in ((updated_post or {}).get("reposts") or []) if value is not None}
            return {"reposted": False, "repost_count": len(repost_ids)}

        created_at = now().isoformat()
        candidate = {
            "id": str(uuid.uuid4()), "post_id": pid, "user_id": u["id"],
            "user_name": u.get("name"), "user_handle": u.get("handle"),
            "avatar_photo": u.get("avatar_photo"), "avatar_bg": u.get("avatar_bg"),
            "avatar_letter": u.get("avatar_letter"), "created_at": created_at,
        }
        relation_added = False
        if relation:
            relation_doc = relation
        else:
            try:
                insert_result = await db.post_reposts.update_one(
                    relation_filter, {"$setOnInsert": candidate}, upsert=True
                )
                relation_added = insert_result.upserted_id is not None
                relation_doc = candidate if relation_added else await db.post_reposts.find_one(relation_filter, {"_id": 0})
            except Exception as upsert_error:
                relation_doc = await db.post_reposts.find_one(relation_filter, {"_id": 0})
                if not relation_doc:
                    raise upsert_error

        update_tasks = [db.posts.update_one({"id": pid}, {"$addToSet": {"reposts": u["id"]}})]
        if legacy and legacy.get("id"):
            update_tasks.append(db.posts.delete_one({"id": legacy["id"]}))
        await asyncio.gather(*update_tasks)
        updated_post = await db.posts.find_one({"id": pid}, {"_id": 0, "reposts": 1})
        repost_ids = {str(value) for value in ((updated_post or {}).get("reposts") or []) if value is not None}

        if relation_added and not already_reposted and post.get("user_id") != u["id"]:
            _bg(_notify(post["user_id"], u, "repost", post_id=pid, push=("Repost", u.get("name", "Someone") + " reposted your post")))
        return {"reposted": True, "repost": relation_doc, "repost_count": len(repost_ids)}

    @api.post("/posts/{pid}/repost-to-friend")
    async def repost_to_friend(pid: str, p: ShareToFriendIn, u=Depends(current_user)):
        friend_id = p.friend_id.strip()
        if not friend_id:
            raise HTTPException(400, "friend_id required")
        if friend_id == u["id"]:
            raise HTTPException(400, "You cannot share a post with yourself")

        post = await _safe_media_find_one(
            db.posts, {"id": pid}, scalar_fields=("photo_url", "avatar_photo"), array_fields=("photo_urls",),
            projection={"_id": 0, "id": 1, "content": 1, "photo_url": 1, "photo_urls": 1,
                        "user_name": 1, "user_handle": 1, "avatar_bg": 1,
                        "avatar_letter": 1, "avatar_photo": 1, **_SHARE_ACCESS_FIELDS},
        )
        if not post or not await _viewer_can_access_item(post, u):
            raise HTTPException(404, "Post not found")
        friend = await db.users.find_one(
            {"id": friend_id},
            {"_id": 0, "id": 1, "name": 1, "blocked_users": 1,
             "is_badge_verified": 1},
        )
        if not friend:
            raise HTTPException(404, "Friend not found")
        if friend_id in (u.get("blocked_users") or []) or u["id"] in (friend.get("blocked_users") or []):
            raise HTTPException(403, "Cannot share with this user")
        friendship = await db.friend_requests.find_one({
            "status": "accepted",
            "$or": [
                {"from_id": u["id"], "to_id": friend_id},
                {"from_id": friend_id, "to_id": u["id"]},
            ],
        })
        if not friendship:
            raise HTTPException(403, "Only connected friends can receive shared posts")

        existing = await db.post_shares.find_one({
            "post_id": pid, "from_id": u["id"], "to_id": friend_id,
        })
        if existing:
            message_id = existing.get("message_id")
            if message_id:
                await db.messages.update_one(
                    {"id": message_id, "from_id": u["id"], "to_id": friend_id},
                    {"$set": {
                        "deleted_for_everyone": True,
                        "text": "",
                        "shared_post": None,
                        "shared_post_id": None,
                    }},
                )
                await _ws_push(friend_id, {"type": "message_deleted", "msg_id": message_id})
            await db.post_shares.delete_one({"id": existing["id"]})
            return {"ok": True, "reposted": False}

        shared_post = {
            "id": post["id"],
            "content": (post.get("content") or "")[:200],
            "photo_url": post.get("photo_url") or ((post.get("photo_urls") or [None])[0]),
            "user_name": post.get("user_name", ""),
            "user_handle": post.get("user_handle", ""),
            "avatar_bg": post.get("avatar_bg", ""),
            "avatar_letter": post.get("avatar_letter", ""),
            "avatar_photo": post.get("avatar_photo"),
            "type": "post",
        }
        message_id = str(uuid.uuid4())
        message = {
            "id": message_id,
            "from_id": u["id"],
            "from_name": u["name"],
            "to_id": friend_id,
            "text": "",
            "photo_url": None,
            "gif_url": None,
            "mood_color": None,
            "created_at": now().isoformat(),
            "status": "sent",
            "deleted_for": [],
            "deleted_for_everyone": False,
            "reply_to_id": None,
            "reply_to_preview": None,
            "shared_post": shared_post,
            "shared_post_id": pid,
            "shared_via_post_share": True,
            "audio_url": None,
            "audio_duration": None,
        }
        await db.messages.insert_one(message.copy())
        await db.post_shares.insert_one({
            "id": str(uuid.uuid4()),
            "post_id": pid,
            "from_id": u["id"],
            "to_id": friend_id,
            "message_id": message_id,
            "created_at": message["created_at"],
        })
        await _persist_user_activity_notification(
            friend_id, u, "message", message="Shared a post with you", message_id=message_id
        )
        await _ws_push(friend_id, {"type": "new_message", "message": message})
        share_count = await _record_share(db.posts, pid, u["id"])
        return {"ok": True, "reposted": True, "share_count": share_count}

    @api.post("/posts/{pid}/mention")
    async def mention_in_post(pid: str, body: dict, u=Depends(current_user)):
        mentioned_username = (body.get("username") or "").lstrip("@")
        if not mentioned_username: raise HTTPException(400, "username required")
        target = await _safe_user_find_one({"username": mentioned_username})
        if not target: raise HTTPException(404, "User not found")
        if target["id"] == u["id"]: return {"ok": True}
        _bg(_notify(target["id"], u, "mention", post_id=pid, push=("Mention 📢", u["name"] + " mentioned you in a post")))
        return {"ok": True}

    @api.post("/reels/{reel_id}/repost")
    async def repost_reel(reel_id: str, desired: Optional[bool] = Query(default=None), u=Depends(current_user)):
        reel = await _safe_media_find_one(
            db.reels, {"id": reel_id},
            scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
            projection={"_id": 0, "id": 1, "user_id": 1, "user_name": 1, "user_handle": 1, "reposts": 1, "audience": 1, "audience_users": 1},
        )
        if not reel:
            raise HTTPException(404, "Reel not found")
        owner = await _safe_user_find_one({"id": reel.get("user_id")})
        if not owner:
            raise HTTPException(404, "User not found")
        if reel.get("user_id") in (u.get("blocked_users") or []) or u["id"] in (owner.get("blocked_users") or []):
            raise HTTPException(403, "Action not allowed")
        if owner.get("is_private") and owner.get("id") != u["id"] and u["id"] not in (owner.get("followers") or []):
            raise HTTPException(403, "This reel is not available to you")
        if owner.get("id") != u["id"]:
            audience = reel.get("audience") or "public"
            if audience == "friends" and u["id"] not in (owner.get("followers") or []):
                raise HTTPException(403, "This reel is not available to you")
            if audience == "only_show" and u["id"] not in (reel.get("audience_users") or []):
                raise HTTPException(403, "This reel is not available to you")
            if audience not in ("public", "friends", "only_show"):
                raise HTTPException(403, "This reel is not available to you")

        relation_filter = {"reel_id": reel_id, "user_id": u["id"]}
        legacy_filter = {"reel_id": reel_id, "target_user_id": u["id"], "source_user_id": u["id"]}
        legacy, existing = await asyncio.gather(
            db.reel_mentions.find_one(legacy_filter, {"_id": 0, "id": 1}),
            db.reel_reposts.find_one(relation_filter, {"_id": 0}),
        )
        repost_ids = {str(value) for value in (reel.get("reposts") or []) if value is not None}
        already_reposted = bool(existing or legacy or str(u["id"]) in repost_ids)
        should_repost = (not already_reposted) if desired is None else desired

        if not should_repost:
            if already_reposted:
                removal_tasks = [
                    db.reel_reposts.delete_many(relation_filter),
                    db.reels.update_one({"id": reel_id}, {"$pull": {"reposts": u["id"]}}),
                ]
                if legacy and legacy.get("id"):
                    removal_tasks.extend([
                        db.reel_mentions.delete_one({"id": legacy["id"]}),
                        db.notifications.delete_many({"type": "reel_mention", "reel_id": reel_id, "user_id": u["id"], "from_user_id": u["id"]}),
                    ])
                await asyncio.gather(*removal_tasks)
                updated_reel = await db.reels.find_one({"id": reel_id}, {"_id": 0, "reposts": 1})
                repost_ids = {str(value) for value in ((updated_reel or {}).get("reposts") or []) if value is not None}
            return {"reposted": False, "repost_count": len(repost_ids)}

        created_at = now().isoformat()
        candidate = {
            "id": str(uuid.uuid4()), "reel_id": reel_id, "user_id": u["id"],
            "user_name": u.get("name"), "user_handle": u.get("handle"),
            "avatar_photo": u.get("avatar_photo"), "avatar_bg": u.get("avatar_bg"),
            "avatar_letter": u.get("avatar_letter"), "created_at": created_at,
        }
        relation_added = False
        if existing:
            relation_doc = existing
        else:
            try:
                insert_result = await db.reel_reposts.update_one(
                    relation_filter, {"$setOnInsert": candidate}, upsert=True
                )
                relation_added = insert_result.upserted_id is not None
                relation_doc = candidate if relation_added else await db.reel_reposts.find_one(relation_filter, {"_id": 0})
            except Exception as upsert_error:
                relation_doc = await db.reel_reposts.find_one(relation_filter, {"_id": 0})
                if not relation_doc:
                    raise upsert_error

        update_tasks = [db.reels.update_one({"id": reel_id}, {"$addToSet": {"reposts": u["id"]}})]
        if legacy and legacy.get("id"):
            update_tasks.extend([
                db.reel_mentions.delete_one({"id": legacy["id"]}),
                db.notifications.delete_many({"type": "reel_mention", "reel_id": reel_id, "user_id": u["id"], "from_user_id": u["id"]}),
            ])
        await asyncio.gather(*update_tasks)
        updated_reel = await db.reels.find_one({"id": reel_id}, {"_id": 0, "reposts": 1})
        repost_ids = {str(value) for value in ((updated_reel or {}).get("reposts") or []) if value is not None}

        if relation_added and not already_reposted and reel.get("user_id") != u["id"]:
            _bg(_notify(reel["user_id"], u, "reel_repost", reel_id=reel_id, push=("Repost", u.get("name", "Someone") + " reposted your reel")))
        return {"reposted": True, "repost": relation_doc, "repost_count": len(repost_ids)}

    @api.post("/reels/{reel_id}/mention")
    async def mention_in_reel(reel_id: str, body: dict, u=Depends(current_user)):
        """Save the original reel into another user's home/profile media feed.

        This is a reference, not a media copy: the target feed reads the
        source reel so the original photo/video URL and natural aspect ratio
        remain unchanged.
        """
        reel = await _safe_media_find_one(db.reels, {"id": reel_id}, scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"), overlay_fields=("sticker_overlays",), comment_fields=("comments",), projection={"_id": 0})
        if not reel or not await _viewer_can_access_item(reel, u):
            raise HTTPException(404, "Reel not found")
        raw_target_user_id = body.get("target_user_id")
        if not isinstance(raw_target_user_id, str):
            raise HTTPException(400, "Select exactly one user")
        target_user_id = raw_target_user_id.strip()
        if not target_user_id:
            raise HTTPException(400, "target_user_id required")
        target = await _safe_user_find_one({"id": target_user_id})
        if not target:
            raise HTTPException(404, "User not found")
        blocked_by_target = target_user_id in (u.get("blocked_users") or []) or u["id"] in (target.get("blocked_users") or [])
        if blocked_by_target:
            raise HTTPException(403, "Action not allowed")

        async def sync_mention_rank_stats(mention_count: int):
            try:
                await db.reel_rank_stats.update_one(
                    {"reel_id": reel_id},
                    {"$set": {"reel_id": reel_id, "mentions": mention_count, "updated_at": now().isoformat()}},
                    upsert=True,
                )
            except Exception:
                logging.exception("Could not refresh mention rank stats for reel %s", reel_id)

        mention = {
            "id": str(uuid.uuid4()),
            "reel_id": reel_id,
            "target_user_id": target_user_id,
            "source_user_id": u["id"],
            "source_user_name": u.get("name"),
            "source_user_handle": u.get("handle"),
            "source_user_avatar": u.get("avatar_photo"),
            "source_user_bg": u.get("avatar_bg"),
            "source_user_letter": u.get("avatar_letter"),
            "created_at": now().isoformat(),
        }
        existing_mention = await db.reel_mentions.find_one(
            {"reel_id": reel_id, "target_user_id": target_user_id},
            {"_id": 0, "source_user_id": 1},
        )
        if existing_mention:
            # Mentioning the same user again is a true toggle: only the user
            # who created this mention may remove it. A mention created by
            # somebody else must stay untouched.
            if existing_mention.get("source_user_id") == u["id"]:
                await db.reel_mentions.delete_one(
                    {"reel_id": reel_id, "target_user_id": target_user_id, "source_user_id": u["id"]}
                )
                await db.notifications.delete_many({
                    "type": "reel_mention",
                    "reel_id": reel_id,
                    "user_id": target_user_id,
                    "from_user_id": u["id"],
                })
                mention_count = await db.reel_mentions.count_documents({"reel_id": reel_id})
                await sync_mention_rank_stats(mention_count)
                return {"ok": True, "mentioned": False, "target_user_id": target_user_id, "reel_id": reel_id, "mention_count": mention_count}
            mention_count = await db.reel_mentions.count_documents({"reel_id": reel_id})
            await sync_mention_rank_stats(mention_count)
            return {"ok": True, "mentioned": True, "already": True, "target_user_id": target_user_id, "reel_id": reel_id, "mention_count": mention_count}

        await db.reel_mentions.insert_one(mention)
        if target_user_id != u["id"]:
            _bg(_notify(target_user_id, u, "reel_mention", reel_id=reel_id, push=("Mention", u.get("name", "Someone") + " mentioned you in a reel")))
        mention_count = await db.reel_mentions.count_documents({"reel_id": reel_id})
        await sync_mention_rank_stats(mention_count)
        # Sending a reel to ANOTHER user is a share (a self-repost to own feed is not).
        share_count = await _record_share(db.reels, reel_id, u["id"]) if target_user_id != u["id"] else None
        return {"ok": True, "target_user_id": target_user_id, "reel_id": reel_id, "mention_count": mention_count, "share_count": share_count}

    @api.delete("/reels/{reel_id}/mention/{target_user_id}")
    async def unmention_reel(reel_id: str, target_user_id: str, u=Depends(current_user)):
        if target_user_id == u["id"]:
            raise HTTPException(400, "Invalid target")
        reel = await db.reels.find_one({"id": reel_id}, {"_id": 0, "user_id": 1})
        if not reel:
            raise HTTPException(404, "Reel not found")
        if reel["user_id"] != u["id"] and not u.get("is_admin"):
            raise HTTPException(403, "Only the reel owner can remove a mention")
        await db.reel_mentions.delete_one({"reel_id": reel_id, "target_user_id": target_user_id})
        await db.notifications.delete_many({"type": "reel_mention", "reel_id": reel_id, "user_id": target_user_id})
        mention_count = await db.reel_mentions.count_documents({"reel_id": reel_id})
        await db.reel_rank_stats.update_one(
            {"reel_id": reel_id},
            {"$set": {"reel_id": reel_id, "mentions": mention_count, "updated_at": now().isoformat()}},
            upsert=True,
        )
        return {"ok": True, "mention_count": mention_count}


    @api.post("/posts/{pid}/report")
    async def report_post(pid: str, body: dict, u=Depends(current_user)):
        reason = (body.get("reason") or "").strip()
        if not reason: raise HTTPException(400, "Reason required")
        post = await db.posts.find_one({"id": pid}, {"_id": 0, "user_id": 1})
        if not post: raise HTTPException(404, "Post not found")
        already = await db.reports.find_one({"post_id": pid, "reported_by": u["id"]})
        if already: return {"ok": True, "already": True}
        await db.reports.insert_one({"id": str(uuid.uuid4()), "post_id": pid, "reported_by": u["id"], "reported_user_id": post.get("user_id"), "reason": reason, "created_at": now().isoformat(), "status": "pending"})
        return {"ok": True}
    @api.post("/report/general")
    async def report_general(body: dict, u=Depends(current_user)):
        report_type = (body.get("type") or "").strip()
        description = (body.get("description") or "").strip()
        username = (body.get("username") or "").strip()
        if not report_type: raise HTTPException(400, "Report type required")
        if not description or len(description) < 5: raise HTTPException(400, "Description too short")
        if len(description) > 2000: raise HTTPException(400, "Description too long")
        doc = {
            "id": str(uuid.uuid4()),
            "reported_by": u["id"],
            "reporter_handle": u.get("handle", ""),
            "type": report_type,
            "description": description,
            "target_username": username or None,
            "created_at": now().isoformat(),
            "status": "pending"
        }
        await db.general_reports.insert_one(doc)
        return {"ok": True, "message": "Report submitted. Our team will review it within 24 hours."}

    @api.delete("/users/me/reports/{report_id}")
    async def delete_my_report(report_id: str, u=Depends(current_user)):
        """Allow a user to remove only their own submitted report."""
        deleted = await db.reports.delete_one({"id": report_id, "reported_by": u["id"]})
        if deleted.deleted_count == 0:
            deleted = await db.general_reports.delete_one({"id": report_id, "reported_by": u["id"]})
        if deleted.deleted_count == 0:
            raise HTTPException(404, "Report not found")
        return {"ok": True}

    @api.get("/users/me/reports")
    async def get_my_reports(u=Depends(current_user)):
        """Return all reports submitted by the current user (general + content reports)."""
        gen_cursor = db.general_reports.find({"reported_by": u["id"]}, {"_id": 0}).sort("created_at", -1).limit(50)
        general_reports = await gen_cursor.to_list(50)
        content_cursor = db.reports.find({"reported_by": u["id"]}, {"_id": 0}).sort("created_at", -1).limit(50)
        content_reports = await content_cursor.to_list(50)
        all_reports = []
        for r in general_reports:
            r["report_kind"] = "general"
            all_reports.append(r)
        for r in content_reports:
            r["report_kind"] = r.get("type", "content")
            if not r.get("type"):
                r["type"] = "post" if r.get("post_id") else "reel"
            target_id = r.get("reported_user_id")
            if target_id:
                target = await _safe_user_find_one(
            {"id": target_id},
            {"_id": 0, "name": 1, "handle": 1, "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1},
        )
                if target:
                    r["reported_user"] = target
            source = None
            if r.get("post_id"):
                source = await _safe_media_find_one(db.posts, {"id": r["post_id"]}, scalar_fields=("photo_url", "video_url"), array_fields=("photo_urls",), projection={"_id": 0, "photo_urls": 1, "photo_url": 1, "video_url": 1})
            elif r.get("reel_id"):
                source = await _safe_media_find_one(db.reels, {"id": r["reel_id"]}, scalar_fields=("photo_url", "video_url"), array_fields=("photo_urls",), projection={"_id": 0, "photo_urls": 1, "photo_url": 1, "video_url": 1})
            if source:
                photos = source.get("photo_urls") or ([source.get("photo_url")] if source.get("photo_url") else [])
                if photos:
                    r["reported_media_url"] = photos[0]
                    r["reported_media_type"] = "image"
                elif source.get("video_url"):
                    r["reported_media_url"] = source["video_url"]
                    r["reported_media_type"] = "video"
            all_reports.append(r)
        all_reports.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return {"reports": all_reports[:50]}


    @api.post("/users/me/badge-request")
    async def request_badge(body: dict, u=Depends(current_user)):
        if u.get("is_badge_verified"): raise HTTPException(400, "Already verified")
        existing = await db.badge_requests.find_one({"user_id": u["id"], "status": "pending"})
        if existing: raise HTTPException(400, "A request is already pending review")
        await db.badge_requests.insert_one({"id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"], "user_handle": u.get("handle"), "reason": (body.get("reason") or "").strip(), "created_at": now().isoformat(), "status": "pending"})
        return {"ok": True}

    @api.get("/users/me/saved-posts")
    async def get_saved_posts(u=Depends(current_user)):
        user_id = u["id"]
        result = await _safe_media_find(db.posts, {"saves": user_id}, scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"), array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",), sort={"created_at": -1}, projection={"_id": 0}, limit=50)
        return {"posts": [_attach_counts(_p) for _p in result]}

    def _saved_collection_public(doc):
        if not isinstance(doc, dict):
            return None
        items = doc.get("items") if isinstance(doc.get("items"), list) else []
        return {
            "id": str(doc.get("id") or ""),
            "name": str(doc.get("name") or "Saved collection"),
            "items": [{"item_id": str(item.get("item_id")), "item_type": item.get("item_type")} for item in items if isinstance(item, dict) and item.get("item_id") and item.get("item_type") in {"post", "reel"}],
            "created_at": doc.get("created_at"),
            "updated_at": doc.get("updated_at"),
            "privacy": "only_me",
        }

    @api.get("/users/me/saved-items")
    async def get_saved_library_items(skip: int = Query(default=0), limit: int = Query(default=100), u=Depends(current_user)):
        skip = max(0, min(int(skip), 5000))
        limit = max(1, min(int(limit), 100))
        fetch_limit = min(skip + limit + 1, 5001)
        user_id = u["id"]
        posts, reels = await asyncio.gather(
            _safe_media_find(db.posts, {"saves": user_id}, scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"), array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",), sort={"created_at": -1}, projection={"_id": 0}, limit=fetch_limit),
            _safe_media_find(db.reels, {"saves": user_id, "moderation_status": {"$nin": ["flagged", "under_review", "removed"]}}, scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"), overlay_fields=("sticker_overlays",), comment_fields=("comments",), sort={"created_at": -1}, projection={"_id": 0}, limit=fetch_limit),
        )
        items = []
        for post in posts:
            post["is_reel"] = False
            items.append(_attach_counts(post))
        items.extend(_reel_to_feed_item(reel) for reel in reels)
        items.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        page = items[skip:skip + limit]
        return {"items": page, "has_more": len(items) > skip + limit, "skip": skip, "limit": limit}

    @api.get("/users/me/saved-planet")
    async def get_saved_planet(u=Depends(current_user)):
        docs = await db.saved_planet.find({"user_id": u["id"]}, {"_id": 0}).sort("saved_at", -1).limit(200).to_list(200)
        return {"items": docs}

    @api.post("/users/me/saved-planet/toggle")
    async def toggle_saved_planet(body: dict, u=Depends(current_user)):
        item = body.get("item") if isinstance(body.get("item"), dict) else {}
        planet_id = str(item.get("id") or "").strip()[:200]
        if not planet_id:
            raise HTTPException(400, "Missing Our Planet item id")
        key = {"user_id": u["id"], "planet_id": planet_id}
        if await db.saved_planet.find_one(key):
            await db.saved_planet.delete_one(key)
            return {"saved": False}
        def _num(v):
            try:
                f = float(v)
                return f if -1000 <= f <= 1000 else None
            except (TypeError, ValueError):
                return None
        photo = str(item.get("photo_url") or "")[:1000]
        if not photo.startswith("https://"):
            photo = ""
        doc = {
            "id": str(uuid.uuid4()), "user_id": u["id"], "planet_id": planet_id,
            "name": str(item.get("name") or planet_id)[:200],
            "entity_type": str(item.get("entity_type") or "")[:100],
            "description": str(item.get("description") or "")[:600],
            "photo_url": photo, "lat": _num(item.get("lat")), "lon": _num(item.get("lon")),
            "saved_at": now().isoformat(),
        }
        await db.saved_planet.insert_one(dict(doc))
        return {"saved": True}

    @api.get("/users/me/saved-collections")
    async def get_saved_collections(u=Depends(current_user)):
        docs = await db.saved_collections.find({"user_id": u["id"]}, {"_id": 0}).sort("updated_at", -1).limit(100).to_list(100)
        return {"collections": [_saved_collection_public(doc) for doc in docs]}

    @api.post("/users/me/saved-collections")
    async def create_saved_collection(body: dict, u=Depends(current_user)):
        name = str(body.get("name") or "").strip()
        if not name: raise HTTPException(400, "Collection name is required")
        if len(name) > 80: raise HTTPException(400, "Collection name must be 80 characters or fewer")
        user_id = u["id"]
        if await db.saved_collections.count_documents({"user_id": user_id}) >= 100: raise HTTPException(400, "You can create up to 100 collections")
        name_key = name.casefold()
        if await db.saved_collections.find_one({"user_id": user_id, "name_key": name_key}, {"_id": 1}): raise HTTPException(409, "A collection with that name already exists")
        stamp = now().isoformat()
        doc = {"id": str(uuid.uuid4()), "user_id": user_id, "name": name, "name_key": name_key, "items": [], "created_at": stamp, "updated_at": stamp}
        await db.saved_collections.insert_one(doc)
        return {"collection": _saved_collection_public(doc)}

    @api.get("/users/me/saved-collections/{collection_id}")
    async def get_saved_collection(collection_id: str, u=Depends(current_user)):
        doc = await db.saved_collections.find_one({"id": collection_id, "user_id": u["id"]}, {"_id": 0})
        if not doc: raise HTTPException(404, "Collection not found")
        refs = _saved_collection_public(doc)["items"]
        post_ids = [item["item_id"] for item in refs if item["item_type"] == "post"]
        reel_ids = [item["item_id"] for item in refs if item["item_type"] == "reel"]
        posts, reels = await asyncio.gather(
            _safe_media_find(db.posts, {"id": {"$in": post_ids}, "saves": u["id"]}, scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"), array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",), projection={"_id": 0}, limit=max(1, len(post_ids))),
            _safe_media_find(db.reels, {"id": {"$in": reel_ids}, "saves": u["id"], "moderation_status": {"$nin": ["flagged", "under_review", "removed"]}}, scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"), overlay_fields=("sticker_overlays",), comment_fields=("comments",), projection={"_id": 0}, limit=max(1, len(reel_ids))),
        )
        by_key = {}
        for post in posts:
            post["is_reel"] = False
            by_key["post:" + str(post.get("id"))] = _attach_counts(post)
        for reel in reels:
            shaped = _reel_to_feed_item(reel)
            by_key["reel:" + str(shaped.get("id"))] = shaped
        ordered = [by_key[key] for key in (item["item_type"] + ":" + item["item_id"] for item in refs) if key in by_key]
        return {"collection": _saved_collection_public(doc), "items": ordered}

    @api.post("/users/me/saved-collections/{collection_id}/items")
    async def add_saved_collection_item(collection_id: str, body: dict, u=Depends(current_user)):
        if not await db.saved_collections.find_one({"id": collection_id, "user_id": u["id"]}, {"_id": 1}): raise HTTPException(404, "Collection not found")
        item_id = str(body.get("item_id") or "").strip()
        item_type = str(body.get("item_type") or "post").strip().lower()
        if not item_id or item_type not in {"post", "reel"}: raise HTTPException(400, "A saved post or reel is required")
        media_collection = db.reels if item_type == "reel" else db.posts
        if not await media_collection.find_one({"id": item_id, "saves": u["id"]}, {"_id": 1}): raise HTTPException(404, "Save this item before adding it to a collection")
        ref = {"item_id": item_id, "item_type": item_type}
        await db.saved_collections.update_one({"id": collection_id, "user_id": u["id"]}, {"$addToSet": {"items": ref}, "$set": {"updated_at": now().isoformat()}})
        updated = await db.saved_collections.find_one({"id": collection_id, "user_id": u["id"]}, {"_id": 0})
        return {"collection": _saved_collection_public(updated), "added": True}

    @api.delete("/users/me/saved-collections/{collection_id}/items/{item_type}/{item_id}")
    async def remove_saved_collection_item(collection_id: str, item_type: str, item_id: str, u=Depends(current_user)):
        item_type = str(item_type or "").strip().lower()
        if item_type not in {"post", "reel"}: raise HTTPException(400, "Invalid saved item type")
        result = await db.saved_collections.update_one({"id": collection_id, "user_id": u["id"]}, {"$pull": {"items": {"item_id": item_id, "item_type": item_type}}, "$set": {"updated_at": now().isoformat()}})
        if not result.matched_count: raise HTTPException(404, "Collection not found")
        return {"ok": True}

    @api.delete("/users/me/saved-collections/{collection_id}")
    async def delete_saved_collection(collection_id: str, u=Depends(current_user)):
        result = await db.saved_collections.delete_one({"id": collection_id, "user_id": u["id"]})
        if not result.deleted_count: raise HTTPException(404, "Collection not found")
        return {"ok": True}

    @api.get("/users/{target_user_id}/mentioned-reels")
    async def get_user_mentioned_reels(target_user_id: str, skip: int = 0, limit: int = 50, u=Depends(current_user)):
        skip = max(0, min(skip, 10000))
        limit = max(1, min(limit, 50))
        target = await db.users.find_one(
            {"id": target_user_id},
            {"_id": 0, "id": 1, "is_private": 1, "followers": 1, "blocked_users": 1},
        )
        if not target:
            raise HTTPException(404, "User not found")
        if target_user_id in (u.get("blocked_users") or []) or u["id"] in (target.get("blocked_users") or []):
            return {"reels": [], "private_locked": True, "has_more": False, "skip": skip, "limit": limit, "total": 0}
        if target.get("is_private") and target_user_id != u["id"] and u["id"] not in (target.get("followers") or []):
            return {"reels": [], "private_locked": True, "has_more": False, "skip": skip, "limit": limit, "total": 0}

        mention_query = {"target_user_id": target_user_id}
        mention_rows = await db.reel_mentions.find(
            mention_query,
            {"_id": 0, "reel_id": 1, "source_user_id": 1, "source_user_name": 1, "source_user_handle": 1, "source_user_avatar": 1, "source_user_bg": 1, "source_user_letter": 1, "created_at": 1},
        ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
        total = await db.reel_mentions.count_documents(mention_query)
        if not mention_rows:
            return {"reels": [], "has_more": False, "skip": skip, "limit": limit, "total": total}

        reel_ids = list(dict.fromkeys(row.get("reel_id") for row in mention_rows if row.get("reel_id")))
        raw_reels = await _safe_media_find(
            db.reels,
            {"id": {"$in": reel_ids}, "moderation_status": {"$nin": ["flagged", "under_review", "removed"]}},
            scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
            overlay_fields=("sticker_overlays",),
            comment_fields=("comments",),
            projection={"_id": 0},
            limit=len(reel_ids),
        )
        reels_by_id = {str(reel.get("id")): reel for reel in raw_reels}
        owner_ids = list({str(reel.get("user_id") or "") for reel in raw_reels if reel.get("user_id")})
        author_rows = await db.users.find(
            {"id": {"$in": owner_ids}},
            {"_id": 0, "id": 1, "is_private": 1, "followers": 1},
        ).to_list(length=len(owner_ids)) if owner_ids else []
        authors_by_id = {str(author.get("id")): author for author in author_rows}
        excluded_ids = set((u.get("blocked_users") or []) + (u.get("muted_users") or []))
        following_ids = set(u.get("following") or [])
        result = []
        for mention in mention_rows:
            reel = reels_by_id.get(str(mention.get("reel_id") or ""))
            if not reel:
                continue
            owner_id = str(reel.get("user_id") or "")
            if owner_id in excluded_ids or not _reels_user_can_see(reel, u["id"], following_ids):
                continue
            author = authors_by_id.get(owner_id)
            if owner_id != u["id"] and (not author or (author.get("is_private") and u["id"] not in (author.get("followers") or []))):
                continue
            mentioned_by = {
                "id": mention.get("source_user_id"),
                "name": mention.get("source_user_name"),
                "handle": mention.get("source_user_handle"),
                "avatar_photo": mention.get("source_user_avatar"),
                "avatar_bg": mention.get("source_user_bg"),
                "avatar_letter": mention.get("source_user_letter"),
            }
            item = _reel_to_feed_item(reel, True, mentioned_by)
            item["mention_created_at"] = mention.get("created_at")
            result.append(item)
        return {"reels": result, "has_more": skip + len(mention_rows) < total, "skip": skip, "limit": limit, "total": total}


    @api.get("/users/{target_user_id}/tagged-posts")
    async def get_user_tagged_posts(target_user_id: str, skip: int = 0, limit: int = 50, u=Depends(current_user)):
        """Return visible posts and reels whose existing tagged_users include this profile."""
        skip = max(0, min(skip, 10000))
        limit = max(1, min(limit, 50))
        target = await db.users.find_one(
            {"id": target_user_id},
            {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
             "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1,
             "is_badge_verified": 1, "is_private": 1, "followers": 1,
             "blocked_users": 1},
        )
        if not target:
            raise HTTPException(404, "User not found")
        if target_user_id in (u.get("blocked_users") or []) or u["id"] in (target.get("blocked_users") or []):
            return {"posts": [], "private_locked": True, "has_more": False, "skip": skip, "limit": limit}
        if target.get("is_private") and target_user_id != u["id"] and u["id"] not in (target.get("followers") or []):
            return {"posts": [], "private_locked": True, "has_more": False, "skip": skip, "limit": limit}

        tag_handles = list(dict.fromkeys(
            str(value).strip().lstrip("@")
            for value in (target.get("handle"), target.get("username"))
            if isinstance(value, str) and value.strip()
        ))
        if not tag_handles:
            return {"posts": [], "has_more": False, "skip": skip, "limit": limit}
        tag_pattern = r"^@?(?:" + "|".join(re.escape(handle) for handle in tag_handles) + r")$"
        tag_filter = {"tagged_users": {"$elemMatch": {"$regex": tag_pattern, "$options": "i"}}}
        following_ids = list(dict.fromkeys(u.get("following") or []))
        excluded_user_ids = list(set((u.get("blocked_users") or []) + (u.get("muted_users") or [])))
        fetch_n = min(10001, skip + limit + 1)
        public_audience = {"$or": [{"audience": {"$exists": False}}, {"audience": "public"}]}
        visible_authors = {"$or": [
            {"user_id": u["id"]},
            {"$and": [{"_author.is_private": {"$ne": True}}, public_audience]},
            {"$and": [
                {"user_id": {"$in": following_ids}},
                {"audience": {"$nin": ["only_me", "only_show"]}},
            ]},
            {"$and": [
                {"_author.is_private": {"$ne": True}},
                {"audience": "only_show"},
                {"audience_users": u["id"]},
            ]},
        ]}
        author_safety = {"$and": [
            {"user_id": {"$nin": excluded_user_ids}},
            visible_authors,
            {"$nor": [{"_author.blocked_users": u["id"]}]},
        ]}
        legacy_media_filter = {"$nor": [
            {"video_url": {"$regex": "^data:"}},
            {"photo_url": {"$regex": "^data:"}},
            {"photo_urls": {"$elemMatch": {"$regex": "^data:"}}},
        ]}
        post_rows = await db.posts.aggregate([
            {"$match": {"$and": [tag_filter, legacy_media_filter]}},
            {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "id", "as": "_author"}},
            {"$match": author_safety},
            {"$sort": {"created_at": -1}},
            {"$limit": fetch_n},
            _safe_media_sanitize_stage(
                scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"),
                array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",),
            ),
            {"$project": {"_id": 0, "_author": 0}},
        ]).to_list(fetch_n)
        reel_rows = await db.reels.aggregate([
            {"$match": {"$and": [
                tag_filter,
                legacy_media_filter,
                {"moderation_status": {"$nin": ["flagged", "under_review", "removed"]}},
            ]}},
            {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "id", "as": "_author"}},
            {"$match": author_safety},
            {"$sort": {"created_at": -1}},
            {"$limit": fetch_n},
            _safe_media_sanitize_stage(
                scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
                overlay_fields=("sticker_overlays",), comment_fields=("comments",),
            ),
            {"$project": {"_id": 0, "_author": 0}},
        ]).to_list(fetch_n)

        tagged_user = {field: target.get(field) for field in (
            "id", "name", "handle", "username", "avatar_photo", "avatar_bg", "avatar_letter", "is_badge_verified"
        )}
        combined = []
        for post in post_rows:
            post["tagged_user"] = tagged_user
            combined.append(_attach_counts(post))
        for reel in reel_rows:
            item = _reel_to_feed_item(reel)
            item["is_reel"] = True
            item["tagged_users"] = reel.get("tagged_users") or []
            item["tagged_user"] = tagged_user
            combined.append(item)
        combined.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        page = combined[skip:skip + limit]
        return {
            "posts": page,
            "has_more": len(combined) > skip + limit,
            "skip": skip,
            "limit": limit,
        }

    @api.get("/users/{target_user_id}/saved-posts")
    async def get_user_saved_posts(target_user_id: str, u=Depends(current_user)):
        target = await db.users.find_one({"id": target_user_id}, {"_id": 0, "id": 1, "is_private": 1, "followers": 1})
        if not target:
            raise HTTPException(404, "User not found")
        if target.get("is_private") and target_user_id != u["id"] and u["id"] not in (target.get("followers") or []):
            return {"posts": [], "private_locked": True}
        result = await _safe_media_find(db.posts, {"saves": target_user_id}, scalar_fields=("photo_url", "video_url", "avatar_photo", "gif_url", "music_artwork", "music_preview_url", "thumbnail_url"), array_fields=("photo_urls",), overlay_fields=("sticker_overlays",), comment_fields=("comments",), sort={"created_at": -1}, projection={"_id": 0}, limit=50)
        return {"posts": [_attach_counts(_p) for _p in result]}

    # ── Friends ───────────────────────────────────────────────────
    @api.post("/friends/request")
    async def friend_request(p: FriendIn, u=Depends(current_user)):
        if p.target_user_id == u["id"]: raise HTTPException(400, "Can't friend yourself")
        target = await _safe_user_find_one({"id": p.target_user_id})
        if not target: raise HTTPException(404, "User not found")
        if target.get("account_type") == "organisation":
            raise HTTPException(400, "You can only follow organisation accounts, not connect")
        # Verified users CAN receive connect requests: the request goes to their notifications,
        # and chat unlocks only after they accept (enforced in send_message).
        existing = await db.friend_requests.find_one({"from_id": u["id"], "to_id": p.target_user_id})
        if existing: return {"status": existing["status"]}
        already_accepted = await db.friend_requests.find_one({
            "$or": [
                {"from_id": u["id"], "to_id": p.target_user_id, "status": "accepted"},
                {"from_id": p.target_user_id, "to_id": u["id"], "status": "accepted"},
            ]
        })
        if already_accepted: return {"status": "accepted"}
        await db.friend_requests.insert_one({
            "id": str(uuid.uuid4()), "from_id": u["id"], "to_id": p.target_user_id,
            "status": "pending", "created_at": now().isoformat(),
        })
        _bg(_notify(p.target_user_id, u, "friend_request", push=("Connect request", u["name"] + " sent you a connect request")))
        return {"status": "pending"}

    @api.post("/friends/accept")
    async def friend_accept(p: FriendIn, u=Depends(current_user)):
        _res = await db.friend_requests.update_one(
            {"from_id": p.target_user_id, "to_id": u["id"], "status": "pending"},
            {"$set": {"status": "accepted"}},
        )
        # Delete the notification from DB so it never reappears
        await db.notifications.delete_one(
            {"user_id": u["id"], "from_user_id": p.target_user_id, "type": "friend_request"}
        )
        if _res.matched_count:
            _bg(_notify(p.target_user_id, u, "friend_accept", push=("Connect accepted", u["name"] + " accepted your connect request")))
        return {"ok": True}

    @api.post("/friends/decline")
    async def friend_decline(p: FriendIn, u=Depends(current_user)):
        await db.friend_requests.delete_one({"from_id": p.target_user_id, "to_id": u["id"]})
        # Delete the notification from DB so it never reappears
        await db.notifications.delete_one(
            {"user_id": u["id"], "from_user_id": p.target_user_id, "type": "friend_request"}
        )
        return {"ok": True}

    @api.post("/friends/cancel")
    async def friend_cancel(p: FriendIn, u=Depends(current_user)):
        await db.friend_requests.delete_one({"from_id": u["id"], "to_id": p.target_user_id})
        await db.notifications.delete_many({"user_id": p.target_user_id, "from_user_id": u["id"], "type": "friend_request"})
        return {"ok": True}

    @api.get("/friends")
    async def list_friends(u=Depends(current_user)):
        accepted = await db.friend_requests.find(
            {"$or": [{"from_id": u["id"], "status": "accepted"}, {"to_id": u["id"], "status": "accepted"}]},
            {"_id": 0},
        ).to_list(500)
        friend_ids  = [r["to_id"] if r["from_id"] == u["id"] else r["from_id"] for r in accepted]
        pending_in  = await db.friend_requests.find({"to_id": u["id"], "status": "pending"}, {"_id": 0}).to_list(500)
        pending_out = await db.friend_requests.find({"from_id": u["id"], "status": "pending"}, {"_id": 0}).to_list(500)
        PUBLIC_FIELDS = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
                         "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1,
                         "category": 1, "location": 1, "about": 1, "cover_photo": 1,
                         "stats": 1, "following": 1}
        friends = await _safe_user_find({"id": {"$in": friend_ids}}, PUBLIC_FIELDS, limit=500)
        in_from_ids  = [r["from_id"] for r in pending_in]
        out_to_ids   = [r["to_id"]   for r in pending_out]
        in_users_list  = await _safe_user_find({"id": {"$in": in_from_ids}}, PUBLIC_FIELDS, limit=500) if in_from_ids else []
        out_users_list = await _safe_user_find({"id": {"$in": out_to_ids}}, PUBLIC_FIELDS, limit=500) if out_to_ids else []
        in_users  = {usr["id"]: usr for usr in in_users_list}
        out_users = {usr["id"]: usr for usr in out_users_list}
        for r in pending_in:  r["from_user"] = in_users.get(r["from_id"], {})
        for r in pending_out: r["to_user"]   = out_users.get(r["to_id"], {})
        return {"friends": friends, "pending_incoming": pending_in, "pending_outgoing": pending_out}

    # ── WebSocket connection manager ────────────────────────────────
    _ws_connections: dict = {}   # user_id → WebSocket

    async def _ws_push(user_id: str, payload: dict) -> bool:
        """Push a JSON payload to a connected user's WebSocket. Returns True if sent."""
        ws = _ws_connections.get(user_id)
        if not ws:
            return False
        try:
            await ws.send_text(_json.dumps(payload))
            return True
        except Exception:
            _ws_connections.pop(user_id, None)
            return False

    @app.websocket("/ws/{user_id}")
    async def ws_endpoint(websocket: WebSocket, user_id: str):
        """Persistent WebSocket per user for real-time messaging."""
        # ── Authenticate via ?token= query param ─────────────────
        token_val = websocket.query_params.get("token", "")
        try:
            payload = jwt.decode(token_val, JWT_SECRET, algorithms=["HS256"])
            if payload.get("sub") != user_id:
                await websocket.close(code=4001)
                return
        except Exception:
            await websocket.close(code=4001)
            return

        await websocket.accept()
        _ws_connections[user_id] = websocket
        await db.users.update_one(
            {"id": user_id},
            {"$set": {"is_online": True, "last_seen": now().isoformat()}}
        )
        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    data = _json.loads(raw)
                except Exception:
                    continue   # ignore malformed frames

                msg_type = data.get("type", "")

                # ── delivered ACK: receiver got message via WS ────
                if msg_type == "delivered":
                    msg_id = data.get("msg_id", "")
                    if not msg_id:
                        continue
                    msg = await db.messages.find_one(
                        {"id": msg_id},
                        {"_id": 0, "from_id": 1, "to_id": 1, "status": 1}
                    )
                    # Only upgrade if we are the intended receiver and status is still "sent"
                    if msg and msg.get("to_id") == user_id and msg.get("status") == "sent":
                        await db.messages.update_one(
                            {"id": msg_id},
                            {"$set": {"status": "delivered", "delivered_at": now().isoformat()}}
                        )
                        # Notify sender: their ✓ upgrades to ✓✓ grey
                        await _ws_push(msg["from_id"], {
                            "type": "status_update",
                            "msg_id": msg_id,
                            "status": "delivered",
                        })

                # ── seen ACK: receiver opened the chat ────────────
                elif msg_type == "seen":
                    partner_id = data.get("partner_id", "")
                    if not partner_id:
                        continue
                    unseen = await db.messages.find(
                        {
                            "from_id": partner_id,
                            "to_id": user_id,
                            "status": {"$ne": "seen"},
                            "deleted_for_everyone": {"$ne": True},
                        },
                        {"_id": 0, "id": 1}
                    ).to_list(500)
                    ids = [m["id"] for m in unseen]
                    if ids:
                        await db.messages.update_many(
                            {"id": {"$in": ids}},
                            {"$set": {"status": "seen", "seen_at": now().isoformat()}}
                        )
                        # Notify sender: their ✓✓ turns blue
                        await _ws_push(partner_id, {
                            "type": "bulk_seen",
                            "msg_ids": ids,
                            "by_user_id": user_id,
                        })

                # ── typing indicator: DM or group chat ─────────────
                elif msg_type == "typing":
                    to_uid = data.get("to_user_id", "")
                    group_id = data.get("group_id", "")
                    is_t = bool(data.get("is_typing", True))
                    if group_id:
                        group = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1})
                        if not group or user_id not in group.get("members", []):
                            continue
                        payload = {"type": "typing", "group_id": group_id, "from_user_id": user_id, "is_typing": is_t}
                        await asyncio.gather(*[_ws_push(member_id, payload) for member_id in group.get("members", []) if member_id != user_id])
                    elif to_uid:
                        await _ws_push(to_uid, {"type": "typing", "from_user_id": user_id, "is_typing": is_t})

                    # ── ping / keepalive — no-op ──────────────────────
                elif msg_type == "ping":
                    pass

        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            _ws_connections.pop(user_id, None)
            await db.users.update_one(
                {"id": user_id},
                {"$set": {"is_online": False, "last_seen": now().isoformat()}}
            )

    # ── Live counters (WebSocket) ───────────────────────────────────
    # Separate endpoint on purpose: /ws/{user_id} keeps ONE socket per user for
    # chat/online-status, so a second connection there would evict it.
    #
    # Memory/CPU safe by design:
    #  * clients only receive items they explicitly "watch" (capped per client)
    #  * an item nobody watches costs nothing (no DB read, no queue entry)
    #  * bursts are batched: at most one count query per second, one message per client
    #  * counts are computed with $size in Mongo, comments arrays are never loaded
    _LIVE_MAX_CLIENTS   = int(os.environ.get("LIVE_MAX_CLIENTS", "3000"))
    _LIVE_MAX_PER_USER  = 3
    _LIVE_MAX_WATCH     = 200
    _LIVE_FLUSH_SECONDS = float(os.environ.get("LIVE_FLUSH_SECONDS", "1.0"))
    _live_clients: dict  = {}   # key -> {"ws", "uid", "watch": set(item_id)}
    _live_watchers: dict = {}   # item_id -> set(key)
    _live_pending: set   = set()
    _live_state: dict    = {"task": None, "seq": 0}

    def _live_unwatch_all(key):
        client = _live_clients.get(key)
        if not client:
            return
        for item_id in client["watch"]:
            keys = _live_watchers.get(item_id)
            if keys:
                keys.discard(key)
                if not keys:
                    _live_watchers.pop(item_id, None)
        client["watch"] = set()

    def _live_set_watch(key, ids):
        client = _live_clients.get(key)
        if not client:
            return
        new = set()
        for item_id in (ids or [])[:_LIVE_MAX_WATCH]:
            if isinstance(item_id, str) and 0 < len(item_id) <= 64:
                new.add(item_id)
        old = client["watch"]
        for item_id in old - new:
            keys = _live_watchers.get(item_id)
            if keys:
                keys.discard(key)
                if not keys:
                    _live_watchers.pop(item_id, None)
        for item_id in new - old:
            _live_watchers.setdefault(item_id, set()).add(key)
        client["watch"] = new

    def _live_drop(key):
        _live_unwatch_all(key)
        _live_clients.pop(key, None)

    def _live_mark(item_id):
        """Called after any like/comment/save/repost/share/view. No-op unless someone watches the item."""
        if item_id in _live_watchers:
            _live_pending.add(item_id)

    def _live_size(field):
        return {"$size": {"$cond": [{"$isArray": "$" + field}, "$" + field, []]}}

    def _live_int(field):
        return {"$convert": {"input": "$" + field, "to": "int", "onError": 0, "onNull": 0}}

    _LIVE_PROJECTION = {
        "_id": 0, "id": 1,
        "like_count":    _live_size("likes"),
        "comment_count": {"$max": [_live_size("comments"), _live_int("comment_count")]},
        "repost_count":  _live_size("reposts"),
        "share_count":   {"$max": [_live_size("shares"), _live_int("share_count")]},
        "save_count":    {"$max": [_live_size("saves"), _live_int("save_count")]},
        "view_count":    {"$max": [
            {"$size": {"$setUnion": [{"$cond": [{"$isArray": "$views"}, "$views", []]}, []]}},
            _live_int("view_count"),
        ]},
    }

    async def _live_flush_once():
        if not _live_pending:
            return
        ids = list(_live_pending)[:200]
        for item_id in ids:
            _live_pending.discard(item_id)
        rows = {}
        for collection in (db.posts, db.reels):
            try:
                cursor = collection.aggregate([{"$match": {"id": {"$in": ids}}}, {"$project": _LIVE_PROJECTION}])
                async for row in cursor:
                    rows[row["id"]] = {k: int(v or 0) for k, v in row.items() if k != "id"}
            except Exception:
                logging.exception("live counts query failed")
        per_client = {}
        for item_id, counts in rows.items():
            for key in list(_live_watchers.get(item_id, ())):
                per_client.setdefault(key, []).append(dict(counts, id=item_id))
        for key, items in per_client.items():
            client = _live_clients.get(key)
            if not client:
                continue
            try:
                await client["ws"].send_text(_json.dumps({"type": "counts", "items": items}))
            except Exception:
                _live_drop(key)

    async def _live_flusher():
        while True:
            await asyncio.sleep(_LIVE_FLUSH_SECONDS)
            if not _live_clients:
                _live_pending.clear()
                _live_state["task"] = None
                return
            try:
                await _live_flush_once()
            except Exception:
                logging.exception("live flusher error")

    @app.websocket("/ws-live/{user_id}")
    async def ws_live_endpoint(websocket: WebSocket, user_id: str):
        token_val = websocket.query_params.get("token", "")
        try:
            payload = jwt.decode(token_val, JWT_SECRET, algorithms=["HS256"])
            if payload.get("sub") != user_id:
                await websocket.close(code=4001)
                return
        except Exception:
            await websocket.close(code=4001)
            return
        mine = [k for k, c in _live_clients.items() if c["uid"] == user_id]
        if len(_live_clients) >= _LIVE_MAX_CLIENTS or len(mine) >= _LIVE_MAX_PER_USER:
            if len(mine) >= _LIVE_MAX_PER_USER:
                _stale = _live_clients.get(mine[0])    # newest tab wins, never grow past the cap
                _live_drop(mine[0])
                try:
                    if _stale:
                        await _stale["ws"].close(code=1000)
                except Exception:
                    pass
            else:
                await websocket.close(code=1013)
                return
        await websocket.accept()
        _live_state["seq"] += 1
        key = _live_state["seq"]
        _live_clients[key] = {"ws": websocket, "uid": user_id, "watch": set()}
        task = _live_state.get("task")
        if task is None or task.done():
            _live_state["task"] = asyncio.create_task(_live_flusher())
        try:
            while True:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=120)
                try:
                    data = _json.loads(raw)
                except Exception:
                    continue
                msg_type = data.get("type", "") if isinstance(data, dict) else ""
                if msg_type == "watch":
                    ids = data.get("ids")
                    before = set((_live_clients.get(key) or {}).get("watch", ()))
                    _live_set_watch(key, ids if isinstance(ids, list) else [])
                    # snapshot only the newly watched items so a fresh screen is correct at once
                    for item_id in (_live_clients.get(key) or {}).get("watch", set()) - before:
                        _live_pending.add(item_id)
                # "ping" and anything else: keepalive only
        except Exception:
            pass
        finally:
            _live_drop(key)

    _LIVE_ROUTE = re.compile(r"^/api/(?:posts|reels)/([^/]+)/(?:like|comments|save|repost-to-friend|repost|share|view)(?:/|$)")

    @app.middleware("http")
    async def _live_counts_middleware(request: Request, call_next):
        response = await call_next(request)
        try:
            if _live_watchers and request.method in ("POST", "DELETE") and response.status_code < 400:
                match = _LIVE_ROUTE.match(request.url.path)
                if match:
                    _live_mark(match.group(1))
        except Exception:
            pass
        return response

    # ── Messages ──────────────���───────────────────────────────────

    @api.post("/messages")
    async def send_message(p: MessageIn, u=Depends(current_user)):
        """Save message to DB, then push to receiver via WebSocket if online."""
        for field, value in (("photo_url", p.photo_url), ("gif_url", p.gif_url), ("audio_url", p.audio_url)):
            _reject_inline_data_uri(value, field)
        file_fields = _clean_chat_file(p.file_url, p.file_name, p.file_size, p.file_type)
        if not p.text.strip() and not p.photo_url and not p.gif_url and not p.shared_post_id and not p.shared_reel_id and not p.audio_url and not file_fields["file_url"]:
            raise HTTPException(400, "Message cannot be empty")
        recipient = await db.users.find_one({"id": p.to_user_id})
        if not recipient:
            raise HTTPException(404, "Recipient not found")
        if u["id"] in recipient.get("blocked_users", []) or p.to_user_id in u.get("blocked_users", []):
            raise HTTPException(403, "Cannot message this user")
        direct_to_verified = bool(recipient.get("is_badge_verified") and not u.get("is_badge_verified"))

        # Cross-continent rule: must follow each other or be connected friends
        same_continent = (
            (u.get("continent") or "").strip() == (recipient.get("continent") or "").strip()
            and bool(u.get("continent"))
        )
        if not same_continent and not direct_to_verified:
            sender_follows    = p.to_user_id in (u.get("following") or [])
            recipient_follows = u["id"] in (recipient.get("followers") or [])
            if not (sender_follows or recipient_follows):
                fr = await db.friend_requests.find_one({
                    "status": "accepted",
                    "$or": [
                        {"from_id": u["id"], "to_id": p.to_user_id},
                        {"from_id": p.to_user_id, "to_id": u["id"]},
                    ],
                })
                if not fr:
                    raise HTTPException(403, "Connect with this user first to message across countries")

        # ── Build reply-to preview ────────────────────────────────
        reply_to_preview = None
        if p.reply_to_id:
            ref_rows = await db.messages.aggregate([
                {"$match": {"id": p.reply_to_id}},
                {"$project": {"_id": 0, "text": 1, "from_name": 1, "from_id": 1, "has_photo": {"$and": [{"$ne": [{"$ifNull": ["$photo_url", None]}, None]}, {"$ne": ["$photo_url", ""]}]}, "has_audio": {"$and": [{"$ne": [{"$ifNull": ["$audio_url", None]}, None]}, {"$ne": ["$audio_url", ""]}]}, "has_gif": {"$and": [{"$ne": [{"$ifNull": ["$gif_url", None]}, None]}, {"$ne": ["$gif_url", ""]}]}}},
            ]).to_list(1)
            ref = ref_rows[0] if ref_rows else None
            if ref:
                reply_to_preview = {
                    "id":       p.reply_to_id,
                    "from_name": ref.get("from_name", ""),
                    "from_id":  ref.get("from_id", ""),
                    "text":     (ref.get("text") or "")[:120],
                    "has_photo": bool(ref.get("has_photo")),
                    "has_audio": bool(ref.get("has_audio")),
                    "has_gif": bool(ref.get("has_gif")),
                }

        # ── Build shared-post preview ─────────────────────────────
        shared_post = None
        if p.shared_post_id:
            sp = await _safe_media_find_one(
                db.posts, {"id": p.shared_post_id},
                scalar_fields=("photo_url", "avatar_photo"), array_fields=("photo_urls",),
                projection={"_id": 0, "id": 1, "content": 1, "photo_url": 1, "photo_urls": 1,
                            "user_name": 1, "user_handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1,
                            **_SHARE_ACCESS_FIELDS},
            )
            if sp and await _viewer_can_access_item(sp, u):
                shared_post = {
                    "id":           sp["id"],
                    "content":      (sp.get("content") or "")[:200],
                    "photo_url":    sp.get("photo_url") or ((sp.get("photo_urls") or [None])[0]),
                    "user_name":    sp.get("user_name", ""),
                    "user_handle":  sp.get("user_handle", ""),
                    "avatar_bg":    sp.get("avatar_bg", ""),
                    "avatar_letter": sp.get("avatar_letter", ""),
                    "avatar_photo": sp.get("avatar_photo"),
                    "type": "post",
                }
                await _record_share(db.posts, sp["id"], u["id"])

        # ── Build shared-reel preview ─────────────────────────────
        shared_reel = None
        if p.shared_reel_id:
            sr = await _safe_media_find_one(
                db.reels, {"id": p.shared_reel_id}, scalar_fields=("video_url", "avatar_photo"),
                projection={"_id": 0, "id": 1, "caption": 1, "video_url": 1,
                            "user_name": 1, "user_handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1,
                            **_SHARE_ACCESS_FIELDS},
            )
            if sr and await _viewer_can_access_item(sr, u):
                shared_reel = {
                    "id":           sr["id"],
                    "caption":      (sr.get("caption") or "")[:200],
                    "video_url":    sr.get("video_url"),
                    "user_name":    sr.get("user_name", ""),
                    "user_handle":  sr.get("user_handle", ""),
                    "avatar_bg":    sr.get("avatar_bg", ""),
                    "avatar_letter": sr.get("avatar_letter", ""),
                    "avatar_photo": sr.get("avatar_photo"),
                    "type": "reel",
                }
                await _record_share(db.reels, sr["id"], u["id"])

        # ── Assemble message document ─────────────────────────────
        m = {
            "id":               str(uuid.uuid4()),
            "from_id":          u["id"],
            "from_name":        u["name"],
            "to_id":            p.to_user_id,
            "text":             p.text,
            "photo_url":        p.photo_url,
            "gif_url":          p.gif_url,
            "mood_color":       p.mood_color,
            "created_at":       now().isoformat(),
            "status":           "sent",           # ✓ — server received
            "deleted_for":      [],
            "deleted_for_everyone": False,
            "reply_to_id":      p.reply_to_id or None,
            "reply_to_preview": reply_to_preview,
            "shared_post":      shared_post,
            "shared_reel":      shared_reel,
            "audio_url":        p.audio_url or None,
            "audio_duration":   p.audio_duration or None,
            **file_fields,
            "edited":           False,
        }
        await db.messages.insert_one(m.copy())
        m.pop("_id", None)

        # Keep direct messages in the same user-activity notification stream
        # as likes, comments, follows, tags, and mentions.
        message_preview = p.text.strip() if p.text and p.text.strip() else (
            "📷 Photo" if p.photo_url else
            ("GIF" if p.gif_url else
            ("📎 Post" if p.shared_post_id or p.shared_reel_id else
            ("🎤 Voice" if p.audio_url else ("📎 " + file_fields["file_name"] if file_fields["file_url"] else "Message"))))
        )
        await _persist_user_activity_notification(
            p.to_user_id, u, "message", message=message_preview[:120], message_id=m["id"]
        )

        # ── Push to receiver via WebSocket ────────────────────────
        # Receiver client will reply with a "delivered" ACK that upgrades
        # the status to "delivered" (✓✓ grey) and notifies the sender.
        await _ws_push(p.to_user_id, {"type": "new_message", "message": m})

        return m

    @api.get("/messages/conversations")
    async def get_conversations(u=Depends(current_user)):
        pipeline = [
            {"$match": {
                "$or": [{"from_id": u["id"]}, {"to_id": u["id"]}],
                "deleted_for_everyone": {"$ne": True},
                "deleted_for": {"$nin": [u["id"]]},
            }},
            {"$sort": {"created_at": -1}},
            {"$project": {
                "_id": 0,
                "other_id": {"$cond": [{"$eq": ["$from_id", u["id"]]}, "$to_id", "$from_id"]},
                "text": {"$cond": [
                    {"$and": [
                        {"$eq": [{"$strLenCP": {"$trim": {"input": {"$ifNull": ["$text", ""]}}}}, 0]},
                        {"$gt": [{"$strLenCP": {"$ifNull": ["$file_url", ""]}}, 0]},
                    ]},
                    {"$concat": ["📎 ", {"$ifNull": ["$file_name", "File"]}]},
                    "$text",
                ]},
                "photo_url": 1, "gif_url": 1, "shared_post_id": 1, "shared_reel_id": 1, "audio_url": 1, "created_at": 1, "status": 1, "from_id": 1, "mood_color": 1,
            }},
            {"$group": {
                "_id":         "$other_id",
                "last_text":   {"$first": "$text"},
                "last_photo":  {"$first": "$photo_url"},
                "last_gif":    {"$first": "$gif_url"},
                "last_shared_post": {"$first": "$shared_post_id"},
                "last_shared_reel": {"$first": "$shared_reel_id"},
                "last_audio":  {"$first": "$audio_url"},
                "last_time":   {"$first": "$created_at"},
                "last_status": {"$first": "$status"},
                "last_from":   {"$first": "$from_id"},
                "last_mood":   {"$first": "$mood_color"},
            }},
        ]
        pipeline.append(_safe_media_sanitize_stage(scalar_fields=("last_photo", "last_gif", "last_audio")))
        convs      = await db.messages.aggregate(pipeline).to_list(200)
        user_ids   = [c["_id"] for c in convs]
        pub = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
               "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1,
               "followers": 1, "following": 1,
               "is_badge_verified": 1, "is_online": 1, "last_seen": 1}
        users_list = await _safe_user_find({"id": {"$in": user_ids}}, pub, limit=200)
        for uu in users_list:
            uu["followers_count"] = len(uu.get("followers") or [])
            uu["following_count"] = len(uu.get("following") or [])
            uu.pop("followers", None)
            uu.pop("following", None)
        users_map  = {uu["id"]: _apply_presence_visibility(uu, u) for uu in users_list}

        async def _unread(cid: str) -> int:
            return await db.messages.count_documents({
                "from_id": cid, "to_id": u["id"],
                "status": {"$ne": "seen"},
                "deleted_for_everyone": {"$ne": True},
                "deleted_for": {"$nin": [u["id"]]},
            })

        unread_counts = await asyncio.gather(*[_unread(c["_id"]) for c in convs])
        for c, uc in zip(convs, unread_counts):
            partner_user = users_map.get(c["_id"], {})
            c["user"] = partner_user
            c["unread"] = uc
            if not (partner_user.get("is_badge_verified") and not u.get("is_badge_verified")):
                c["is_partner_online"] = c["_id"] in _ws_connections
            else:
                c.pop("is_partner_online", None)
        convs.sort(key=lambda x: x.get("last_time", ""), reverse=True)
        return {"conversations": convs}

    @api.get("/messages/unread-count")
    async def get_msg_unread_count(u=Depends(current_user)):
        count = await db.messages.count_documents({
            "to_id": u["id"],
            "status": {"$ne": "seen"},
            "deleted_for_everyone": {"$ne": True},
        })
        return {"unread_count": count}

    @api.get("/messages")
    async def list_messages(
        with_user: Optional[str] = Query(None, max_length=64), skip: int = Query(0, ge=0, le=100000), limit: int = Query(50, ge=1, le=100),
        u=Depends(current_user),
    ):
        if with_user:
            q = {"$or": [
                {"from_id": u["id"], "to_id": with_user},
                {"from_id": with_user, "to_id": u["id"]},
            ]}
        else:
            q = {"$or": [{"from_id": u["id"]}, {"to_id": u["id"]}]}
        # Filter deleted messages at MongoDB level so skip/limit work on already-filtered results.
        # This is the critical fix: previously, skip/limit ran first then Python filtered,
        # meaning cleared messages could re-appear when the conversation was re-opened.
        fq = {**q, "deleted_for": {"$ne": u["id"]}, "deleted_for_everyone": {"$ne": True}}
        msgs = await _safe_media_find(
            db.messages, fq,
            scalar_fields=("photo_url", "gif_url", "audio_url", "from_avatar_photo", "shared_post.photo_url", "shared_post.avatar_photo"),
            projection={"_id": 0}, sort={"created_at": 1}, skip=skip, limit=limit,
        )
        total = await db.messages.count_documents(fq)
        return {"messages": msgs, "total": total, "skip": skip, "limit": limit}

    @api.delete("/messages/{msg_id}")
    async def delete_message(msg_id: str, delete_for: str = "self", u=Depends(current_user)):
        msg = await db.messages.find_one({"id": msg_id}, {"_id": 0, "from_id": 1, "to_id": 1})
        if not msg:
            raise HTTPException(404, "Message not found")
        if delete_for == "everyone":
            if msg["from_id"] != u["id"]:
                raise HTTPException(403, "Only sender can delete for everyone")
            await db.messages.update_one(
                {"id": msg_id},
                {"$set": {"deleted_for_everyone": True, "text": "", "photo_url": None, "audio_url": None, "file_url": None, "file_name": None}}
            )
        else:
            await db.messages.update_one({"id": msg_id}, {"$addToSet": {"deleted_for": u["id"]}})
        return {"ok": True}

    MAX_EDIT_TEXT_LEN = 5000

    @api.patch("/messages/{msg_id}")
    async def edit_message(msg_id: str, p: MessageEditIn, u=Depends(current_user)):
        """Edit the text of one of your own direct messages."""
        new_text = (p.text or "").strip()
        if not new_text:
            raise HTTPException(400, "Message cannot be empty")
        if len(new_text) > MAX_EDIT_TEXT_LEN:
            raise HTTPException(400, "Message is too long")
        msg = await db.messages.find_one({"id": msg_id}, {"_id": 0, "from_id": 1, "to_id": 1, "text": 1, "deleted_for_everyone": 1})
        if not msg:
            raise HTTPException(404, "Message not found")
        if msg.get("from_id") != u["id"]:
            raise HTTPException(403, "You can only edit your own messages")
        if msg.get("deleted_for_everyone"):
            raise HTTPException(400, "This message was deleted")
        if not (msg.get("text") or "").strip():
            raise HTTPException(400, "Only text messages can be edited")
        edited_at = now().isoformat()
        if new_text != (msg.get("text") or ""):
            await db.messages.update_one({"id": msg_id}, {"$set": {"text": new_text, "edited": True, "edited_at": edited_at}})
            # keep quoted previews of this message in sync
            await db.messages.update_many({"reply_to_id": msg_id}, {"$set": {"reply_to_preview.text": new_text[:120]}})
        payload = {"type": "message_edited", "msg_id": msg_id, "text": new_text, "edited": True, "edited_at": edited_at,
                   "from_id": msg["from_id"], "to_id": msg["to_id"]}
        await _ws_push(msg["to_id"], payload)
        return {"ok": True, "id": msg_id, "text": new_text, "edited": True, "edited_at": edited_at}

    @api.delete("/messages/conversations/{partner_id}")
    async def delete_conversation(partner_id: str, u=Depends(current_user)):
        """Soft-delete entire conversation for the current user only."""
        await db.messages.update_many(
            {"$or": [
                {"from_id": u["id"], "to_id": partner_id},
                {"from_id": partner_id, "to_id": u["id"]},
            ]},
            {"$addToSet": {"deleted_for": u["id"]}}
        )
        return {"ok": True}

    @api.post("/messages/conversations/{partner_id}/seen")
    async def mark_conversation_seen(partner_id: str, u=Depends(current_user)):
        """REST fallback: bulk-mark messages seen (used when WS is unavailable)."""
        unseen = await db.messages.find(
            {
                "from_id": partner_id,
                "to_id": u["id"],
                "status": {"$ne": "seen"},
                "deleted_for_everyone": {"$ne": True},
            },
            {"_id": 0, "id": 1}
        ).to_list(500)
        ids = [m["id"] for m in unseen]
        if ids:
            await db.messages.update_many(
                {"id": {"$in": ids}},
                {"$set": {"status": "seen", "seen_at": now().isoformat()}}
            )
            await _ws_push(partner_id, {"type": "bulk_seen", "msg_ids": ids, "by_user_id": u["id"]})
        return {"ok": True}

    @api.patch("/users/me/timezone")
    async def update_timezone(body: dict, u=Depends(current_user)):
        offset = body.get("offset")
        if offset is None: raise HTTPException(400, "offset required")
        await db.users.update_one({"id": u["id"]}, {"$set": {"timezone_offset": float(offset)}})
        return {"ok": True}

    # ── Notifications ─────────────────────────────────────────────
    @api.get("/notifications")
    async def get_notifications(u=Depends(current_user)):
        notifs = await db.notifications.find(
            {"user_id": u["id"]}, {"_id": 0}
        ).sort("created_at", -1).limit(100).to_list(100)
        actor_ids = {
            str(n.get("from_user_id") or n.get("from_id"))
            for n in notifs
            if n.get("from_user_id") or n.get("from_id")
        }
        if actor_ids:
            actors = await db.users.find(
                {"id": {"$in": list(actor_ids)}},
                {"_id": 0, "id": 1, "name": 1, "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1, "is_badge_verified": 1},
            ).to_list(len(actor_ids))
            actor_map = {str(actor.get("id")): actor for actor in actors}
            for notification in notifs:
                actor_id = str(notification.get("from_user_id") or notification.get("from_id") or "")
                actor = actor_map.get(actor_id)
                if actor:
                    notification["from_user_name"] = actor.get("name", notification.get("from_user_name", ""))
                    notification["from_user_avatar"] = actor.get("avatar_photo")
                    notification["from_user_bg"] = actor.get("avatar_bg")
                    notification["from_user_letter"] = actor.get("avatar_letter")
                    notification["from_user_is_verified"] = bool(actor.get("is_badge_verified"))
        _blocked = set(u.get("blocked_users") or [])
        if _blocked:
            notifs = [n for n in notifs if str(n.get("from_user_id") or "") not in _blocked]
        unread_count = await db.notifications.count_documents({"user_id": u["id"], "read": False, "type": {"$ne": "group_message"}})
        return {"notifications": notifs, "unread_count": unread_count,
                "muted": {"types": u.get("notif_muted_types") or [], "posts": u.get("notif_muted_posts") or []}}

    @api.post("/notifications/{notif_id}/read")
    async def mark_notification_read(notif_id: str, u=Depends(current_user)):
        await db.notifications.update_one(
            {"id": notif_id, "user_id": u["id"]}, {"$set": {"read": True}}
        )
        return {"ok": True}

    @api.get("/notifications/vapid-key")
    async def get_vapid_key(u=Depends(current_user)):
        pub, _ = await get_vapid_keys()
        return {"public_key": pub}

    @api.post("/notifications/push-subscribe")
    async def push_subscribe(req: Request, u=Depends(current_user)):
        data = await req.json()
        endpoint = (data or {}).get("endpoint", "")
        if not endpoint: raise HTTPException(400, "Invalid subscription")
        # the same browser/device now belongs to this account only (account switch on one phone)
        await db.push_subscriptions.delete_many({"subscription.endpoint": endpoint, "user_id": {"$ne": u["id"]}})
        await db.push_subscriptions.update_one(
            {"user_id": u["id"], "subscription.endpoint": endpoint},
            {"$set": {"user_id": u["id"], "subscription": data, "updated_at": now().isoformat()}},
            upsert=True
        )
        return {"ok": True}

    @api.post("/notifications/read-all")
    async def mark_all_notifications_read(u=Depends(current_user)):
        await db.notifications.update_many(
            {"user_id": u["id"], "read": False}, {"$set": {"read": True}}
        )
        return {"ok": True}

    _MUTE_TYPE_RE = re.compile(r"^[a-z_]{2,40}$")

    def _mute_target(body):
        body = body or {}
        ntype = str(body.get("type") or "").strip()
        pid = str(body.get("post_id") or "").strip()
        if ntype:
            if not _MUTE_TYPE_RE.match(ntype) or ntype in _NOTIFY_SELF_OK:
                raise HTTPException(400, "This notification can't be turned off")
            return "notif_muted_types", ntype
        if pid:
            if len(pid) > 64: raise HTTPException(400, "Invalid post")
            return "notif_muted_posts", pid
        raise HTTPException(400, "Nothing to mute")

    @api.post("/notifications/mute")
    async def mute_notifications(body: dict, u=Depends(current_user)):
        field, value = _mute_target(body)
        if field == "notif_muted_posts":
            await db.users.update_one({"id": u["id"], field: {"$ne": value}}, {"$push": {field: {"$each": [value], "$slice": -500}}})
        else:
            await db.users.update_one({"id": u["id"]}, {"$addToSet": {field: value}})
        fresh = await db.users.find_one({"id": u["id"]}, {"_id": 0, "notif_muted_types": 1, "notif_muted_posts": 1}) or {}
        return {"ok": True, "muted": {"types": fresh.get("notif_muted_types") or [], "posts": fresh.get("notif_muted_posts") or []}}

    @api.post("/notifications/unmute")
    async def unmute_notifications(body: dict, u=Depends(current_user)):
        field, value = _mute_target(body)
        await db.users.update_one({"id": u["id"]}, {"$pull": {field: value}})
        fresh = await db.users.find_one({"id": u["id"]}, {"_id": 0, "notif_muted_types": 1, "notif_muted_posts": 1}) or {}
        return {"ok": True, "muted": {"types": fresh.get("notif_muted_types") or [], "posts": fresh.get("notif_muted_posts") or []}}

    @api.post("/notifications/{notif_id}/report")
    async def report_notification(notif_id: str, body: dict, u=Depends(current_user)):
        n = await db.notifications.find_one({"id": notif_id, "user_id": u["id"]}, {"_id": 0})
        if not n: raise HTTPException(404, "Notification not found")
        if await db.notification_reports.find_one({"notification_id": notif_id, "reported_by": u["id"]}):
            return {"ok": True, "already": True}
        report = {
            "id": str(uuid.uuid4()), "notification_id": notif_id, "reported_by": u["id"], "reporter_handle": u.get("handle", ""),
            "notification_type": n.get("type"), "from_user_id": n.get("from_user_id"), "post_id": n.get("post_id"),
            "text": str(n.get("body") or n.get("text") or n.get("message") or n.get("snippet") or "")[:300],
            "created_at": now().isoformat(), "status": "pending",
        }
        await db.notification_reports.insert_one(report.copy())
        try:   # tell the admins, same way verification requests do
            for _ad in await db.users.find({"is_admin": True}, {"_id": 0, "id": 1}).to_list(20):
                _bg(_notify(_ad["id"], {"id": u["id"], "name": "POST Team"}, "system", title="Notification issue reported",
                            body=f"{u.get('name', 'A user')} reported a '{n.get('type')}' notification.",
                            push=("Notification issue reported", f"{u.get('name', 'A user')} reported a notification issue")))
        except Exception:
            logging.exception("admin notification-report notice failed")
        return {"ok": True}

    @api.delete("/notifications/{notif_id}")
    async def delete_notification(notif_id: str, u=Depends(current_user)):
        await db.notifications.delete_one({"id": notif_id, "user_id": u["id"]})
        return {"ok": True}

    @api.get("/notifications/unread-count")
    async def get_notif_unread_count(u=Depends(current_user)):
        count = await db.notifications.count_documents({"user_id": u["id"], "read": False, "type": {"$ne": "group_message"}})
        return {"unread_count": count}

    # ── Settings ──────────────────────────────────────────────────
    @api.patch("/settings/notifications")
    async def update_notifications_prefs(p: NotificationsPrefsIn, u=Depends(current_user)):
        upd = {k: v for k, v in p.model_dump().items() if v is not None}
        if upd:
            await db.users.update_one(
                {"id": u["id"]},
                {"$set": {f"notifications_prefs.{k}": v for k, v in upd.items()}},
            )
        fresh = await db.users.find_one({"id": u["id"]}, {"_id": 0, "notifications_prefs": 1})
        return fresh.get("notifications_prefs", {})

    @api.patch("/settings/theme")
    async def update_theme(p: ThemeIn, u=Depends(current_user)):
        await db.users.update_one({"id": u["id"]}, {"$set": {"theme": p.theme}})
        return {"theme": p.theme}

    @api.post("/settings/change-password")
    async def change_password(p: ChangePasswordIn, u=Depends(current_user)):
        user_with_hash = await db.users.find_one({"id": u["id"]}, {"_id": 0, "password_hash": 1})
        if not user_with_hash or not await verifypw(p.current_password, user_with_hash.get("password_hash", "")):
            raise HTTPException(400, "Current password is incorrect")
        if len(p.new_password) < 6:
            raise HTTPException(400, "New password must be at least 6 characters")
        await db.users.update_one({"id": u["id"]}, {"$set": {"password_hash": await hashpw(p.new_password)}})
        return {"message": "Password updated successfully"}

    # ── Username check ────────────────────────────────────────────
    @api.get("/check-username")
    async def check_username(username: str, u=Depends(current_user)):
        if not re.match(r'^[a-z0-9_]{3,30}$', username):
            return {"available": False, "reason": "3-30 chars, only a-z 0-9 _"}
        existing = await db.users.find_one({"username": username})
        if existing and existing["id"] != u["id"]:
            return {"available": False, "reason": "Already taken"}
        return {"available": True, "reason": "Available!"}

    # ── Translation ───────────────────────────────────────────────
    TRANSLATE_LANG_MAP = {
        "zh": "zh-CN", "en": "en", "hi": "hi", "ur": "ur", "es": "es",
        "fr": "fr", "ar": "ar", "pt": "pt", "de": "de", "ja": "ja",
        "ru": "ru", "bn": "bn", "id": "id", "tr": "tr",
        "mr": "mr", "ta": "ta", "te": "te", "gu": "gu", "pa": "pa",
        "ko": "ko", "it": "it", "nl": "nl", "pl": "pl", "vi": "vi",
    }

    def _detect_tone_hint(text: str) -> Optional[str]:
        t = text.lower()
        if any(w in t for w in ["please","kindly","would you","could you","sir","ma'am","madam","dear"]):
            return "Formal tone — polite phrasing used"
        if any(w in t for w in ["hey","yo","sup","lol","haha","bruh","bro","sis","wanna","gonna","kinda"]):
            return "Informal tone — casual/slang phrasing"
        if any(w in t for w in ["urgent","asap","immediately","now","hurry","quickly"]):
            return "Urgent tone — time-sensitive message"
        if text.endswith("?") or text.count("?") > 1:
            return "Questioning tone — expecting a reply"
        if any(w in t for w in ["sorry","apolog","forgive","excuse me","pardon"]):
            return "Apologetic tone — expressing regret"
        return None

    async def _translate_plain_text(value: str, tl: str) -> str:
        """Translate a caption segment while preserving its surrounding whitespace."""
        if not value or not value.strip():
            return value
        leading = value[:len(value) - len(value.lstrip())]
        trailing = value[len(value.rstrip()):]
        core = value.strip()
        translated = None

        # MyMemory is fast when available.
        try:
            url = (
                "https://api.mymemory.translated.world/get"
                f"?q={urllib.parse.quote(core)}&langpair=autodetect|{tl}"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "PostApp/1.0"})
            def _fetch_mymemory():
                with urllib.request.urlopen(req, timeout=6) as resp:
                    return _json.loads(resp.read().decode())
            data = await asyncio.to_thread(_fetch_mymemory)
            result = (data.get("responseData") or {}).get("translatedText", "")
            if result and "MYMEMORY WARNING" not in result and result.strip() != core:
                translated = result.strip()
        except Exception as e:
            logging.warning(f"MyMemory translation failed: {e}")

        # LibreTranslate is the second fallback.
        if not translated:
            try:
                lt_body = _json.dumps({"q": core, "source": "auto", "target": tl, "format": "text"}).encode()
                lt_req = urllib.request.Request(
                    "https://libretranslate.com/translate", data=lt_body,
                    headers={"Content-Type": "application/json", "User-Agent": "PostApp/1.0"}, method="POST",
                )
                def _fetch_libretranslate():
                    with urllib.request.urlopen(lt_req, timeout=6) as resp:
                        return _json.loads(resp.read().decode())
                data = await asyncio.to_thread(_fetch_libretranslate)
                result = data.get("translatedText", "")
                if result and result.strip() != core:
                    translated = result.strip()
            except Exception as e:
                logging.warning(f"LibreTranslate fallback failed: {e}")

        # Google Translate's public endpoint handles short prompts and non-Latin text
        # when the two keyless services are unavailable.
        if not translated:
            try:
                url = (
                    "https://translate.googleapis.com/translate_a/single"
                    f"?client=gtx&sl=auto&tl={urllib.parse.quote(tl)}&dt=t&q={urllib.parse.quote(core)}"
                )
                req = urllib.request.Request(url, headers={"User-Agent": "PostApp/1.0"})
                def _fetch_google():
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        return _json.loads(resp.read().decode())
                data = await asyncio.to_thread(_fetch_google)
                chunks = data[0] if isinstance(data, list) and data else []
                result = "".join(
                    str(chunk[0]) for chunk in chunks
                    if isinstance(chunk, list) and chunk and chunk[0]
                )
                if result and result.strip() != core:
                    translated = result.strip()
            except Exception as e:
                logging.warning(f"Google translation fallback failed: {e}")

        return leading + (translated or core) + trailing

    async def _translate_caption(text: str, tl: str) -> str:
        # Translate hashtag words separately so providers cannot leave #tags untouched.
        parts = re.split(r"(#[\w-]+)", text, flags=re.UNICODE)
        if len(parts) == 1:
            return await _translate_plain_text(text, tl)

        async def translate_part(part: str) -> str:
            if part.startswith("#") and len(part) > 1:
                translated_tag = await _translate_plain_text(part[1:], tl)
                translated_tag = re.sub(r"\s+", "_", translated_tag.strip()).lstrip("#")
                return "#" + translated_tag if translated_tag else part
            return await _translate_plain_text(part, tl)

        translated_parts = await asyncio.gather(*(translate_part(part) for part in parts))
        return "".join(translated_parts)

    @api.post("/translate")
    async def translate_endpoint(body: dict):
        raw_text = body.get("text") or ""
        if not isinstance(raw_text, str):
            raise HTTPException(status_code=400, detail="Text must be a string.")
        text = raw_text.strip()
        if len(text) > 5000:
            raise HTTPException(status_code=413, detail="Text is too long to translate.")
        target = body.get("target", "en")
        if not isinstance(target, str):
            raise HTTPException(status_code=400, detail="Target language must be a string.")
        target = target[:20]
        include_tone = body.get("tone", False)
        if not text:
            return {"translated": text, "tone_hint": None}
        tl = TRANSLATE_LANG_MAP.get(target, target)
        # Versioned key prevents an older untranslated result from masking this fix.
        cache_key = "caption-v2|" + tl + "||" + text
        cached = _cache_get(cache_key)
        if cached:
            return {"translated": cached, "tone_hint": _detect_tone_hint(text) if include_tone else None}
        translated = await _translate_caption(text, tl)
        _cache_set(cache_key, translated)
        return {"translated": translated, "tone_hint": _detect_tone_hint(text) if include_tone else None}


    # ── Verification ─────────────────────────────────────────────────────

    async def _is_admin(u=Depends(current_user)):
        if not u.get("is_admin"):
            raise HTTPException(403, "Admin access required")
        return u

    @api.post("/verification/request")
    async def submit_verification_request(p: VerificationRequestIn, u=Depends(current_user)):
        if u.get("is_badge_verified"):
            raise HTTPException(400, "Your account is already verified")
        existing_pending = await db.verification_requests.find_one({"user_id": u["id"], "status": "pending"})
        if existing_pending:
            raise HTTPException(400, "You already have a pending verification request")
        similar = await db.users.find_one({
            "is_badge_verified": True,
            "$or": [
                {"username": {"$regex": f"^{re.escape(u.get('username',''))}$", "$options": "i"}},
                {"name": {"$regex": f"^{re.escape(p.full_name)}$", "$options": "i"}},
            ]
        })
        req = {
            "id": str(uuid.uuid4()),
            "user_id": u["id"],
            "user_name": u["name"],
            "user_handle": u.get("handle", ""),
            "user_username": u.get("username", ""),
            "user_avatar_photo": u.get("avatar_photo"),
            "user_avatar_bg": u.get("avatar_bg"),
            "user_avatar_letter": u.get("avatar_letter"),
            "full_name": p.full_name,
            "category": p.category,
            "id_proof_url": p.id_proof_url or "",
            "social_links": p.social_links or "",
            "status": "pending",
            "flagged": bool(similar),
            "flag_reason": (f"Similar name/username matches verified @{similar.get('username')}" if similar else None),
            "submitted_at": now().isoformat(),
            "reviewed_at": None,
            "reject_reason": None,
        }
        await db.verification_requests.insert_one(req)
        req.pop("_id", None)
        try:
            for _ad in await db.users.find({"is_admin": True}, {"_id": 0, "id": 1}).to_list(20):
                _bg(_notify(_ad["id"], {"id": u["id"], "name": "POST Team"}, "system", title="New verification request",
                            body=f"{u['name']} requested a '{p.category}' verified badge.",
                            push=("New verification request", f"{u['name']} requested a verified badge")))
        except Exception:
            logging.exception("admin verification notice failed")
        return {"ok": True, "flagged": req["flagged"]}

    @api.get("/verification/my-status")
    async def my_verification_status(u=Depends(current_user)):
        if u.get("is_badge_verified"):
            return {
                "status": "verified",
                "category": u.get("verified_category") or u.get("category") or "",
                "verified_at": u.get("badge_verified_at"),
            }
        req = await db.verification_requests.find_one(
            {"user_id": u["id"]}, {"_id": 0}, sort=[("submitted_at", -1)]
        )
        if not req:
            return {"status": "none"}
        return {"status": req["status"], "category": req.get("category"), "reject_reason": req.get("reject_reason"), "submitted_at": req.get("submitted_at")}

    @api.get("/admin/verification/requests")
    async def admin_list_requests(status: Optional[str] = "pending", skip: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=200), admin=Depends(_is_admin)):
        query = {} if status == "all" else {"status": status}
        reqs = await db.verification_requests.find(query, {"_id": 0}).sort("submitted_at", -1).skip(skip).limit(limit).to_list(limit)
        total = await db.verification_requests.count_documents(query)
        return {"requests": reqs, "total": total}

    @api.post("/admin/verification/approve/{request_id}")
    async def admin_approve_request(request_id: str, admin=Depends(_is_admin)):
        req = await db.verification_requests.find_one({"id": request_id})
        if not req:
            raise HTTPException(404, "Request not found")
        if req["status"] != "pending":
            raise HTTPException(400, f"Request is already {req['status']}")
        now_str = now().isoformat()
        category = req.get("category", "Public Figure")
        uid = req["user_id"]
        await db.users.update_one(
            {"id": uid},
            {"$set": {"is_badge_verified": True, "verified_category": category, "badge_verified_at": now_str, "username_locked": True}}
        )
        await db.posts.update_many({"user_id": uid}, {"$set": {"is_badge_verified": True, "verified_category": category}})
        await db.verification_requests.update_one(
            {"id": request_id},
            {"$set": {"status": "approved", "reviewed_at": now_str, "reviewed_by": admin["id"]}}
        )
        _bg(_notify(uid, {"id": admin["id"], "name": "POST Team"}, "verification_approved",
                    text=f"Congratulations! Your account is now verified as '{category}'. ✅",
                    push=("You're verified ✅", f"Your account is now verified as '{category}'.")))
        return {"ok": True}

    @api.post("/admin/verification/reject/{request_id}")
    async def admin_reject_request(request_id: str, p: AdminRejectIn, admin=Depends(_is_admin)):
        req = await db.verification_requests.find_one({"id": request_id})
        if not req:
            raise HTTPException(404, "Request not found")
        if req["status"] != "pending":
            raise HTTPException(400, f"Request is already {req['status']}")
        now_str = now().isoformat()
        await db.verification_requests.update_one(
            {"id": request_id},
            {"$set": {"status": "rejected", "reject_reason": p.reason, "reviewed_at": now_str, "reviewed_by": admin["id"]}}
        )
        _bg(_notify(req["user_id"], {"id": admin["id"], "name": "POST Team"}, "verification_rejected",
                    text=f"Your verification request was not approved. Reason: {p.reason}",
                    push=("Verification update", "Your verification request was not approved.")))
        return {"ok": True}

    @api.post("/admin/verification/grant")
    async def admin_grant_badge(p: AdminGrantIn, admin=Depends(_is_admin)):
        target = await db.users.find_one({"id": p.user_id})
        if not target:
            raise HTTPException(404, "User not found")
        now_str = now().isoformat()
        await db.users.update_one(
            {"id": p.user_id},
            {"$set": {"is_badge_verified": True, "verified_category": p.category, "badge_verified_at": now_str, "username_locked": True}}
        )
        await db.posts.update_many({"user_id": p.user_id}, {"$set": {"is_badge_verified": True, "verified_category": p.category}})
        await db.verification_requests.update_many(
            {"user_id": p.user_id, "status": "pending"},
            {"$set": {"status": "approved", "reviewed_at": now_str, "reviewed_by": admin["id"]}}
        )
        _bg(_notify(p.user_id, {"id": admin["id"], "name": "POST Team"}, "verification_approved",
                    text=f"Congratulations! Your account is now verified as '{p.category}'. ✅",
                    push=("You're verified ✅", f"Your account is now verified as '{p.category}'.")))
        return {"ok": True}

    @api.post("/admin/verification/revoke/{user_id}")
    async def admin_revoke_badge(user_id: str, admin=Depends(_is_admin)):
        target = await db.users.find_one({"id": user_id})
        if not target:
            raise HTTPException(404, "User not found")
        await db.users.update_one(
            {"id": user_id},
            {"$unset": {"is_badge_verified": "", "verified_category": "", "badge_verified_at": "", "username_locked": ""}}
        )
        await db.posts.update_many({"user_id": user_id}, {"$unset": {"is_badge_verified": "", "verified_category": ""}})
        return {"ok": True}

    @api.get("/admin/users")
    async def admin_list_users(q: Optional[str] = Query(None, max_length=100), skip: int = Query(0, ge=0, le=10000), limit: int = Query(50, ge=1, le=100), admin=Depends(_is_admin)):
        query: dict = {}
        if q:
            query["$or"] = [
                {"name": {"$regex": q, "$options": "i"}},
                {"username": {"$regex": q, "$options": "i"}},
                {"email": {"$regex": q, "$options": "i"}},
            ]
        users_list = await _safe_user_find(query, {"_id": 0, "password_hash": 0, "otp_hash": 0, "known_devices": 0}, skip=skip, limit=limit)
        total = await db.users.count_documents(query)
        return {"users": users_list, "total": total}

    @api.post("/admin/users/{user_id}/toggle-admin")
    async def admin_toggle_admin(user_id: str, admin=Depends(_is_admin)):
        target = await db.users.find_one({"id": user_id})
        if not target:
            raise HTTPException(404, "User not found")
        new_val = not target.get("is_admin", False)
        await db.users.update_one({"id": user_id}, {"$set": {"is_admin": new_val}})
        return {"ok": True, "is_admin": new_val}

    # ── Health ────────────────────────────────────────────────────
    @api.get("/")
    async def root():
        return {"status": "ok", "demo_mode": DEMO_MODE, "twilio": bool(TWILIO_SID), "version": "5.0"}

    # ── Startup: indexes ──────────────────────────────────────────
    @app.on_event("startup")
    async def create_indexes():
        # Each index is created independently — a name/option conflict on one
        # (e.g. an older non-sparse "username_1" index already existing) must
        # not abort the rest. Previously all calls shared a single try/except,
        # so a conflict on an early index (users.username) silently skipped
        # every index declared after it, including the newer world_reports /
        # world_active indexes added for the Join World feature.
        index_specs = [
            (db.users, "id", {"unique": True, "background": True}),
            (db.users, "username", {"unique": True, "sparse": True, "background": True}),
            (db.users, "email", {"background": True}),
            (db.users, "phone", {"background": True}),
            (db.users, "handle", {"background": True}),
            (db.posts, "user_id", {"background": True}),
            (db.posts, [("created_at", -1)], {"background": True}),
            (db.posts, "id", {"unique": True, "background": True}),
            (db.messages, [("from_id", 1), ("to_id", 1)], {"background": True}),
            (db.messages, [("created_at", 1)], {"background": True}),
            (db.notifications, "user_id", {"background": True}),
            (db.notifications, [("created_at", -1)], {"background": True}),
            (db.notifications, [("user_id", 1), ("created_at", -1)], {"background": True}),
            (db.notifications, [("user_id", 1), ("read", 1)], {"background": True}),
            (db.push_subscriptions, "user_id", {"background": True}),
            (db.push_subscriptions, "subscription.endpoint", {"background": True}),
            (db.follow_requests, [("from_id", 1), ("to_id", 1)], {"background": True}),
            (db.follow_requests, "status", {"background": True}),
            (db.friend_requests, [("from_id", 1), ("to_id", 1)], {"background": True}),
            (db.friend_requests, "status", {"background": True}),
            (db.email_otps, "email", {"background": True}),
            (db.twofa_challenges, "id", {"unique": True, "background": True}),
            (db.twofa_challenges, "expires_at", {"expireAfterSeconds": 3600, "background": True}),
            (db.phone_otps, "phone", {"background": True}),
            (db.account_deletions, "identifier", {"background": True}),
            # Feed query indexes
            (db.users, "is_badge_verified", {"background": True}),
            (db.users, "is_private", {"background": True}),
            (db.verification_requests, "user_id", {"background": True}),
            (db.verification_requests, "status", {"background": True}),
            (db.verification_requests, "id", {"unique": True, "sparse": True, "background": True}),
            (db.users, "followers", {"background": True}),
            (db.world_reports, [("created_at", -1)], {"background": True}),
            (db.world_reports, "location_type", {"background": True}),
            (db.world_reports, "id", {"unique": True, "sparse": True, "background": True}),
            (db.world_active, "user_id", {"unique": True, "background": True}),
            (db.world_active, "last_ping", {"background": True}),
            (db.reel_mentions, [("reel_id", 1), ("target_user_id", 1)], {"unique": True, "background": True}),
            (db.reel_mentions, [("target_user_id", 1), ("created_at", -1)], {"background": True}),
            (db.post_reposts, [("post_id", 1), ("user_id", 1)], {"unique": True, "background": True}),
            (db.post_reposts, [("user_id", 1), ("created_at", -1)], {"background": True}),
            (db.reel_reposts, [("reel_id", 1), ("user_id", 1)], {"unique": True, "background": True}),
            (db.reel_reposts, [("user_id", 1), ("created_at", -1)], {"background": True}),
        ]
        ok_count = 0
        for collection, keys, options in index_specs:
            try:
                await collection.create_index(keys, **options)
                ok_count += 1
            except Exception as e:
                # Code 86 = IndexKeySpecsConflict: existing index has different options.
                # Drop the old index and recreate with new specs.
                details = getattr(e, "details", None)
                detail_code = details.get("code") if isinstance(details, dict) else None
                err_code = getattr(e, "code", None) or detail_code
                if err_code == 86:
                    try:
                        index_name = options.get("name")
                        if not index_name:
                            if isinstance(keys, str):
                                index_name = f"{keys}_1"
                            else:
                                index_name = "_".join(f"{k}_{v}" for k, v in keys)
                        await collection.drop_index(index_name)
                        await collection.create_index(keys, **options)
                        ok_count += 1
                        logging.info(f"Rebuilt conflicting index ({collection.name}.{keys})")
                    except Exception as e2:
                        logging.warning(f"Index rebuild failed ({collection.name}.{keys}): {e2}")
                else:
                    logging.warning(f"Index creation warning ({collection.name}.{keys}): {e}")
        logging.info(f"✅ MongoDB indexes created ({ok_count}/{len(index_specs)})")

    # ── Startup: make official account an admin + verified ──────────
    @app.on_event("startup")
    async def promote_official_account():
        if not OFFICIAL_ACCOUNT_ID:
            return
        try:
            result = await db.users.update_one(
                {"id": OFFICIAL_ACCOUNT_ID},
                {"$set": {
                    "is_admin": True,
                    "is_badge_verified": True,
                    "verified_category": "Business / Brand",
                    "badge_verified_at": now().isoformat(),
                    "username_locked": True,
                }},
            )
            if result.matched_count:
                await db.posts.update_many(
                    {"user_id": OFFICIAL_ACCOUNT_ID},
                    {"$set": {"is_badge_verified": True, "verified_category": "Business / Brand"}},
                )
                logging.info("✅ Official account promoted to admin + verified badge")
            else:
                logging.warning("⚠️ OFFICIAL_ACCOUNT_ID set but no matching user found")
        except Exception as e:
            logging.warning(f"Official account admin promotion warning: {e}")

    # ── Startup: seed demo users ──────────────────────────────────
    @app.on_event("startup")
    async def seed():
        if await db.users.count_documents({"is_seed": True}) > 0:
            return
        WORLD = [
            ("Aryan",  "@aryan_world",  "Mumbai, India",         "Photographer & traveller 📷", "Asia",     "#FFD600"),
            ("Bella",  "@bella_creates","London, UK",            "Designer. Coffee lover ☕",    "Europe",   "#00C853"),
            ("Carlos", "@carlos_global","Mexico City",           "Entrepreneur 🚀",             "Americas", "#29B6F6"),
            ("Yuki",   "@yuki_jp",      "Tokyo, Japan",          "Manga artist 🎨",             "Asia",     "#00C853"),
            ("Fatima", "@fatima_sa",    "Riyadh, Saudi Arabia",  "Writer & poet ✍️",            "Asia",     "#FF1744"),
            ("Pierre", "@pierre_fr",    "Paris, France",         "Chef & food blogger 🥐",      "Europe",   "#FF1744"),
            ("Lucas",  "@lucas_br",     "São Paulo, Brazil",     "Carnaval organizer 🎉",       "Americas", "#00C853"),
            ("Chioma", "@chioma_ng",    "Lagos, Nigeria",        "Fashion designer 👗",         "Africa",   "#29B6F6"),
            ("Jack",   "@jack_au",      "Sydney, Australia",     "Surfer & barista ☕",          "Oceania",  "#00C853"),
            ("Soo-Jin","@soojin_kr",    "Seoul, South Korea",    "K-pop enthusiast 🎵",         "Asia",     "#FF1744"),
            ("Anna",   "@anna_se",      "Stockholm, Sweden",     "Environmentalist 🌿",         "Europe",   "#29B6F6"),
            ("Amara",  "@amara_ke",     "Nairobi, Kenya",        "Safari guide 🦁",             "Africa",   "#FFD600"),
        ]
        for name, handle, loc, about, continent, color in WORLD:
            uid = str(uuid.uuid4())
            await db.users.insert_one({
                "id": uid, "email": f"{handle[1:]}@post.demo",
                "username": handle[1:], "name": name, "handle": handle,
                "is_verified": True, "is_seed": True, "avatar_bg": color,
                "avatar_letter": name[0], "location": loc, "about": about, "continent": continent,
                "created_at": now(), "followers": [], "following": [], "blocked_users": [],
                "notifications_prefs": {"likes": True, "comments": True, "friend_requests": True, "messages": True, "mentions": True, "tags": True},
            })
        logging.info("✅ World users seeded")

    # ── Self-ping keepalive (prevents Render free tier sleep) ────
    # List holds a strong ref to the task — no nonlocal / global needed
    _keepalive_holder = []

    @app.on_event("startup")
    async def keepalive_self_ping():
        import urllib.request as _ur2
        # Render only resets its 15-min inactivity/sleep timer on requests that
        # arrive through its public edge — pinging 127.0.0.1 never reaches the
        # edge, so it did NOT prevent the free-tier service from sleeping.
        # RENDER_EXTERNAL_URL is auto-injected by Render with the real public
        # URL (e.g. https://post-app-backend.onrender.com); use that instead,
        # and only fall back to localhost when running outside Render.
        external_url = os.environ.get("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
        if external_url:
            ping_url = f"{external_url}/api/ping"
        else:
            port = os.environ.get("PORT", "10000")
            ping_url = f"http://127.0.0.1:{port}/api/ping"
        logging.info(f"[KeepAlive] starting → {ping_url} every 10 min")

        async def _ping_loop():
            await asyncio.sleep(30)   # let server fully boot first
            loop = asyncio.get_running_loop()   # correct for Python 3.10+
            def _do_ping():
                with _ur2.urlopen(ping_url, timeout=15):
                    pass
            while True:
                try:
                    await loop.run_in_executor(None, _do_ping)
                    logging.info("[KeepAlive] ✅ ping OK — server awake")
                except Exception as _pe:
                    logging.warning(f"[KeepAlive] ⚠️ ping failed: {_pe}")
                await asyncio.sleep(10 * 60)   # every 10 min — safe margin under 15 min limit

        task = asyncio.ensure_future(_ping_loop())
        _keepalive_holder.append(task)   # strong ref → GC can never collect this

    # ── Shutdown ──────────────────────────────────────────────────
    @app.on_event("shutdown")
    async def shutdown():
        client.close()

    # ── Health / keep-alive ping ─────────────────────────────────
    @api.get("/ping")
    async def ping():
        return {"ok": True}

    # ── Join World ────────────────────────────────────────────────
    import urllib.parse as _uparse, urllib.request as _ureq, urllib.error as _uerr, re as _re_news

    # Every country selectable in the app (ISO code -> name)
    _NEWS_COUNTRIES = {
        "ad": "Andorra",
        "ae": "United Arab Emirates",
        "af": "Afghanistan",
        "ag": "Antigua and Barbuda",
        "al": "Albania",
        "am": "Armenia",
        "ao": "Angola",
        "ar": "Argentina",
        "at": "Austria",
        "au": "Australia",
        "az": "Azerbaijan",
        "ba": "Bosnia and Herzegovina",
        "bb": "Barbados",
        "bd": "Bangladesh",
        "be": "Belgium",
        "bf": "Burkina Faso",
        "bg": "Bulgaria",
        "bh": "Bahrain",
        "bi": "Burundi",
        "bj": "Benin",
        "bn": "Brunei",
        "bo": "Bolivia",
        "br": "Brazil",
        "bs": "Bahamas",
        "bt": "Bhutan",
        "bw": "Botswana",
        "by": "Belarus",
        "bz": "Belize",
        "ca": "Canada",
        "cd": "DR Congo",
        "cf": "Central African Republic",
        "cg": "Republic of the Congo",
        "ch": "Switzerland",
        "ci": "Ivory Coast",
        "cl": "Chile",
        "cm": "Cameroon",
        "cn": "China",
        "co": "Colombia",
        "cr": "Costa Rica",
        "cu": "Cuba",
        "cv": "Cape Verde",
        "cy": "Cyprus",
        "cz": "Czech Republic",
        "de": "Germany",
        "dj": "Djibouti",
        "dk": "Denmark",
        "dm": "Dominica",
        "do": "Dominican Republic",
        "dz": "Algeria",
        "ec": "Ecuador",
        "ee": "Estonia",
        "eg": "Egypt",
        "er": "Eritrea",
        "es": "Spain",
        "et": "Ethiopia",
        "fi": "Finland",
        "fj": "Fiji",
        "fm": "Micronesia",
        "fr": "France",
        "ga": "Gabon",
        "gb": "United Kingdom",
        "gd": "Grenada",
        "ge": "Georgia",
        "gh": "Ghana",
        "gm": "Gambia",
        "gn": "Guinea",
        "gq": "Equatorial Guinea",
        "gr": "Greece",
        "gt": "Guatemala",
        "gw": "Guinea-Bissau",
        "gy": "Guyana",
        "hk": "Hong Kong",
        "hn": "Honduras",
        "hr": "Croatia",
        "ht": "Haiti",
        "hu": "Hungary",
        "id": "Indonesia",
        "ie": "Ireland",
        "il": "Israel",
        "in": "India",
        "iq": "Iraq",
        "ir": "Iran",
        "is": "Iceland",
        "it": "Italy",
        "jm": "Jamaica",
        "jo": "Jordan",
        "jp": "Japan",
        "ke": "Kenya",
        "kg": "Kyrgyzstan",
        "kh": "Cambodia",
        "ki": "Kiribati",
        "km": "Comoros",
        "kn": "Saint Kitts and Nevis",
        "kp": "North Korea",
        "kr": "South Korea",
        "kw": "Kuwait",
        "kz": "Kazakhstan",
        "la": "Laos",
        "lb": "Lebanon",
        "lc": "Saint Lucia",
        "li": "Liechtenstein",
        "lk": "Sri Lanka",
        "lr": "Liberia",
        "ls": "Lesotho",
        "lt": "Lithuania",
        "lu": "Luxembourg",
        "lv": "Latvia",
        "ly": "Libya",
        "ma": "Morocco",
        "mc": "Monaco",
        "md": "Moldova",
        "me": "Montenegro",
        "mg": "Madagascar",
        "mh": "Marshall Islands",
        "mk": "North Macedonia",
        "ml": "Mali",
        "mm": "Myanmar",
        "mn": "Mongolia",
        "mr": "Mauritania",
        "mt": "Malta",
        "mu": "Mauritius",
        "mv": "Maldives",
        "mw": "Malawi",
        "mx": "Mexico",
        "my": "Malaysia",
        "mz": "Mozambique",
        "na": "Namibia",
        "ne": "Niger",
        "ng": "Nigeria",
        "ni": "Nicaragua",
        "nl": "Netherlands",
        "no": "Norway",
        "np": "Nepal",
        "nr": "Nauru",
        "nz": "New Zealand",
        "om": "Oman",
        "pa": "Panama",
        "pe": "Peru",
        "pg": "Papua New Guinea",
        "ph": "Philippines",
        "pk": "Pakistan",
        "pl": "Poland",
        "ps": "Palestine",
        "pt": "Portugal",
        "pw": "Palau",
        "py": "Paraguay",
        "qa": "Qatar",
        "ro": "Romania",
        "rs": "Serbia",
        "ru": "Russia",
        "rw": "Rwanda",
        "sa": "Saudi Arabia",
        "sb": "Solomon Islands",
        "sc": "Seychelles",
        "sd": "Sudan",
        "se": "Sweden",
        "sg": "Singapore",
        "si": "Slovenia",
        "sk": "Slovakia",
        "sl": "Sierra Leone",
        "sm": "San Marino",
        "sn": "Senegal",
        "so": "Somalia",
        "sr": "Suriname",
        "ss": "South Sudan",
        "st": "Sao Tome and Principe",
        "sv": "El Salvador",
        "sy": "Syria",
        "sz": "Eswatini",
        "td": "Chad",
        "tg": "Togo",
        "th": "Thailand",
        "tj": "Tajikistan",
        "tl": "Timor-Leste",
        "tm": "Turkmenistan",
        "tn": "Tunisia",
        "to": "Tonga",
        "tr": "Turkey",
        "tt": "Trinidad and Tobago",
        "tv": "Tuvalu",
        "tw": "Taiwan",
        "tz": "Tanzania",
        "ua": "Ukraine",
        "ug": "Uganda",
        "us": "United States",
        "uy": "Uruguay",
        "uz": "Uzbekistan",
        "va": "Vatican City",
        "vc": "Saint Vincent and the Grenadines",
        "ve": "Venezuela",
        "vn": "Vietnam",
        "vu": "Vanuatu",
        "ws": "Samoa",
        "xk": "Kosovo",
        "ye": "Yemen",
        "za": "South Africa",
        "zm": "Zambia",
        "zw": "Zimbabwe"
    }
    # Countries NewsAPI supports natively on /top-headlines (everything else uses /everything)
    _NEWS_TOP_HEADLINE_COUNTRIES = set((
        "ae ar at au be bg br ca ch cn co cu cz de eg fr gb gr hk hu id ie il in it jp kr lt lv "
        "ma mx my ng nl no nz ph pl pt ro rs ru sa se sg si sk th tr tw ua us ve za"
    ).split())
    # Better search phrases for countries whose plain name is ambiguous / commonly written differently
    _NEWS_COUNTRY_QUERY = {
        "us": '"United States" OR USA OR "U.S."',
        "gb": '"United Kingdom" OR UK OR Britain OR England',
        "ae": 'UAE OR "United Arab Emirates" OR Dubai OR "Abu Dhabi"',
        "kr": '"South Korea" OR Seoul',
        "kp": '"North Korea" OR Pyongyang',
        "cd": '"DR Congo" OR "Democratic Republic of Congo" OR Kinshasa',
        "cg": '"Republic of the Congo" OR Brazzaville',
        "ci": '"Ivory Coast" OR "Cote d\'Ivoire" OR Abidjan',
        "cz": '"Czech Republic" OR Czechia OR Prague',
        "tl": '"Timor-Leste" OR "East Timor"',
        "mm": 'Myanmar OR Burma',
        "tr": 'Turkey OR Turkiye OR Ankara',
        "ps": 'Palestine OR Gaza OR "West Bank"',
        "va": '"Vatican City" OR Vatican',
        "mk": '"North Macedonia" OR Skopje',
        "sz": 'Eswatini OR Swaziland',
        "st": '"Sao Tome" OR "Sao Tome and Principe"',
        "cv": '"Cape Verde" OR "Cabo Verde"',
        "ge": 'Tbilisi OR "Republic of Georgia" OR "country of Georgia"',
        "ne": 'Niamey OR "Niger junta" OR "Republic of Niger"',
        "gn": 'Conakry OR "Guinea junta" OR "Republic of Guinea"',
        "in": 'India OR Delhi OR Mumbai',
        "cn": 'China OR Beijing',
        "ru": 'Russia OR Moscow OR Kremlin',
        "jo": 'Amman OR "Jordan government" OR "Kingdom of Jordan"',
        "ie": 'Ireland OR Dublin',
        "sa": '"Saudi Arabia" OR Riyadh',
    }
    _NEWS_NATIVE = {
        "top": "general", "business": "business", "technology": "technology",
        "sports": "sports", "health": "health", "science": "science",
        "entertainment": "entertainment", "ai-tech": "technology",
    }
    # Keywords used for native categories when we have to fall back to /everything (country not supported natively)
    _NEWS_NATIVE_KW = {
        "business": "business OR economy OR market OR company",
        "technology": "technology OR tech OR software OR internet",
        "ai-tech": '"artificial intelligence" OR AI OR technology OR software OR OpenAI OR chip',
        "sports": "sports OR cricket OR football OR match OR tournament",
        "health": "health OR hospital OR disease OR medical",
        "science": "science OR research OR space OR scientists",
        "entertainment": "entertainment OR film OR movie OR music OR celebrity",
    }
    _NEWS_KEYWORDS = {
        "politics": "politics OR government OR parliament OR election OR senate",
        "economy": "economy OR inflation OR GDP OR recession OR economic policy",
        "ai": '"artificial intelligence" OR "machine learning" OR GPT OR LLM OR OpenAI',
        "infrastructure": '"infrastructure development" OR "smart city" OR highway OR railway OR metro',
        "automobile": "electric vehicle OR EV OR car industry OR Tesla OR automotive OR automobile",
        "manufacturing": "manufacturing OR factory OR industrial production OR supply chain",
        "environment": "climate change OR environment OR carbon OR global warming OR pollution OR renewable energy",
        "education": "education OR school OR university OR student OR curriculum OR learning",
        "crime": "crime OR law enforcement OR court OR arrest OR verdict OR criminal justice",
        "world-affairs": "diplomacy OR foreign policy OR UN OR summit OR bilateral OR treaty OR geopolitics",
        "weather": "weather OR storm OR flood OR drought OR hurricane OR cyclone OR earthquake OR tsunami",
        "startups": "startup OR venture capital OR IPO OR funding OR fintech OR unicorn OR entrepreneur",
        "energy": "energy OR oil OR gas OR solar OR wind power OR nuclear OR electricity grid",
    }
    # "Worldwide" view = mix of headlines from several regions (not just the US default)
    _NEWS_WORLD_MIX = ["us", "gb", "in", "au", "ae", "za", "sg", "ca"]

    _news_cache: dict = {}
    _NEWS_CACHE_TTL = 600  # 10 minutes (NewsAPI free plan has a daily request cap)
    _NEWS_CACHE_MAX_ENTRIES = 256

    def _news_cache_get(key):
        now_mono = _time.monotonic()
        entry = _news_cache.get(key)
        if not entry:
            return None
        if now_mono - entry[1] >= _NEWS_CACHE_TTL:
            _news_cache.pop(key, None)
            return None
        return entry[0]

    def _news_cache_set(key, value):
        now_mono = _time.monotonic()
        for cached_key, (_, cached_at) in list(_news_cache.items()):
            if now_mono - cached_at >= _NEWS_CACHE_TTL:
                _news_cache.pop(cached_key, None)
        if key not in _news_cache and len(_news_cache) >= _NEWS_CACHE_MAX_ENTRIES:
            oldest_key = min(_news_cache, key=lambda cached_key: _news_cache[cached_key][1])
            _news_cache.pop(oldest_key, None)
        _news_cache[key] = (value, now_mono)

    def _news_country_query(country: str) -> str:
        code = (country or "").strip().lower()
        if code in _NEWS_COUNTRY_QUERY:
            return "(" + _NEWS_COUNTRY_QUERY[code] + ")"
        name = _NEWS_COUNTRIES.get(code)
        if not name:  # unknown code -> treat the text as a country name
            name = _re_news.sub(r"[^\w\s\-\.']", " ", country or "").strip()[:60]
        return ('"' + name + '"') if name else ""

    def _news_hq_image(url: str) -> str:
        """Force https (http images are blocked on an https site) and ask BBC-style CDNs for the large rendition."""
        u = (url or "").strip()
        if not u:
            return ""
        if u.startswith("//"):
            u = "https:" + u
        if u.startswith("http://"):
            u = "https://" + u[7:]
        u = _re_news.sub(r"(ichef\.bbci\.co\.uk/(?:news|ace/standard)/)(\d{2,4})(/)", lambda m: m.group(1) + "976" + m.group(3), u)
        return u

    def _news_friendly_error(msg: str) -> str:
        m = (msg or "").lower()
        if "ratelimit" in m or "too many" in m or "maximum" in m:
            return "News limit reached for now. Please try again later."
        if "apikey" in m or "api key" in m or "unauthorized" in m:
            return "News API key is missing or invalid on the server."
        return "News service is temporarily unavailable."

    def _newsapi_request(endpoint: str, params: dict):
        """Blocking call to NewsAPI. Returns (articles, error_message_or_None)."""
        q = dict(params)
        q["apiKey"] = NEWS_API_KEY
        url = "https://newsapi.org/v2/" + endpoint + "?" + _uparse.urlencode(q)
        req = _ureq.Request(url, headers={"User-Agent": "PostApp/1.0"})
        try:
            with _ureq.urlopen(req, timeout=12) as resp:
                data = _json.loads(resp.read())
        except _uerr.HTTPError as he:
            try:
                data = _json.loads(he.read())
            except Exception:
                data = {"status": "error", "code": "http" + str(he.code), "message": "HTTP " + str(he.code)}
        except Exception as ex:
            return [], "network: " + str(ex)
        if data.get("status") != "ok":
            return [], str(data.get("code") or "") + " " + str(data.get("message") or "error")
        return data.get("articles") or [], None

    async def _fetch_news_articles(category: str, country: Optional[str], page_size: int = 20):
        """Returns (articles, error). Handles every country + every category."""
        if not NEWS_API_KEY:
            return [], None
        loop = asyncio.get_running_loop()
        cat = _re_news.sub(r"[^a-z0-9\- ]", "", (category or "top").lower()) or "top"
        code = (country or "").strip().lower()
        fetch_n = min(page_size * 3, 100)
        errors: list = []
        fatal = {"stop": False}

        async def call(endpoint, params):
            if fatal["stop"]:
                return []
            arts, err = await loop.run_in_executor(None, _newsapi_request, endpoint, params)
            if err:
                errors.append(err)
                el = err.lower()
                if "ratelimit" in el or "apikey" in el or "maximum" in el:
                    fatal["stop"] = True
            return arts

        def ev_params(q, lang=True):
            p = {"q": q[:490], "pageSize": fetch_n, "sortBy": "publishedAt", "searchIn": "title,description"}
            if lang:
                p["language"] = "en"
            p["from"] = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")  # current news only
            return p

        kw = _NEWS_KEYWORDS.get(cat) or _NEWS_NATIVE_KW.get(cat) or ("" if cat == "top" else cat)
        articles: list = []

        if code:
            # 1) Native top-headlines for the ~54 countries NewsAPI supports
            if cat in _NEWS_NATIVE and code in _NEWS_TOP_HEADLINE_COUNTRIES:
                articles = await call("top-headlines", {"country": code, "category": _NEWS_NATIVE[cat], "pageSize": fetch_n})
            # 2) Any other country, or any keyword category: search by country name
            if len(articles) < min(8, page_size):
                cq = _news_country_query(code)
                if cq:
                    q = (cq + " AND (" + kw + ")") if kw else cq
                    more = await call("everything", ev_params(q))
                    if len(more) < 5:
                        more = more + await call("everything", ev_params(q, lang=False))
                    if len(more) < 5 and kw:
                        more = more + await call("everything", ev_params(cq))
                    articles = articles + more
            articles.sort(key=lambda a: a.get("publishedAt") or "", reverse=True)
        else:
            if cat in _NEWS_NATIVE:
                lists = await asyncio.gather(*[
                    call("top-headlines", {"country": c, "category": _NEWS_NATIVE[cat], "pageSize": 20})
                    for c in _NEWS_WORLD_MIX
                ])
                # round-robin so every region is represented
                for i in range(max([len(l) for l in lists] or [0])):
                    for l in lists:
                        if i < len(l):
                            articles.append(l[i])
            else:
                articles = await call("everything", ev_params(kw))
                if len(articles) < 5:
                    articles = articles + await call("everything", ev_params(kw, lang=False))

        seen = set()
        out = []
        for a in articles:
            title = (a.get("title") or "").strip()
            url = (a.get("url") or "").strip()
            if not title or not url or "[Removed]" in title or "removed.com" in url:
                continue
            ukey = url.split("?")[0].lower()
            tkey = title.lower()
            if ukey in seen or tkey in seen:
                continue
            seen.add(ukey)
            seen.add(tkey)
            out.append(a)
        # Current news only: keep last 48h; if too few, widen to 7 days. Always newest first.
        def _age_h(a):
            try:
                return (datetime.now(timezone.utc) - datetime.fromisoformat((a.get("publishedAt") or "").replace("Z", "+00:00"))).total_seconds() / 3600
            except Exception:
                return None
        fresh = out
        for max_h in (48, 168):
            fresh = [a for a in out if _age_h(a) is not None and 0 <= _age_h(a) + 1 and _age_h(a) <= max_h]
            if len(fresh) >= min(6, page_size):
                break
        out = sorted(fresh, key=lambda a: a.get("publishedAt") or "", reverse=True)
        with_img = [a for a in out if a.get("urlToImage")]
        if len(with_img) >= min(page_size, 10):
            out = with_img
        else:
            out = with_img + [a for a in out if not a.get("urlToImage")]
        err = errors[0] if (errors and not out) else None
        return out[:page_size], err

    # NewsAPI has no Hindi filter, so Hindi = same stories with headlines translated server-side.
    _NEWS_LANGS = ("en", "hi")

    def _news_cache_age(key):
        entry = _news_cache.get(key)
        return (_time.monotonic() - entry[1]) if entry else None

    async def _news_translate_text(text: str, tl: str) -> str:
        text = (text or "").strip()
        if not text:
            return text
        ck = "newstr1|" + tl + "|" + text
        hit = _cache_get(ck)
        if hit:
            return hit
        out = None
        try:
            url = ("https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl="
                   + _uparse.quote(tl) + "&dt=t&q=" + _uparse.quote(text))
            req = _ureq.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            def _fetch():
                with _ureq.urlopen(req, timeout=6) as resp:
                    return _json.loads(resp.read().decode())
            data = await asyncio.to_thread(_fetch)
            chunks = data[0] if isinstance(data, list) and data else []
            res = "".join(str(c[0]) for c in chunks if isinstance(c, list) and c and c[0]).strip()
            if res and res != text:
                out = res
        except Exception as ex:
            logging.warning("[News] translate (gtx) failed: %s", ex)
        if not out:
            try:
                res = (await _translate_plain_text(text, tl)).strip()
                if res and res != text:
                    out = res
            except Exception as ex:
                logging.warning("[News] translate fallback failed: %s", ex)
        if out:
            _cache_set(ck, out)
        return out or text

    @api.get("/world/news")
    async def world_news(
        category: str = "top",
        country: Optional[str] = None,
        lang: str = "en",
        refresh: bool = False,
        u=Depends(current_user),
    ):
        country = (country or "").strip()
        if country.lower() in ("", "world", "all", "worldwide"):
            country = ""
        lang = (lang or "en").strip().lower()[:5]
        if lang not in _NEWS_LANGS:
            lang = "en"
        cat_key = (category or "top").lower()
        cache_key = "news:" + lang + ":" + cat_key + ":" + (country.lower() or "world")
        cached = _news_cache_get(cache_key)
        if cached:
            # Refresh bypasses the cache, but at most once per 15 s per view (protects the daily API quota)
            age = _news_cache_age(cache_key)
            if not refresh or (age is not None and age < 15):
                return cached
        articles, err = await _fetch_news_articles(category, country or None, page_size=20)
        items = [
            {
                "title": a.get("title", ""),
                "description": a.get("description") or "",
                "url": a.get("url", ""),
                "image": _news_hq_image(a.get("urlToImage") or ""),
                "source": (a.get("source") or {}).get("name", "Unknown"),
                "published_at": a.get("publishedAt", ""),
            }
            for a in articles
        ]
        if lang != "en" and items:
            sem = asyncio.Semaphore(8)
            async def _tr(it):
                async with sem:
                    it["title"] = await _news_translate_text(it["title"], lang)
            await asyncio.gather(*[_tr(it) for it in items])
        result = {
            "articles": items,
            "category": category,
            "country": country or None,
            "lang": lang,
            "no_key": not bool(NEWS_API_KEY),
            "error": _news_friendly_error(err) if err else None,
        }
        if err:
            logging.warning("[News] %s/%s failed: %s", cat_key, country or "world", err)
        if result["articles"]:  # never cache empty/failed results
            _news_cache_set(cache_key, result)
        return result

    # ── Badge: how many news are newer than the user's last visit ──
    # Uses the already-cached world feed when available (zero API cost); otherwise ONE light
    # request that is shared by all users and refreshed at most every 30 min (protects the quota).
    _news_badge_state = {"at": 0.0, "items": []}

    @api.get("/world/news/new-count")
    async def world_news_new_count(since: str = "", u=Depends(current_user)):
        since = (since or "").strip()[:40]
        stamps = None
        cached = _news_cache_get("news:en:top:world")
        if cached and cached.get("articles"):
            stamps = [a.get("published_at") or "" for a in cached["articles"]]
        elif NEWS_API_KEY:
            if (not _news_badge_state["items"]) or (_time.monotonic() - _news_badge_state["at"] > 1800):
                loop = asyncio.get_running_loop()
                raw, err = await loop.run_in_executor(None, _newsapi_request, "top-headlines", {"country": "in", "category": "general", "pageSize": 40})
                if raw:
                    _news_badge_state["items"] = [a.get("publishedAt") or "" for a in raw if (a.get("title") or "").strip() and "[Removed]" not in (a.get("title") or "")]
                _news_badge_state["at"] = _time.monotonic()  # also on failure, so errors don't hammer the API
            stamps = _news_badge_state["items"]
        stamps = [x for x in (stamps or []) if x]
        latest = max(stamps) if stamps else since
        count = sum(1 for x in stamps if x > since) if since else 0
        return {"count": min(count, 99), "latest": latest}

    # ── In-app article reader ────────────────────────────────────
    # Most news sites refuse to load inside an iframe, so the server fetches the page and
    # returns clean text/images that the app renders itself (stays inside the app).
    from html.parser import HTMLParser as _HTMLParser
    import socket as _socket

    class _NewsNoRedirect(_ureq.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    def _news_url_is_public(url: str) -> bool:
        try:
            pu = _uparse.urlparse(url)
            if pu.scheme not in ("http", "https") or not pu.hostname:
                return False
            infos = _socket.getaddrinfo(pu.hostname, pu.port or (443 if pu.scheme == "https" else 80), proto=_socket.IPPROTO_TCP)
            for info in infos:
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                    return False
            return bool(infos)
        except Exception:
            return False

    class _NewsReaderParser(_HTMLParser):
        _SKIP = {"script", "style", "noscript", "nav", "footer", "aside", "form", "header", "svg", "iframe", "button", "figcaption", "template"}
        _VOID = {"br", "img", "meta", "link", "input", "hr", "source", "area", "base", "col", "embed", "param", "track", "wbr"}

        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.meta = {}
            self.title_tag = ""
            self._in_title = False
            self._skip_depth = 0
            self._article_depth = 0
            self.in_article_seen = False
            self._cur = None          # (tag, [text parts])
            self.blocks_article = []
            self.blocks_all = []

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "meta":
                key = (a.get("property") or a.get("name") or "").lower()
                if key and a.get("content") and key not in self.meta:
                    self.meta[key] = a.get("content")
                return
            if tag in self._VOID:
                return
            if tag == "title":
                self._in_title = True
            if tag in self._SKIP:
                self._skip_depth += 1
                return
            if self._skip_depth:
                return
            if tag == "article":
                self._article_depth += 1
                self.in_article_seen = True
            if tag in ("p", "h2", "h3", "li", "blockquote"):
                self._flush()
                self._cur = (tag, [])

        def handle_endtag(self, tag):
            if tag == "title":
                self._in_title = False
            if tag in self._SKIP:
                if self._skip_depth:
                    self._skip_depth -= 1
                return
            if self._skip_depth:
                return
            if tag == "article" and self._article_depth:
                self._flush()
                self._article_depth -= 1
            if self._cur and tag == self._cur[0]:
                self._flush()

        def handle_data(self, data):
            if self._in_title:
                self.title_tag += data
            if self._skip_depth or not self._cur:
                return
            self._cur[1].append(data)

        def _flush(self):
            if not self._cur:
                return
            tag, parts = self._cur
            self._cur = None
            text = _re_news.sub(r"\s+", " ", "".join(parts)).strip()
            if not text:
                return
            item = {"type": "h" if tag in ("h2", "h3") else "p", "text": text}
            if tag == "li" and len(text) < 40:
                return
            if tag != "h2" and tag != "h3" and len(text) < 40:
                return
            if item["type"] == "h" and len(text) > 140:
                return
            self.blocks_all.append(item)
            if self._article_depth:
                self.blocks_article.append(item)

    def _news_fetch_page(url: str):
        """Blocking. Returns (html_text, final_url) or raises."""
        opener = _ureq.build_opener(_NewsNoRedirect)
        cur = url
        for _ in range(5):
            if not _news_url_is_public(cur):
                raise ValueError("blocked url")
            req = _ureq.Request(cur, headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en,hi;q=0.8",
            })
            try:
                resp = opener.open(req, timeout=10)
            except _uerr.HTTPError as he:
                if he.code in (301, 302, 303, 307, 308) and he.headers.get("Location"):
                    cur = _uparse.urljoin(cur, he.headers["Location"])
                    continue
                raise
            with resp:
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "html" not in ctype and "xml" not in ctype:
                    raise ValueError("not html")
                raw = resp.read(2_500_000)
                charset = resp.headers.get_content_charset() or "utf-8"
            try:
                return raw.decode(charset, errors="replace"), cur
            except LookupError:
                return raw.decode("utf-8", errors="replace"), cur
        raise ValueError("too many redirects")

    def _news_extract(html_text: str, base_url: str):
        parser = _NewsReaderParser()
        try:
            parser.feed(html_text)
            parser.close()
        except Exception:
            pass
        m = parser.meta
        blocks = parser.blocks_article if sum(len(b["text"]) for b in parser.blocks_article) > 400 else parser.blocks_all
        seen, out, total = set(), [], 0
        for b in blocks:
            k = b["text"].lower()
            if k in seen:
                continue
            seen.add(k)
            out.append(b)
            total += len(b["text"])
            if len(out) >= 60 or total > 30000:
                break
        title = (m.get("og:title") or m.get("twitter:title") or parser.title_tag or "").strip()
        image = (m.get("og:image") or m.get("twitter:image") or "").strip()
        if image:
            image = _news_hq_image(_uparse.urljoin(base_url, image))
        return {
            "title": title,
            "description": (m.get("og:description") or m.get("description") or "").strip(),
            "image": image,
            "site": (m.get("og:site_name") or "").strip(),
            "blocks": out,
        }

    @api.get("/world/news/read")
    async def world_news_read(url: str, lang: str = "en", u=Depends(current_user)):
        url = (url or "").strip()[:2000]
        lang = (lang or "en").strip().lower()[:5]
        if lang not in _NEWS_LANGS:
            lang = "en"
        if not url.lower().startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Invalid link")
        ck = "newsread:" + lang + ":" + url
        cached = _news_cache_get(ck)
        if cached:
            return cached
        try:
            html_text, final_url = await asyncio.to_thread(_news_fetch_page, url)
            data = await asyncio.to_thread(_news_extract, html_text, final_url)
        except Exception as ex:
            logging.warning("[News] reader failed for %s: %s", url, ex)
            return {"ok": False, "url": url, "blocks": []}
        if sum(len(b["text"]) for b in data["blocks"]) < 200:
            # paywalled / script-rendered page: nothing readable, let the app offer "open original"
            return {"ok": False, "url": url, "title": data["title"], "image": data["image"], "site": data["site"], "blocks": []}
        if lang != "en":
            sem = asyncio.Semaphore(8)
            async def _tr(it):
                async with sem:
                    it["text"] = await _news_translate_text(it["text"][:1500], lang)
            data["blocks"] = data["blocks"][:40]
            await asyncio.gather(*([_tr(b) for b in data["blocks"]]))
            if data["title"]:
                data["title"] = await _news_translate_text(data["title"], lang)
        result = {"ok": True, "url": url, **data}
        _news_cache_set(ck, result)
        return result

    @api.get("/world/active-count")
    async def world_active_count(u=Depends(current_user)):
        cutoff = (now() - timedelta(seconds=45)).isoformat()
        count = await db.world_active.count_documents({"last_ping": {"$gte": cutoff}})
        return {"count": count}

    @api.post("/world/active-ping")
    async def world_active_ping(u=Depends(current_user)):
        await db.world_active.update_one(
            {"user_id": u["id"]},
            {"$set": {"user_id": u["id"], "last_ping": now().isoformat()}},
            upsert=True,
        )
        cutoff = (now() - timedelta(seconds=45)).isoformat()
        count = await db.world_active.count_documents({"last_ping": {"$gte": cutoff}})
        return {"count": count}

    class WorldReportIn(BaseModel):
        text: str
        photo_url: Optional[str] = None
        location_type: str = "world"
        location_label: Optional[str] = None

    @api.get("/world/reports")
    async def world_reports_list(
        location_type: Optional[str] = None,
        skip: int = Query(0, ge=0, le=10000),
        limit: int = Query(20, ge=1, le=100),
        u=Depends(current_user),
    ):
        query: dict = {"is_flagged": {"$ne": True}}
        if location_type and location_type.lower() != "world":
            query["location_type"] = location_type.upper()
        reports = await db.world_reports.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
        total = await db.world_reports.count_documents(query)
        for r in reports:
            r["is_liked"] = u["id"] in r.get("likes", [])
            r["like_count"] = len(r.get("likes", []))
            r["comment_count"] = len(r.get("comments", []))
        return {"reports": reports, "total": total}

    @api.post("/world/reports")
    async def create_world_report(p: WorldReportIn, u=Depends(current_user)):
        if not p.text or len(p.text.strip()) < 5:
            raise HTTPException(400, "Report too short (min 5 chars)")
        if len(p.text) > 2000:
            raise HTTPException(400, "Report too long (max 2000 chars)")
        loc_type = p.location_type.upper() if p.location_type and p.location_type.lower() != "world" else "world"
        report_id = str(uuid.uuid4())
        photo_url = await _cloudinaryize_inline_image(
            p.photo_url, "post-app/world-reports", f"report_{report_id}_{uuid.uuid4().hex}",
        )
        doc = {
            "id": report_id,
            "user_id": u["id"],
            "user_name": u["name"],
            "user_handle": u["handle"],
            "avatar_bg": u["avatar_bg"],
            "avatar_letter": u["avatar_letter"],
            "avatar_photo": u.get("avatar_photo"),
            "photo_width": p.photo_width or None,
            "photo_height": p.photo_height or None,
            "aspect_ratio": p.aspect_ratio or (round(p.photo_width/p.photo_height,4) if p.photo_width and p.photo_height else None),
            "is_badge_verified": bool(u.get("is_badge_verified")),
            "verified_category": u.get("verified_category") or None,
            "text": p.text.strip(),
            "photo_url": photo_url or None,
            "location_type": loc_type,
            "location_label": p.location_label or ("World" if loc_type == "world" else loc_type),
            "likes": [], "like_count": 0,
            "comments": [], "comment_count": 0,
            "flag_count": 0, "is_flagged": False,
            "created_at": now().isoformat(),
        }
        await db.world_reports.insert_one(doc.copy())
        doc.pop("_id", None)
        doc["is_liked"] = False
        return doc

    @api.post("/world/reports/{report_id}/like")
    async def like_world_report(report_id: str, u=Depends(current_user)):
        report = await db.world_reports.find_one({"id": report_id})
        if not report:
            raise HTTPException(404, "Not found")
        likes = report.get("likes", [])
        if u["id"] in likes:
            likes.remove(u["id"])
            liked = False
        else:
            likes.append(u["id"])
            liked = True
        await db.world_reports.update_one({"id": report_id}, {"$set": {"likes": likes, "like_count": len(likes)}})
        if liked and report.get("user_id") and report["user_id"] != u["id"]:
            _bg(_notify(report["user_id"], u, "world_like", text="liked your report", push=("New like ♥️", u["name"] + " liked your report")))
        return {"liked": liked, "like_count": len(likes)}

    @api.post("/world/reports/{report_id}/flag")
    async def flag_world_report(report_id: str, u=Depends(current_user)):
        report = await db.world_reports.find_one({"id": report_id})
        if not report:
            raise HTTPException(404, "Not found")
        new_flag_count = report.get("flag_count", 0) + 1
        await db.world_reports.update_one(
            {"id": report_id},
            {"$set": {"flag_count": new_flag_count, "is_flagged": new_flag_count >= 5}}
        )
        return {"ok": True}

    @api.get("/world/reports/{report_id}/comments")
    async def get_world_report_comments(report_id: str, u=Depends(current_user)):
        report = await db.world_reports.find_one({"id": report_id}, {"comments": 1, "_id": 0})
        if not report:
            raise HTTPException(404, "Not found")
        return {"comments": report.get("comments", [])}

    @api.post("/world/reports/{report_id}/comments")
    async def add_world_report_comment(report_id: str, body: dict, u=Depends(current_user)):
        text = (body.get("text") or "").strip()
        if not text:
            raise HTTPException(400, "Empty comment")
        comment = {
            "id": str(uuid.uuid4()),
            "user_id": u["id"],
            "user_name": u["name"],
            "user_handle": u["handle"],
            "avatar_bg": u["avatar_bg"],
            "avatar_letter": u["avatar_letter"],
            "avatar_photo": u.get("avatar_photo"),
            "text": text,
            "created_at": now().isoformat(),
        }
        await db.world_reports.update_one(
            {"id": report_id},
            {"$push": {"comments": comment}, "$inc": {"comment_count": 1}}
        )
        _wr = await db.world_reports.find_one({"id": report_id}, {"_id": 0, "user_id": 1})
        if _wr and _wr.get("user_id") and _wr["user_id"] != u["id"]:
            _bg(_notify(_wr["user_id"], u, "world_comment", text="commented on your report: " + text[:60], push=("New comment 💬", u["name"] + " commented on your report")))
        return comment

    @api.delete("/world/reports/{report_id}")
    async def delete_world_report(report_id: str, u=Depends(current_user)):
        report = await db.world_reports.find_one({"id": report_id})
        if not report:
            raise HTTPException(404, "Not found")
        if report["user_id"] != u["id"] and not u.get("is_admin"):
            raise HTTPException(403, "Not your report")
        await db.world_reports.delete_one({"id": report_id})
        return {"ok": True}

    # ── Reels ─────────────────────────────────────────────────────

    @api.post("/reels/upload-signature")
    async def sign_reel_upload(u=Depends(current_user)):
        """Create a short-lived signature for direct browser -> Cloudinary reel uploads."""
        cloud_name = CLOUDINARY_CLOUD_NAME
        api_key = CLOUDINARY_API_KEY
        api_secret = CLOUDINARY_API_SECRET
        if not (cloud_name and api_key and api_secret) and CLOUDINARY_URL:
            parsed = urllib.parse.urlparse(CLOUDINARY_URL)
            cloud_name = parsed.hostname or ""
            api_key = urllib.parse.unquote(parsed.username or "")
            api_secret = urllib.parse.unquote(parsed.password or "")
        if not (cloud_name and api_key and api_secret):
            raise HTTPException(500, "Video hosting is not configured on the server")
        timestamp = int(_time.time())
        folder = "post-app/reels"
        public_id = f"reel_{u['id']}_{uuid.uuid4().hex}"
        sign_params = f"folder={folder}&public_id={public_id}&timestamp={timestamp}"
        signature = _hl.sha1((sign_params + api_secret).encode("utf-8")).hexdigest()
        return {
            "upload_url": f"https://api.cloudinary.com/v1_1/{cloud_name}/video/upload",
            "api_key": api_key,
            "timestamp": timestamp,
            "signature": signature,
            "folder": folder,
            "public_id": public_id,
        }

    @api.post("/reels/upload")
    async def upload_reel_video(
        file: UploadFile = File(...),
        u=Depends(current_user),
    ):
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) and not CLOUDINARY_URL:
            raise HTTPException(500, "Video hosting is not configured on the server")
        if not file.content_type or not file.content_type.startswith("video/"):
            raise HTTPException(400, "Please upload a valid video file")
        upload_size = await _get_upload_size(file)
        if upload_size > MAX_UPLOAD_VIDEO_BYTES:
            raise HTTPException(400, "Video is too large. Max 100 MB.")
        try:
            result = await _upload_large_to_cloudinary(
                file.file,
                resource_type="video",
                folder="post-app/reels",
                public_id=f"reel_{u['id']}_{uuid.uuid4().hex}",
                overwrite=False,
            )
        except Exception as e:
            logging.exception("Cloudinary reel upload failed")
            msg = str(e)
            if "Invalid Signature" in msg or "String to sign" in msg:
                raise HTTPException(500, "Video hosting is misconfigured (invalid Cloudinary credentials).")
            raise HTTPException(502, "Video upload failed. Please try again.")
        return {
            "video_url": result.get("secure_url"),
            "duration": result.get("duration"),
        }

    @api.post("/reels")
    async def create_reel(body: dict, u=Depends(current_user)):
        video_url      = (body.get("video_url") or "").strip()
        photo_url      = (body.get("photo_url") or "").strip()
        _reject_inline_data_uri(video_url, "video_url")
        _reject_inline_data_uri(photo_url, "photo_url")
        _reject_inline_data_uri((body.get("music_artwork") or "").strip(), "music_artwork")
        _reject_inline_data_uri((body.get("music_url") or "").strip(), "music_url")
        for sticker in body.get("sticker_overlays") or []:
            if isinstance(sticker, dict):
                _reject_inline_data_uri(sticker.get("url"), "sticker URL")
        caption        = (body.get("caption") or "").strip()
        audio_label    = (body.get("audio_label") or "Original Audio").strip()
        duration       = int(body.get("duration") or 0)
        category       = (body.get("category") or u.get("category") or "general").strip().lower()[:40] or "general"
        tags_input     = body.get("tags") or body.get("hashtags") or []
        if isinstance(tags_input, str):
            tags_input = tags_input.split()
        tags            = list(dict.fromkeys(str(tag).strip().lower().lstrip("#")[:40] for tag in tags_input if str(tag).strip()))[:20]
        location       = (body.get("location") or "").strip() or None
        tagged_users   = [h.lstrip("@") for h in (body.get("tagged_users") or []) if h][:20]
        audience       = (body.get("audience") or "public").strip()
        audience_users = [h.lstrip("@") for h in (body.get("audience_users") or []) if h][:100]
        def _ov_pct(val, default=50.0):
            # photo-space overlays may sit on the black area around the photo, so allow a wider range
            try:
                f = float(val)
            except (TypeError, ValueError):
                return default
            if f != f or f in (float("inf"), float("-inf")):
                return default
            return max(-500.0, min(500.0, f))
        def _ov_space(o):
            return {"space": "media"} if o.get("space") == "media" else {}
        sticker_overlays = [{"id": s["id"], "url": s["url"], "xPct": _ov_pct(s.get("xPct", 50)), "yPct": _ov_pct(s.get("yPct", 50)), **_ov_space(s)} for s in (body.get("sticker_overlays") or []) if s.get("url")][:10]
        text_overlays    = [{"id": t.get("id",""), "text": str(t.get("text",""))[:500], "xPct": _ov_pct(t.get("xPct",50)), "yPct": _ov_pct(t.get("yPct",50)), "color": str(t.get("color","#ffffff"))[:30], "size": int(t.get("size",22)), "font": str(t.get("font","Classic"))[:30], "bgColor": str(t.get("bgColor","transparent"))[:30], **_ov_space(t)} for t in (body.get("text_overlays") or []) if t.get("text")][:20]
        emoji_overlays   = [{"id": e.get("id",""), "emoji": str(e.get("emoji",""))[:8], "xPct": _ov_pct(e.get("xPct",50)), "yPct": _ov_pct(e.get("yPct",50)), "size": int(e.get("size",64)), **_ov_space(e)} for e in (body.get("emoji_overlays") or []) if e.get("emoji")][:20]
        video_effect     = (body.get("video_effect") or "none").strip()[:20]
        music_url        = (body.get("music_url") or "").strip() or None
        try:
            music_start_time = max(0.0, float(body.get("music_start_time") or 0))
        except (TypeError, ValueError):
            music_start_time = 0.0
        try:
            requested_music_clip = int(float(body.get("music_clip_duration") or 15))
        except (TypeError, ValueError):
            requested_music_clip = 15
        music_clip_duration = max(1, min(30, requested_music_clip))
        music_title      = (body.get("music_title") or "").strip() or None
        music_artist     = (body.get("music_artist") or "").strip() or None
        music_artwork    = (body.get("music_artwork") or "").strip() or None
        if audience not in ("public", "friends", "only_show", "only_me"):
            audience = "public"
        remix_of       = str(body.get("remix_of") or "").strip() or None
        is_photo_reel  = bool(photo_url) and not video_url
        if not video_url and not photo_url:
            raise HTTPException(400, "video_url or photo_url is required")
        if not is_photo_reel and (duration < 1 or duration > MAX_POST_VIDEO_SECONDS):
            raise HTTPException(400, f"Reel must be 1–{MAX_POST_VIDEO_SECONDS} seconds")
        doc = {
            "id":                str(uuid.uuid4()),
            "user_id":           u["id"],
            "user_name":         u["name"],
            "user_handle":       u["handle"],
            "avatar_bg":         u["avatar_bg"],
            "avatar_letter":     u["avatar_letter"],
            "avatar_photo":      u.get("avatar_photo"),
            "is_badge_verified": bool(u.get("is_badge_verified")),
            "video_url":         video_url if not is_photo_reel else None,
            "photo_url":         photo_url if is_photo_reel else None,
            "remix_of":          remix_of,
            "caption":           caption,
            "category":          category,
            "tags":              tags,
            "audio_label":       audio_label,
            "duration":          duration if not is_photo_reel else 0,
            "location":          location,
            "tagged_users":      tagged_users,
            "audience":          audience,
            "audience_users":    audience_users if audience == "only_show" else [],
            "likes":             [],
            "saves":             [],
            "shares":            [],
            "comments":          [],
            "comment_count":     0,
            "views":             [],
            "view_count":        0,
            "created_at":        now().isoformat(),
            "sticker_overlays":  sticker_overlays,
            "text_overlays":     text_overlays,
            "emoji_overlays":    emoji_overlays,
            "video_effect":      video_effect,
            "music_url":         music_url,
            "music_start_time":  music_start_time,
            "music_clip_duration": music_clip_duration,
            "music_title":       music_title,
            "music_artist":      music_artist,
            "music_artwork":     music_artwork,
        }
        await db.reels.insert_one(doc.copy())
        doc.pop("_id", None)
        _tagged_ids = await _notify_tags(u, tagged_users, reel_id=doc["id"])
        _bg(_notify_mentions(u, caption, exclude=_tagged_ids, where="reel", reel_id=doc["id"]))
        _bg(_notify_followers(u, "new_reel", audience=audience, reel_id=doc["id"],
                              push=("New reel", f"{u['name']} shared a new reel")))
        doc["is_liked"]     = False
        doc["like_count"]   = 0
        doc["is_saved"]     = False
        doc["save_count"]   = 0
        doc["share_count"]  = 0
        doc["is_following"] = False
        return doc

    @api.get("/reels")
    async def list_reels(skip: int = Query(0, ge=0, le=10000), limit: int = Query(10, ge=1, le=50), u=Depends(current_user)):
        """Legacy Reels endpoint; use the same personalized ranking as /reels/feed."""
        # The current frontend paginates by skip. The ranking feed reserves an
        # exploration slot per page, so translate the visible offset to its
        # ranked main-slot page index.
        exploration_count = max(1, int(limit * 0.15))
        main_slot_count = max(1, limit - exploration_count)
        page = skip // main_slot_count
        result = await get_algorithmic_reels_feed(page=page, limit=limit, q="", u=u)
        result["skip"] = skip
        return result


    @api.get("/reels/{reel_id}/remixes")
    async def list_reel_remixes(reel_id: str, u=Depends(current_user)):
        """Return the source reel and public reels using the same audio."""
        source = await _safe_media_find_one(
            db.reels, {"id": reel_id},
            scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
            overlay_fields=("sticker_overlays",), comment_fields=("comments",), projection={"_id": 0},
        )
        if not source:
            raise HTTPException(404, "Reel not found")
        excluded = set((u.get("blocked_users", []) or []) + (u.get("muted_users", []) or []))
        if source.get("user_id") in excluded:
            raise HTTPException(404, "Reel not found")
        source_music_url = str(source.get("music_url") or "").strip()
        source_title = str(source.get("music_title") or "").strip()
        source_label = str(source.get("audio_label") or "").strip()
        if source_music_url:
            audio_match = {"music_url": source_music_url}
        elif source_title:
            audio_match = {"$or": [{"music_title": source_title}, {"audio_label": source_title}]}
        elif source_label:
            audio_match = {"$or": [{"audio_label": source_label}, {"music_title": source_label}]}
        else:
            audio_match = {"id": reel_id}
        query = {
            "$and": [
                audio_match,
                {"$or": [
                    {"audience": {"$exists": False}},
                    {"audience": "public"},
                    {"user_id": u["id"]},
                ]},
            ],
            "moderation_status": {"$nin": ["flagged", "under_review", "removed"]},
        }
        if excluded:
            query["user_id"] = {"$nin": list(excluded)}
        rows = await _safe_media_find(
            db.reels, query,
            scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
            overlay_fields=("sticker_overlays",), comment_fields=("comments",),
            projection={"_id": 0}, sort={"created_at": -1}, limit=50,
        )
        if not any(str(row.get("id")) == str(reel_id) for row in rows):
            rows.insert(0, source)
        for row in rows:
            embedded_views = row.get("views") if isinstance(row.get("views"), list) else []
            row["view_count"] = len(set(embedded_views))
            row.pop("likes", None)
            row.pop("saves", None)
            row.pop("comments", None)
            row.pop("views", None)
        source_view = next((row for row in rows if str(row.get("id")) == str(reel_id)), source)
        return {
            "source": source_view,
            "reels": rows,
            "total": len(rows),
            "audio_title": source_title or source_label or "Original Audio",
        }

    @api.get("/reels/discover")
    async def discover_reels(
        skip: int = Query(0, ge=0, le=10000),
        limit: int = Query(21, ge=1, le=50),
        category: Optional[str] = None,
        u=Depends(current_user),
    ):
        """Paginated discovery grid ranked with the Reels v2 algorithm (quality, popularity, freshness, taste, variety)."""
        blocked = u.get("blocked_users", [])
        muted   = u.get("muted_users", [])
        excluded = list(set(blocked + muted))
        following_ids = list(set(u.get("following", []) or []))
        query = {
            "moderation_status": {"$nin": ["flagged", "under_review", "removed"]},
            "$or": [
                {"audience": {"$exists": False}},
                {"audience": "public"},
                {"user_id": u["id"]},
                {"audience": "friends", "user_id": {"$in": following_ids}},
                {"audience": "only_show", "audience_users": u["id"]},
            ],
        }
        if excluded:
            query["user_id"] = {"$nin": excluded}
        if category and category.lower() != "all":
            query["category"] = {"$regex": category, "$options": "i"}
        pool_limit = 300
        reels_raw = await _safe_media_find(
            db.reels, query,
            scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
            overlay_fields=("sticker_overlays",), comment_fields=("comments",),
            projection={"_id": 0}, sort={"created_at": -1}, limit=pool_limit,
        )
        mention_rows = await db.reel_mentions.aggregate([
            {"$match": {"reel_id": {"$in": [r.get("id") for r in reels_raw if r.get("id")]}}},
            {"$group": {"_id": "$reel_id", "count": {"$sum": 1}}},
        ]).to_list(pool_limit)
        mention_counts = {row["_id"]: int(row.get("count") or 0) for row in mention_rows}
        def _score(r):
            try:
                created = r.get("created_at", "")
                if created:
                    from datetime import datetime, timezone as _tz
                    if isinstance(created, str):
                        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    else:
                        dt = created
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=_tz.utc)
                    age_hours = max(0, (datetime.now(_tz.utc) - dt).total_seconds() / 3600)
                else:
                    age_hours = 0
            except Exception:
                age_hours = 0
            _va=r.get("views",[]); views=len(set(_va)) if isinstance(_va,list) else 0
            likes = len(r.get("likes") or [])
            comments = max(len(r.get("comments") or []), int(r.get("comment_count") or 0))
            shares = max(len(r.get("shares") or []), int(r.get("share_count") or 0))
            saves = max(len(r.get("saves") or []), int(r.get("save_count") or 0))
            mentions = mention_counts.get(r.get("id"), int(r.get("mention_count") or 0))
            # Keep discovery consistent with the main Reels ranking signals.
            return (views * 1 + likes * 3 + comments * 5 + mentions * 6
                    + shares * 7 + saves * 8 - age_hours * 0.5)
        for _r in reels_raw:
            _r["mention_count"] = mention_counts.get(_r.get("id"), int(_r.get("mention_count") or 0))
        reels_raw = await _reels_v2_rank(reels_raw, u)      # same high-version ranking as the Reels feed
        page = reels_raw[skip: skip + limit]
        mention_docs = {
            doc["reel_id"]: doc
            async for doc in db.reel_mentions.find(
                {"target_user_id": u["id"], "reel_id": {"$in": [r["id"] for r in page]}},
                
                {"_id": 0, "reel_id": 1, "source_user_id": 1, "source_user_name": 1, "source_user_handle": 1, "source_user_avatar": 1, "source_user_bg": 1, "source_user_letter": 1}
            )
        } if page else {}
        following_ids = set(u.get("following", []))
        for r in page:
            likes = r.get("likes") or []
            saves = r.get("saves") or []
            shares = r.get("shares") or []

            mention = mention_docs.get(r["id"])
            r["is_mentioned"] = bool(mention)
            r["mentioned_by"] = (
                {"id": mention.get("source_user_id"), "name": mention.get("source_user_name"), "handle": mention.get("source_user_handle"), "avatar_photo": mention.get("source_user_avatar"), "avatar_bg": mention.get("source_user_bg"), "avatar_letter": mention.get("source_user_letter")}
                if mention else None
            )
            r["is_liked"]     = u["id"] in likes
            r["like_count"]   = len(likes)
            r["comment_count"] = max(len(r.get("comments") or []), int(r.get("comment_count") or 0))
            r["is_saved"]     = u["id"] in saves
            r["save_count"]   = max(len(saves), int(r.get("save_count") or 0))
            r["share_count"]  = max(len(shares), int(r.get("share_count") or 0))
            r["mention_count"] = mention_counts.get(r["id"], int(r.get("mention_count") or 0))
            r["is_following"] = r["user_id"] in following_ids or r["user_id"] == u["id"]
            _va=r.get("views",[]); r["view_count"]=len(set(_va)) if isinstance(_va,list) else 0; r["views_count"]=r["view_count"]; r["repost_count"]=len(r.get("reposts") or [])
            r.pop("likes", None); r.pop("saves", None); r.pop("comments", None); r.pop("views", None)
        return {"reels": page, "has_more": (skip + limit) < len(reels_raw), "skip": skip, "limit": limit}

    @api.post("/reels/{reel_id}/view")
    async def view_reel(reel_id: str, body: Optional[dict] = None, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"_id": 0, "user_id": 1, "category": 1, "duration": 1, "video_url": 1, "photo_url": 1, "music_url": 1, "music_clip_duration": 1})
        if not reel:
            raise HTTPException(404, "Reel not found")
        payload = body or {}
        try:
            watch_seconds = max(0.0, min(3600.0, float(payload.get("watch_seconds") or 0)))
        except (TypeError, ValueError):
            watch_seconds = 0.0
        try:
            completion_ratio = max(0.0, min(1.0, float(payload.get("completion_ratio") or 0)))
        except (TypeError, ValueError):
            completion_ratio = 0.0
        # Photo reels: completion = watched time / effective duration (same rule as videos), whatever the client sent.
        _eff = _reel_effective_duration(reel)
        if _eff > 0 and not reel.get("video_url") and watch_seconds > 0:
            completion_ratio = max(0.0, min(1.0, watch_seconds / _eff))
        category = str(payload.get("category") or reel.get("category") or "general").strip().lower()[:40] or "general"
        viewer_id = u["id"]
        safe_views = {"$cond": [{"$isArray": "$views"}, "$views", []]}
        viewer_views = {"$setUnion": [safe_views, [{"$literal": viewer_id}]]}
        view_update = await db.reels.update_one(
            {"id": reel_id, "views": {"$ne": viewer_id}},
            [{"$set": {"views": viewer_views, "view_count": {"$size": viewer_views}}}],
        )
        is_new_view = view_update.modified_count > 0
        if not is_new_view:
            # Legacy counters could already include duplicate plays. Keep the stored
            # aggregate equal to the distinct viewer IDs instead of preserving it.
            unique_views = {"$setUnion": [safe_views, []]}
            await db.reels.update_one(
                {"id": reel_id},
                [{"$set": {"view_count": {"$size": unique_views}}}],
            )

        event_at = now().isoformat()
        await db.reel_view_events.update_one(
            {"user_id": viewer_id, "reel_id": reel_id},
            {
                "$setOnInsert": {"event_at": event_at},
                "$set": {"creator_id": reel.get("user_id"), "category": category},
                "$max": {"watch_seconds": watch_seconds, "completion_ratio": completion_ratio},
            },
            upsert=True,
        )
        if is_new_view:
            await db.reel_rank_stats.update_one(
                {"reel_id": reel_id},
                {"$inc": {"total_views": 1, "completion_sum": completion_ratio, "watch_seconds_sum": watch_seconds},
                 "$set": {"reel_id": reel_id, "updated_at": event_at}},
                upsert=True,
            )
        _row = await db.reels.find_one({"id": reel_id}, {"_id": 0, "views": 1})
        _views = (_row or {}).get("views")
        return {"ok": True, "view_count": len(set(_views)) if isinstance(_views, list) else 0}

    @api.get("/search")
    async def unified_search(
        q: str = Query("", max_length=200),
        type: str = Query("all", max_length=20),
        skip: int = Query(0, ge=0, le=10000),
        limit: int = Query(20, ge=1, le=50),
        u=Depends(current_user),
    ):
        """Unified search: reels (by caption/hashtag/audio), users, hashtags."""
        q = q.strip()
        if not q:
            return {"reels": [], "users": [], "hashtags": []}
        blocked  = u.get("blocked_users", [])
        muted    = u.get("muted_users", [])
        excluded = list(set(blocked + muted))
        search_type = type.lower()
        results = {"reels": [], "users": [], "hashtags": []}

        if search_type in ("all", "reels"):
            q_rx = re.escape(q)
            following_list = list(set(u.get("following", []) or []))
            # same visibility rules as Discover: no flagged/removed reels, and never reels the viewer is not allowed to see
            reel_q = {"$and": [
                {"$or": [
                    {"caption": {"$regex": q_rx, "$options": "i"}},
                    {"hashtags": {"$regex": q_rx, "$options": "i"}},
                    {"audio_label": {"$regex": q_rx, "$options": "i"}},
                    {"category": {"$regex": q_rx, "$options": "i"}},
                ]},
                {"moderation_status": {"$nin": ["flagged", "under_review", "removed"]}},
                {"$or": [
                    {"audience": {"$exists": False}}, {"audience": "public"}, {"user_id": u["id"]},
                    {"audience": "friends", "user_id": {"$in": following_list}},
                    {"audience": "only_show", "audience_users": u["id"]},
                ]},
            ]}
            if excluded:
                reel_q["$and"].append({"user_id": {"$nin": excluded}})
            reels_pool = await _safe_media_find(
                db.reels, reel_q,
                scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
                overlay_fields=("sticker_overlays",), comment_fields=("comments",),
                projection={"_id": 0}, sort={"created_at": -1}, limit=250,
            )
            q_low = q.lower().lstrip("#")

            def _search_relevance(r):
                tags = _reels_tags(r)
                if q_low and q_low in tags:
                    return 0.6
                if q_low and any(q_low in t for t in tags):
                    return 0.35
                if q_low and q_low in str(r.get("caption") or "").lower():
                    return 0.3
                return 0.15
            reels_found = (await _reels_v2_rank(reels_pool, u, relevance=_search_relevance))[skip: skip + limit]
            following_ids = set(u.get("following", []))
            for r in reels_found:
                likes = r.get("likes") or []
                saves = r.get("saves") or []
                r["is_liked"]     = u["id"] in likes
                r["like_count"]   = len(likes)
                r["comment_count"] = max(len(r.get("comments") or []), int(r.get("comment_count") or 0))
                r["is_saved"]     = u["id"] in saves
                r["save_count"]   = max(len(saves), int(r.get("save_count") or 0))
                r["share_count"]  = max(len(r.get("shares") or []), int(r.get("share_count") or 0))
                r["is_following"] = r["user_id"] in following_ids or r["user_id"] == u["id"]
                _va=r.get("views",[]); r["view_count"]=len(set(_va)) if isinstance(_va,list) else 0; r["views_count"]=r["view_count"]; r["repost_count"]=len(r.get("reposts") or [])
                r.pop("likes", None); r.pop("saves", None); r.pop("comments", None); r.pop("views", None)
            results["reels"] = reels_found

        if search_type in ("all", "users"):
            user_q = {
                "$or": [
                    {"handle": {"$regex": q, "$options": "i"}},
                    {"name": {"$regex": q, "$options": "i"}},
                ],
                "is_deleted": {"$ne": True},
            }
            if excluded:
                user_q["id"] = {"$nin": excluded}
            my_following_list = list(set(u.get("following", []) or []))
            _fol = {"$cond": [{"$isArray": "$followers"}, "$followers", []]}
            cand_rows = await db.users.aggregate([
                {"$match": user_q}, {"$limit": 250},
                {"$project": {"_id": 0, "id": 1, "handle": 1, "name": 1, "is_badge_verified": 1,
                              "fc": {"$size": _fol},
                              "mutual": {"$size": {"$setIntersection": [_fol, my_following_list]}}}},
            ]).to_list(250)
            import math as _math
            q_user = q.lower().lstrip("@")
            my_set = set(my_following_list)

            def _user_rank(row):
                handle = str(row.get("handle") or "").lower().lstrip("@")
                name = str(row.get("name") or "").lower()
                if q_user and q_user in (handle, name):
                    rel = 1.0
                elif q_user and handle.startswith(q_user):
                    rel = 0.8
                elif q_user and (name.startswith(q_user) or any(part.startswith(q_user) for part in name.split())):
                    rel = 0.6
                else:
                    rel = 0.3
                return (rel + 0.25 * min(1.0, _math.log1p(int(row.get("fc") or 0)) / _math.log1p(10000))
                        + 0.35 * min(1.0, int(row.get("mutual") or 0) / 5.0)
                        + (0.25 if row.get("id") in my_set else 0.0)
                        + (0.10 if row.get("is_badge_verified") else 0.0))
            top_ids = [r["id"] for r in sorted(cand_rows, key=_user_rank, reverse=True)[:limit]]
            users_by_id = {
                usr["id"]: usr for usr in await db.users.find(
                    {"id": {"$in": top_ids}}, {"_id": 0, "password": 0, "email": 0, "phone": 0}
                ).to_list(len(top_ids) or 1)
            } if top_ids else {}
            users_found = [users_by_id[i] for i in top_ids if i in users_by_id]
            following_ids = set(u.get("following", []))
            for usr in users_found:
                usr["is_following"] = usr["id"] in following_ids
            results["users"] = [_apply_user_visibility(profile, u) for profile in users_found]

        if search_type in ("all", "hashtags"):
            pipeline = [
                {"$match": {"hashtags.0": {"$exists": True}}},
                {"$unwind": "$hashtags"},
                {"$match": {"hashtags": {"$regex": q, "$options": "i"}}},
                {"$group": {"_id": "$hashtags", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 20},
                {"$project": {"_id": 0, "tag": "$_id", "count": 1}},
            ]
            results["hashtags"] = await db.reels.aggregate(pipeline).to_list(20)

        return results

    @api.post("/reels/{reel_id}/like")
    async def like_reel(reel_id: str, body: dict = None, u=Depends(current_user)):
        _like_rate_check(u["id"])
        """Apply an idempotent like state and return the authoritative count.

        The client sends the desired state instead of asking the endpoint to
        toggle. That makes safe retries possible when a mobile connection or a
        cold-started backend drops the response after the write already landed.
        Requests without a desired state retain the legacy toggle behavior.
        """
        reel = await db.reels.find_one({"id": reel_id}, {"likes": 1, "user_id": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")

        likes = reel.get("likes") or []
        requested_state = body.get("liked") if isinstance(body, dict) else None
        if not isinstance(requested_state, bool):
            requested_state = u["id"] not in likes

        if requested_state:
            await db.reels.update_one(
                {"id": reel_id},
                {"$addToSet": {"likes": u["id"]}},
            )
        else:
            await db.reels.update_one(
                {"id": reel_id},
                {"$pull": {"likes": u["id"]}},
            )

        # Read after the atomic write so concurrent users always receive the
        # current source-of-truth count, not a count from a stale pre-read.
        updated = await db.reels.find_one({"id": reel_id}, {"likes": 1, "_id": 0})
        authoritative_likes = (updated or {}).get("likes") or []
        like_count = len(authoritative_likes)

        # Ranking already reads the source likes array. Keep the aggregate rank
        # stats current as well, without allowing a stats-write problem to turn
        # a successful like into a UI error.
        try:
            await db.reel_rank_stats.update_one(
                {"reel_id": reel_id},
                {"$set": {"reel_id": reel_id, "likes": like_count, "updated_at": now().isoformat()}},
                upsert=True,
            )
        except Exception:
            logging.exception("Could not refresh like rank stats for reel %s", reel_id)
        if requested_state and reel.get("user_id") != u["id"]:
            await _persist_user_activity_notification(
                reel["user_id"], u, "like", reel_id=reel_id
            )
        elif not requested_state and reel.get("user_id") != u["id"]:
            _bg(_unnotify(reel["user_id"], u["id"], "like", reel_id=reel_id))   # un-like → notification goes away

        return {"liked": u["id"] in authoritative_likes, "like_count": like_count}

    @api.post("/reels/{reel_id}/save")
    async def save_reel(reel_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"saves": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        saves = reel.get("saves", [])
        was_saved = u["id"] in saves
        if was_saved:
            await db.reels.update_one({"id": reel_id}, {"$pull": {"saves": u["id"]}})
            await db.saved_collections.update_many({"user_id": u["id"]}, {"$pull": {"items": {"item_id": reel_id, "item_type": "reel"}}})
            return {"saved": False, "save_count": max(0, len(saves) - 1)}
        await db.reels.update_one({"id": reel_id}, {"$addToSet": {"saves": u["id"]}})
        return {"saved": True, "save_count": len(saves) + 1}

    @api.get("/reels/{reel_id}/comments")
    async def get_reel_comments(reel_id: str, u=Depends(current_user)):
        reel = await _safe_media_find_one(db.reels, {"id": reel_id}, comment_fields=("comments",), projection={"_id": 0, "comments": 1})
        if not reel:
            raise HTTPException(404, "Reel not found")
        comments = reel.get("comments", []) or []
        return {"comments": comments}

    @api.post("/reels/{reel_id}/share")
    async def share_reel(reel_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"shares": 1, "share_count": 1, "_id": 0, **_SHARE_ACCESS_FIELDS})
        # Same answer for "missing" and "not allowed" so ids can't be probed.
        if not reel or not await _viewer_can_access_item(reel, u):
            raise HTTPException(404, "Reel not found")
        result = await db.reels.update_one(
            {"id": reel_id, "shares": {"$ne": u["id"]}},
            {"$addToSet": {"shares": u["id"]}},
        )
        updated = await db.reels.find_one({"id": reel_id}, {"shares": 1, "share_count": 1, "_id": 0})
        shares = (updated or reel).get("shares") or []
        share_count = max(len(shares), int((updated or reel).get("share_count") or 0))
        return {"shared": result.modified_count > 0, "share_count": share_count}

    @api.post("/reels/{reel_id}/comments")
    async def add_reel_comment(reel_id: str, body: dict, u=Depends(current_user)):
        text = (body.get("text") or "").strip()
        gif_url = (body.get("gif_url") or "").strip() or None
        _reject_inline_data_uri(gif_url, "gif_url")
        if not text and not gif_url:
            raise HTTPException(400, "Empty comment")
        reel = await db.reels.find_one({"id": reel_id}, {"user_id": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        comment = {
            "id":            str(uuid.uuid4()),
            "user_id":       u["id"],
            "user_name":     u["name"],
            "user_handle":   u["handle"],
            "avatar_bg":     u["avatar_bg"],
            "avatar_letter": u["avatar_letter"],
            "avatar_photo":  u.get("avatar_photo"),
            "is_badge_verified": bool(u.get("is_badge_verified")),
            "text":          text,
            "gif_url":       gif_url,
            "created_at":    now().isoformat(),
        }
        await _hydrate_comment_profiles([comment])
        await db.reels.update_one(
            {"id": reel_id},
            {"$push": {"comments": comment}, "$inc": {"comment_count": 1}}
        )
        if reel.get("user_id") != u["id"]:
            await _persist_user_activity_notification(
                reel["user_id"], u, "comment", reel_id=reel_id, comment_id=comment["id"], snippet=(text or "GIF")[:80]
            )
        _bg(_notify_mentions(u, text, exclude={reel.get("user_id")}, where="comment", reel_id=reel_id, comment_id=comment["id"]))
        return comment

    @api.delete("/reels/{reel_id}/comments/{comment_id}")
    async def delete_reel_comment(reel_id: str, comment_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"comments": 1, "user_id": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        comment = next((c for c in reel.get("comments", []) if c["id"] == comment_id), None)
        if not comment:
            raise HTTPException(404, "Comment not found")
        if comment["user_id"] != u["id"] and reel["user_id"] != u["id"] and not u.get("is_admin"):
            raise HTTPException(403, "Not allowed")
        await db.reels.update_one(
            {"id": reel_id},
            {"$pull": {"comments": {"id": comment_id}}, "$inc": {"comment_count": -1}}
        )
        _bg(_purge_notifs({"reel_id": reel_id, "comment_id": comment_id}))
        return {"ok": True}


    @api.post("/reels/{reel_id}/comments/{comment_id}/like")
    async def like_reel_comment(reel_id: str, comment_id: str, body: dict = None, u=Depends(current_user)):
        _like_rate_check(u["id"])
        """Persist an explicit like/dislike state and return canonical likes."""
        reel = await db.reels.find_one({"id": reel_id}, {"comments": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        comment = next((c for c in reel.get("comments", []) if str(c.get("id")) == str(comment_id)), None)
        if not comment:
            raise HTTPException(404, "Comment not found")
        user_id = str(u["id"])
        existing_likes = [str(like_id) for like_id in (comment.get("likes") or [])]
        requested_state = body.get("liked") if isinstance(body, dict) else None
        if not isinstance(requested_state, bool):
            requested_state = user_id not in existing_likes
        # $addToSet/$pull makes the operation idempotent, so retries cannot
        # duplicate a like or remove another user's like.
        update = {"$addToSet": {"comments.$.likes": user_id}} if requested_state else {"$pull": {"comments.$.likes": user_id}}
        await db.reels.update_one({"id": reel_id, "comments.id": comment_id}, update)
        updated = await db.reels.find_one({"id": reel_id}, {"comments": 1, "_id": 0})
        updated_comment = next((c for c in (updated or {}).get("comments", []) if str(c.get("id")) == str(comment_id)), None)
        authoritative_likes = [str(like_id) for like_id in ((updated_comment or {}).get("likes") or [])]
        if requested_state and comment.get("user_id") != u["id"]:
            await _persist_user_activity_notification(
                comment["user_id"], u, "like", reel_id=reel_id, comment_id=comment_id
            )
        elif not requested_state and comment.get("user_id") and comment.get("user_id") != u["id"]:
            _bg(_unnotify(comment["user_id"], u["id"], "like", reel_id=reel_id, comment_id=comment_id))
        return {
            "liked": user_id in authoritative_likes,
            "like_count": len(authoritative_likes),
            "likes": authoritative_likes,
        }

    @api.post("/reels/{reel_id}/comments/{comment_id}/replies")
    async def add_reel_comment_reply(reel_id: str, comment_id: str, body: dict, u=Depends(current_user)):
        text = (body.get("text") or "").strip()
        gif_url = (body.get("gif_url") or "").strip() or None
        _reject_inline_data_uri(gif_url, "gif_url")
        if not text and not gif_url:
            raise HTTPException(400, "Empty reply")
        reel = await db.reels.find_one({"id": reel_id}, {"comments": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        parent_comment = next((c for c in reel.get("comments", []) if str(c.get("id")) == str(comment_id)), None)
        if not parent_comment:
            raise HTTPException(404, "Comment not found")
        reply = {
            "id":            str(uuid.uuid4()),
            "user_id":       u["id"],
            "user_name":     u["name"],
            "user_handle":   u["handle"],
            "avatar_bg":     u["avatar_bg"],
            "avatar_letter": u["avatar_letter"],
            "avatar_photo":  u.get("avatar_photo"),
            "is_badge_verified": bool(u.get("is_badge_verified")),
            "text":          text,
            "gif_url":       gif_url,
            "created_at":    now().isoformat(),
        }
        await _hydrate_comment_profiles([reply])
        await db.reels.update_one(
            {"id": reel_id, "comments.id": comment_id},
            {"$push": {"comments.$.replies": reply}}
        )
        if parent_comment.get("user_id") != u["id"]:
            await _persist_user_activity_notification(
                parent_comment["user_id"], u, "reply", reel_id=reel_id, comment_id=comment_id, snippet=(text or "GIF")[:80]
            )
        _bg(_notify_mentions(u, text, exclude={parent_comment.get("user_id")}, where="comment", reel_id=reel_id, comment_id=comment_id, reply_id=reply["id"]))
        return reply

    @api.delete("/reels/{reel_id}/comments/{comment_id}/replies/{reply_id}")
    async def delete_reel_comment_reply(reel_id: str, comment_id: str, reply_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"comments": 1, "user_id": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        comment = next((c for c in reel.get("comments", []) if c["id"] == comment_id), None)
        if not comment:
            raise HTTPException(404, "Comment not found")
        reply = next((r for r in comment.get("replies", []) if r["id"] == reply_id), None)
        if not reply:
            raise HTTPException(404, "Reply not found")
        if reply["user_id"] != u["id"] and reel["user_id"] != u["id"] and not u.get("is_admin"):
            raise HTTPException(403, "Not allowed")
        await db.reels.update_one(
            {"id": reel_id, "comments.id": comment_id},
            {"$pull": {"comments.$.replies": {"id": reply_id}}}
        )
        return {"ok": True}

    @api.delete("/reels/{reel_id}")
    async def delete_reel(reel_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"user_id": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        if reel["user_id"] != u["id"] and not u.get("is_admin"):
            raise HTTPException(403, "Not your reel")
        await db.reels.delete_one({"id": reel_id})
        await db.reel_mentions.delete_many({"reel_id": reel_id})
        # every notification of this reel (likes, comments, tags, mentions, reposts, new_reel …), not only reel_mention
        await db.notifications.delete_many({"$or": [{"reel_id": reel_id}, {"post_id": reel_id, "is_reel": True}]})
        return {"ok": True}

    @api.post("/reels/{reel_id}/report")
    async def report_reel(reel_id: str, body: dict, u=Depends(current_user)):
        reason = (body.get("reason") or "").strip()
        if not reason: raise HTTPException(400, "Reason required")
        reel = await db.reels.find_one({"id": reel_id}, {"_id": 0, "user_id": 1})
        if not reel: raise HTTPException(404, "Reel not found")
        already = await db.reports.find_one({"reel_id": reel_id, "reported_by": u["id"]})
        if already: return {"ok": True, "already": True}
        await db.reports.insert_one({"id": str(uuid.uuid4()), "reel_id": reel_id, "reported_by": u["id"], "reported_user_id": reel.get("user_id"), "reason": reason, "created_at": now().isoformat(), "status": "pending", "type": "reel"})
        return {"ok": True}


    # ── Group Chat ─────────────────────────────────────────────────
    class GroupIn(BaseModel):
        name: str
        member_ids: List[str] = []
        avatar_color: Optional[str] = None
        avatar_photo: Optional[str] = None

    class GroupMessageIn(BaseModel):
        text: str = ""
        photo_url: Optional[str] = None
        gif_url: Optional[str] = None
        shared_post_id: Optional[str] = None
        shared_reel_id: Optional[str] = None
        reply_to_id: Optional[str] = None
        audio_url: Optional[str] = None
        audio_duration: Optional[int] = None
        file_url: Optional[str] = None
        file_name: Optional[str] = None
        file_size: Optional[int] = None
        file_type: Optional[str] = None

    @api.post("/groups")
    async def create_group(p: GroupIn, u=Depends(current_user)):
        name = p.name.strip()
        if not name:
            raise HTTPException(400, "Group name required")
        if not u.get("is_badge_verified") and p.member_ids:
            verified_member = await db.users.find_one(
                {"id": {"$in": p.member_ids}, "is_badge_verified": True},
                {"_id": 0, "id": 1},
            )
            if verified_member:
                raise HTTPException(403, "Non-verified accounts cannot add verified users to groups")
        members = list(set([u["id"]] + p.member_ids))
        group_id = str(uuid.uuid4())
        avatar_photo = await _cloudinaryize_inline_image(
            p.avatar_photo, "post-app/group-avatars",
            f"group_{group_id}_{uuid.uuid4().hex}",
        )
        doc = {
            "id": group_id,
            "name": name,
            "avatar_color": p.avatar_color or "#FFD600",
            "avatar_letter": name[0].upper(),
            "avatar_photo": avatar_photo or None,
            "creator_id": u["id"],
            "admins": [u["id"]],
            "members": members,
            "created_at": now().isoformat(),
            "last_message": None,
            "last_message_at": now().isoformat(),
        }
        await db.groups.insert_one(doc.copy())
        doc.pop("_id", None)
        for _mid in members:
            if _mid != u["id"]:
                _bg(_notify(_mid, u, "group_add", group_id=group_id, text=f"added you to the group “{name}”",
                            push=(name, f"{u['name']} added you to the group")))
        return doc

    @api.get("/groups")
    async def list_groups(u=Depends(current_user)):
        grps = await _safe_media_find(
            db.groups, {"members": u["id"]}, scalar_fields=("avatar_photo",),
            projection={"_id": 0}, sort={"last_message_at": -1}, limit=100,
        )
        result = []
        for g in grps:
            unread = await db.group_messages.count_documents({
                "group_id": g["id"], "seen_by": {"$ne": u["id"]}, "from_id": {"$ne": u["id"]}
            })
            g["unread"] = unread
            result.append(g)
        return {"groups": result}

    @api.get("/groups/{group_id}")
    async def get_group(group_id: str, u=Depends(current_user)):
        g = await _safe_media_find_one(db.groups, {"id": group_id}, scalar_fields=("avatar_photo",), projection={"_id": 0})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []): raise HTTPException(403, "Not a member")
        member_docs = await _safe_user_find(
            {"id": {"$in": g["members"]}},
            {"_id": 0, "id": 1, "name": 1, "handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1, "bio": 1, "is_online": 1, "is_badge_verified": 1},
            limit=200,
        )
        member_docs = [_apply_presence_visibility(member, u) for member in member_docs]
        g["member_details"] = member_docs
        return g

    @api.post("/groups/{group_id}/avatar")
    async def upload_group_avatar(group_id: str, file: UploadFile = File(...), u=Depends(current_user)):
        """Upload group avatar image to Cloudinary and save URL."""
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "admins": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("admins", []): raise HTTPException(403, "Only admins can change avatar")
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) and not CLOUDINARY_URL:
            raise HTTPException(500, "Image hosting not configured")
        if not file.content_type or not file.content_type.startswith("image/"):
            raise HTTPException(400, "Please upload a valid image file")
        upload_size = await _get_upload_size(file)
        if upload_size <= 0:
            raise HTTPException(400, "Image file is empty")
        if upload_size > 10 * 1024 * 1024:
            raise HTTPException(400, "Image too large. Max 10MB.")
        # _get_upload_size rewinds the stream; rewind once more immediately before
        # handing it to Cloudinary so the complete selected image is uploaded.
        file.file.seek(0)
        try:
            async with _cloudinary_upload_semaphore:
                result = await asyncio.to_thread(
                    cloudinary.uploader.upload,
                    file.file, resource_type="image",
                    folder="post-app/group-avatars",
                    public_id=f"group_{group_id}_{uuid.uuid4().hex}",
                    overwrite=False,
                )
        except Exception:
            logging.exception("Group avatar upload failed")
            raise HTTPException(502, "Image upload failed. Please try again.")
        photo_url = result.get("secure_url") or result.get("url")
        if not photo_url:
            raise HTTPException(502, "Image upload did not return a URL")
        update_result = await db.groups.update_one({"id": group_id}, {"$set": {"avatar_photo": photo_url}})
        if not update_result.matched_count:
            raise HTTPException(404, "Group not found")
        return {"ok": True, "group_id": group_id, "avatar_photo": photo_url}

    @api.patch("/groups/{group_id}")
    async def update_group(group_id: str, body: dict, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "admins": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("admins", []): raise HTTPException(403, "Only admins can edit group")
        upd = {}
        if "name" in body and body["name"].strip():
            upd["name"] = body["name"].strip()
            upd["avatar_letter"] = body["name"].strip()[0].upper()
        if "avatar_color" in body: upd["avatar_color"] = body["avatar_color"]
        if "avatar_photo" in body:
            upd["avatar_photo"] = await _cloudinaryize_inline_image(
                body["avatar_photo"], "post-app/group-avatars",
                f"group_{group_id}_{uuid.uuid4().hex}",
            )
        if upd: await db.groups.update_one({"id": group_id}, {"$set": upd})
        return {"ok": True}

    @api.post("/groups/{group_id}/members")
    async def add_group_member(group_id: str, body: dict, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "admins": 1, "members": 1, "name": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("admins", []): raise HTTPException(403, "Only admins can add members")
        new_uid = body.get("user_id")
        if not new_uid: raise HTTPException(400, "user_id required")
        if new_uid == u["id"]: raise HTTPException(400, "You are already in the group")
        if new_uid in g.get("members", []): return {"ok": True, "already_member": True}
        target = await db.users.find_one({"id": new_uid}, {"_id": 0, "id": 1, "is_badge_verified": 1})
        if not target: raise HTTPException(404, "User not found")
        if target.get("is_badge_verified") and not u.get("is_badge_verified"): 
            raise HTTPException(403, "Non-verified accounts cannot add verified users to groups")
        connected_ids = set((u.get("followers") or []) + (u.get("following") or []))
        if new_uid not in connected_ids: raise HTTPException(403, "You can only add your followers, following, or mutual connections")
        await db.groups.update_one({"id": group_id}, {"$addToSet": {"members": new_uid}})
        _gname = g.get("name") or "a group"
        _bg(_notify(new_uid, u, "group_add", group_id=group_id, text=f"added you to the group “{_gname}”",
                    push=(_gname, f"{u['name']} added you to the group")))
        return {"ok": True}

    @api.delete("/groups/{group_id}/members/{member_id}")
    async def remove_group_member(group_id: str, member_id: str, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "admins": 1, "creator_id": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("admins", []) and member_id != u["id"]:
            raise HTTPException(403, "Not allowed")
        await db.groups.update_one({"id": group_id}, {"$pull": {"members": member_id, "admins": member_id}})
        return {"ok": True}

    @api.delete("/groups/{group_id}")
    async def delete_group(group_id: str, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "creator_id": 1})
        if not g: raise HTTPException(404, "Group not found")
        if g["creator_id"] != u["id"] and not u.get("is_admin"):
            raise HTTPException(403, "Only creator can delete group")
        await db.groups.delete_one({"id": group_id})
        await db.group_messages.delete_many({"group_id": group_id})
        return {"ok": True}

    @api.get("/groups/{group_id}/messages")
    async def get_group_messages(group_id: str, skip: int = Query(0, ge=0, le=100000), limit: int = Query(40, ge=1, le=100), u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []): raise HTTPException(403, "Not a member")
        msgs = await _safe_media_find(
            db.group_messages, {"group_id": group_id, "deleted_for": {"$ne": u["id"]}},
            scalar_fields=("photo_url", "gif_url", "audio_url", "from_avatar_photo", "shared_post.photo_url", "shared_post.avatar_photo"),
            projection={"_id": 0}, sort={"created_at": -1}, skip=skip, limit=limit,
        )
        msgs.reverse()
        # Do not render stale/empty shared-post markers as real post shares.
        for msg in msgs:
            shared_post = msg.get("shared_post")
            if shared_post is not None and (
                not isinstance(shared_post, dict)
                or not str(shared_post.get("id") or "").strip()
            ): 
                msg["shared_post"] = None

        # Older group messages may predate sender-avatar snapshots. Fill missing
        # photos from current profiles so history keeps showing member avatars.
        sender_ids = list(dict.fromkeys(
            str(msg.get("from_id"))
            for msg in msgs
            if msg.get("from_id") and not msg.get("from_avatar_photo")
        ))
        if sender_ids:
            sender_profiles = await _safe_user_find(
                {"id": {"$in": sender_ids}},
                {"_id": 0, "id": 1, "name": 1, "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1},
                limit=len(sender_ids),
            )
            profiles_by_id = {
                str(profile.get("id")): profile
                for profile in sender_profiles if profile.get("id") is not None
            }
            for msg in msgs:
                profile = profiles_by_id.get(str(msg.get("from_id")))
                if not profile:
                    continue
                if profile.get("avatar_photo"): 
                    msg["from_avatar_photo"] = profile["avatar_photo"]
                if not msg.get("from_avatar_bg"):
                    msg["from_avatar_bg"] = profile.get("avatar_bg")
                if not msg.get("from_avatar_letter"):
                    name = msg.get("from_name") or profile.get("name") or "User"
                    msg["from_avatar_letter"] = profile.get("avatar_letter") or str(name)[0].upper()
        await db.group_messages.update_many(
            {"group_id": group_id, "from_id": {"$ne": u["id"]}, "seen_by": {"$ne": u["id"]}},
            {"$addToSet": {"seen_by": u["id"]}}
        )
        return {"messages": msgs, "has_more": len(msgs) == limit}

    @api.post("/groups/{group_id}/messages")
    async def send_group_message(group_id: str, p: GroupMessageIn, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1, "name": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []): raise HTTPException(403, "Not a member")
        for field, value in (("photo_url", p.photo_url), ("gif_url", p.gif_url), ("audio_url", p.audio_url)):
            _reject_inline_data_uri(value, field)
        file_fields = _clean_chat_file(p.file_url, p.file_name, p.file_size, p.file_type)
        if not p.text.strip() and not p.photo_url and not p.gif_url and not p.shared_post_id and not p.shared_reel_id and not p.audio_url and not file_fields["file_url"]:
            raise HTTPException(400, "Message cannot be empty")
        reply_to_preview = None
        if p.reply_to_id:
            ref_rows = await db.group_messages.aggregate([
                {"$match": {"id": p.reply_to_id}},
                {"$project": {"_id": 0, "text": 1, "from_name": 1, "from_id": 1, "has_photo": {"$and": [{"$ne": [{"$ifNull": ["$photo_url", None]}, None]}, {"$ne": ["$photo_url", ""]}]}, "has_audio": {"$and": [{"$ne": [{"$ifNull": ["$audio_url", None]}, None]}, {"$ne": ["$audio_url", ""]}]}, "has_gif": {"$and": [{"$ne": [{"$ifNull": ["$gif_url", None]}, None]}, {"$ne": ["$gif_url", ""]}]}}},
            ]).to_list(1)
            ref = ref_rows[0] if ref_rows else None
            if ref:
                reply_to_preview = {"id": p.reply_to_id, "from_name": ref.get("from_name",""), "from_id": ref.get("from_id",""), "text": (ref.get("text") or "")[:120], "has_photo": bool(ref.get("has_photo")), "has_audio": bool(ref.get("has_audio")), "has_gif": bool(ref.get("has_gif"))}
        shared_post = None
        if p.shared_post_id:
            sp = await _safe_media_find_one(db.posts, {"id": p.shared_post_id}, scalar_fields=("photo_url", "avatar_photo"), array_fields=("photo_urls",), projection={"_id": 0, "id": 1, "content": 1, "photo_url": 1, "photo_urls": 1, "user_name": 1, "user_handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1})
            if sp:
                shared_post = {"id": sp["id"], "content": (sp.get("content") or "")[:200], "photo_url": sp.get("photo_url") or ((sp.get("photo_urls") or [None])[0]), "user_name": sp.get("user_name",""), "user_handle": sp.get("user_handle",""), "avatar_bg": sp.get("avatar_bg",""), "avatar_letter": sp.get("avatar_letter",""), "avatar_photo": sp.get("avatar_photo"), "type": "post"}
        doc = {
            "id": str(uuid.uuid4()), "group_id": group_id,
            "from_id": u["id"], "from_name": u["name"], "from_handle": u["handle"],
            "from_avatar_bg": u["avatar_bg"], "from_avatar_letter": u["avatar_letter"], "from_avatar_photo": u.get("avatar_photo"),
            "text": p.text.strip(), "photo_url": p.photo_url, "gif_url": p.gif_url or None,
            "audio_url": p.audio_url or None, "audio_duration": p.audio_duration or None,
            **file_fields, "edited": False,
            "reply_to_preview": reply_to_preview, "shared_post": shared_post,
            "seen_by": [u["id"]], "reactions": {}, "deleted_for": [], "created_at": now().isoformat(),
        }
        await db.group_messages.insert_one(doc.copy())
        doc.pop("_id", None)
        last_text = p.text.strip() or ("🎤 Voice" if p.audio_url else ("📷 Photo" if p.photo_url else ("GIF" if p.gif_url else ("📎 Post" if p.shared_post_id else (("📎 " + file_fields["file_name"]) if file_fields["file_url"] else "")))))
        await db.groups.update_one({"id": group_id}, {"$set": {"last_message": last_text, "last_message_at": now().isoformat(), "last_from_name": u["name"]}})
        for mid in [m for m in g.get("members", []) if m != u["id"]]:
            await _persist_user_activity_notification(
                mid, u, "group_message", from_id=u["id"], from_name=u["name"],
                group_id=group_id, group_name=g.get("name", "Group"), message=last_text[:80]
            )
        return doc

    # ── Group – leave / clear chat / invite link ──────────────────
    # NOTE: literal-path routes (/leave, /clear, /invite-link) must be defined
    # BEFORE any parametric routes (/{msg_id}) so FastAPI matches them correctly.

    @api.post("/groups/{group_id}/leave")
    async def leave_group(group_id: str, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1, "creator_id": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []): raise HTTPException(400, "Not a member")
        await db.groups.update_one({"id": group_id}, {"$pull": {"members": u["id"], "admins": u["id"]}})
        await db.group_messages.insert_one({
            "id": str(uuid.uuid4()), "group_id": group_id,
            "from_id": u["id"], "from_name": u["name"],
            "text": f"{u['name']} left the group",
            "is_system": True, "created_at": now().isoformat(),
            "seen_by": [], "reactions": {}, "deleted_for": [],
        })
        return {"ok": True}

    @api.post("/groups/{group_id}/clear-chat")
    async def clear_group_chat(group_id: str, u=Depends(current_user)):
        """Clear chat for current user only (soft delete)."""
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []): raise HTTPException(403, "Not a member")
        await db.group_messages.update_many(
            {"group_id": group_id},
            {"$addToSet": {"deleted_for": u["id"]}}
        )
        return {"ok": True}

    @api.get("/groups/{group_id}/invite-link")
    async def get_group_invite_link(group_id: str, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1, "invite_code": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []): raise HTTPException(403, "Not a member")
        invite_code = g.get("invite_code")
        if not invite_code:
            invite_code = str(uuid.uuid4())[:8].upper()
            await db.groups.update_one({"id": group_id}, {"$set": {"invite_code": invite_code}})
        frontend_url = PUBLIC_APP_URL
        return {"invite_code": invite_code, "invite_link": f"{frontend_url}?join={invite_code}"}

    @api.post("/groups/join")
    async def join_group_via_invite(body: dict, u=Depends(current_user)):
        invite_code = (body.get("invite_code") or "").strip().upper()
        if not invite_code: raise HTTPException(400, "invite_code required")
        g = await _safe_media_find_one(db.groups, {"invite_code": invite_code}, scalar_fields=("avatar_photo",), projection={"_id": 0})
        if not g: raise HTTPException(404, "Invalid invite link")
        if u["id"] in g.get("members", []):
            return {"group": g, "already_member": True}
        await db.groups.update_one({"id": g["id"]}, {"$addToSet": {"members": u["id"]}})
        await db.group_messages.insert_one({
            "id": str(uuid.uuid4()), "group_id": g["id"],
            "from_id": u["id"], "from_name": u["name"],
            "text": f"{u['name']} joined via invite link",
            "is_system": True, "created_at": now().isoformat(),
            "seen_by": [], "reactions": {}, "deleted_for": [],
        })
        g["members"] = g.get("members", []) + [u["id"]]
        return {"group": g, "already_member": False}

    @api.delete("/groups/{group_id}/messages/{msg_id}")
    async def delete_group_message(group_id: str, msg_id: str, body: dict = None, u=Depends(current_user)):
        body = body or {}
        msg = await db.group_messages.find_one({"id": msg_id, "group_id": group_id}, {"_id": 0, "from_id": 1})
        if not msg: raise HTTPException(404, "Message not found")
        if body.get("delete_for") == "everyone" and msg["from_id"] == u["id"]:
            await db.group_messages.update_one({"id": msg_id}, {"$set": {"deleted_for_everyone": True, "text": "", "photo_url": None, "audio_url": None, "file_url": None, "file_name": None}})
        else:
            await db.group_messages.update_one({"id": msg_id}, {"$addToSet": {"deleted_for": u["id"]}})
        return {"ok": True}

    @api.patch("/groups/{group_id}/messages/{msg_id}")
    async def edit_group_message(group_id: str, msg_id: str, p: MessageEditIn, u=Depends(current_user)):
        """Edit the text of one of your own group messages."""
        new_text = (p.text or "").strip()
        if not new_text:
            raise HTTPException(400, "Message cannot be empty")
        if len(new_text) > MAX_EDIT_TEXT_LEN:
            raise HTTPException(400, "Message is too long")
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1})
        if not g:
            raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []):
            raise HTTPException(403, "Not a member")
        msg = await db.group_messages.find_one({"id": msg_id, "group_id": group_id}, {"_id": 0, "from_id": 1, "text": 1, "deleted_for_everyone": 1})
        if not msg:
            raise HTTPException(404, "Message not found")
        if msg.get("from_id") != u["id"]:
            raise HTTPException(403, "You can only edit your own messages")
        if msg.get("deleted_for_everyone"):
            raise HTTPException(400, "This message was deleted")
        if not (msg.get("text") or "").strip():
            raise HTTPException(400, "Only text messages can be edited")
        edited_at = now().isoformat()
        if new_text != (msg.get("text") or ""):
            await db.group_messages.update_one({"id": msg_id}, {"$set": {"text": new_text, "edited": True, "edited_at": edited_at}})
            await db.group_messages.update_many({"group_id": group_id, "reply_to_preview.id": msg_id}, {"$set": {"reply_to_preview.text": new_text[:120]}})
            latest = await db.group_messages.find_one(
                {"group_id": group_id, "deleted_for_everyone": {"$ne": True}}, {"_id": 0, "id": 1}, sort=[("created_at", -1)]
            )
            if latest and latest.get("id") == msg_id:
                await db.groups.update_one({"id": group_id}, {"$set": {"last_message": new_text}})
        return {"ok": True, "id": msg_id, "text": new_text, "edited": True, "edited_at": edited_at}

    # ── Call Signaling (WebRTC polling) ───────────────────────────
    _call_state: dict = {}
    _CALL_STATE_MAX = 200
    _CALL_SIGNAL_MAX_COUNT = 200
    _CALL_SIGNAL_MAX_BYTES = 256 * 1024
    _CALL_SIGNAL_MAX_ONE_BYTES = 32 * 1024

    # Dedicated call-event sockets. Ringing, pickup, decline, hang-up and WebRTC
    # signals are pushed here the instant they happen, instead of the other phone
    # having to discover them on its next poll.
    _call_ws: dict = {}          # user_id -> set(WebSocket)
    _call_bg_tasks: set = set()

    async def _call_push(user_id, payload):
        sockets = list(_call_ws.get(user_id, ()))
        if not sockets:
            return
        text = _json.dumps(payload)

        async def _send(ws):
            try:
                await asyncio.wait_for(ws.send_text(text), timeout=3)
            except Exception:
                socks = _call_ws.get(user_id)
                if socks:
                    socks.discard(ws)

        await asyncio.gather(*[_send(ws) for ws in sockets])

    def _call_notify(user_ids, payload):
        """Fire-and-forget push so the HTTP response never waits on a slow socket."""
        for uid in dict.fromkeys(i for i in user_ids if i):
            task = asyncio.create_task(_call_push(uid, payload))
            _call_bg_tasks.add(task)
            task.add_done_callback(_call_bg_tasks.discard)

    def _call_peers(call, actor_id):
        return [i for i in (call.get("from_id"), call.get("to_user_id")) if i and i != actor_id]

    @app.websocket("/ws-call/{user_id}")
    async def ws_call_endpoint(websocket: WebSocket, user_id: str):
        token_val = websocket.query_params.get("token", "")
        try:
            payload = jwt.decode(token_val, JWT_SECRET, algorithms=["HS256"])
            if payload.get("sub") != user_id:
                await websocket.close(code=4001)
                return
        except Exception:
            await websocket.close(code=4001)
            return
        await websocket.accept()
        _call_ws.setdefault(user_id, set()).add(websocket)
        try:
            while True:
                raw = await websocket.receive_text()
                if raw and "ping" in raw:
                    await websocket.send_text('{"type":"pong"}')
        except Exception:
            pass
        finally:
            socks = _call_ws.get(user_id)
            if socks:
                socks.discard(websocket)
                if not socks:
                    _call_ws.pop(user_id, None)

    def _prune_call_state():
        current = now()
        for call_id, call in list(_call_state.items()):
            status = call.get("status")
            ttl = 300 if status in ("ended", "declined") else 120 if status == "ringing" else 4 * 60 * 60 if status == "active" else 600
            try:
                age = (current - datetime.fromisoformat(call["created_at"])).total_seconds()
            except (KeyError, TypeError, ValueError):
                age = float("inf")
            if age > ttl:
                _call_state.pop(call_id, None)
        if len(_call_state) >= _CALL_STATE_MAX:
            closed = sorted(
                (item for item in _call_state.items() if item[1].get("status") in ("ended", "declined")),
                key=lambda item: item[1].get("created_at", ""),
            )
            for call_id, _ in closed:
                if len(_call_state) < _CALL_STATE_MAX:
                    break
                _call_state.pop(call_id, None)

    def _public_call(call):
        return {
            key: ([{name: value for name, value in signal.items() if name != "_bytes"} for signal in value]
                  if key == "signals" else value)
            for key, value in call.items() if not str(key).startswith("_")
        }

    async def _require_call_participant(call, user_id: str):
        if user_id in (call.get("from_id"), call.get("to_user_id")):
            return
        group_id = call.get("group_id")
        if group_id:
            group = await db.groups.find_one({"id": group_id, "members": user_id}, {"_id": 1})
            if group:
                return
        raise HTTPException(status_code=403, detail="Not a participant in this call.")

    _ice_cache: dict = {"at": 0.0, "data": None}

    @api.get("/calls/ice-servers")
    async def get_ice_servers(u=Depends(current_user)):
        fallback = {"iceServers": [{"urls": "stun:stun.l.google.com:19302"}]}
        api_key = os.environ.get("METERED_API_KEY", "")
        if not api_key:
            return fallback
        cached = _ice_cache.get("data")
        if cached and (_time.monotonic() - _ice_cache["at"]) < 600:
            return cached

        def _fetch():
            url = f"https://post.metered.live/api/v1/turn/credentials?apiKey={api_key}"
            with urllib.request.urlopen(url, timeout=4) as resp:
                return _json.loads(resp.read().decode())

        try:
            data = await asyncio.to_thread(_fetch)
            _ice_cache["data"] = {"iceServers": data}
            _ice_cache["at"] = _time.monotonic()
            return _ice_cache["data"]
        except Exception:
            return cached or fallback

    @api.post("/calls/initiate")
    async def initiate_call(body: dict, u=Depends(current_user)):
        to_user_id = body.get("to_user_id")
        call_type = body.get("call_type", "voice")
        group_id = body.get("group_id")
        if not to_user_id and not group_id: raise HTTPException(400, "to_user_id or group_id required")
        if group_id:
            group = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1})
            if not group or u["id"] not in group.get("members", []):
                raise HTTPException(status_code=403, detail="Not a member of this group.")
        _prune_call_state()
        if len(_call_state) >= _CALL_STATE_MAX:
            raise HTTPException(status_code=503, detail="Call capacity is temporarily full. Try again shortly.")
        call_id = str(uuid.uuid4())
        _call_state[call_id] = {"id": call_id, "from_id": u["id"], "from_name": u["name"], "from_avatar_bg": u["avatar_bg"], "from_avatar_letter": u["avatar_letter"], "from_avatar_photo": u.get("avatar_photo"), "to_user_id": to_user_id, "group_id": group_id, "call_type": call_type, "status": "ringing", "signals": [], "_signal_bytes": 0, "_seq": 0, "created_at": now().isoformat(), "ended_at": None}
        if to_user_id:
            _call_notify([to_user_id], {"type": "call_incoming", "call": _public_call(_call_state[call_id])})
        return {"call_id": call_id, "status": "ringing"}

    @api.get("/calls/{call_id}")
    async def get_call_state(call_id: str, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        await _require_call_participant(call, u["id"])
        return _public_call(call)

    @api.post("/calls/{call_id}/signal")
    async def add_call_signal(call_id: str, body: dict, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        await _require_call_participant(call, u["id"])
        signal_type = str(body.get("type") or "")[:50]
        signal_data = body.get("data")
        try:
            signal_size = len(_json.dumps(signal_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) + len(signal_type.encode("utf-8"))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid call signal.")
        if signal_size > _CALL_SIGNAL_MAX_ONE_BYTES:
            raise HTTPException(status_code=413, detail="Call signal is too large.")
        call["_seq"] = call.get("_seq", 0) + 1
        new_signal = {"from_id": u["id"], "type": signal_type, "data": signal_data, "seq": call["_seq"], "ts": now().isoformat(), "_bytes": signal_size}
        call["signals"].append(new_signal)
        call["_signal_bytes"] = call.get("_signal_bytes", 0) + signal_size
        while len(call["signals"]) > _CALL_SIGNAL_MAX_COUNT or call["_signal_bytes"] > _CALL_SIGNAL_MAX_BYTES:
            removed = call["signals"].pop(0)
            call["_signal_bytes"] = max(0, call["_signal_bytes"] - removed.get("_bytes", 0))
        _call_notify(_call_peers(call, u["id"]), {"type": "call_signal", "call_id": call_id, "signal": {k: v for k, v in new_signal.items() if k != "_bytes"}})
        return {"ok": True}

    @api.get("/calls/{call_id}/signals")
    async def get_call_signals(call_id: str, since: int = Query(0, ge=0, le=200), u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        await _require_call_participant(call, u["id"])
        my_signals = [
            {key: value for key, value in signal.items() if key != "_bytes"}
            for signal in call["signals"][since:] if signal["from_id"] != u["id"]
        ]
        return {"signals": my_signals, "total": len(call["signals"]), "status": call.get("status")}

    @api.post("/calls/{call_id}/answer")
    async def answer_call(call_id: str, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        await _require_call_participant(call, u["id"])
        if call.get("status") in ("ended", "declined"):
            return {"ok": False, "status": call["status"]}
        if call.get("status") != "active":
            call["status"] = "active"
            call["answered_at"] = now().isoformat()
            _call_notify(_call_peers(call, u["id"]), {"type": "call_answered", "call_id": call_id})
        return {"ok": True}

    @api.post("/calls/{call_id}/end")
    async def end_call(call_id: str, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        await _require_call_participant(call, u["id"])
        if call.get("status") not in ("ended", "declined"):
            _was_ringing = call.get("status") == "ringing"
            call["status"] = "ended"
            call["ended_at"] = now().isoformat()
            _call_notify(_call_peers(call, u["id"]), {"type": "call_ended", "call_id": call_id, "status": "ended"})
            if _was_ringing and call.get("to_user_id") and u["id"] == call.get("from_id"):
                _vid = call.get("call_type") == "video"
                _bg(_notify(call["to_user_id"], u, "missed_call", is_video=_vid,
                            push=("Missed " + ("video" if _vid else "voice") + " call", "You missed a call from " + u["name"])))
        return {"ok": True}

    @api.post("/calls/{call_id}/decline")
    async def decline_call(call_id: str, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        await _require_call_participant(call, u["id"])
        if call.get("status") not in ("ended", "declined"):
            call["status"] = "declined"
            call["ended_at"] = now().isoformat()
            _call_notify(_call_peers(call, u["id"]), {"type": "call_ended", "call_id": call_id, "status": "declined"})
        return {"ok": True}

    @api.get("/calls/incoming/check")
    async def check_incoming_call(u=Depends(current_user)):
        _prune_call_state()
        for call_id, call in list(_call_state.items()):
            if call["to_user_id"] == u["id"] and call["status"] == "ringing":
                age = (now() - datetime.fromisoformat(call["created_at"])).total_seconds()
                if age > 60:
                    call["status"] = "ended"
                    call["ended_at"] = now().isoformat()
                    _vid = call.get("call_type") == "video"
                    _caller = {"id": call.get("from_id"), "name": call.get("from_name"), "avatar_photo": call.get("from_avatar_photo"),
                               "avatar_bg": call.get("from_avatar_bg"), "avatar_letter": call.get("from_avatar_letter")}
                    _bg(_notify(u["id"], _caller, "missed_call", is_video=_vid,
                                push=("Missed " + ("video" if _vid else "voice") + " call", "You missed a call from " + str(call.get("from_name") or "someone"))))
                else: return {"call": _public_call(call)}
        return {"call": None}


    # ── GIF proxy (Giphy) ─────────────────────────────────────────────────────
    @api.get("/gifs")
    async def gif_proxy(q: str = Query("", max_length=200), limit: int = Query(30, ge=1, le=50)):
        import httpx
        GIPHY_KEY = os.environ.get("GIPHY_API_KEY", "").strip()
        if not GIPHY_KEY:
            return {"gifs": [], "error": "GIPHY_API_KEY not configured on server"}
        params = {"api_key": GIPHY_KEY, "limit": limit, "rating": "pg"}
        if q.strip():
            endpoint = "https://api.giphy.com/v1/gifs/search"
            params["q"] = q.strip()
        else:
            endpoint = "https://api.giphy.com/v1/gifs/trending"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(endpoint, params=params)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            body = e.response.text[:300]
            logging.error(f"Giphy /gifs HTTP {e.response.status_code}: {body}")
            return {"gifs": [], "error": f"Giphy error {e.response.status_code}: {body}"}
        except Exception as e:
            logging.error(f"Giphy /gifs fetch failed: {e}")
            return {"gifs": [], "error": str(e)}
        gifs = []
        for g in data.get("data", []):
            try:
                imgs = g.get("images", {})
                preview = (imgs.get("fixed_width_small") or imgs.get("fixed_width") or {}).get("url", "")
                full = (imgs.get("fixed_width") or {}).get("url", "")
                if full:
                    gifs.append({"id": g["id"], "title": g.get("title", ""), "preview": preview or full, "full": full})
            except Exception:
                pass
        return {"gifs": gifs}

    # ── Stickers proxy (Giphy) ────────────────────────────────────────────────
    @api.get("/stickers")
    async def sticker_proxy(q: str = Query("", max_length=200), limit: int = Query(30, ge=1, le=50)):
        import httpx
        GIPHY_KEY = os.environ.get("GIPHY_API_KEY", "").strip()
        if not GIPHY_KEY:
            return {"stickers": [], "error": "GIPHY_API_KEY not configured on server"}
        params = {"api_key": GIPHY_KEY, "limit": limit, "rating": "pg"}
        if q.strip():
            endpoint = "https://api.giphy.com/v1/stickers/search"
            params["q"] = q.strip()
        else:
            endpoint = "https://api.giphy.com/v1/stickers/trending"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(endpoint, params=params)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            body = e.response.text[:300]
            logging.error(f"Giphy /stickers HTTP {e.response.status_code}: {body}")
            return {"stickers": [], "error": f"Giphy error {e.response.status_code}: {body}"}
        except Exception as e:
            logging.error(f"Giphy /stickers fetch failed: {e}")
            return {"stickers": [], "error": str(e)}
        stickers = []
        for g in data.get("data", []):
            try:
                imgs = g.get("images", {})
                preview = (imgs.get("fixed_width_small") or imgs.get("fixed_width") or {}).get("url", "")
                full = (imgs.get("fixed_width") or {}).get("url", "")
                if full:
                    stickers.append({"id": g["id"], "title": g.get("title", ""), "preview": preview or full, "full": full})
            except Exception:
                pass
        return {"stickers": stickers}

    # ── Security helpers ──────────────────────────────────────────────────────
    def _parse_device_name(ua: str) -> str:
        """Extract human-readable device name from User-Agent."""
        ua_lower = ua.lower()
        if "iphone" in ua_lower: return "iPhone"
        if "ipad" in ua_lower: return "iPad"
        if "android" in ua_lower:
            # Android browsers expose the model between the version and Build/.
            match = re.search(r"Android[^;)]*;\s*(?:[a-z]{2}-[A-Z]{2};\s*)?([^;)]+?)(?:\s+Build[/;]|;wv|\))", ua)
            if match:
                model = re.sub(r"\s+Build.*$", "", match.group(1)).replace("_", " ").strip()
                if model and model.lower() not in {"wv", "mobile", "tablet"}: return model
            return "Android Mobile" if "mobile" in ua_lower else "Android Tablet"
        if "windows" in ua_lower: return "Windows PC"
        if "macintosh" in ua_lower or "mac os" in ua_lower: return "Mac"
        if "linux" in ua_lower: return "Linux PC"
        if ua.strip(): return ua[:40]
        return "Unknown device"

    # ── Security & Sessions endpoints ─────────────────────────────────────────
    @api.get("/security/sessions")
    async def get_security_sessions(request: Request, u=Depends(current_user)):
        current_sid = u.get("_current_session_id")
        # A login token lives 30 days, so older session records can never be used again.
        # Drop them so "active sessions" only lists devices that can really still get in.
        cutoff = (now() - timedelta(days=30)).isoformat()
        stale_q = {"user_id": u["id"], "created_at": {"$lt": cutoff}}
        if current_sid:
            stale_q["id"] = {"$ne": current_sid}
        await db.sessions.delete_many(stale_q)
        if current_sid:
            # Only look up location when we don't have one yet; never overwrite the
            # more precise location captured at login, and skip slow IP lookups otherwise.
            cur = await db.sessions.find_one({"id": current_sid, "user_id": u["id"]}, {"_id": 0, "location": 1})
            if cur and (not cur.get("location") or cur.get("location") == "Unknown location"):
                current_metadata = await asyncio.to_thread(_session_metadata, request)
                if current_metadata.get("location") != "Unknown location":
                    await db.sessions.update_one(
                        {"id": current_sid, "user_id": u["id"]},
                        {"$set": current_metadata},
                    )
        sessions = await db.sessions.find(
            {"user_id": u["id"]}, {"_id": 0}
        ).sort("last_active", -1).to_list(50)
        for s in sessions:
            s["is_current"] = (s.get("id") == current_sid)
        return {"sessions": sessions}

    @api.delete("/security/sessions/{session_id}")
    async def revoke_security_session(session_id: str, u=Depends(current_user)):
        if session_id == "all":
            current_sid = u.get("_current_session_id")
            query = {"user_id": u["id"]}
            if current_sid:
                query["id"] = {"$ne": current_sid}
            await db.sessions.delete_many(query)
            return {"ok": True}
        session = await db.sessions.find_one({"id": session_id, "user_id": u["id"]})
        if not session:
            raise HTTPException(404, "Session not found")
        await db.sessions.delete_one({"id": session_id, "user_id": u["id"]})
        return {"ok": True}


    # ── Our Planet: public Earth explorer adapters ───────────────────────────
    _PLANET_CONTACT_EMAIL = os.environ.get("OUR_PLANET_CONTACT_EMAIL", "support@postbluom.online").strip()
    _PLANET_UA = f"PostApp-OurPlanet/1.0 ({_PLANET_CONTACT_EMAIL})"
    _PLANET_CACHE = {}
    _PLANET_CACHE_TTL = 1800
    _PLANET_CACHE_MAX_ENTRIES = 128

    def _planet_cache_get(key):
        now_mono = _time.monotonic()
        entry = _PLANET_CACHE.get(key)
        if not entry:
            return None
        if now_mono - entry[0] >= _PLANET_CACHE_TTL:
            _PLANET_CACHE.pop(key, None)
            return None
        return entry[1]

    def _planet_cache_set(key, value):
        now_mono = _time.monotonic()
        for cached_key, (cached_at, _) in list(_PLANET_CACHE.items()):
            if now_mono - cached_at >= _PLANET_CACHE_TTL:
                _PLANET_CACHE.pop(cached_key, None)
        if key not in _PLANET_CACHE and len(_PLANET_CACHE) >= _PLANET_CACHE_MAX_ENTRIES:
            oldest_key = min(_PLANET_CACHE, key=lambda cached_key: _PLANET_CACHE[cached_key][0])
            _PLANET_CACHE.pop(oldest_key, None)
        _PLANET_CACHE[key] = (now_mono, value)

    _PLANET_NOMINATIM_LOCK = _threading.Lock()
    _PLANET_NOMINATIM_LAST = 0.0
    _PLANET_NOMINATIM = "https://nominatim.openstreetmap.org/search"
    _PLANET_WIKI = "https://en.wikipedia.org/api/rest_v1/page/summary/"
    _PLANET_COMMONS = "https://commons.wikimedia.org/w/api.php"
    _PLANET_GBIF = "https://api.gbif.org/v1/species/match"
    _PLANET_NASA = "https://cmr.earthdata.nasa.gov/search/granules.json"
    _PLANET_ARCGIS = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/export"
    _PLANET_NASA_KEY = os.environ.get("NASA_API_KEY", "").strip()
    _PLANET_GFW_KEY = os.environ.get("GFW_API_KEY", "").strip()

    from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor

    def _planet_weather(lat, lon):
        if lat is None or lon is None: return {}
        return _planet_get_json("https://api.open-meteo.com/v1/forecast", {"latitude":lat,"longitude":lon,"current_weather":"true","daily":"temperature_2m_max,temperature_2m_min,precipitation_sum","timezone":"auto"}, 10)

    def _planet_power(lat, lon):
        if lat is None or lon is None: return {}
        return _planet_get_json("https://power.larc.nasa.gov/api/temporal/climatology/point", {"parameters":"T2M,PRECTOTCORR,ALLSKY_SFC_SW_DWN","community":"RE","longitude":lon,"latitude":lat,"format":"JSON"}, 12)

    def _planet_gfw(lat, lon):
        if lat is None or lon is None or not _PLANET_GFW_KEY: return {}
        try:
            lat, lon = float(lat), float(lon)
            west, east = max(-180.0, lon - 0.5), min(180.0, lon + 0.5)
            south, north = max(-90.0, lat - 0.5), min(90.0, lat + 0.5)
            geometry = {"type":"Polygon","coordinates":[[[west,south],[east,south],[east,north],[west,north],[west,south]]]}
            sql = "SELECT SUM(area__ha) AS loss_ha FROM data"
            return _planet_post_json("https://data-api.globalforestwatch.org/dataset/umd_tree_cover_loss/latest/query/json", {"sql":sql,"geometry":geometry}, 15, {"x-api-key":_PLANET_GFW_KEY})
        except (TypeError, ValueError): return {}

    def _planet_nasa_library(query):
        if not _PLANET_NASA_KEY: return {}
        data = _planet_get_json("https://images-api.nasa.gov/search", {"q":query,"media_type":"image"}, 15)
        item = (data.get("collection",{}).get("items") or [{}])[0]
        return {"nasa_image_url":((item.get("links") or [{}])[0]).get("href")} if item else {}

    def _planet_addons(query, lat, lon):
        with _ThreadPoolExecutor(max_workers=4) as pool:
            jobs = {
                "weather": pool.submit(_planet_weather, lat, lon),
                "power": pool.submit(_planet_power, lat, lon),
                "gfw": pool.submit(_planet_gfw, lat, lon),
                "nasa": pool.submit(_planet_nasa_library, query),
            }
            data = {name:job.result() for name,job in jobs.items()}
        weather, power, gfw = data["weather"] or {}, data["power"] or {}, data["gfw"] or {}
        current, daily = weather.get("current_weather") or {}, weather.get("daily") or {}
        parameter = (power.get("properties") or {}).get("parameter") or {}
        climate=[]
        if current:
            climate.append(f"Live conditions: {current.get('temperature','—')}°C, wind {current.get('windspeed','—')} km/h")
            highs, lows, rain = daily.get("temperature_2m_max") or [], daily.get("temperature_2m_min") or [], daily.get("precipitation_sum") or []
            if highs or lows: climate.append(f"Today's forecast: {highs[0] if highs else '—'}°C high / {lows[0] if lows else '—'}°C low")
            if rain: climate.append(f"Precipitation today: {rain[0]} mm")
        if parameter:
            climate.extend([f"Long-term temperature: {parameter.get('T2M',{}).get('ANN','—')}°C",f"Average precipitation: {parameter.get('PRECTOTCORR',{}).get('ANN','—')} mm/day",f"Average solar energy: {parameter.get('ALLSKY_SFC_SW_DWN',{}).get('ANN','—')} kWh/m²/day"])
        environment=None
        if _PLANET_GFW_KEY:
            try:
                row=(gfw.get("data") or [{}])[0]
                value=row.get("loss_ha") or row.get("sum(area__ha)")
                environment=f"Tree cover loss in the surrounding area: {round(float(value)):,} hectares." if value is not None else "Global Forest Watch returned no tree-cover-loss record for this location."
            except (AttributeError,TypeError,ValueError): environment="Global Forest Watch returned no tree-cover-loss record for this location."
        sources=[]
        if current: sources.append("Open-Meteo")
        if parameter: sources.append("NASA POWER")
        if data["nasa"].get("nasa_image_url"): sources.append("NASA Image Library")
        if _PLANET_GFW_KEY and gfw: sources.append("Global Forest Watch")
        return {"nasa_image_url":data["nasa"].get("nasa_image_url"),"climate":"\\n".join(climate) or None,"environment":environment,"source_suffix":(" + "+" + ".join(sources)) if sources else ""}


    def _planet_get_json(url, params=None, timeout=10, extra_headers=None):
        try:
            if params:
                url += "?" + urllib.parse.urlencode(params, doseq=True)
            request_headers = {"User-Agent": _PLANET_UA, "Accept": "application/json"}
            if extra_headers:
                request_headers.update(extra_headers)
            req = urllib.request.Request(url, headers=request_headers)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return _json.loads(response.read(4_000_000).decode("utf-8"))
        except Exception:
            return {}

    def _planet_post_json(url, payload, timeout=10, extra_headers=None):
        try:
            # urllib normalizes x-api-key to X-api-key; GFW's gateway requires the lowercase header.
            import http.client as _http_client
            request_headers = {"User-Agent": _PLANET_UA, "Accept": "application/json", "Content-Type": "application/json"}
            if extra_headers:
                request_headers.update(extra_headers)
            body = _json.dumps(payload).encode("utf-8")
            for _attempt in range(2):
                parsed = urllib.parse.urlsplit(url)
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                connection = _http_client.HTTPSConnection(parsed.netloc, timeout=timeout)
                connection.request("POST", path, body=body, headers=request_headers)
                response = connection.getresponse()
                raw = response.read(4_000_000)
                if response.status in (301, 302, 307, 308) and response.getheader("location"):
                    url = urllib.parse.urljoin(url, response.getheader("location"))
                    connection.close()
                    continue
                connection.close()
                if response.status >= 400:
                    return {}
                return _json.loads(raw.decode("utf-8"))
            return {}
        except Exception:
            return {}

    def _planet_geo(query):
        global _PLANET_NOMINATIM_LAST
        with _PLANET_NOMINATIM_LOCK:
            pause = 1.0 - (_time.time() - _PLANET_NOMINATIM_LAST)
            if pause > 0:
                _time.sleep(pause)
            data = _planet_get_json(_PLANET_NOMINATIM, {"q": query, "format": "json", "limit": 1}, 10)
            _PLANET_NOMINATIM_LAST = _time.time()
        try:
            item = data[0]
            return {"lat": float(item["lat"]), "lon": float(item["lon"]), "display": item.get("display_name", ""), "osm_class": item.get("class"), "osm_type": item.get("type")}
        except (IndexError, KeyError, TypeError, ValueError):
            return {}

    def _planet_wiki(query):
        data = _planet_get_json(_PLANET_WIKI + urllib.parse.quote(query.replace(" ", "_")), timeout=10)
        if data.get("type") == "disambiguation" or not data.get("title"):
            return {}
        return {"title": data.get("title"), "extract": data.get("extract"), "description": (data.get("description") or "").lower(), "thumbnail": (data.get("thumbnail") or {}).get("source"), "page_url": (data.get("content_urls") or {}).get("desktop", {}).get("page")}

    def _planet_photo(query):
        data = _planet_get_json(_PLANET_COMMONS, {"action":"query", "generator":"search", "gsrsearch":query + " filetype:bitmap", "gsrnamespace":6, "gsrlimit":3, "prop":"imageinfo", "iiprop":"url|extmetadata", "iiurlwidth":1400, "format":"json"}, 12)
        for page in (data.get("query", {}).get("pages", {}) or {}).values():
            info = (page.get("imageinfo") or [{}])[0]
            meta = info.get("extmetadata") or {}
            artist = (meta.get("Artist") or {}).get("value", "")
            return {"photo_url": info.get("thumburl") or info.get("url"), "photo_credit": __import__("html").unescape(str(artist))}
        return {}

    _PLANET_PLACE_CLASSES = {"boundary", "place", "natural", "waterway", "landuse", "highway", "railway", "aeroway", "amenity", "tourism", "historic", "leisure", "water", "building", "man_made"}

    def _planet_bio(query, geo_data=None):
        # strict=true stops GBIF from fuzzy-matching place names (e.g. "Sikkim") to unrelated taxa.
        data = _planet_get_json(_PLANET_GBIF, {"name": query, "strict": "true"}, 10)
        key = data.get("usageKey")
        match_type = data.get("matchType")
        if not key or not (match_type == "EXACT" or (match_type == "FUZZY" and (data.get("confidence") or 0) >= 95)):
            return {}
        is_place = bool(geo_data and geo_data.get("osm_class") in _PLANET_PLACE_CLASSES)
        if is_place and data.get("rank") not in ("SPECIES", "SUBSPECIES", "VARIETY", "FORM"):
            return {}
        return {"scientific": data.get("scientificName"), "key": key}

    def _planet_gbif_map(taxon_key):
        # GBIF Map API v2 requires the srs parameter; without it the tile request returns HTTP 400.
        if not taxon_key:
            return None
        return ("https://api.gbif.org/v2/map/occurrence/density/0/0/0@2x.png?"
                + urllib.parse.urlencode({"srs": "EPSG:3857", "taxonKey": taxon_key, "style": "purpleYellow.point"}))

    def _planet_nasa(query):
        data = _planet_get_json(_PLANET_NASA, [("keyword", query), ("page_size", 3), ("sort_key[]", "-start_date")], 12)
        entry = (data.get("feed", {}).get("entry") or [{}])[0]
        for link in entry.get("links", []):
            marker = ((link.get("title") or "") + " " + (link.get("type") or "")).lower()
            if any(word in marker for word in ("image", "browse", "thumbnail")):
                return {"satellite_desc": entry.get("summary"), "source_url": entry.get("id"), "satellite_url": link.get("href")}
        return {}

    def _planet_satellite(lat, lon):
        if lat is None or lon is None:
            return None
        params = {"bbox": f"{lon-0.2},{lat-0.2},{lon+0.2},{lat+0.2}", "bboxSR":4326, "imageSR":4326, "size":"800,500", "format":"jpg", "f":"image"}
        return _PLANET_ARCGIS + "?" + urllib.parse.urlencode(params)

    _PLANET_TYPES = {("waterway","river"):"River", ("waterway","stream"):"River", ("natural","water"):"Lake", ("place","ocean"):"Ocean / Sea", ("place","sea"):"Ocean / Sea", ("natural","peak"):"Mountain / Peak", ("natural","ridge"):"Mountain / Range", ("natural","wood"):"Forest", ("landuse","forest"):"Forest", ("natural","desert"):"Desert", ("place","country"):"Country / Region", ("boundary","administrative"):"Country / Region", ("place","city"):"City", ("place","town"):"Town"}
    _PLANET_WORDS = [("river","River"), ("mountain range","Mountain / Range"), ("mountain","Mountain / Peak"), ("ocean","Ocean / Sea"), ("sea","Ocean / Sea"), ("rainforest","Forest"), ("forest","Forest"), ("desert","Desert"), ("lake","Lake"), ("country","Country / Region"), ("city","City")]

    def _planet_type(bio, geo_data, wiki_data):
        if bio:
            return "Species"
        mapped = _PLANET_TYPES.get((geo_data.get("osm_class"), geo_data.get("osm_type")))
        if mapped:
            return mapped
        for word, label in _PLANET_WORDS:
            if word in (wiki_data.get("description") or ""):
                return label
        return "Place / Geographic Feature" if geo_data else "Earth Entity"

    def _planet_profile(query):
        key = " ".join(query.strip().lower().split())
        cached_profile = _planet_cache_get(key)
        if cached_profile is not None:
            return cached_profile
        geo_data = _planet_geo(query)
        bio = _planet_bio(query, geo_data)
        wiki_data = _planet_wiki(query)
        photo = _planet_photo(query)
        nasa = _planet_nasa(query)
        satellite_url = _planet_satellite(geo_data.get("lat"), geo_data.get("lon"))
        addons = _planet_addons(query, geo_data.get("lat"), geo_data.get("lon"))
        result = {
            "id": "earth-" + _hl.sha1(key.encode("utf-8")).hexdigest()[:16],
            "name": wiki_data.get("title") or query,
            "entity_type": _planet_type(bio, geo_data, wiki_data),
            "description": wiki_data.get("extract") or geo_data.get("display") or f"Explore detailed Earth information about {query}.",
            "lat": geo_data.get("lat"), "lon": geo_data.get("lon"),
            "photo_url": photo.get("photo_url") or wiki_data.get("thumbnail"), "photo_credit": photo.get("photo_credit"),
            "satellite_url": satellite_url,
            "map_url": _planet_gbif_map(bio.get("key")),
            "map_taxon": bio.get("key"),
            "nasa_image_url": addons.get("nasa_image_url"),
            "sections": {
                "geography": geo_data.get("display") or "Coordinates, terrain, boundaries and nearby places when available.",
                "satellite": nasa.get("satellite_desc") or ("Satellite view centered on this location." if satellite_url else "No location found to generate a satellite view."),
                "photos": photo.get("photo_credit") or ("Wikipedia" if wiki_data.get("thumbnail") else "Real source photographs when available."),
                "water": "Hydrology, water level, discharge and water-quality data when available.",
                "environment": addons.get("environment") or "Ecosystems, land cover, vegetation and environmental observations when available.",
                "biodiversity": f"Scientific name: {bio.get('scientific')}" if bio else "Species and biodiversity observations when available.",
                "climate": addons.get("climate") or "Temperature, rainfall, climate normals and trends when available.",
                "events": "Earthquakes, floods, fires, storms and other events when available.",
                "culture": "Nearby cities, protected places, landmarks and cultural information when available.",
                "statistics": "Provider-specific measurements, counts and trends when available.",
                "history": "Historical satellite/data records when available.",
                "ai": "Earth AI can summarize returned data, compare dates and explain the entity with source citations.",
            },
            "related": [query + " map", query + " photos", query + " satellite", query + " biodiversity"],
            "source": "Wikipedia + Wikimedia Commons + OpenStreetMap + GBIF + Esri World Imagery" + (" + NASA Earthdata" if nasa.get("satellite_desc") else "") + addons.get("source_suffix", ""),
            "source_url": wiki_data.get("page_url") or nasa.get("source_url"),
        }
        _planet_cache_set(key, result)
        return result

    @api.get("/our-planet/search")
    async def our_planet_search(q: str = Query("", max_length=200)):
        clean_query = q.strip()
        return {"results": [] if not clean_query else [await asyncio.to_thread(_planet_profile, clean_query)]}

    @api.get("/our-planet/health")
    async def our_planet_health():
        return {"ok": True, "feature": "universal-earth-profiles", "providers": ["Wikipedia", "Wikimedia Commons", "OpenStreetMap/Nominatim", "GBIF", "Open-Meteo", "NASA POWER", "NASA Earthdata", "NASA Image Library", "Esri World Imagery", "Global Forest Watch"],
            "configured": {"nasa_api": bool(_PLANET_NASA_KEY), "global_forest_watch": bool(_PLANET_GFW_KEY)}}



    # ===================================================================
    # REELS RECOMMENDATION ALGORITHM (schema-compatible, live signals)
    # ===================================================================
    # This lives on the existing /api router so the frontend can later call
    # GET /api/reels/feed without adding another service or database client.
    REELS_ALGO_PAGE_SIZE = 20
    REELS_ALGO_LOOKBACK_DAYS = 7
    REELS_ALGO_SEEN_LOOKBACK_DAYS = 7
    REELS_ALGO_QUICK_SKIP_SECONDS = 2.0
    REELS_ALGO_QUICK_SKIP_MIN_COUNT = 3
    REELS_ALGO_VIRAL_MIN_VIEWS_1H = 500
    REELS_ALGO_VIRAL_RATIO = 0.15
    REELS_ALGO_TASK = None

    PHOTO_REEL_DEFAULT_SECONDS = 7.0

    def _reel_effective_duration(reel):
        """Seconds a reel 'lasts'. Videos use their real duration. Photo reels have duration 0, so they use the
        selected music clip length (or a 7s default) - otherwise a 3s glance on a photo counted as 100% completion
        while the same glance on a video counted as ~20%, which inflated photo reels in the ranking."""
        try:
            d = float(reel.get("duration") or 0)
        except (TypeError, ValueError):
            d = 0.0
        if d > 0:
            return d
        if reel.get("video_url") and not reel.get("photo_url"):
            return 0.0
        if reel.get("music_url"):
            try:
                return max(3.0, min(30.0, float(reel.get("music_clip_duration") or PHOTO_REEL_DEFAULT_SECONDS)))
            except (TypeError, ValueError):
                pass
        return PHOTO_REEL_DEFAULT_SECONDS if reel.get("photo_url") else 0.0

    _REELS_WEIGHTS = {
        "A": {"completion_rate": 0.35, "engagement_rate": 0.30, "recency": 0.15, "affinity": 0.05, "velocity": 0.15},
        "B": {"completion_rate": 0.30, "engagement_rate": 0.35, "recency": 0.15, "affinity": 0.05, "velocity": 0.15},
    }

    def _reels_parse_datetime(value):
        if isinstance(value, datetime):
            parsed = value
        else:
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except (TypeError, ValueError):
                return now()
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _reels_category(reel):
        return str(reel.get("category") or "general").strip().lower()[:40] or "general"

    def _reels_tags(reel):
        raw = reel.get("tags") or reel.get("hashtags") or []
        if isinstance(raw, str):
            raw = raw.split()
        return [str(tag).strip().lower().lstrip("#")[:40] for tag in raw if str(tag).strip()][:20]

    def _reels_user_can_see(reel, user_id, following_ids):
        owner_id = str(reel.get("user_id") or "")
        if owner_id == user_id:
            return True
        audience = reel.get("audience") or "public"
        if audience == "only_me":
            return False
        if audience == "friends" and owner_id not in following_ids:
            return False
        if audience == "only_show" and user_id not in (reel.get("audience_users") or []):
            return False
        return True

    async def _reels_user_categories(user_id, days=14, limit=5):
        since = (now() - timedelta(days=days)).isoformat()
        rows = await db.reel_view_events.aggregate([
            {"$match": {"user_id": user_id, "event_at": {"$gte": since}, "category": {"$nin": [None, ""]}}},
            {"$group": {"_id": "$reel_id", "category": {"$max": "$category"}, "watch_seconds": {"$max": "$watch_seconds"}}},
            {"$group": {"_id": "$category", "watch_seconds": {"$sum": "$watch_seconds"}}},
            {"$sort": {"watch_seconds": -1}},
            {"$limit": limit},
        ]).to_list(length=limit)
        learned = [row["_id"] for row in rows if row.get("_id")]
        profile = await db.users.find_one({"id": user_id}, {"_id": 0, "onboarding_categories": 1})
        onboarding = [
            str(category).strip().lower()[:40]
            for category in (profile or {}).get("onboarding_categories", [])
            if str(category).strip()
        ]
        return list(dict.fromkeys(onboarding + learned))[:limit]

    async def _reels_session_categories(user_id):
        since = (now() - timedelta(minutes=5)).isoformat()
        rows = await db.reel_view_events.aggregate([
            {"$match": {"user_id": user_id, "event_at": {"$gte": since}, "category": {"$nin": [None, ""]}}},
            {"$group": {"_id": "$reel_id", "category": {"$max": "$category"}, "watch_seconds": {"$max": "$watch_seconds"}}},
            {"$group": {"_id": "$category", "watch_seconds": {"$sum": "$watch_seconds"}}},
            {"$sort": {"watch_seconds": -1}},
            {"$limit": 3},
        ]).to_list(length=3)
        return [row["_id"] for row in rows if row.get("_id")]

    async def _reels_active_hour_categories(user_id):
        since = (now() - timedelta(days=14)).isoformat()
        current_hour = now().hour
        rows = await db.reel_view_events.aggregate([
            {"$match": {"user_id": user_id, "event_at": {"$gte": since}, "category": {"$nin": [None, ""]}}},
            {"$group": {
                "_id": "$reel_id",
                "category": {"$max": "$category"},
                "watch_seconds": {"$max": "$watch_seconds"},
                "event_at": {"$max": "$event_at"},
            }},
            {"$project": {"_id": 0, "category": 1, "watch_seconds": 1, "event_at": 1}},
        ]).to_list(2000)
        totals = {}
        for row in rows:
            if _reels_parse_datetime(row.get("event_at")).hour != current_hour:
                continue
            category = row.get("category")
            totals[category] = totals.get(category, 0.0) + float(row.get("watch_seconds") or 0)
        return [category for category, _ in sorted(totals.items(), key=lambda item: item[1], reverse=True)[:3]]

    async def _reels_seen_ids(user_id, reel_ids):
        if not reel_ids:
            return set()
        since = (now() - timedelta(days=REELS_ALGO_SEEN_LOOKBACK_DAYS)).isoformat()
        return set(await db.reel_view_events.distinct(
            "reel_id",
            {"user_id": user_id, "reel_id": {"$in": reel_ids}, "event_at": {"$gte": since}},
        ))

    async def _reels_negative_signals(user_id, reel_ids, creator_ids, categories):
        not_interested = set(await db.reel_feedback.distinct(
            "reel_id",
            {"user_id": user_id, "action": "not_interested", "reel_id": {"$in": reel_ids}},
        )) if reel_ids else set()
        hidden_creators = set(await db.reel_feedback.distinct(
            "creator_id",
            {"user_id": user_id, "action": {"$in": ["report", "hide_creator"]}, "creator_id": {"$in": creator_ids}},
        )) if creator_ids else set()
        since = (now() - timedelta(days=3)).isoformat()
        quick_rows = await db.reel_view_events.aggregate([
            {"$match": {"user_id": user_id, "event_at": {"$gte": since}, "category": {"$in": categories}}},
            {"$group": {"_id": "$reel_id", "category": {"$max": "$category"}, "watch_seconds": {"$max": "$watch_seconds"}}},
            {"$match": {"watch_seconds": {"$lt": REELS_ALGO_QUICK_SKIP_SECONDS}}},
            {"$group": {"_id": "$category", "skip_count": {"$sum": 1}}},
            {"$match": {"skip_count": {"$gte": REELS_ALGO_QUICK_SKIP_MIN_COUNT}}},
        ]).to_list(len(categories)) if categories else []
        return {
            "not_interested_ids": not_interested,
            "hidden_creator_ids": hidden_creators,
            "quick_skip_categories": {row["_id"] for row in quick_rows if row.get("_id")},
        }

    async def _reels_positive_signals(user_id, reel_ids):
        if not reel_ids:
            return set()
        return set(await db.reel_feedback.distinct(
            "reel_id",
            {"user_id": user_id, "action": "interested", "reel_id": {"$in": reel_ids}},
        ))

    async def _reels_liked_creators(user_id):
        liked_reels = await db.reels.find({"likes": user_id}, {"_id": 0, "user_id": 1}).to_list(100)
        return {row.get("user_id") for row in liked_reels if row.get("user_id")}

    async def _reels_similar_user_reels(user_id):
        liked = await db.reels.find({"likes": user_id}, {"_id": 0, "id": 1}).to_list(100)
        liked_ids = [row.get("id") for row in liked if row.get("id")]
        if not liked_ids:
            return set()
        liked_docs = await db.reels.find({"id": {"$in": liked_ids}}, {"_id": 0, "likes": 1}).to_list(100)
        similar_users = set()
        for row in liked_docs:
            similar_users.update(row.get("likes") or [])
        similar_users.discard(user_id)
        if not similar_users:
            return set()
        recommendations = await db.reels.find(
            {"likes": {"$in": list(similar_users)}, "id": {"$nin": liked_ids}},
            {"_id": 0, "id": 1},
        ).limit(100).to_list(100)
        return {row.get("id") for row in recommendations if row.get("id")}

    async def _reels_live_stats(reel_ids):
        if not reel_ids:
            return {}
        stats = {}
        all_time = await db.reel_view_events.aggregate([
            {"$match": {"reel_id": {"$in": reel_ids}}},
            {"$group": {
                "_id": {"reel_id": "$reel_id", "user_id": "$user_id"},
                "completion_ratio": {"$max": "$completion_ratio"},
                "watch_seconds": {"$max": "$watch_seconds"},
            }},
            {"$group": {
                "_id": "$_id.reel_id",
                "total_views": {"$sum": 1},
                "completion_sum": {"$sum": "$completion_ratio"},
                "watch_seconds_sum": {"$sum": "$watch_seconds"},
            }},
        ]).to_list(len(reel_ids))
        for row in all_time:
            reel_stats = stats.setdefault(row["_id"], {})
            total_views = int(row.get("total_views") or 0)
            reel_stats["total_views"] = total_views
            reel_stats["completion_sum"] = float(row.get("completion_sum") or 0)
            reel_stats["watch_seconds_sum"] = float(row.get("watch_seconds_sum") or 0)
            reel_stats["avg_completion"] = float(row.get("completion_sum") or 0) / max(total_views, 1)
        since = (now() - timedelta(hours=1)).isoformat()
        hourly = await db.reel_view_events.aggregate([
            {"$match": {"reel_id": {"$in": reel_ids}, "event_at": {"$gte": since}}},
            {"$group": {
                "_id": {"reel_id": "$reel_id", "user_id": "$user_id"},
                "watch_seconds": {"$max": "$watch_seconds"},
            }},
            {"$group": {
                "_id": "$_id.reel_id",
                "views_1h": {"$sum": 1},
                "watch_seconds_1h": {"$sum": "$watch_seconds"},
            }},
        ]).to_list(len(reel_ids))
        for row in hourly:
            stats.setdefault(row["_id"], {}).update({
                "views_1h": int(row.get("views_1h") or 0),
                "watch_seconds_1h": float(row.get("watch_seconds_1h") or 0),
            })
        return stats

    def _reels_diversify(items, page_size):
        result, pool, categories = [], list(items), []
        last_creator = None
        while pool and len(result) < page_size:
            selected = None
            for index, item in enumerate(pool):
                category = item.get("category") or "general"
                creator = item.get("user_id")
                category_ok = categories[-2:].count(category) < 2
                creator_ok = creator != last_creator
                if category_ok and creator_ok:
                    selected = index
                    break
            if selected is None:
                selected = 0
            chosen = pool.pop(selected)
            result.append(chosen)
            categories.append(chosen.get("category") or "general")
            last_creator = chosen.get("user_id")
        return result

    async def _reels_v2_rank(reels_raw, u, relevance=None):
        """Reels v2 ranking for any list of raw reel docs (Discover grid, Search results).

        Same model as the main Reels feed: smoothed completion + engagement, recency, velocity,
        followed / liked creators, favourite + current-session categories, new-reel test batch,
        already-seen penalty, not-interested / hidden-creator filtering and creator/category variety.
        `relevance(reel) -> float` adds a text-match score for search.
        """
        import math as _math
        if not reels_raw:
            return []
        user_id = u["id"]
        following = set(str(x) for x in (u.get("following") or []))
        ids = [r.get("id") for r in reels_raw if r.get("id")]
        creators = list(dict.fromkeys(r.get("user_id") for r in reels_raw if r.get("user_id")))
        categories = list(dict.fromkeys(_reels_category(r) for r in reels_raw))
        try:
            stats_map, top_rows, liked_creators, seen_ids, negative, session_rows = await asyncio.gather(
                _reels_live_stats(ids), _reels_user_categories(user_id), _reels_liked_creators(user_id),
                _reels_seen_ids(user_id, ids), _reels_negative_signals(user_id, ids, creators, categories),
                _reels_session_categories(user_id),
            )
        except Exception:
            logging.exception("reels v2 personalisation failed; ranking without it")
            stats_map, top_rows, liked_creators, seen_ids, session_rows = {}, [], set(), set(), []
            negative = {"not_interested_ids": set(), "hidden_creator_ids": set(), "quick_skip_categories": set()}
        top_categories, session_categories = set(top_rows), set(session_rows)
        ab_group = "A" if int(_hl.md5(user_id.encode()).hexdigest(), 16) % 2 == 0 else "B"
        weights = _REELS_WEIGHTS[ab_group]
        now_utc = now()
        scored = []
        for reel in reels_raw:
            rid = reel.get("id")
            if not rid or rid in negative["not_interested_ids"] or reel.get("user_id") in negative["hidden_creator_ids"]:
                continue
            st = stats_map.get(rid, {})
            views_field = reel.get("views")
            views_n = len(set(views_field)) if isinstance(views_field, list) else int(reel.get("view_count") or 0)
            total_views = max(views_n, int(st.get("total_views") or 0))
            observed = max(int(st.get("total_views") or 0), 1)
            completion = float(st.get("avg_completion") or 0)
            avg_watch = float(st.get("watch_seconds_sum") or 0) / observed
            _eff_dur = _reel_effective_duration(reel)
            dur = max(_eff_dur, 1.0)
            watch_score = min(1.0, avg_watch / dur) if _eff_dur > 0 else completion
            quality = max(0.0, min(1.0, completion * 0.70 + watch_score * 0.30))
            quality = (quality * observed + 0.40 * 5) / (observed + 5)
            likes = len(reel.get("likes") or []) if isinstance(reel.get("likes"), list) else int(reel.get("like_count") or 0)
            comments = max(len(reel.get("comments") or []) if isinstance(reel.get("comments"), list) else 0, int(reel.get("comment_count") or 0))
            shares = max(len(reel.get("shares") or []) if isinstance(reel.get("shares"), list) else 0, int(reel.get("share_count") or 0))
            saves = max(len(reel.get("saves") or []) if isinstance(reel.get("saves"), list) else 0, int(reel.get("save_count") or 0))
            mentions = int(reel.get("mention_count") or 0)
            points = likes + comments * 3 + mentions * 2 + shares * 5 + saves * 4
            engagement = min(1.0, (points / (max(total_views, 1) + 20.0)) / 0.5)
            hours_old = max(0.0, (now_utc - _reels_parse_datetime(reel.get("created_at"))).total_seconds() / 3600)
            recency = _math.exp(-hours_old / 36.0)
            hourly = int(st.get("views_1h") or 0)
            velocity = min(1.0, (hourly / max(total_views, 1)) * 4.0)
            owner = reel.get("user_id")
            affinity = 1 if (owner in liked_creators or str(owner) in following) else 0
            category = _reels_category(reel)
            score = (weights["completion_rate"] * quality + weights["engagement_rate"] * engagement
                     + weights["recency"] * recency + weights["affinity"] * affinity + weights["velocity"] * velocity)
            if category in top_categories: score += 0.35
            if category in session_categories: score += 0.30
            if owner in liked_creators: score += 0.25
            if str(owner) in following: score += 0.20
            if total_views < 30 and hours_old < 72:
                score += 0.25 * (1.0 - min(1.0, total_views / 30.0))
            if rid in seen_ids: score -= 0.25
            if category in negative["quick_skip_categories"]: score -= 0.35
            if relevance:
                score += 1.2 * float(relevance(reel) or 0)
            reel["category"] = category
            reel["score"] = score
            scored.append(reel)
        scored.sort(key=lambda r: r["score"], reverse=True)
        return _reels_diversify(scored, len(scored))

    @api.get("/reels/feed")
    async def get_algorithmic_reels_feed(
        page: int = Query(0, ge=0),
        limit: int = Query(REELS_ALGO_PAGE_SIZE, ge=1, le=50),
        q: str = Query("", max_length=200),
        u=Depends(current_user),
    ):
        import math as _math
        user_id = u["id"]
        limit = min(limit, 50)
        now_utc = now()
        cutoff = now_utc - timedelta(days=REELS_ALGO_LOOKBACK_DAYS)
        following_ids = set(u.get("following") or [])
        pending_follow_ids = {
            row["to_id"]
            for row in await db.follow_requests.find(
                {"from_id": u["id"], "status": "pending"},
                {"_id": 0, "to_id": 1},
            ).to_list(5000)
        }
        excluded_users = set((u.get("blocked_users") or []) + (u.get("muted_users") or []))
        # Rank compact metadata for the candidate pool; media and embedded
        # engagement arrays are loaded only for the final page below.
        def _reel_array_size(field):
            return {"$size": {"$cond": [{"$isArray": field}, field, []]}}

        def _reel_unique_array_size(field):
            safe_array = {"$cond": [{"$isArray": field}, field, []]}
            return {"$size": {"$setUnion": [safe_array, []]}}

        def _reel_array(field):
            return {"$cond": [{"$isArray": field}, field, []]}

        def _reel_count_value(field):
            return {"$convert": {"input": field, "to": "long", "onError": 0, "onNull": 0}}

        raw_candidates = await db.reels.aggregate([
            {"$match": {"moderation_status": {"$nin": ["flagged", "under_review", "removed"]}}},
            {"$sort": {"created_at": -1}},
            {"$limit": 2000},
            {"$project": {
                "_id": 0,
                "id": 1,
                "user_id": 1,
                "category": 1,
                "caption": 1,
                "audio_label": 1,
                "hashtags": 1,
                "tags": 1,
                "audience": 1,
                "audience_users": 1,
                "created_at": 1,
                "duration": 1,
                "video_url": 1,
                "photo_url": 1,
                "music_url": 1,
                "music_clip_duration": 1,
                "mention_count": 1,
                "_rank_view_count": _reel_unique_array_size("$views"),
                "_rank_like_count": _reel_array_size("$likes"),
                "_rank_comment_count": {"$max": [_reel_array_size("$comments"), _reel_count_value("$comment_count")]},
                "_rank_comment_likes": {"$reduce": {
                    "input": {"$cond": [{"$isArray": "$comments"}, "$comments", []]},
                    "initialValue": 0,
                    "in": {"$add": ["$$value", _reel_array_size("$$this.likes")]},
                }},
                "_rank_share_count": {"$max": [_reel_array_size("$shares"), _reel_count_value("$share_count")]},
                "_rank_save_count": {"$max": [_reel_array_size("$saves"), _reel_count_value("$save_count")]},
            }},
        ]).to_list(2000)

        # Search keeps the same eligibility and scoring model as the main feed,
        # but narrows the candidate pool to the requested search term first.
        search_term = str(q or "").strip().lower()
        if search_term:
            normalized_term = search_term.lstrip("#")
            def _matches_search(reel):
                text_fields = (
                    reel.get("caption"),
                    reel.get("audio_label"),
                    reel.get("category"),
                )
                if any(search_term in str(value or "").lower() for value in text_fields):
                    return True
                raw_tags = reel.get("hashtags") or []
                if isinstance(raw_tags, str):
                    raw_tags = raw_tags.split()
                return any(
                    normalized_term and normalized_term in str(tag).strip().lower().lstrip("#")
                    for tag in raw_tags
                )
            raw_candidates = [reel for reel in raw_candidates if _matches_search(reel)]

        # Recency is a ranking signal, never an availability gate. The old
        # hard cutoff made an otherwise healthy feed return [] as soon as a
        # user's content was older than seven days. Keep recent reels first
        # while retaining every eligible reel as a real fallback pool.
        recent_candidates = []
        older_candidates = []
        for reel in raw_candidates:
            created_at = _reels_parse_datetime(reel.get("created_at"))
            owner_id = str(reel.get("user_id") or "")
            if owner_id in excluded_users:
                continue
            if not _reels_user_can_see(reel, user_id, following_ids):
                continue
            if created_at >= cutoff:
                recent_candidates.append(reel)
            else:
                older_candidates.append(reel)
        candidates = recent_candidates + older_candidates
        if not candidates:
            return {"page": page, "limit": limit, "reels": [], "has_more": False, "ab_group": "A", "algorithm": "reels_v2"}

        candidate_ids = list(dict.fromkeys(
            reel.get("id") for reel in candidates if reel.get("id")
        ))
        candidate_creator_ids = list(dict.fromkeys(
            reel.get("user_id") for reel in candidates if reel.get("user_id")
        ))
        candidate_categories = list(dict.fromkeys(_reels_category(reel) for reel in candidates))
        seen_ids, negative = await asyncio.gather(
            _reels_seen_ids(user_id, candidate_ids),
            _reels_negative_signals(user_id, candidate_ids, candidate_creator_ids, candidate_categories),
        )
        filtered = [
            reel for reel in candidates
            if reel.get("id") not in negative["not_interested_ids"]
            and reel.get("user_id") not in negative["hidden_creator_ids"]
        ]
        unseen = [reel for reel in filtered if reel.get("id") not in seen_ids]
        if unseen:
            filtered = unseen
        if not filtered:
            filtered = candidates

        reel_ids = [reel.get("id") for reel in filtered if reel.get("id")]
        (
            live_stats,
            top_category_rows,
            liked_creators,
            similar_reel_ids,
            positive_reel_ids,
            session_category_rows,
            active_hour_category_rows,
            active_tags,
            mention_rows,
        ) = await asyncio.gather(
            _reels_live_stats(reel_ids),
            _reels_user_categories(user_id),
            _reels_liked_creators(user_id),
            _reels_similar_user_reels(user_id),
            _reels_positive_signals(user_id, candidate_ids),
            _reels_session_categories(user_id),
            _reels_active_hour_categories(user_id),
            db.trending_tags.find({"active": True}, {"_id": 0, "tag": 1, "boost": 1}).to_list(100),
            db.reel_mentions.aggregate([
                {"$match": {"reel_id": {"$in": reel_ids}}},
                {"$group": {"_id": "$reel_id", "count": {"$sum": 1}}},
            ]).to_list(len(reel_ids)),
        )
        top_categories = set(top_category_rows)
        session_categories = set(session_category_rows)
        active_hour_categories = set(active_hour_category_rows)
        tag_boosts = {str(row.get("tag")): float(row.get("boost") or 0) for row in active_tags if row.get("tag")}
        mention_counts = {row["_id"]: int(row.get("count") or 0) for row in mention_rows}
        ab_group = "A" if int(_hl.md5(user_id.encode()).hexdigest(), 16) % 2 == 0 else "B"
        weights = _REELS_WEIGHTS[ab_group]
        scored = []

        for reel in filtered:
            reel_id = reel.get("id")
            if not reel_id:
                continue
            stats = live_stats.get(reel_id, {})
            total_views = max(int(reel.get("_rank_view_count") or 0), int(stats.get("total_views") or 0))
            observed_views = max(int(stats.get("total_views") or 0), 1)
            completion_sum = float(stats.get("completion_sum") or 0)
            completion = completion_sum / observed_views if completion_sum else float(stats.get("avg_completion") or 0)
            avg_watch_seconds = float(stats.get("watch_seconds_sum") or 0) / observed_views
            _eff_dur = _reel_effective_duration(reel)
            duration_seconds = max(_eff_dur, 1.0)
            watch_time_score = min(1.0, avg_watch_seconds / duration_seconds) if _eff_dur > 0 else completion
            completion_quality = max(0.0, min(1.0, completion * 0.70 + watch_time_score * 0.30))
            # v2: a reel with only a few views must not look perfect (or terrible) by luck -> blend with a neutral prior.
            completion_quality = (completion_quality * observed_views + 0.40 * 5) / (observed_views + 5)
            likes = int(reel.get("_rank_like_count") or 0)
            comments = int(reel.get("_rank_comment_count") or 0)
            comment_likes = int(reel.get("_rank_comment_likes") or 0)
            shares = int(reel.get("_rank_share_count") or 0)
            saves = int(reel.get("_rank_save_count") or 0)
            mentions = mention_counts.get(reel_id, int(reel.get("mention_count") or 0))
            # Documented intent order: share > save > comment > comment-like > like.
            engagement_points = likes + comments * 3 + comment_likes + mentions * 2 + shares * 5 + saves * 4
            # v2: smoothed + capped (old formula was unbounded: 1 like on 1 view = 100% and outranked everything)
            engagement_rate_raw = engagement_points / (max(total_views, 1) + 20.0)
            engagement = min(1.0, engagement_rate_raw / 0.5)
            hours_old = max(0.0, (now_utc - _reels_parse_datetime(reel.get("created_at"))).total_seconds() / 3600)
            recency = _math.exp(-hours_old / 36.0)
            category = _reels_category(reel)
            affinity = 1 if (reel.get("user_id") in liked_creators or reel.get("user_id") in following_ids) else 0
            hourly_views = int(stats.get("views_1h") or 0)
            velocity = hourly_views / max(total_views, 1)
            velocity_score = min(1.0, velocity * 4.0)
            is_viral = hourly_views >= REELS_ALGO_VIRAL_MIN_VIEWS_1H and velocity >= REELS_ALGO_VIRAL_RATIO
            score = (
                weights["completion_rate"] * completion_quality
                + weights["engagement_rate"] * engagement
                + weights["recency"] * recency
                + weights["affinity"] * affinity
                + weights["velocity"] * velocity_score
            )
            # v2: personalisation bonuses are now on the same 0-1 scale as the quality score. Before they were
            # +20..+50 vs a 0-1 base, so quality/popularity never mattered; now taste AND quality both count.
            if category in top_categories:
                score += 0.35
            if reel.get("user_id") in liked_creators:
                score += 0.25
            if reel.get("user_id") in following_ids:
                score += 0.20
            if reel_id in similar_reel_ids:
                score += 0.30
            if reel_id in positive_reel_ids:
                score += 0.15
            if category in session_categories:
                score += 0.30
            if category in active_hour_categories:
                score += 0.15
            score += sum(tag_boosts.get(tag, 0) for tag in _reels_tags(reel))
            # new-reel test batch: fresh reels with few views get a push so creators are discovered
            if total_views < 30 and hours_old < 72:
                score += 0.25 * (1.0 - min(1.0, total_views / 30.0))
            if is_viral:
                score += 1000
            if category in negative["quick_skip_categories"]:
                score -= 0.35
            scored.append({
                **reel,
                "category": category,
                "score": score,
                "is_viral": is_viral,
                "mention_count": mentions,
                "ranking_signals": {
                    "views": total_views,
                    "likes": likes,
                    "comments": comments,
                    "comment_likes": comment_likes,
                    "mentions": mentions,
                    "shares": shares,
                    "saves": saves,
                    "engagement_points": engagement_points,
                    "engagement_rate": round(float(engagement), 6),
                    "completion_rate": round(float(completion_quality), 6),
                    "avg_watch_seconds": round(float(avg_watch_seconds), 3),
                    "velocity_1h": round(float(velocity), 6),
                },
            })

        viral = sorted([item for item in scored if item["is_viral"]], key=lambda item: item["score"], reverse=True)
        normal = sorted([item for item in scored if not item["is_viral"]], key=lambda item: item["score"], reverse=True)
        ordered = (viral[:3] + viral[3:] + normal) if page == 0 else (viral[3:] + normal)
        exploration_count = max(1, int(limit * 0.15))
        main_slot_count = max(1, limit - exploration_count)
        start = page * main_slot_count
        main_slice = ordered[start:start + main_slot_count]
        main_ids = {item.get("id") for item in main_slice}
        exploration = [
            item for item in scored
            if item.get("id") not in main_ids
            and (int(item.get("_rank_view_count") or 0) < 10
                 or (now_utc - _reels_parse_datetime(item.get("created_at"))).days <= 30)
        ]
        random.Random(f"{user_id}:{page}").shuffle(exploration)
        combined = main_slice + exploration[:exploration_count]
        final_items = _reels_diversify(combined, limit)
        final_reel_ids = [item.get("id") for item in final_items if item.get("id")]
        full_reels = await db.reels.aggregate([
            {"$match": {"id": {"$in": final_reel_ids}}},
            {"$addFields": {
                "is_liked": {"$in": [user_id, _reel_array("$likes")]},
                "like_count": {"$max": [_reel_array_size("$likes"), _reel_count_value("$like_count")]},
                "is_saved": {"$in": [user_id, _reel_array("$saves")]},
                "save_count": {"$max": [_reel_array_size("$saves"), _reel_count_value("$save_count")]},
                "comment_count": {"$max": [_reel_array_size("$comments"), _reel_count_value("$comment_count")]},
                "share_count": {"$max": [_reel_array_size("$shares"), _reel_count_value("$share_count")]},
                "view_count": _reel_unique_array_size("$views"),
            }},
            _safe_media_sanitize_stage(scalar_fields=("avatar_photo",)),
            {"$project": {"_id": 0, "likes": 0, "saves": 0, "shares": 0, "views": 0}},
        ]).to_list(len(final_reel_ids)) if final_reel_ids else []
        await _hydrate_author_avatars(full_reels)
        full_reels_by_id = {reel.get("id"): reel for reel in full_reels if reel.get("id")}
        ranking_fields = (
            "_rank_view_count", "_rank_like_count", "_rank_comment_count",
            "_rank_comment_likes", "_rank_share_count", "_rank_save_count",
            "category", "score", "is_viral", "mention_count", "ranking_signals",
        )
        hydrated_items = []
        for item in final_items:
            full_reel = full_reels_by_id.get(item.get("id"))
            if not full_reel:
                continue
            ranking_data = {key: item[key] for key in ranking_fields if key in item}
            item.update(full_reel)
            item.update(ranking_data)
            hydrated_items.append(item)
        final_items = hydrated_items
        final_reel_ids = [item.get("id") for item in final_items if item.get("id")]
        mention_docs = {}
        if final_reel_ids:
            mention_docs = {
                doc["reel_id"]: doc
                async for doc in db.reel_mentions.find(
                    {"target_user_id": user_id, "reel_id": {"$in": final_reel_ids}},
                    {"_id": 0, "reel_id": 1, "source_user_id": 1, "source_user_name": 1, "source_user_handle": 1, "source_user_avatar": 1, "source_user_bg": 1, "source_user_letter": 1},
                )
            }
        response_reels = []
        for item in final_items:
            mention = mention_docs.get(item.get("id"))
            mentioned_by = (
                {"id": mention.get("source_user_id"), "name": mention.get("source_user_name"), "handle": mention.get("source_user_handle"), "avatar_photo": mention.get("source_user_avatar"), "avatar_bg": mention.get("source_user_bg"), "avatar_letter": mention.get("source_user_letter")}
                if mention else None
            )
            shaped = _reel_to_feed_item(item, bool(mention), mentioned_by)
            shaped.update({
                # Keep the Reels tab relationship state identical to Home/Profile.
                "is_following": item.get("user_id") in following_ids or item.get("user_id") == u["id"],
                "is_follow_pending": item.get("user_id") in pending_follow_ids,
                "category": item.get("category") or "general",
                "score": round(float(item.get("score") or 0), 6),
                "is_liked": bool(item.get("is_liked")),
                "like_count": int(item.get("like_count") or 0),
                "is_saved": bool(item.get("is_saved")),
                "save_count": int(item.get("save_count") or 0),
                "comment_count": int(item.get("comment_count") or 0),
                "share_count": int(item.get("share_count") or 0),
                "view_count": int(item.get("view_count") or 0),
                "views_count": int(item.get("view_count") or 0),
                "mention_count": int(item.get("mention_count") or 0),
                "ranking_signals": item.get("ranking_signals") or {},
                "is_viral": bool(item.get("is_viral")),
                "algorithm": "reels_v2",
            })
            response_reels.append(shaped)
        return {
            "page": page,
            "limit": limit,
            "reels": response_reels,
            "has_more": start + main_slot_count < len(ordered),
            "ab_group": ab_group,
            "algorithm": "reels_v2",
        }

    @api.get("/reels/{reel_id}")
    async def get_reel(reel_id: str, u=Depends(current_user)):
        """Open ONE reel by id (share links: ?reel=ID). Registered after the fixed
        /reels/feed and /reels/discover routes so it never shadows them."""
        reel = await _safe_media_find_one(
            db.reels, {"id": reel_id},
            scalar_fields=("photo_url", "video_url", "avatar_photo", "music_artwork", "thumbnail_url"),
            comment_fields=("comments",),
            projection={"_id": 0},
        )
        if not reel or not await _viewer_can_access_item(reel, u):
            raise HTTPException(404, "Reel not found")
        await _hydrate_author_avatars([reel])
        shaped = _reel_to_feed_item(reel)
        shaped.update({
            "is_liked": u["id"] in (reel.get("likes") or []),
            "is_saved": u["id"] in (reel.get("saves") or []),
            "is_following": reel.get("user_id") in (u.get("following") or []) or reel.get("user_id") == u["id"],
        })
        return shaped

    @api.post("/reels/feedback")
    async def submit_reels_feedback(body: dict, u=Depends(current_user)):
        action = str(body.get("action") or "").strip().lower()
        if action not in {"interested", "not_interested", "report", "hide_creator"}:
            raise HTTPException(400, "action must be interested, not_interested, report, or hide_creator")
        reel_id = str(body.get("reel_id") or "").strip()
        if not reel_id:
            raise HTTPException(400, "reel_id is required")
        reel = await db.reels.find_one({"id": reel_id}, {"_id": 0, "user_id": 1})
        if not reel:
            raise HTTPException(404, "Reel not found")
        await db.reel_feedback.update_one(
            {"user_id": u["id"], "reel_id": reel_id, "action": action},
            {"$set": {"user_id": u["id"], "reel_id": reel_id, "creator_id": reel.get("user_id"), "action": action, "created_at": now().isoformat()}},
            upsert=True,
        )
        return {"status": "ok", "action": action}

    @api.post("/reels/onboarding")
    async def save_reels_onboarding(body: dict, u=Depends(current_user)):
        raw_categories = body.get("categories") or []
        if isinstance(raw_categories, str):
            raw_categories = [raw_categories]
        categories = list(dict.fromkeys(str(item).strip().lower()[:40] for item in raw_categories if str(item).strip()))[:20]
        await db.users.update_one({"id": u["id"]}, {"$set": {"onboarding_categories": categories}})
        return {"status": "ok", "categories": categories}

    @api.post("/reels/ab-metric")
    async def log_reels_ab_metric(body: dict, u=Depends(current_user)):
        event = str(body.get("event") or "").strip().lower()[:60]
        if not event:
            raise HTTPException(400, "event is required")
        group = str(body.get("group") or "A").strip().upper()
        if group not in {"A", "B"}:
            group = "A"
        await db.ab_test_events.insert_one({"user_id": u["id"], "group": group, "event": event, "created_at": now().isoformat()})
        return {"status": "ok"}

    async def _refresh_reels_rank_stats():
        # Compute aggregate counts in Mongo so large embedded reaction arrays
        # are not copied into the application process every refresh cycle.
        def _array_size(field):
            return {"$size": {"$cond": [{"$isArray": field}, field, []]}}

        def _count_value(field):
            return {"$convert": {"input": field, "to": "long", "onError": 0, "onNull": 0}}

        rows = await db.reels.aggregate([
            {"$match": {"moderation_status": {"$nin": ["flagged", "under_review", "removed"]}}},
            {"$limit": 2000},
            {"$project": {
                "_id": 0,
                "id": 1,
                "mention_count": 1,
                "content_views": {"$size": {"$setUnion": [{"$cond": [{"$isArray": "$views"}, "$views", []]}, []]}},
                "likes": _array_size("$likes"),
                "comments": _array_size("$comments"),
                "comment_likes": {"$reduce": {
                    "input": {"$cond": [{"$isArray": "$comments"}, "$comments", []]},
                    "initialValue": 0,
                    "in": {"$add": ["$$value", _array_size("$$this.likes")]},
                }},
                "shares": _array_size("$shares"),
                "saves": _array_size("$saves"),
            }},
        ]).to_list(2000)
        reel_ids = [r.get("id") for r in rows if r.get("id")]
        mention_rows = await db.reel_mentions.aggregate([
            {"$match": {"reel_id": {"$in": reel_ids}}},
            {"$group": {"_id": "$reel_id", "count": {"$sum": 1}}},
        ]).to_list(len(reel_ids))
        mention_counts = {row["_id"]: int(row.get("count") or 0) for row in mention_rows}
        for reel in rows:
            reel_id = reel.get("id")
            if not reel_id:
                continue
            await db.reel_rank_stats.update_one(
                {"reel_id": reel_id},
                {"$set": {
                    "reel_id": reel_id,
                    "content_views": int(reel.get("content_views") or 0),
                    "total_views": int(reel.get("content_views") or 0),
                    "likes": int(reel.get("likes") or 0),
                    "comments": int(reel.get("comments") or 0),
                    "comment_likes": int(reel.get("comment_likes") or 0),
                    "shares": int(reel.get("shares") or 0),
                    "saves": int(reel.get("saves") or 0),
                    "mentions": mention_counts.get(reel_id, int(reel.get("mention_count") or 0)),
                    "updated_at": now().isoformat(),
                }},
                upsert=True,
            )

    async def _reels_algorithm_worker():
        while True:
            try:
                await _refresh_reels_rank_stats()
            except Exception:
                logging.exception("Reels rank refresh failed")
            await asyncio.sleep(600)

    @app.on_event("startup")
    async def start_reels_algorithm_worker():
        global REELS_ALGO_TASK
        try:
            await db.reel_view_events.create_index([("user_id", 1), ("event_at", -1)])
            await db.reel_view_events.create_index([("reel_id", 1), ("event_at", -1)])
            await db.reel_rank_stats.create_index("reel_id", unique=True)
            await db.reel_feedback.create_index([("user_id", 1), ("reel_id", 1), ("action", 1)], unique=True)
        except Exception:
            logging.exception("Reels algorithm index setup failed")
        if REELS_ALGO_TASK is None or REELS_ALGO_TASK.done():
            REELS_ALGO_TASK = asyncio.create_task(_reels_algorithm_worker())


    # ══════════════════════════════════════════════════════════════
    #  Contact-based "Find Friends"
    #  - User chooses to share phone numbers from their contacts.
    #  - We match them with registered users (by phone) and return profiles.
    #  - Numbers are NOT stored in clear text: only keyed hashes (HMAC-SHA256)
    #    of the canonical 10-digit key are kept, so that when a contact joins
    #    LATER, the people who already have that number get a suggestion + push.
    #  - A user who creates an account sees (a) contacts already on POST and
    #    (b) people who already have their number saved — instantly.
    # ══════════════════════════════════════════════════════════════
    CONTACT_PEPPER = (os.environ.get("CONTACT_PEPPER") or JWT_SECRET).encode()
    CONTACT_MAX_PER_SYNC = 3000
    CONTACT_MAX_SYNCS_PER_DAY = 10

    def _phone_key(raw):
        """Canonical key = last 10 digits (handles +91XXXXXXXXXX, 91..., 0..., bare 10 digits)."""
        digits = re.sub(r"\D", "", str(raw or ""))
        return digits[-10:] if len(digits) >= 10 else None

    def _phone_hash(key):
        return _hmac.new(CONTACT_PEPPER, key.encode(), _hl.sha256).hexdigest()

    def _phone_variants(key):
        return [key, "+91" + key, "91" + key, "0" + key]

    class ContactSyncIn(BaseModel):
        phones: List[str]
        save: bool = True   # False = one-time lookup, nothing about the contacts is stored

    class ContactDiscoverIn(BaseModel):
        enabled: bool

    async def _set_phone_key(uid, phone):
        try:
            k = _phone_key(phone)
            if k: await db.users.update_one({"id": uid}, {"$set": {"phone_key": k}})
        except Exception:
            pass

    async def _contact_profiles(me, ids, in_contacts=frozenset(), has_my_number=frozenset()):
        """Public, safe profile cards (no phone/email/dob) + follow state for candidate ids."""
        blocked = set(me.get("blocked_users") or [])
        ids = [i for i in dict.fromkeys(ids) if i != me["id"] and i not in blocked]
        if not ids: return []
        profiles = await _safe_user_find(
            {"id": {"$in": ids}, "is_verified": True, "deleted_at": None},
            {"_id": 0, "id": 1, "name": 1, "username": 1, "handle": 1, "avatar_bg": 1, "avatar_letter": 1,
             "avatar_photo": 1, "is_badge_verified": 1, "is_private": 1, "blocked_users": 1, "discoverable_by_phone": 1},
            limit=len(ids) + 1,
        )
        my_following = set(me.get("following") or [])
        my_followers = set(me.get("followers") or [])
        reqs = await db.follow_requests.find(
            {"from_id": me["id"], "to_id": {"$in": ids}, "status": "pending"}, {"_id": 0, "to_id": 1}
        ).to_list(length=len(ids) + 1)
        pending = {r["to_id"] for r in reqs}
        out = []
        for pr in profiles:
            if me["id"] in (pr.get("blocked_users") or []): continue
            if pr.get("discoverable_by_phone") is False: continue
            out.append({
                "id": pr["id"], "name": pr.get("name"), "username": pr.get("username"), "handle": pr.get("handle"),
                "avatar_bg": pr.get("avatar_bg"), "avatar_letter": pr.get("avatar_letter"),
                "avatar_photo": pr.get("avatar_photo"), "is_badge_verified": bool(pr.get("is_badge_verified")),
                "is_private": bool(pr.get("is_private")),
                "in_contacts": pr["id"] in in_contacts, "has_your_number": pr["id"] in has_my_number,
                "following": pr["id"] in my_following, "requested": pr["id"] in pending,
                "follows_me": pr["id"] in my_followers,
            })
        out.sort(key=lambda x: (-(x["in_contacts"] and x["has_your_number"]), -x["in_contacts"], -x["has_your_number"], (x["name"] or "").lower()))
        return out

    async def _who_has_me(u):
        """Ids of users whose saved contacts (device or Google) contain MY phone number or MY email."""
        conds = []
        my_key = _phone_key(u.get("phone"))
        if my_key:
            h = _phone_hash(my_key)
            conds += [{"hashes": h}, {"g_hashes": h}]
        my_email = (u.get("email") or "").strip().lower()
        if my_email:
            conds.append({"email_hashes": _phone_hash(my_email)})
        if not conds: return set()
        owners = await db.contact_books.find({"$or": conds, "user_id": {"$ne": u["id"]}}, {"_id": 0, "user_id": 1}).to_list(length=300)
        return {o["user_id"] for o in owners}

    class GoogleContactSyncIn(BaseModel):
        phones: List[str] = []
        emails: List[str] = []
        save: bool = True

    @api.post("/contacts/google-sync")
    async def contacts_google_sync(p: GoogleContactSyncIn, u=Depends(current_user)):
        """Numbers + emails read from the user's Google Contacts (Gmail): return the ones already on POST."""
        my_key = _phone_key(u.get("phone"))
        my_email = (u.get("email") or "").strip().lower()
        keys, seen = [], set()
        for raw in p.phones[:CONTACT_MAX_PER_SYNC]:
            k = _phone_key(raw)
            if k and k != my_key and k not in seen:
                seen.add(k); keys.append(k)
        emails, seen_e = [], set()
        for raw in p.emails[:CONTACT_MAX_PER_SYNC]:
            em = str(raw or "").strip().lower()
            if "@" in em and 3 <= len(em) <= 254 and em != my_email and em not in seen_e:
                seen_e.add(em); emails.append(em)
        if not keys and not emails:
            return {"matches": [], "total_contacts": 0, "matched": 0}

        book = await db.contact_books.find_one({"user_id": u["id"]}, {"_id": 0, "sync_window_start": 1, "sync_count": 1}) or {}
        win = _aware(book.get("sync_window_start"))
        count = book.get("sync_count", 0)
        if not win or now() - win > timedelta(days=1):
            win, count = now(), 0
        if count >= CONTACT_MAX_SYNCS_PER_DAY:
            raise HTTPException(429, "Too many contact syncs today. Please try again tomorrow.")

        conds = []
        if keys:
            conds += [{"phone_key": {"$in": keys}}, {"phone": {"$in": [v for k in keys for v in _phone_variants(k)]}}]
        if emails:
            # only emails the owner has verified (email sign-ups, or an email added + verified later)
            conds.append({"$and": [{"email": {"$in": emails}}, {"$or": [{"signup_method": "email"}, {"email_verified": True}]}]})
        found = await db.users.find(
            {"$or": conds, "is_verified": True, "deleted_at": None},
            {"_id": 0, "id": 1, "phone": 1, "phone_key": 1},
            collation={"locale": "en", "strength": 2},   # e-mails match regardless of upper/lower case
        ).to_list(length=len(keys) + len(emails) + 10)
        matched_ids = [f["id"] for f in found if f["id"] != u["id"]]

        update = {"sync_window_start": win, "sync_count": count + 1}
        if p.save:
            update.update({"user_id": u["id"], "g_hashes": [_phone_hash(k) for k in keys],
                           "email_hashes": [_phone_hash(em) for em in emails],
                           "google_matched_ids": matched_ids, "google_synced_at": now(), "updated_at": now()})
        await db.contact_books.update_one({"user_id": u["id"]}, {"$set": update}, upsert=True)

        has_me = await _who_has_me(u)
        matches = await _contact_profiles(u, matched_ids + list(has_me), set(matched_ids), has_me)
        return {"matches": matches, "total_contacts": len(keys) + len(emails), "matched": len([m for m in matches if m["in_contacts"]])}

    @api.post("/contacts/sync")
    async def contacts_sync(p: ContactSyncIn, u=Depends(current_user)):
        """Receive phone numbers from the user's contacts, return the ones already on POST."""
        my_key = _phone_key(u.get("phone"))
        keys, seen = [], set()
        for raw in p.phones[:CONTACT_MAX_PER_SYNC]:
            k = _phone_key(raw)
            if k and k != my_key and k not in seen:
                seen.add(k); keys.append(k)
        if not keys:
            return {"matches": [], "total_contacts": 0, "matched": 0}

        # light rate-limit: stops people from enumerating who is registered
        book = await db.contact_books.find_one({"user_id": u["id"]}, {"_id": 0, "sync_window_start": 1, "sync_count": 1}) or {}
        win = _aware(book.get("sync_window_start"))
        count = book.get("sync_count", 0)
        if not win or now() - win > timedelta(days=1):
            win, count = now(), 0
        if count >= CONTACT_MAX_SYNCS_PER_DAY:
            raise HTTPException(429, "Too many contact syncs today. Please try again tomorrow.")

        variants = [v for k in keys for v in _phone_variants(k)]
        found = await db.users.find(
            {"$or": [{"phone_key": {"$in": keys}}, {"phone": {"$in": variants}}], "is_verified": True, "deleted_at": None},
            {"_id": 0, "id": 1, "phone": 1, "phone_key": 1},
        ).to_list(length=len(keys) * 2 + 10)
        matched_ids = []
        for f in found:
            if f["id"] == u["id"]: continue
            matched_ids.append(f["id"])
            if not f.get("phone_key"): asyncio.create_task(_set_phone_key(f["id"], f.get("phone")))

        update = {"sync_window_start": win, "sync_count": count + 1}
        if p.save:
            update.update({"user_id": u["id"], "hashes": [_phone_hash(k) for k in keys],
                           "matched_ids": matched_ids, "updated_at": now()})
        await db.contact_books.update_one({"user_id": u["id"]}, {"$set": update}, upsert=True)

        # Also fold in people who already have MY number, so one call returns the full picture
        has_my_number = await _who_has_me(u)
        matches = await _contact_profiles(u, matched_ids + list(has_my_number), set(matched_ids), has_my_number)
        return {"matches": matches, "total_contacts": len(keys), "matched": len([m for m in matches if m["in_contacts"]])}

    @api.get("/contacts/suggestions")
    async def contacts_suggestions(u=Depends(current_user)):
        """Find-friends list without needing the contact permission again:
        (a) contacts I synced earlier who are on POST, (b) people who have MY number saved."""
        book = await db.contact_books.find_one({"user_id": u["id"]}, {"_id": 0, "matched_ids": 1, "google_matched_ids": 1, "updated_at": 1, "google_synced_at": 1}) or {}
        in_contacts = set(book.get("matched_ids") or []) | set(book.get("google_matched_ids") or [])
        has_my_number = await _who_has_me(u)
        my_key = _phone_key(u.get("phone"))
        users = await _contact_profiles(u, list(in_contacts | has_my_number), in_contacts, has_my_number)
        return {
            "users": users,
            "has_phone": bool(my_key),
            "google_client_id": os.environ.get("GOOGLE_CLIENT_ID", "").strip(),
            "google_synced": bool(book.get("google_synced_at")),
            "synced": bool(book.get("updated_at")),
            "discoverable": u.get("discoverable_by_phone", True) is not False,
        }

    @api.post("/contacts/discoverability")
    async def contacts_discoverability(p: ContactDiscoverIn, u=Depends(current_user)):
        await db.users.update_one({"id": u["id"]}, {"$set": {"discoverable_by_phone": bool(p.enabled)}})
        return {"ok": True, "discoverable": bool(p.enabled)}

    @api.delete("/contacts")
    async def contacts_delete(u=Depends(current_user)):
        """Remove everything we stored about the user's contacts."""
        await db.contact_books.delete_many({"user_id": u["id"]})
        return {"ok": True}

    # ── Verified accounts directory: "Find people → Verified" ─────────────────
    # Verified users are grouped (in this exact display order) by their verified_category /
    # profile category / account_type. First match wins, using _VERIFIED_PRIORITY, so e.g. a
    # "Startup Founder" lands in CEOs & Founders and not in Business.
    # (key, title shown in the app, one-line description, regex on verified_category + category + account_type)
    # LIST ORDER = display order in the app.  _VERIFIED_PRIORITY (below) decides which group wins when
    # a user matches several: specific groups first, broad ones last.
    VERIFIED_GROUPS = [
        ("business",     "Business",                    "Verified brands, companies and organisations to follow.",
         re.compile(r"business|brand|company|corporate|organi[sz]ation|real estate|\bshop\b|\bstore\b", re.I)),
        ("politicians",  "Politicians",                 "Elected leaders and government officials sharing updates and announcements.",
         re.compile(r"politic|government|minister|\bmla\b|\bmp\b|parliament|sarpanch|mayor", re.I)),
        ("ngos",         "NGOs & Non-profits",          "Organisations making a difference on the ground.",
         re.compile(r"\bngo\b|non[\s\-]?profit|charity|foundation|humanitarian", re.I)),
        ("tech",         "Tech & AI",                   "Tech breakthroughs, AI developments and industry insights.",
         re.compile(r"\btech|software|developer|engineer|programmer|\bai\b|artificial|machine learning|data scien|cyber|blockchain|devops", re.I)),
        ("founders",     "CEOs & Founders",             "Founders and leaders building companies and sharing what they learn.",
         re.compile(r"\bceo\b|founder|entrepreneur|chief executive|managing director|startup", re.I)),
        ("news_channels","News channels",               "Trusted news channels and media houses for breaking stories.",
         re.compile(r"news[\s\-]?(channel|network|agency|portal)|\bnews\b|tv channel|television|broadcast|media house|newspaper", re.I)),
        ("journalists",  "Top journalists",             "Leading reporters and anchors sharing trusted news and on-ground insights.",
         re.compile(r"journalis|reporter|anchor|correspondent|\beditor\b|columnist", re.I)),
        ("sports_media", "Sports media",                "Commentators, analysts and channels covering every game.",
         re.compile(r"sports?[\s\-/&]*(media|analyst|commentat|channel|journalis|anchor|broadcast|news|presenter)|commentator|cricket[\s\-]*(analyst|commentat|media|journalis)", re.I)),
        ("filmmakers",   "Filmmakers",                  "Directors, producers and storytellers behind the movies you love.",
         re.compile(r"film[\s\-]?maker|film director|movie director|film producer|cinematograph|screenwriter|\bmovies?\b|\bfilms?\b", re.I)),
        ("actors",       "Actors & Actresses",          "Film and TV stars sharing life on and off screen.",
         re.compile(r"\bactor|actress|bollywood|tollywood|kollywood|film star|movie star|tv star|television star", re.I)),
        ("musicians",    "Musicians & Singers",         "Artists, singers, composers and DJs sharing new music.",
         re.compile(r"music|singer|rapper|\bdj\b|composer|songwriter|vocalist|instrumentalist|\bband\b|guitarist|drummer|pianist|playback", re.I)),
        ("tech_women",   "Women in Tech",               "Women engineers, founders and leaders shaping technology.",
         re.compile(r"women in tech|woman in tech|tech women|tech woman|female (developer|engineer|founder|techie)|girls? who code", re.I)),
        ("social_workers","Social workers & Activists", "People working on the ground for their communities.",
         re.compile(r"social[\s\-]?work|activist|volunteer", re.I)),
        ("cricketers",   "Cricketers",                  "Cricket stars sharing matches, training and life off the field.",
         re.compile(r"cricket", re.I)),
        ("athletes",     "Athletes",                    "Olympians and sportspeople across every sport.",
         re.compile(r"athlet|sports[\s\-]?(person|man|woman)|footballer|football|soccer|hockey|badminton|kabaddi|wrestl|boxer|boxing|olympi|runner|sprinter|swimm|cyclist|chess|basketball|archer|shooter|weightlift|gymnast|\bplayer\b", re.I)),
        ("tennis",       "Tennis players",              "Grand Slam champions and rising tennis stars.",
         re.compile(r"tennis", re.I)),
        ("golfers",      "Golfers",                     "Pro golfers and tour stars.",
         re.compile(r"golf", re.I)),
        ("mma",          "MMA fighters",                "Fighters and martial artists from the cage and the ring.",
         re.compile(r"\bmma\b|mixed martial|\bufc\b|martial art|cage fight|fighter", re.I)),
        ("comedians",    "Comedians",                   "Stand-up comics and funny creators.",
         re.compile(r"comedian|comedy|stand[\s\-]?up|mimicry", re.I)),
        ("dancers",      "Dancers & Performers",        "Dancers, choreographers and stage performers.",
         re.compile(r"danc|choreograph|performer|theat(re|er)|magician", re.I)),
        ("authors",      "Authors & Writers",           "Writers, poets and storytellers.",
         re.compile(r"author|writer|poet|novelist|storyteller", re.I)),
        ("educators",    "Educators & Mentors",         "Teachers, coaches and speakers who help you grow.",
         re.compile(r"teacher|educator|professor|tutor|mentor|coach|motivational|speaker|academic|lecturer|trainer", re.I)),
        ("health",       "Health & Wellness",           "Doctors, nutritionists and wellness experts.",
         re.compile(r"doctor|healthcare|health care|physician|surgeon|nurse|dentist|medical|nutrition|dietitian|wellness|fitness|yoga|\bgym\b", re.I)),
        ("scientists",   "Scientists & Researchers",    "Researchers and scientists explaining the world.",
         re.compile(r"scientist|researcher|research|astronom|physicist|chemist|biolog|\bisro\b|\bnasa\b", re.I)),
        ("lawyers",      "Lawyers & Legal experts",     "Advocates and legal experts explaining your rights.",
         re.compile(r"lawyer|advocate|attorney|legal|barrister|judge", re.I)),
        ("chefs",        "Chefs & Food creators",       "Chefs, home cooks and food explorers.",
         re.compile(r"food|chef|\bcook|restaurant|baker|culinary|recipe", re.I)),
        ("gamers",       "Gamers & Streamers",          "Gamers, streamers and esports talent.",
         re.compile(r"gamer|gaming|streamer|e-?sports", re.I)),
        ("fashion",      "Fashion & Beauty",            "Models, stylists and beauty creators.",
         re.compile(r"\bmodel\b|modell|fashion|makeup|make-up|stylist|beauty", re.I)),
        ("artists",      "Artists & Photographers",     "Painters, illustrators and photographers.",
         re.compile(r"artist|painter|illustrator|sculpt|photograph|\bart\b|artwork", re.I)),
        ("designers",    "Designers & Architects",      "Designers and architects shaping what we see and build.",
         re.compile(r"designer|architect|interior", re.I)),
        ("religious",    "Spiritual & Religious leaders","Spiritual teachers and religious leaders.",
         re.compile(r"religio|spiritual|priest|guru|saint|pandit|monk|imam|swami|pastor|baba", re.I)),
        ("travel",       "Travel creators",             "Travellers and storytellers exploring the world.",
         re.compile(r"travel|tourism", re.I)),
        ("podcasters",   "Podcasters",                  "Hosts with conversations worth listening to.",
         re.compile(r"podcast", re.I)),
        ("creators",     "Creators & Influencers",      "Creators, vloggers and influencers.",
         re.compile(r"influencer|content creator|creator|blogger|youtuber|vlogger|personal blog|\bblog", re.I)),
        ("celebrities",  "Celebrities",                 "Verified celebrities from entertainment, sports and the arts.",
         re.compile(r"celebrit", re.I)),
        ("public_figures","Public figures",             "Notable public personalities.",
         re.compile(r"public figure|community figure|\bfigure\b", re.I)),
    ]
    # first match wins: specific groups before broad ones (a "Cricketer" must not land in Athletes,
    # a "Startup Founder" not in Business, a "Music producer" not in Filmmakers ...)
    _VERIFIED_PRIORITY = [
        "sports_media", "mma", "cricketers", "tennis", "golfers", "athletes",
        "tech_women", "social_workers", "journalists", "news_channels",
        "musicians", "actors", "filmmakers", "comedians", "dancers",
        "politicians", "ngos", "founders", "tech", "scientists", "health", "lawyers",
        "chefs", "gamers", "fashion", "artists", "designers", "authors", "educators",
        "religious", "travel", "podcasters", "business", "creators", "celebrities", "public_figures",
    ]
    assert set(_VERIFIED_PRIORITY) == {g[0] for g in VERIFIED_GROUPS}
    _VERIFIED_RX = {g[0]: g[3] for g in VERIFIED_GROUPS}

    def _verified_group_of(doc):
        text = " ".join(str(doc.get(k) or "") for k in ("verified_category", "category", "account_type"))
        for key in _VERIFIED_PRIORITY:
            if _VERIFIED_RX[key].search(text):
                return key
        return None

    @api.get("/verified/directory")
    async def verified_directory(per_group: int = Query(15, ge=1, le=30), u=Depends(current_user)):
        blocked = list(set(u.get("blocked_users") or []))
        pipeline = [
            {"$match": {"is_badge_verified": True, "is_verified": True, "deleted_at": None, "id": {"$nin": [u["id"]] + blocked}}},
            {"$project": {"_id": 0, "id": 1, "verified_category": 1, "category": 1, "account_type": 1,
                          "fc": {"$size": {"$cond": [{"$isArray": "$followers"}, "$followers", []]}}}},
            {"$sort": {"fc": -1}},
            {"$limit": 2500},
        ]
        rows = await db.users.aggregate(pipeline).to_list(length=2500)
        by_group = {g[0]: [] for g in VERIFIED_GROUPS}
        for r in rows:
            k = _verified_group_of(r)
            if k: by_group[k].append(r["id"])
        chosen = {k: ids[:per_group] for k, ids in by_group.items()}
        all_ids = [i for ids in chosen.values() for i in ids]
        profiles = {}
        if all_ids:
            plist = await _safe_user_find(
                {"id": {"$in": all_ids}},
                {"_id": 0, "id": 1, "name": 1, "username": 1, "handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1,
                 "is_private": 1, "verified_category": 1, "blocked_users": 1},
                limit=len(all_ids) + 1,
            )
            profiles = {pr["id"]: pr for pr in plist}
        my_following = set(u.get("following") or [])
        my_followers = set(u.get("followers") or [])
        reqs = await db.follow_requests.find(
            {"from_id": u["id"], "to_id": {"$in": all_ids or [""]}, "status": "pending"}, {"_id": 0, "to_id": 1}
        ).to_list(length=len(all_ids) + 1)
        pending = {r["to_id"] for r in reqs}
        groups = []
        for key, title, desc, _rx in VERIFIED_GROUPS:
            cards = []
            for uid in chosen[key]:
                pr = profiles.get(uid)
                if not pr or u["id"] in (pr.get("blocked_users") or []): continue
                cards.append({
                    "id": pr["id"], "name": pr.get("name"), "username": pr.get("username"), "handle": pr.get("handle"),
                    "avatar_bg": pr.get("avatar_bg"), "avatar_letter": pr.get("avatar_letter"), "avatar_photo": pr.get("avatar_photo"),
                    "is_badge_verified": True, "is_private": bool(pr.get("is_private")),
                    "verified_category": pr.get("verified_category"),
                    "following": uid in my_following, "requested": uid in pending, "follows_me": uid in my_followers,
                })
            # every category is returned (even when empty) so the app can always show the full chip row
            groups.append({"key": key, "title": title, "description": desc, "total": len(by_group[key]), "users": cards})
        return {"groups": groups}

    async def _on_phone_registered(uid: str, phone: str):
        """A user just registered/verified a phone: tell everyone who already has this number saved."""
        try:
            key = _phone_key(phone)
            if not key: return
            await db.users.update_one({"id": uid}, {"$set": {"phone_key": key}})
            me = await db.users.find_one({"id": uid}, {"_id": 0, "id": 1, "name": 1, "avatar_photo": 1, "blocked_users": 1, "discoverable_by_phone": 1})
            if not me or me.get("discoverable_by_phone") is False: return
            owners = await db.contact_books.find({"$or": [{"hashes": _phone_hash(key)}, {"g_hashes": _phone_hash(key)}], "user_id": {"$ne": uid}}, {"_id": 0, "user_id": 1}).to_list(length=500)
            for o in owners:
                oid = o["user_id"]
                owner = await db.users.find_one({"id": oid}, {"_id": 0, "blocked_users": 1, "deleted_at": 1})
                if not owner or owner.get("deleted_at"): continue
                if uid in (owner.get("blocked_users") or []) or oid in (me.get("blocked_users") or []): continue
                await db.contact_books.update_one({"user_id": oid}, {"$addToSet": {"matched_ids": uid}})
                _bg(_notify(oid, me, "contact_joined", push=("A friend joined POST", f"{me.get('name')} from your contacts is now on POST")))
        except Exception:
            logging.exception("contact-joined hook failed")

    @app.on_event("startup")
    async def backfill_notification_prefs_on():
        """One-time: accounts whose six notification toggles are all OFF (the old forced default) are switched ON,
        so likes / comments / follows / messages / mentions / tags all notify. Accounts with any toggle ON are untouched."""
        try:
            flag_key = "notif_prefs_default_on_v1"
            if await db.settings.find_one({"key": flag_key}):
                return
            keys = ["likes", "comments", "friend_requests", "messages", "mentions", "tags"]
            res = await db.users.update_many(
                {f"notifications_prefs.{k}": {"$ne": True} for k in keys},
                {"$set": {f"notifications_prefs.{k}": True for k in keys}},
            )
            await db.settings.insert_one({"key": flag_key, "at": now().isoformat(), "modified": res.modified_count})
            logging.info("notification prefs backfill: %s accounts switched on", res.modified_count)
        except Exception:
            logging.exception("notification prefs backfill failed")

    @app.on_event("startup")
    async def setup_contact_finder():
        try:
            await db.contact_books.create_index("user_id", unique=True)
            await db.contact_books.create_index("hashes")
            await db.contact_books.create_index("g_hashes")
            await db.contact_books.create_index("email_hashes")
            await db.users.create_index("phone_key")
        except Exception:
            logging.exception("contact index setup failed")
        async def _backfill():
            # one-time: give existing users a phone_key so number matching is indexed
            try:
                cur = db.users.find({"phone": {"$nin": [None, ""]}, "phone_key": {"$exists": False}}, {"_id": 0, "id": 1, "phone": 1})
                async for doc in cur:
                    await _set_phone_key(doc["id"], doc.get("phone"))
            except Exception:
                logging.exception("phone_key backfill failed")
        asyncio.create_task(_backfill())

    # Register all routes
    app.include_router(api)
    app.include_router(ai_router, prefix="/api/ai", tags=["ai-agent"])
    app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
    app.include_router(library_router, prefix="/api/library", tags=["library"])

    print("==> [DIAG] server.py loaded OK — app is ready", file=_sys.stderr, flush=True)

except Exception as _boot_err:
    print(f"==> [DIAG] FATAL BOOT ERROR: {type(_boot_err).__name__}: {_boot_err}", file=_sys.stderr, flush=True)
    _tb.print_exc(file=_sys.stderr)
    _sys.exit(1)

