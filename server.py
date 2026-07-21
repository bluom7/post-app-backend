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
    import os, uuid, random, logging, bcrypt, jwt, re, io
    from pydantic import BaseModel, EmailStr, field_validator
    from typing import Optional, List
    from datetime import datetime, timezone, timedelta
    import base64, asyncio, urllib.request, urllib.parse, json as _json
    import time as _time
    import hashlib as _hl, hmac as _hmac, os as _os
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, ECDSA, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_der_private_key
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    load_dotenv()

    MONGO_URL      = os.environ["MONGO_URL"]
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
            padded = data_bytes + b''
            ct = AESGCM(cek).encrypt(nonce, padded, None)
            # Build record: salt(16) + rs(4) + keylen(1) + sender_pub(65) + ciphertext
            import struct
            header = salt + struct.pack(">I", 4096) + bytes([len(sender_pub)]) + sender_pub
            return header + ct
        except Exception:
            return None

    async def send_push(user_id, title, body):
        try:
            sub_doc = await db.push_subscriptions.find_one({'user_id': user_id})
            if not sub_doc: return
            pub, priv = await get_vapid_keys()
            if not pub or not priv: return
            sub = sub_doc.get('subscription', {})
            endpoint = sub.get('endpoint','')
            if not endpoint: return
            jwt_tok = _make_vapid_jwt(endpoint, priv)
            if not jwt_tok: return
            payload = _json.dumps({'title': title, 'body': body}).encode()
            enc_body = _encrypt_push_payload(sub, payload)
            loop = asyncio.get_event_loop()
            def _req():
                try:
                    import urllib.request as _ur, urllib.error
                    r = _ur.Request(endpoint, method='POST')
                    r.add_header('Authorization', 'vapid t=' + jwt_tok + ',k=' + pub)
                    r.add_header('TTL', '86400')
                    if enc_body:
                        r.data = enc_body
                        r.add_header('Content-Type','application/octet-stream')
                        r.add_header('Content-Encoding','aes128gcm')
                    with _ur.urlopen(r, timeout=10): pass
                except Exception: pass
            await loop.run_in_executor(None, _req)
        except Exception:
            pass
    OFFICIAL_ACCOUNT_ID = os.environ.get("OFFICIAL_ACCOUNT_ID", "").strip()
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
    TWILIO_SID     = os.environ.get("TWILIO_SID", "").strip()
    TWILIO_TOKEN   = os.environ.get("TWILIO_TOKEN", "").strip()
    TWILIO_PHONE   = os.environ.get("TWILIO_PHONE", "").strip()
    NEWS_API_KEY   = os.environ.get("NEWS_API_KEY", "").strip()

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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], allow_credentials=True,
        allow_methods=["*"], allow_headers=["*"],
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

    def make_token(uid):
        return jwt.encode(
            {"sub": uid, "exp": now() + timedelta(days=30)},
            JWT_SECRET, algorithm="HS256",
        )

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

    # ── Auth helpers ─────────────────────────────────────────────
    async def raw_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
        if not creds:
            raise HTTPException(401, "Missing token")
        try:
            payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
            uid = payload["sub"]
        except Exception:
            raise HTTPException(401, "Invalid token")
        u = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0, "otp_hash": 0})
        if not u:
            raise HTTPException(401, "User not found")
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
                "notifications_prefs": {"likes": False, "comments": False, "friend_requests": False, "messages": False},
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
    def send_otp_email(email, code):
        if DEMO_MODE:
            logging.info(f"[DEMO] Email OTP for {email}: {code}")
            return True
        try:
            import resend
            resend.api_key = RESEND_API_KEY

            plain_text = f"""Hi,

Your POST App verification code is: {code}

This code is valid for 10 minutes only.

If you did not request this code, please ignore this email.

- POST App Team
postbluom.online"""

            html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your POST App Code</title>
</head>
<body style="margin:0;padding:0;background:#ffffff;font-family:Arial,Helvetica,sans-serif;color:#111111;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;">
    <tr>
      <td style="padding:40px 20px;">
        <table role="presentation" width="100%" style="max-width:480px;margin:0 auto;background:#ffffff;border:1px solid #e0e0e0;border-radius:8px;padding:40px;">
          <tr>
            <td style="padding-bottom:24px;border-bottom:1px solid #eeeeee;">
              <p style="margin:0;font-size:22px;font-weight:900;letter-spacing:4px;">
                <span style="color:#FFD600;">P</span><span style="color:#00C853;">O</span><span style="color:#FF1744;">S</span><span style="color:#29B6F6;">T</span>
                <span style="font-size:14px;font-weight:400;color:#666;letter-spacing:1px;margin-left:8px;">App</span>
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:32px 0 24px 0;">
              <p style="margin:0 0 8px 0;font-size:15px;color:#333;">Hi,</p>
              <p style="margin:0 0 24px 0;font-size:15px;color:#333;line-height:1.6;">
                Here is your verification code for POST App:
              </p>
              <table role="presentation" width="100%">
                <tr>
                  <td style="text-align:center;padding:20px 0;">
                    <span style="display:inline-block;background:#f5f5f5;border:2px solid #FFD600;border-radius:8px;padding:16px 32px;font-size:32px;font-weight:900;letter-spacing:10px;color:#111111;">{code}</span>
                  </td>
                </tr>
              </table>
              <p style="margin:16px 0 0 0;font-size:13px;color:#888;text-align:center;">
                This code expires in <strong>10 minutes</strong>.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding-top:24px;border-top:1px solid #eeeeee;">
              <p style="margin:0 0 8px 0;font-size:13px;color:#999;">
                If you did not request this code, you can safely ignore this email.
              </p>
              <p style="margin:0;font-size:12px;color:#bbb;">
                &copy; 2025 POST App &middot; postbluom.online
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

            resend.Emails.send({
                "from": "POST App <otp@postbluom.online>",
                "to": [email],
                "subject": "Your POST App verification code",
                "html": html_body,
                "text": plain_text,
                "reply_to": "support@postbluom.online",
                "headers": {"X-Entity-Ref-ID": str(uuid.uuid4())},
            })
            logging.info(f"✅ OTP email sent to {email}")
            return True
        except Exception as e:
            logging.warning(f"Email failed: {e}")
            return False

    def send_otp_sms(phone, code):
        if not TWILIO_SID or not TWILIO_TOKEN or not TWILIO_PHONE:
            missing = [k for k,v in {"TWILIO_SID": TWILIO_SID, "TWILIO_TOKEN": TWILIO_TOKEN, "TWILIO_PHONE": TWILIO_PHONE}.items() if not v]
            logging.warning(f"[SMS] Missing env vars: {missing}. OTP for {phone}: {code}")
            return None  # None = not configured
        try:
            from twilio.rest import Client
            twilio = Client(TWILIO_SID, TWILIO_TOKEN)
            twilio.messages.create(
                body=f"POST App verification code: {code}\nValid for 10 minutes.",
                from_=TWILIO_PHONE,
                to=phone,
            )
            logging.info(f"[SMS] Sent to {phone}")
            return True
        except Exception as e:
            logging.error(f"[SMS] FAILED to {phone}: {e}")
            return str(e)  # Return error string so callers can surface it

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

    class LoginIn(BaseModel):
        email: EmailStr; password: str

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
        gender: Optional[str] = None
        dob: Optional[str] = None
        is_private: Optional[bool] = None
        theme: Optional[str] = None
        chat_translation_enabled: Optional[bool] = None
        account_type: Optional[str] = None
        is_badge_verified: Optional[bool] = None
        user_status: Optional[str] = None

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

    class AddEmailInitIn(BaseModel):
        email: EmailStr

    class AddEmailVerifyIn(BaseModel):
        email: EmailStr; otp: str

    class NotificationsPrefsIn(BaseModel):
        likes: Optional[bool] = None
        comments: Optional[bool] = None
        friend_requests: Optional[bool] = None
        messages: Optional[bool] = None

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
        music_duration_ms: Optional[int] = None       # track duration in ms
        alt_text: Optional[str] = None                # accessibility alt text for media
        gif_url: Optional[str] = None                  # Giphy GIF URL
        sticker_overlays: Optional[List[dict]] = None  # [{id, url, x, y}] Giphy stickers placed on media
        video_width: Optional[int] = None              # natural px width of video (captured at pick time from browser)
        video_height: Optional[int] = None             # natural px height of video
        video_text_overlays: Optional[List[dict]] = None  # [{id,text,x,y,color,size}] draggable text overlays baked during compose
        video_effect: Optional[str] = None                # VIDEO_EFFECTS id: none|vivid|warm|cool|bw|fade|vintage

    class CommentIn(BaseModel):
        text: str

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

    class TypingIn(BaseModel):
        to_user_id: str; is_typing: bool = True

    class FriendIn(BaseModel):
        target_user_id: str

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
        code   = f"{random.randint(0,9999):04d}"
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
            "notifications_prefs": {"likes": False, "comments": False, "friend_requests": False, "messages": False},
        }
        if existing:
            await db.users.update_one({"id": uid}, {"$set": doc})
        else:
            await db.users.insert_one(doc)
        asyncio.create_task(run_in_bg(send_otp_email, p.email, code))
        return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

    @api.post("/auth/verify-otp")
    async def verify_otp(p: OtpIn):
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
        return {"token": make_token(u["id"]), "user_id": u["id"]}

    @api.post("/auth/login")
    async def login(p: LoginIn):
        u = await db.users.find_one(_email_q(p.email))          # case-insensitive lookup
        if not u: raise HTTPException(404, "User not found")
        if not u.get("is_verified"):                             # fast check BEFORE slow hash
            raise HTTPException(400, "Account not verified. Please check your email for the OTP verification code.")
        pw_hash = u.get("password_hash", "")
        if not await verifypw(p.password, pw_hash): raise HTTPException(401, "Wrong password")
        if _is_bcrypt(pw_hash) or (pw_hash.startswith(_PBKDF2_PREFIX) and len(pw_hash.split("$")) == 4):
            asyncio.create_task(_migrate_hash(u["id"], p.password))  # upgrade legacy 260k → 100k
        asyncio.create_task(_migrate_prefs_defaults(u))  # background — don't block login
        user_profile = {k: v for k, v in u.items() if k not in ("_id", "password_hash", "otp_hash")}
        resp = {"token": make_token(u["id"]), "user_id": u["id"], "user": user_profile}
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
        code = f"{random.randint(0,9999):04d}"
        await db.users.update_one(
            {"id": u["id"]},
            {"$set": {"otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10)}},
        )
        asyncio.create_task(run_in_bg(send_otp_email, u["email"], code))
        return {"message": "Resent", "demo_otp": code if DEMO_MODE else None}

    # ── Forgot Password ───────────────────────────────────────────
    @api.post("/auth/forgot-password-init")
    async def forgot_password_init(p: ForgotPasswordInitIn):
        identifier = p.identifier.strip()
        if "@" in identifier:
            user = await db.users.find_one({"email": identifier})
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
        # fresh one — this previously caused "OTP arrived but verify fails" for email,
        # since a slow-arriving email could be invalidated by an impatient resend.
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
        code = f"{random.randint(0,9999):04d}"
        await db.reset_otps.update_one(
            {"identifier": identifier},
            {"$set": {
                "identifier": identifier, "user_id": user["id"],
                "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False,
                "otp_sent_at": now(), "_plain": code if DEMO_MODE else None,
            }},
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
            sms_ok = sms_result is True
            sms_err = sms_result if isinstance(sms_result, str) else None
            return {"message": "OTP sent", "demo_otp": code if not sms_ok else None, "method": "sms", "sms_error": sms_err}

    @api.post("/auth/forgot-password-verify")
    async def forgot_password_verify(p: ForgotPasswordVerifyIn):
        rec = await db.reset_otps.find_one({"identifier": p.identifier.strip()})
        if not rec: raise HTTPException(400, "Request not found. Please start again.")
        exp = rec["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "OTP expired. Please request a new one.")
        if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
        await db.reset_otps.update_one({"identifier": p.identifier.strip()}, {"$set": {"verified": True}})
        return {"message": "OTP verified"}

    @api.post("/auth/forgot-password-reset")
    async def forgot_password_reset(p: ForgotPasswordResetIn):
        rec = await db.reset_otps.find_one({"identifier": p.identifier.strip(), "verified": True})
        if not rec: raise HTTPException(400, "Not verified. Please verify OTP first.")
        if len(p.new_password) < 6: raise HTTPException(400, "Password must be at least 6 characters")
        await db.users.update_one(
            {"id": rec["user_id"]},
            {"$set": {"password_hash": await hashpw(p.new_password)}},
        )
        await db.reset_otps.delete_one({"identifier": p.identifier.strip()})
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
        code = f"{random.randint(0,9999):04d}"
        await db.email_otps.update_one(
            {"email": p.email},
            {"$set": {
                "email": p.email, "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False,
                "otp_sent_at": now(), "_plain": code if DEMO_MODE else None,
            }},
            upsert=True,
        )
        asyncio.create_task(run_in_bg(send_otp_email, p.email, code))
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
    async def email_signup(p: EmailSignupIn):
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
            "notifications_prefs": {"likes": False, "comments": False, "friend_requests": False, "messages": False},
        }
        await db.users.insert_one(doc)
        await db.email_otps.delete_one({"email": p.email})
        return {"token": make_token(uid), "user_id": uid, "requires_phone": True}

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
        code = f"{random.randint(0,9999):04d}"
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
    async def phone_signup(p: PhoneSignupIn):
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
            "id": uid, "phone": p.phone, "email": None,
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
            "notifications_prefs": {"likes": False, "comments": False, "friend_requests": False, "messages": False},
        }
        await db.users.insert_one(doc)
        await db.phone_otps.delete_one({"phone": p.phone})
        return {"token": make_token(uid), "user_id": uid, "requires_email": True}

    @api.post("/auth/phone-login")
    async def phone_login(p: PhoneLoginIn):
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
        user_profile = {k: v for k, v in u.items() if k not in ("_id", "password_hash", "otp_hash")}
        resp = {"token": make_token(u["id"]), "user_id": u["id"], "user": user_profile}
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
        code = f"{random.randint(0,9999):04d}"
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
        sms_ok = sms_result is True
        sms_err = sms_result if isinstance(sms_result, str) else None
        demo = code if not sms_ok else None
        if demo: await db.phone_otps.update_one({"phone": p.phone}, {"$set": {"_plain": demo}})
        return {"message": "OTP sent", "demo_otp": demo, "sms_error": sms_err}

    @api.post("/auth/add-phone-verify")
    async def add_phone_verify(p: AddPhoneVerifyIn, u=Depends(raw_user)):
        if u.get("signup_method") != "email": raise HTTPException(403, "Only for email-registered accounts")
        if u.get("phone_verified"): raise HTTPException(400, "Phone already verified")
        rec = await db.phone_otps.find_one({"phone": p.phone, "user_id": u["id"]})
        if not rec: raise HTTPException(400, "OTP not found. Please request a new one.")
        exp = rec["otp_expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if now() > exp: raise HTTPException(400, "OTP expired. Please request a new one.")
        if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
        await db.users.update_one({"id": u["id"]}, {"$set": {"phone": p.phone, "phone_verified": True}})
        await db.phone_otps.delete_one({"phone": p.phone})
        return {"message": "Phone verified successfully", "token": make_token(u["id"])}

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
        code = f"{random.randint(0,9999):04d}"
        await db.email_otps.update_one(
            {"email": p.email},
            {"$set": {
                "email": p.email, "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False, "user_id": u["id"],
                "otp_sent_at": now(), "_plain": code if DEMO_MODE else None,
            }},
            upsert=True,
        )
        asyncio.create_task(run_in_bg(send_otp_email, p.email, code))
        return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

    @api.post("/auth/add-email-verify")
    async def add_email_verify(p: AddEmailVerifyIn, u=Depends(raw_user)):
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
        return {"message": "Email verified successfully", "token": make_token(u["id"])}

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

    # ── Profile ───────────────────────────────────────────────────
    @api.patch("/profile")
    async def update_profile(p: ProfileUpdate, u=Depends(current_user)):
        upd = {k: v for k, v in p.model_dump().items() if v is not None}
        if "username" in upd:
            if u.get("username_locked") and upd["username"] != u.get("username"):
                raise HTTPException(400, "Verified accounts cannot change their username")
            try:
                await ensure_username_unique(upd["username"], exclude_uid=u["id"])
            except ValueError as e:
                raise HTTPException(400, str(e))
            upd["handle"] = f"@{upd['username']}"
        if upd:
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
                        await db.messages.update_many({"from_user_id": uid}, {"$set": msg_upd})
                except Exception:
                    pass
            asyncio.create_task(_bg())

        return await db.users.find_one({"id": u["id"]}, {"_id": 0, "password_hash": 0, "otp_hash": 0})

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
        return await db.users.find(
            {"id": {"$in": ids}}, {"_id": 0, "password_hash": 0, "otp_hash": 0}
        ).to_list(len(ids))

    @api.get("/users/me/follow-requests")
    async def my_follow_requests(u=Depends(current_user)):
        pending = await db.follow_requests.find(
            {"to_id": u["id"], "status": "pending"}, {"_id": 0}
        ).to_list(500)
        from_ids = [r["from_id"] for r in pending]
        PUBLIC = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
                  "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1, "location": 1, "about": 1}
        users_list = await db.users.find({"id": {"$in": from_ids}}, PUBLIC).to_list(500) if from_ids else []
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
        continent: Optional[str] = None, q: Optional[str] = None,
        skip: int = 0, limit: int = 50, u=Depends(current_user),
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
        users = await db.users.find(
            query, {"_id": 0, "password_hash": 0, "otp_hash": 0}
        ).skip(skip).limit(limit).to_list(limit)
        total = await db.users.count_documents(query)
        return {"users": users, "total": total, "skip": skip, "limit": limit}

    @api.get("/users/{user_id}")
    async def get_user(user_id: str, u=Depends(current_user)):
        user = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0, "otp_hash": 0})
        if not user: raise HTTPException(404, "User not found")
        is_self      = user_id == u["id"]
        is_follower  = u["id"] in user.get("followers", [])
        is_private   = user.get("is_private", False)
        is_private_locked = is_private and not is_follower and not is_self
        pending_req  = None
        posts_count_task = db.posts.count_documents({"user_id": user_id})
        follow_req_task  = (
            db.follow_requests.find_one({"from_id": u["id"], "to_id": user_id, "status": "pending"})
            if is_private_locked else None
        )
        if follow_req_task is not None:
            posts_count, pending_req = await asyncio.gather(posts_count_task, follow_req_task)
        else:
            posts_count = await posts_count_task
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
            "is_mutual": is_mutual, "is_following_you": is_following_you,
            "is_private_locked": is_private_locked, "has_pending_request": bool(pending_req),
            "stats": {"posts": posts_count, "followers": followers_count, "following": following_count},
        }
        if is_private_locked:
            return base
        return {
            **user, "is_mutual": is_mutual, "is_following_you": is_following_you,
            "is_private_locked": False, "has_pending_request": False,
            "stats": {"posts": posts_count, "followers": followers_count, "following": following_count},
        }

    # ── Follow / Unfollow ─────────────────────────────────────────
    @api.post("/users/{user_id}/follow")
    async def follow_user(user_id: str, u=Depends(current_user)):
        if user_id == u["id"]: raise HTTPException(400, "Can't follow yourself")
        target = await db.users.find_one({"id": user_id})
        if not target: raise HTTPException(404, "User not found")
        if u["id"] in target.get("blocked_users", []) or user_id in u.get("blocked_users", []):
            raise HTTPException(403, "Action not allowed")
        if target.get("is_private"):
            existing = await db.follow_requests.find_one({"from_id": u["id"], "to_id": user_id})
            if existing: return {"ok": True, "pending": True}
            await db.follow_requests.insert_one({
                "id": str(uuid.uuid4()), "from_id": u["id"], "to_id": user_id,
                "status": "pending", "created_at": now().isoformat(),
            })
            await db.notifications.insert_one({
                "id": str(uuid.uuid4()), "user_id": user_id,
                "from_user_id": u["id"], "from_user_name": u["name"], "from_user_avatar": u.get("avatar_photo"),
                "type": "follow_request", "created_at": now().isoformat(), "read": False,
            })
            asyncio.create_task(send_push(user_id, "New follow request", u["name"] + " wants to follow you"))
            return {"ok": True, "pending": True}
        if u["id"] not in target.get("followers", []):
            await db.users.update_one({"id": user_id}, {"$push": {"followers": u["id"]}})
        if user_id not in u.get("following", []):
            await db.users.update_one({"id": u["id"]}, {"$push": {"following": user_id}})
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": user_id,
            "from_user_id": u["id"], "from_user_name": u["name"], "from_user_avatar": u.get("avatar_photo"),
            "type": "follow", "created_at": now().isoformat(), "read": False,
        })
        asyncio.create_task(send_push(user_id, "New follower", u["name"] + " started following you"))
        return {"ok": True, "pending": False}

    @api.post("/users/{user_id}/unfollow")
    async def unfollow_user(user_id: str, u=Depends(current_user)):
        await db.users.update_one({"id": user_id}, {"$pull": {"followers": u["id"]}})
        await db.users.update_one({"id": u["id"]}, {"$pull": {"following": user_id}})
        return {"ok": True}

    @api.get("/users/{user_id}/followers")
    async def get_followers(user_id: str, u=Depends(current_user)):
        user = await db.users.find_one({"id": user_id})
        if not user: raise HTTPException(404, "User not found")
        return await db.users.find(
            {"id": {"$in": user.get("followers", [])}},
            {"_id": 0, "password_hash": 0, "otp_hash": 0},
        ).to_list(500)

    @api.get("/users/{user_id}/following")
    async def get_following(user_id: str, u=Depends(current_user)):
        user = await db.users.find_one({"id": user_id})
        if not user: raise HTTPException(404, "User not found")
        return await db.users.find(
            {"id": {"$in": user.get("following", [])}},
            {"_id": 0, "password_hash": 0, "otp_hash": 0},
        ).to_list(500)

    # ── Follow Requests (private accounts) ───────────────────────
    @api.post("/users/{user_id}/follow-request/cancel")
    async def cancel_follow_request(user_id: str, u=Depends(current_user)):
        await db.follow_requests.delete_one({"from_id": u["id"], "to_id": user_id})
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
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": user_id,
            "from_user_id": u["id"], "from_user_name": u["name"], "from_user_avatar": u.get("avatar_photo"),
            "type": "follow_accept", "created_at": now().isoformat(), "read": False,
        })
        asyncio.create_task(send_push(user_id, "Follow accepted", u["name"] + " accepted your follow request"))
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
        raw = await file.read()
        if len(raw) > 10 * 1024 * 1024:
            raise HTTPException(400, "Image is too large. Max 10MB.")
        try:
            result = cloudinary.uploader.upload(
                raw,
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
        raw = await file.read()
        if len(raw) > 25 * 1024 * 1024:
            raise HTTPException(400, "Audio is too large. Max 25MB.")
        try:
            result = cloudinary.uploader.upload(
                raw,
                resource_type="video",   # Cloudinary uses "video" resource_type for audio files
                folder="post-app/audio",
                public_id=f"{u['id']}_{uuid.uuid4().hex}",
                overwrite=False,
            )
        except Exception:
            logging.exception("Cloudinary audio upload failed")
            raise HTTPException(502, "Audio upload failed. Please try again.")
        return {"url": result.get("secure_url"), "duration": int(result.get("duration") or 0)}

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

        raw = await file.read()
        if len(raw) > MAX_UPLOAD_VIDEO_BYTES:
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
            result = cloudinary.uploader.upload(raw, **upload_kwargs)
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

    # ── One-time migration: move old base64 videos to Cloudinary ────
    # Posts/profile/cover videos created before the Cloudinary upload was
    # added are still stored as huge base64 "data:video/..." strings, so
    # they still stutter/buffer for existing users. This endpoint finds
    # every one of those, re-uploads the bytes to Cloudinary, and rewrites
    # the field to the new streamable URL. Safe to call more than once —
    # already-migrated (http/https) values are skipped.
    MIGRATION_SECRET = os.environ.get("MIGRATION_SECRET", "").strip()

    def _decode_data_uri_video(data_uri: str) -> bytes:
        header, _, b64data = data_uri.partition(",")
        return base64.b64decode(b64data)

    async def _migrate_one_video(data_uri: str, public_id: str) -> Optional[str]:
        try:
            raw = _decode_data_uri_video(data_uri)
            result = cloudinary.uploader.upload(
                raw, resource_type="video", folder="post-app/videos-migrated",
                public_id=public_id, overwrite=False,
            )
            return result.get("secure_url")
        except Exception:
            logging.exception(f"Video migration failed for {public_id}")
            return None

    @api.post("/admin/migrate-videos-to-cloudinary")
    async def migrate_videos_to_cloudinary(request: Request):
        if not MIGRATION_SECRET or request.headers.get("x-migration-key") != MIGRATION_SECRET:
            raise HTTPException(403, "Not authorized")
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) and not CLOUDINARY_URL:
            raise HTTPException(500, "Video hosting is not configured on the server")

        posts_migrated, posts_failed = 0, 0
        users_migrated, users_failed = 0, 0

        async for post in db.posts.find({"video_url": {"$regex": "^data:video/"}}):
            new_url = await _migrate_one_video(post["video_url"], f"post_{post['id']}")
            if new_url:
                await db.posts.update_one({"id": post["id"]}, {"$set": {"video_url": new_url}})
                posts_migrated += 1
            else:
                posts_failed += 1

        async for user in db.users.find({
            "$or": [
                {"profile_video": {"$regex": "^data:video/"}},
                {"cover_video": {"$regex": "^data:video/"}},
            ]
        }):
            upd = {}
            if user.get("profile_video", "").startswith("data:video/"):
                new_url = await _migrate_one_video(user["profile_video"], f"profile_{user['id']}")
                if new_url: upd["profile_video"] = new_url
                else: users_failed += 1
            if user.get("cover_video", "").startswith("data:video/"):
                new_url = await _migrate_one_video(user["cover_video"], f"cover_{user['id']}")
                if new_url: upd["cover_video"] = new_url
                else: users_failed += 1
            if upd:
                await db.users.update_one({"id": user["id"]}, {"$set": upd})
                users_migrated += 1

        return {
            "ok": True,
            "posts_migrated": posts_migrated, "posts_failed": posts_failed,
            "users_migrated": users_migrated, "users_failed": users_failed,
        }

    @api.post("/posts")
    async def create_post(p: PostIn, u=Depends(current_user)):
        _validate_post_video(p.video_url, p.video_duration)
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
            "alt_text": (p.alt_text or "")[:1000] or None,
            "gif_url": (p.gif_url or "").strip() or None,
            "sticker_overlays": [{"id": s["id"], "url": s["url"], "x": float(s.get("x", 50)), "y": float(s.get("y", 50))} for s in (p.sticker_overlays or []) if s.get("url")][:10],
            "video_text_overlays": [{"id": t.get("id",""), "text": (t.get("text") or "")[:200], "x": float(t.get("x", 50)), "y": float(t.get("y", 50)), "color": (t.get("color") or "#ffffff")[:20], "size": int(t.get("size") or 22)} for t in (p.video_text_overlays or []) if t.get("text")][:10],
            "video_effect": (p.video_effect or "none")[:20] if p.video_effect else None,
            "likes": [], "comments": [], "views": [], "saves": [], "reposts": [],
            "created_at": now().isoformat(), "edited_at": None, "is_pinned": False,
        }
        await db.posts.insert_one(doc.copy())
        doc.pop("_id", None)
        return doc

    def _reel_to_feed_item(r: dict) -> dict:
        """Shapes a raw `reels` doc so it can sit alongside `posts` docs in the
        home feed / profile grid — same field names the frontend post card and
        PostMedia component already know how to render (video_url, content,
        likes as [{user_id,color}], etc). `is_reel` lets the frontend route
        interactions (like/comment/save/delete/open) to the /reels/* endpoints.
        """
        likes_ids = r.get("likes", [])
        return {
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
            "accent": None,
            "location": None,
            "photo_url": None,
            "photo_urls": None,
            "video_url": r.get("video_url"),
            "video_duration": r.get("duration"),
            "photo_width": None, "photo_height": None, "aspect_ratio": 9/16,
            "audience": "public",
            "comments_enabled": True,
            "likes": [{"user_id": uid, "color": "#FF3B30"} for uid in likes_ids],
            "comments": r.get("comments", []),
            "views": [],
            "saves": r.get("saves", []),
            "reposts": [],
            "created_at": r.get("created_at"),
            "edited_at": None,
            "is_pinned": False,
            "is_reel": True,
            "audio_label": r.get("audio_label"),
        }

    @api.get("/posts")
    async def list_posts(
        q: Optional[str] = None, user_id: Optional[str] = None,
        skip: int = 0, limit: int = 20, feed: bool = False,
        following_only: bool = False,
        u=Depends(current_user),
    ):
        query: dict = {}
        following_ids = u.get("following", [])
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
            followers_ids = u.get("followers", [])
            # Users we already have read access to (following + self)
            can_see_ids = set(following_ids + [u["id"]])
            can_see_list = list(can_see_ids)
            # Run both user-set queries in PARALLEL for speed
            async def _empty_list():
                return []
            follower_query = (
                db.users.find(
                    {"id": {"$in": followers_ids},
                     "$or": [{"is_private": {"$ne": True}}, {"id": {"$in": can_see_list}}]},
                    {"id": 1, "_id": 0},
                ).to_list(500)
                if followers_ids else _empty_list()
            )
            verified_query = db.users.find(
                {"is_badge_verified": True,
                 "$or": [{"is_private": {"$ne": True}}, {"id": {"$in": can_see_list}}]},
                {"id": 1, "_id": 0},
            ).to_list(500)
            visible_follower_docs, verified_docs = await asyncio.gather(follower_query, verified_query)
            visible_follower_ids = [v["id"] for v in visible_follower_docs]
            verified_ids = [v["id"] for v in verified_docs]
            feed_ids = list(set(following_ids + visible_follower_ids + verified_ids + [u["id"]]))
            query["user_id"] = {"$in": feed_ids}
        else:
            if q:
                query["$or"] = [
                    {"content": {"$regex": q, "$options": "i"}},
                    {"user_name": {"$regex": q, "$options": "i"}},
                    {"location": {"$regex": q, "$options": "i"}},
                ]
            viewer_can_see = set(following_ids + [u["id"]])
            priv_docs = await db.users.find(
                {"is_private": True, "id": {"$nin": list(viewer_can_see)}}, {"id": 1, "_id": 0}
            ).to_list(None)
            private_ids = [p["id"] for p in priv_docs]
            if private_ids:
                query["user_id"] = {"$nin": private_ids}
        if q and user_id:
            query["$or"] = [
                {"content": {"$regex": q, "$options": "i"}},
                {"user_name": {"$regex": q, "$options": "i"}},
                {"location": {"$regex": q, "$options": "i"}},
            ]
        # Reels get merged into the home feed and profile grid (but not search)
        # so a shared reel shows up for followers/following, and stays on the
        # poster's own profile — reusing the same user_id filter built above.
        include_reels = (feed or bool(user_id)) and not q and "user_id" in query
        fetch_n = skip + limit
        posts_task = db.posts.find(query, {"_id": 0}).sort("created_at", -1).limit(fetch_n).to_list(fetch_n)
        if include_reels:
            reel_query = {"user_id": query["user_id"]}
            reels_task = db.reels.find(reel_query, {"_id": 0}).sort("created_at", -1).limit(fetch_n).to_list(fetch_n)
        else:
            async def _no_reels(): return []
            reels_task = _no_reels()
        posts_raw, reels_raw = await asyncio.gather(posts_task, reels_task)
        merged = posts_raw + [_reel_to_feed_item(r) for r in reels_raw]
        merged.sort(key=lambda d: d.get("created_at") or "", reverse=True)
        posts = merged[skip:skip + limit]
        unviewed_ids = [p["id"] for p in posts if not p.get("is_reel") and u["id"] not in p.get("views", [])]
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
        return {"posts": posts, "has_more": len(posts) == limit, "skip": skip, "limit": limit}

    @api.get("/posts/{pid}")
    async def get_post(pid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid}, {"_id": 0})
        if not post: raise HTTPException(404, "Post not found")
        if u["id"] not in post.get("views", []):
            await db.posts.update_one({"id": pid}, {"$addToSet": {"views": u["id"]}})
            post["views"] = post.get("views", []) + [u["id"]]
        return post

    @api.delete("/posts/{pid}")
    async def delete_post(pid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Not found")
        if post["user_id"] != u["id"]: raise HTTPException(403, "Not your post")
        await db.posts.delete_one({"id": pid})
        return {"ok": True}

    @api.patch("/posts/{pid}")
    async def edit_post(pid: str, p: PostIn, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Post not found")
        if post["user_id"] != u["id"]: raise HTTPException(403, "Not your post")
        _validate_post_video(p.video_url, p.video_duration)
        upd = {"content": p.content, "accent": p.accent, "location": p.location or "", "edited_at": now().isoformat()}
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
        return await db.posts.find_one({"id": pid}, {"_id": 0})

    @api.post("/posts/{pid}/like")
    async def like_post(pid: str, p: LikeIn, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Not found")
        likes = [l for l in post.get("likes", []) if l["user_id"] != u["id"]]
        if p.color:
            likes.append({"user_id": u["id"], "color": p.color, "liked_at": now().isoformat()})
        await db.posts.update_one({"id": pid}, {"$set": {"likes": likes}})
        if p.color and post["user_id"] != u["id"]:
            await db.notifications.insert_one({
                "id": str(uuid.uuid4()), "user_id": post["user_id"],
                "from_user_id": u["id"], "from_user_name": u["name"], "from_user_avatar": u.get("avatar_photo"),
                "type": "like", "post_id": pid, "created_at": now().isoformat(), "read": False,
            })
            asyncio.create_task(send_push(post["user_id"], "New like ♥️", u["name"] + " liked your post"))
        return {"likes": likes, "total": len(likes)}

    @api.post("/posts/{pid}/comments")
    async def add_comment(pid: str, p: CommentIn, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Post not found")
        if not post.get("comments_enabled", True):
            raise HTTPException(403, "Comments are turned off for this post")
        c = {
            "id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"],
            "user_handle": u["handle"], "avatar_bg": u["avatar_bg"],
            "avatar_letter": u["avatar_letter"], "text": p.text,
            "created_at": now().isoformat(),
        }
        await db.posts.update_one({"id": pid}, {"$push": {"comments": c}})
        if post["user_id"] != u["id"]:
            await db.notifications.insert_one({
                "id": str(uuid.uuid4()), "user_id": post["user_id"],
                "from_user_id": u["id"], "from_user_name": u["name"], "from_user_avatar": u.get("avatar_photo"),
                "type": "comment", "post_id": pid, "created_at": now().isoformat(), "read": False,
            })
            asyncio.create_task(send_push(post["user_id"], "New comment 💬", u["name"] + " commented on your post"))
        return c

    @api.delete("/posts/{pid}/comments/{cid}")
    async def delete_comment(pid: str, cid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Post not found")
        comment = next((c for c in post.get("comments", []) if c["id"] == cid), None)
        if not comment: raise HTTPException(404, "Comment not found")
        if comment["user_id"] != u["id"] and post["user_id"] != u["id"]:
            raise HTTPException(403, "Cannot delete")
        await db.posts.update_one({"id": pid}, {"$pull": {"comments": {"id": cid}}})
        return {"ok": True}

    @api.post("/posts/{pid}/view")
    async def view_post(pid: str, u=Depends(current_user)):
        await db.posts.update_one({"id": pid}, {"$addToSet": {"views": u["id"]}})
        return {"ok": True}

    @api.post("/posts/{pid}/save")
    async def save_post(pid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Post not found")
        if u["id"] in (post.get("saves") or []):
            await db.posts.update_one({"id": pid}, {"$pull": {"saves": u["id"]}})
            return {"saved": False}
        await db.posts.update_one({"id": pid}, {"$addToSet": {"saves": u["id"]}})
        return {"saved": True}

    @api.post("/posts/{pid}/repost")
    async def repost_post(pid: str, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Post not found")
        already = await db.posts.find_one({"repost_of": pid, "user_id": u["id"]})
        if already:
            await db.posts.delete_one({"id": already["id"]})
            await db.posts.update_one({"id": pid}, {"$pull": {"reposts": u["id"]}})
            return {"reposted": False}
        doc = {
            "id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"],
            "user_handle": u["handle"], "avatar_bg": u["avatar_bg"],
            "avatar_letter": u["avatar_letter"], "avatar_photo": u.get("avatar_photo"),
            "content": post.get("content", ""), "accent": post.get("accent", "#FFD600"),
            "location": "", "photo_url": post.get("photo_url"), "photo_urls": post.get("photo_urls", []),
            "video_url": post.get("video_url"), "video_duration": post.get("video_duration"),
            "likes": [], "comments": [], "views": [], "saves": [], "reposts": [],
            "repost_of": pid, "repost_user_name": post.get("user_name"),
            "repost_user_handle": post.get("user_handle"),
            "created_at": now().isoformat(), "is_pinned": False,
        }
        await db.posts.insert_one(doc.copy())
        await db.posts.update_one({"id": pid}, {"$addToSet": {"reposts": u["id"]}})
        if post["user_id"] != u["id"]:
            await db.notifications.insert_one({
                "id": str(uuid.uuid4()), "user_id": post["user_id"],
                "from_user_id": u["id"], "from_user_name": u["name"], "from_user_avatar": u.get("avatar_photo"),
                "type": "repost", "post_id": pid, "created_at": now().isoformat(), "read": False,
            })
            asyncio.create_task(send_push(post["user_id"], "Repost", u["name"] + " reposted your post"))
        doc.pop("_id", None)
        return {"reposted": True, "post": doc}

    @api.post("/posts/{pid}/mention")
    async def mention_in_post(pid: str, body: dict, u=Depends(current_user)):
        mentioned_username = (body.get("username") or "").lstrip("@")
        if not mentioned_username: raise HTTPException(400, "username required")
        target = await db.users.find_one({"username": mentioned_username})
        if not target: raise HTTPException(404, "User not found")
        if target["id"] == u["id"]: return {"ok": True}
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": target["id"],
            "from_user_id": u["id"], "from_user_name": u["name"], "from_user_avatar": u.get("avatar_photo"),
            "type": "mention", "post_id": pid, "created_at": now().isoformat(), "read": False,
        })
        asyncio.create_task(send_push(target["id"], "Mention", u["name"] + " mentioned you in a post"))
        return {"ok": True}


    @api.post("/posts/{pid}/report")
    async def report_post(pid: str, body: dict, u=Depends(current_user)):
        reason = (body.get("reason") or "").strip()
        if not reason: raise HTTPException(400, "Reason required")
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Post not found")
        already = await db.reports.find_one({"post_id": pid, "reported_by": u["id"]})
        if already: return {"ok": True, "already": True}
        await db.reports.insert_one({"id": str(uuid.uuid4()), "post_id": pid, "reported_by": u["id"], "reported_user_id": post.get("user_id"), "reason": reason, "created_at": now().isoformat(), "status": "pending"})
        return {"ok": True}

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
        posts_cursor = db.posts.find({"saves": user_id}).sort("created_at", -1).limit(50)
        result = []
        async for p in posts_cursor:
            p.pop("_id", None)
            result.append(p)
        return {"posts": result}

    # ── Friends ───────────────────────────────────────────────────
    @api.post("/friends/request")
    async def friend_request(p: FriendIn, u=Depends(current_user)):
        if p.target_user_id == u["id"]: raise HTTPException(400, "Can't friend yourself")
        target = await db.users.find_one({"id": p.target_user_id})
        if not target: raise HTTPException(404, "User not found")
        if target.get("account_type") == "organisation":
            raise HTTPException(400, "You can only follow organisation accounts, not connect")
        if target.get("is_badge_verified"):
            raise HTTPException(400, "Verified public figures can only be followed, not connected")
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
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": p.target_user_id,
            "from_user_id": u["id"], "from_user_name": u["name"], "from_user_avatar": u.get("avatar_photo"),
            "type": "friend_request", "created_at": now().isoformat(), "read": False,
        })
        asyncio.create_task(send_push(p.target_user_id, "Connect request", u["name"] + " sent you a connect request"))
        return {"status": "pending"}

    @api.post("/friends/accept")
    async def friend_accept(p: FriendIn, u=Depends(current_user)):
        await db.friend_requests.update_one(
            {"from_id": p.target_user_id, "to_id": u["id"], "status": "pending"},
            {"$set": {"status": "accepted"}},
        )
        # Delete the notification from DB so it never reappears
        await db.notifications.delete_one(
            {"user_id": u["id"], "from_user_id": p.target_user_id, "type": "friend_request"}
        )
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
        friends = await db.users.find({"id": {"$in": friend_ids}}, PUBLIC_FIELDS).to_list(500)
        in_from_ids  = [r["from_id"] for r in pending_in]
        out_to_ids   = [r["to_id"]   for r in pending_out]
        in_users_list  = await db.users.find({"id": {"$in": in_from_ids}},  PUBLIC_FIELDS).to_list(500) if in_from_ids  else []
        out_users_list = await db.users.find({"id": {"$in": out_to_ids}},   PUBLIC_FIELDS).to_list(500) if out_to_ids   else []
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

                # ── typing indicator ──────────────────────────────
                elif msg_type == "typing":
                    to_uid = data.get("to_user_id", "")
                    is_t   = bool(data.get("is_typing", True))
                    if to_uid:
                        await _ws_push(to_uid, {
                            "type": "typing",
                            "from_user_id": user_id,
                            "is_typing": is_t,
                        })

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

    # ── Messages ──────────────────────────────────────────────────

    @api.post("/messages")
    async def send_message(p: MessageIn, u=Depends(current_user)):
        """Save message to DB, then push to receiver via WebSocket if online."""
        if not p.text.strip() and not p.photo_url and not p.gif_url and not p.shared_post_id and not p.shared_reel_id and not p.audio_url:
            raise HTTPException(400, "Message cannot be empty")
        recipient = await db.users.find_one({"id": p.to_user_id})
        if not recipient:
            raise HTTPException(404, "Recipient not found")
        if u["id"] in recipient.get("blocked_users", []) or p.to_user_id in u.get("blocked_users", []):
            raise HTTPException(403, "Cannot message this user")
        if recipient.get("is_badge_verified"):
            raise HTTPException(403, "Cannot message verified public figures")

        # Cross-continent rule: must follow each other or be connected friends
        same_continent = (
            (u.get("continent") or "").strip() == (recipient.get("continent") or "").strip()
            and bool(u.get("continent"))
        )
        if not same_continent:
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
            ref = await db.messages.find_one(
                {"id": p.reply_to_id},
                {"_id": 0, "text": 1, "from_name": 1, "from_id": 1, "photo_url": 1}
            )
            if ref:
                reply_to_preview = {
                    "id":       p.reply_to_id,
                    "from_name": ref.get("from_name", ""),
                    "from_id":  ref.get("from_id", ""),
                    "text":     (ref.get("text") or "")[:120],
                    "has_photo": bool(ref.get("photo_url")),
                }

        # ── Build shared-post preview ─────────────────────────────
        shared_post = None
        if p.shared_post_id:
            sp = await db.posts.find_one(
                {"id": p.shared_post_id},
                {"_id": 0, "id": 1, "content": 1, "photo_url": 1, "photo_urls": 1,
                 "user_name": 1, "user_handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1}
            )
            if sp:
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

        # ── Build shared-reel preview ─────────────────────────────
        shared_reel = None
        if p.shared_reel_id:
            sr = await db.reels.find_one(
                {"id": p.shared_reel_id},
                {"_id": 0, "id": 1, "caption": 1, "video_url": 1,
                 "user_name": 1, "user_handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1}
            )
            if sr:
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
        }
        await db.messages.insert_one(m.copy())
        m.pop("_id", None)

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
                "text": 1, "photo_url": 1, "created_at": 1, "status": 1, "from_id": 1, "mood_color": 1,
            }},
            {"$group": {
                "_id":         "$other_id",
                "last_text":   {"$first": "$text"},
                "last_photo":  {"$first": "$photo_url"},
                "last_time":   {"$first": "$created_at"},
                "last_status": {"$first": "$status"},
                "last_from":   {"$first": "$from_id"},
                "last_mood":   {"$first": "$mood_color"},
            }},
        ]
        convs      = await db.messages.aggregate(pipeline).to_list(200)
        user_ids   = [c["_id"] for c in convs]
        pub = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
               "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1,
               "is_online": 1, "last_seen": 1}
        users_list = await db.users.find({"id": {"$in": user_ids}}, pub).to_list(200)
        users_map  = {uu["id"]: uu for uu in users_list}

        async def _unread(cid: str) -> int:
            return await db.messages.count_documents({
                "from_id": cid, "to_id": u["id"],
                "status": {"$ne": "seen"},
                "deleted_for_everyone": {"$ne": True},
                "deleted_for": {"$nin": [u["id"]]},
            })

        unread_counts = await asyncio.gather(*[_unread(c["_id"]) for c in convs])
        for c, uc in zip(convs, unread_counts):
            c["user"]              = users_map.get(c["_id"], {})
            c["unread"]            = uc
            c["is_partner_online"] = c["_id"] in _ws_connections
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
        with_user: Optional[str] = None, skip: int = 0, limit: int = 50,
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
        msgs  = await db.messages.find(fq, {"_id": 0}).sort("created_at", 1).skip(skip).limit(limit).to_list(limit)
        total = await db.messages.count_documents(fq)
        return {"messages": msgs, "total": total, "skip": skip, "limit": limit}

    @api.delete("/messages/{msg_id}")
    async def delete_message(msg_id: str, delete_for: str = "self", u=Depends(current_user)):
        msg = await db.messages.find_one({"id": msg_id})
        if not msg:
            raise HTTPException(404, "Message not found")
        if delete_for == "everyone":
            if msg["from_id"] != u["id"]:
                raise HTTPException(403, "Only sender can delete for everyone")
            await db.messages.update_one(
                {"id": msg_id},
                {"$set": {"deleted_for_everyone": True, "text": "", "photo_url": None, "audio_url": None}}
            )
        else:
            await db.messages.update_one({"id": msg_id}, {"$addToSet": {"deleted_for": u["id"]}})
        return {"ok": True}

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
        unread_count = await db.notifications.count_documents({"user_id": u["id"], "read": False})
        return {"notifications": notifs, "unread_count": unread_count}

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
        await db.push_subscriptions.update_one(
            {"user_id": u["id"]},
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

    @api.delete("/notifications/{notif_id}")
    async def delete_notification(notif_id: str, u=Depends(current_user)):
        await db.notifications.delete_one({"id": notif_id, "user_id": u["id"]})
        return {"ok": True}

    @api.get("/notifications/unread-count")
    async def get_notif_unread_count(u=Depends(current_user)):
        count = await db.notifications.count_documents({"user_id": u["id"], "read": False})
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

    @api.post("/translate")
    async def translate_endpoint(body: dict):
        text         = (body.get("text") or "").strip()
        target       = body.get("target", "en")
        include_tone = body.get("tone", False)
        if not text:
            return {"translated": text, "tone_hint": None}
        tl        = TRANSLATE_LANG_MAP.get(target, target)
        cache_key = tl + "||" + text
        cached    = _cache_get(cache_key)
        if cached:
            return {"translated": cached, "tone_hint": _detect_tone_hint(text) if include_tone else None}
        translated = None
        try:
            url = (
                "https://api.mymemory.translated.world/get"
                f"?q={urllib.parse.quote(text)}&langpair=autodetect|{tl}"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "PostApp/1.0"})
            def _fetch():
                with urllib.request.urlopen(req, timeout=6) as resp:
                    return _json.loads(resp.read().decode())
            data     = await asyncio.to_thread(_fetch)
            t_result = (data.get("responseData") or {}).get("translatedText", "")
            if t_result and "MYMEMORY WARNING" not in t_result and t_result != text:
                translated = t_result
        except Exception as e:
            logging.warning(f"MyMemory translation failed: {e}")
        if not translated:
            try:
                lt_body = _json.dumps({"q": text, "source": "auto", "target": tl, "format": "text"}).encode()
                lt_req  = urllib.request.Request(
                    "https://libretranslate.com/translate", data=lt_body,
                    headers={"Content-Type": "application/json", "User-Agent": "PostApp/1.0"}, method="POST",
                )
                def _fetch_lt():
                    with urllib.request.urlopen(lt_req, timeout=6) as resp:
                        return _json.loads(resp.read().decode())
                lt_data  = await asyncio.to_thread(_fetch_lt)
                t_result = lt_data.get("translatedText", "")
                if t_result and t_result != text:
                    translated = t_result
            except Exception as e:
                logging.warning(f"LibreTranslate fallback failed: {e}")
        if not translated:
            translated = text
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
    async def admin_list_requests(status: Optional[str] = "pending", skip: int = 0, limit: int = 100, admin=Depends(_is_admin)):
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
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": uid,
            "from_user_id": admin["id"], "from_user_name": "POST Team",
            "type": "verification_approved",
            "text": f"Congratulations! Your account is now verified as '{category}'. ✅",
            "created_at": now_str, "read": False,
        })
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
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": req["user_id"],
            "from_user_id": admin["id"], "from_user_name": "POST Team",
            "type": "verification_rejected",
            "text": f"Your verification request was not approved. Reason: {p.reason}",
            "created_at": now_str, "read": False,
        })
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
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": p.user_id,
            "from_user_id": admin["id"], "from_user_name": "POST Team",
            "type": "verification_approved",
            "text": f"Congratulations! Your account is now verified as '{p.category}'. ✅",
            "created_at": now_str, "read": False,
        })
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
    async def admin_list_users(q: Optional[str] = None, skip: int = 0, limit: int = 50, admin=Depends(_is_admin)):
        query: dict = {}
        if q:
            query["$or"] = [
                {"name": {"$regex": q, "$options": "i"}},
                {"username": {"$regex": q, "$options": "i"}},
                {"email": {"$regex": q, "$options": "i"}},
            ]
        users_list = await db.users.find(query, {"_id": 0, "password_hash": 0, "otp_hash": 0}).skip(skip).limit(limit).to_list(limit)
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
            (db.follow_requests, [("from_id", 1), ("to_id", 1)], {"background": True}),
            (db.follow_requests, "status", {"background": True}),
            (db.friend_requests, [("from_id", 1), ("to_id", 1)], {"background": True}),
            (db.friend_requests, "status", {"background": True}),
            (db.email_otps, "email", {"background": True}),
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
        ]
        ok_count = 0
        for collection, keys, options in index_specs:
            try:
                await collection.create_index(keys, **options)
                ok_count += 1
            except Exception as e:
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
                "notifications_prefs": {"likes": True, "comments": True, "friend_requests": True, "messages": True},
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
    _NEWS_NATIVE = {
        "top": "general", "business": "business", "technology": "technology",
        "sports": "sports", "health": "health", "science": "science",
        "entertainment": "entertainment",
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

    _news_cache: dict = {}
    _NEWS_CACHE_TTL = 180  # 3 minutes

    def _news_cache_get(key):
        entry = _news_cache.get(key)
        if entry and (_time.monotonic() - entry[1]) < _NEWS_CACHE_TTL:
            return entry[0]
        return None

    def _news_cache_set(key, value):
        _news_cache[key] = (value, _time.monotonic())

    async def _fetch_news_articles(category: str, country: Optional[str], page_size: int = 20) -> list:
        if not NEWS_API_KEY:
            return []
        loop = asyncio.get_running_loop()
        def _do_fetch():
            cat_lower = (category or "top").lower()
            if cat_lower in _NEWS_NATIVE:
                params: dict = {
                    "apiKey": NEWS_API_KEY,
                    "category": _NEWS_NATIVE[cat_lower],
                    "pageSize": min(page_size * 3, 100),
                    "language": "en",
                }
                if country:
                    params["country"] = country.lower()[:2]
                url = "https://newsapi.org/v2/top-headlines?" + urllib.parse.urlencode(params)
            else:
                kw = _NEWS_KEYWORDS.get(cat_lower, cat_lower)
                if country:
                    kw = f"({kw}) AND {country}"
                params = {
                    "apiKey": NEWS_API_KEY,
                    "q": kw,
                    "pageSize": min(page_size * 3, 100),
                    "language": "en",
                    "sortBy": "publishedAt",
                }
                url = "https://newsapi.org/v2/everything?" + urllib.parse.urlencode(params)
            req = urllib.request.Request(url, headers={"User-Agent": "PostApp/1.0"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = _json.loads(resp.read())
            return data.get("articles", [])
        try:
            articles = await loop.run_in_executor(None, _do_fetch)
            filtered = [
                a for a in articles
                if a.get("urlToImage") and a.get("title") and "[Removed]" not in a.get("title", "")
            ]
            return filtered[:page_size]
        except Exception as e:
            logging.warning(f"[News] fetch failed: {e}")
            return []

    @api.get("/world/news")
    async def world_news(
        category: str = "top",
        country: Optional[str] = None,
        u=Depends(current_user),
    ):
        cache_key = f"news:{(category or 'top').lower()}:{(country or 'world').lower()}"
        cached = _news_cache_get(cache_key)
        if cached:
            return cached
        articles = await _fetch_news_articles(category, country, page_size=20)
        result = {
            "articles": [
                {
                    "title": a.get("title", ""),
                    "description": a.get("description") or "",
                    "url": a.get("url", ""),
                    "image": a.get("urlToImage", ""),
                    "source": (a.get("source") or {}).get("name", "Unknown"),
                    "published_at": a.get("publishedAt", ""),
                }
                for a in articles
            ],
            "category": category,
            "country": country,
            "no_key": not bool(NEWS_API_KEY),
        }
        _news_cache_set(cache_key, result)
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
        skip: int = 0,
        limit: int = 20,
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
        doc = {
            "id": str(uuid.uuid4()),
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
            "photo_url": p.photo_url or None,
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

    @api.post("/reels/upload")
    async def upload_reel_video(
        file: UploadFile = File(...),
        u=Depends(current_user),
    ):
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET) and not CLOUDINARY_URL:
            raise HTTPException(500, "Video hosting is not configured on the server")
        if not file.content_type or not file.content_type.startswith("video/"):
            raise HTTPException(400, "Please upload a valid video file")
        raw = await file.read()
        if len(raw) > MAX_UPLOAD_VIDEO_BYTES:
            raise HTTPException(400, "Video is too large. Max 100 MB.")
        try:
            result = cloudinary.uploader.upload(
                raw,
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
        caption        = (body.get("caption") or "").strip()
        audio_label    = (body.get("audio_label") or "Original Audio").strip()
        duration       = int(body.get("duration") or 0)
        location       = (body.get("location") or "").strip() or None
        tagged_users   = [h.lstrip("@") for h in (body.get("tagged_users") or []) if h][:20]
        audience       = (body.get("audience") or "public").strip()
        audience_users = [h.lstrip("@") for h in (body.get("audience_users") or []) if h][:100]
        sticker_overlays = [{"id": s["id"], "url": s["url"], "xPct": float(s.get("xPct", 50)), "yPct": float(s.get("yPct", 50))} for s in (body.get("sticker_overlays") or []) if s.get("url")][:10]
        if audience not in ("public", "friends", "only_show", "only_me"):
            audience = "public"
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
            "caption":           caption,
            "audio_label":       audio_label,
            "duration":          duration if not is_photo_reel else 0,
            "location":          location,
            "tagged_users":      tagged_users,
            "audience":          audience,
            "audience_users":    audience_users if audience == "only_show" else [],
            "likes":             [],
            "saves":             [],
            "comments":          [],
            "comment_count":     0,
            "view_count":        0,
            "created_at":        now().isoformat(),
            "sticker_overlays":  sticker_overlays,
        }
        await db.reels.insert_one(doc.copy())
        doc.pop("_id", None)
        doc["is_liked"]     = False
        doc["like_count"]   = 0
        doc["is_saved"]     = False
        doc["is_following"] = False
        return doc

    @api.get("/reels")
    async def list_reels(skip: int = 0, limit: int = 10, u=Depends(current_user)):
        blocked  = u.get("blocked", [])
        muted    = u.get("muted", [])
        excluded = list(set(blocked + muted))
        query: dict = {}
        if excluded:
            query["user_id"] = {"$nin": excluded}
        reels_list = await db.reels.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
        following_ids = set(u.get("following", []))
        for r in reels_list:
            likes = r.get("likes", [])
            saves = r.get("saves", [])
            r["is_liked"]     = u["id"] in likes
            r["like_count"]   = len(likes)
            r["is_saved"]     = u["id"] in saves
            r["is_following"] = r["user_id"] in following_ids or r["user_id"] == u["id"]
            r.pop("likes", None)
            r.pop("saves", None)
            r.pop("comments", None)
        return {"reels": reels_list, "has_more": len(reels_list) == limit, "skip": skip, "limit": limit}

    @api.post("/reels/{reel_id}/like")
    async def like_reel(reel_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"likes": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        if u["id"] in reel.get("likes", []):
            await db.reels.update_one({"id": reel_id}, {"$pull": {"likes": u["id"]}})
            return {"liked": False}
        await db.reels.update_one({"id": reel_id}, {"$addToSet": {"likes": u["id"]}})
        return {"liked": True}

    @api.post("/reels/{reel_id}/save")
    async def save_reel(reel_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"saves": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        if u["id"] in reel.get("saves", []):
            await db.reels.update_one({"id": reel_id}, {"$pull": {"saves": u["id"]}})
            return {"saved": False}
        await db.reels.update_one({"id": reel_id}, {"$addToSet": {"saves": u["id"]}})
        return {"saved": True}

    @api.get("/reels/{reel_id}/comments")
    async def get_reel_comments(reel_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"comments": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        return {"comments": reel.get("comments", [])}

    @api.post("/reels/{reel_id}/comments")
    async def add_reel_comment(reel_id: str, body: dict, u=Depends(current_user)):
        text = (body.get("text") or "").strip()
        if not text:
            raise HTTPException(400, "Empty comment")
        comment = {
            "id":            str(uuid.uuid4()),
            "user_id":       u["id"],
            "user_name":     u["name"],
            "user_handle":   u["handle"],
            "avatar_bg":     u["avatar_bg"],
            "avatar_letter": u["avatar_letter"],
            "avatar_photo":  u.get("avatar_photo"),
            "text":          text,
            "created_at":    now().isoformat(),
        }
        await db.reels.update_one(
            {"id": reel_id},
            {"$push": {"comments": comment}, "$inc": {"comment_count": 1}}
        )
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
        return {"ok": True}

    @api.delete("/reels/{reel_id}")
    async def delete_reel(reel_id: str, u=Depends(current_user)):
        reel = await db.reels.find_one({"id": reel_id}, {"user_id": 1, "_id": 0})
        if not reel:
            raise HTTPException(404, "Reel not found")
        if reel["user_id"] != u["id"] and not u.get("is_admin"):
            raise HTTPException(403, "Not your reel")
        await db.reels.delete_one({"id": reel_id})
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

    @api.post("/groups")
    async def create_group(p: GroupIn, u=Depends(current_user)):
        name = p.name.strip()
        if not name:
            raise HTTPException(400, "Group name required")
        members = list(set([u["id"]] + p.member_ids))
        doc = {
            "id": str(uuid.uuid4()),
            "name": name,
            "avatar_color": p.avatar_color or "#FFD600",
            "avatar_letter": name[0].upper(),
            "avatar_photo": p.avatar_photo or None,
            "creator_id": u["id"],
            "admins": [u["id"]],
            "members": members,
            "created_at": now().isoformat(),
            "last_message": None,
            "last_message_at": now().isoformat(),
        }
        await db.groups.insert_one(doc.copy())
        doc.pop("_id", None)
        return doc

    @api.get("/groups")
    async def list_groups(u=Depends(current_user)):
        grps = await db.groups.find({"members": u["id"]}, {"_id": 0}).sort("last_message_at", -1).to_list(100)
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
        g = await db.groups.find_one({"id": group_id}, {"_id": 0})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []): raise HTTPException(403, "Not a member")
        member_docs = await db.users.find(
            {"id": {"$in": g["members"]}},
            {"_id": 0, "id": 1, "name": 1, "handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1, "is_online": 1}
        ).to_list(200)
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
        raw = await file.read()
        if len(raw) > 10 * 1024 * 1024:
            raise HTTPException(400, "Image too large. Max 10MB.")
        try:
            result = cloudinary.uploader.upload(
                raw, resource_type="image",
                folder="post-app/group-avatars",
                public_id=f"group_{group_id}_{uuid.uuid4().hex}",
                overwrite=False,
            )
        except Exception:
            logging.exception("Group avatar upload failed")
            raise HTTPException(502, "Image upload failed. Please try again.")
        photo_url = result.get("secure_url")
        await db.groups.update_one({"id": group_id}, {"$set": {"avatar_photo": photo_url}})
        return {"ok": True, "avatar_photo": photo_url}

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
        if "avatar_photo" in body: upd["avatar_photo"] = body["avatar_photo"]
        if upd: await db.groups.update_one({"id": group_id}, {"$set": upd})
        return {"ok": True}

    @api.post("/groups/{group_id}/members")
    async def add_group_member(group_id: str, body: dict, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "admins": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("admins", []): raise HTTPException(403, "Only admins can add members")
        new_uid = body.get("user_id")
        if not new_uid: raise HTTPException(400, "user_id required")
        await db.groups.update_one({"id": group_id}, {"$addToSet": {"members": new_uid}})
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
    async def get_group_messages(group_id: str, skip: int = 0, limit: int = 40, u=Depends(current_user)):
        g = await db.groups.find_one({"id": group_id}, {"_id": 0, "members": 1})
        if not g: raise HTTPException(404, "Group not found")
        if u["id"] not in g.get("members", []): raise HTTPException(403, "Not a member")
        msgs = await db.group_messages.find(
            {"group_id": group_id, "deleted_for": {"$ne": u["id"]}}, {"_id": 0}
        ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
        msgs.reverse()
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
        if not p.text.strip() and not p.photo_url and not p.gif_url and not p.shared_post_id and not p.shared_reel_id and not p.audio_url:
            raise HTTPException(400, "Message cannot be empty")
        reply_to_preview = None
        if p.reply_to_id:
            ref = await db.group_messages.find_one({"id": p.reply_to_id}, {"_id": 0, "text": 1, "from_name": 1, "from_id": 1, "photo_url": 1})
            if ref:
                reply_to_preview = {"id": p.reply_to_id, "from_name": ref.get("from_name",""), "from_id": ref.get("from_id",""), "text": (ref.get("text") or "")[:120], "has_photo": bool(ref.get("photo_url"))}
        shared_post = None
        if p.shared_post_id:
            sp = await db.posts.find_one({"id": p.shared_post_id}, {"_id": 0, "id": 1, "content": 1, "photo_url": 1, "photo_urls": 1, "user_name": 1, "user_handle": 1, "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1})
            if sp:
                shared_post = {"id": sp["id"], "content": (sp.get("content") or "")[:200], "photo_url": sp.get("photo_url") or ((sp.get("photo_urls") or [None])[0]), "user_name": sp.get("user_name",""), "user_handle": sp.get("user_handle",""), "avatar_bg": sp.get("avatar_bg",""), "avatar_letter": sp.get("avatar_letter",""), "avatar_photo": sp.get("avatar_photo"), "type": "post"}
        doc = {
            "id": str(uuid.uuid4()), "group_id": group_id,
            "from_id": u["id"], "from_name": u["name"], "from_handle": u["handle"],
            "from_avatar_bg": u["avatar_bg"], "from_avatar_letter": u["avatar_letter"], "from_avatar_photo": u.get("avatar_photo"),
            "text": p.text.strip(), "photo_url": p.photo_url, "gif_url": p.gif_url or None,
            "audio_url": p.audio_url or None, "audio_duration": p.audio_duration or None,
            "reply_to_preview": reply_to_preview, "shared_post": shared_post,
            "seen_by": [u["id"]], "reactions": {}, "deleted_for": [], "created_at": now().isoformat(),
        }
        await db.group_messages.insert_one(doc.copy())
        doc.pop("_id", None)
        last_text = p.text.strip() or ("🎤 Voice" if p.audio_url else ("📷 Photo" if p.photo_url else ("GIF" if p.gif_url else ("📎 Post" if p.shared_post_id else ""))))
        await db.groups.update_one({"id": group_id}, {"$set": {"last_message": last_text, "last_message_at": now().isoformat(), "last_from_name": u["name"]}})
        for mid in [m for m in g.get("members", []) if m != u["id"]]:
            await db.notifications.insert_one({"id": str(uuid.uuid4()), "user_id": mid, "type": "group_message", "from_id": u["id"], "from_name": u["name"], "group_id": group_id, "group_name": g.get("name","Group"), "message": last_text[:80], "read": False, "created_at": now().isoformat()})
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
        frontend_url = os.environ.get("FRONTEND_URL", "https://post-app-frontend.onrender.com")
        return {"invite_code": invite_code, "invite_link": f"{frontend_url}?join={invite_code}"}

    @api.post("/groups/join")
    async def join_group_via_invite(body: dict, u=Depends(current_user)):
        invite_code = (body.get("invite_code") or "").strip().upper()
        if not invite_code: raise HTTPException(400, "invite_code required")
        g = await db.groups.find_one({"invite_code": invite_code}, {"_id": 0})
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
        msg = await db.group_messages.find_one({"id": msg_id, "group_id": group_id})
        if not msg: raise HTTPException(404, "Message not found")
        if body.get("delete_for") == "everyone" and msg["from_id"] == u["id"]:
            await db.group_messages.update_one({"id": msg_id}, {"$set": {"deleted_for_everyone": True, "text": "", "photo_url": None, "audio_url": None}})
        else:
            await db.group_messages.update_one({"id": msg_id}, {"$addToSet": {"deleted_for": u["id"]}})
        return {"ok": True}

    # ── Call Signaling (WebRTC polling) ───────────────────────────
    _call_state: dict = {}

    @api.get("/calls/ice-servers")
    async def get_ice_servers(u=Depends(current_user)):
        import urllib.request, json as _json
        api_key = os.environ.get("METERED_API_KEY", "")
        if not api_key:
            # fallback to Google STUN only
            return {"iceServers": [{"urls": "stun:stun.l.google.com:19302"}]}
        try:
            url = f"https://post.metered.live/api/v1/turn/credentials?apiKey={api_key}"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = _json.loads(resp.read().decode())
            return {"iceServers": data}
        except Exception:
            return {"iceServers": [{"urls": "stun:stun.l.google.com:19302"}]}



    @api.post("/calls/initiate")
    async def initiate_call(body: dict, u=Depends(current_user)):
        to_user_id = body.get("to_user_id")
        call_type = body.get("call_type", "voice")
        group_id = body.get("group_id")
        if not to_user_id and not group_id: raise HTTPException(400, "to_user_id or group_id required")
        call_id = str(uuid.uuid4())
        _call_state[call_id] = {"id": call_id, "from_id": u["id"], "from_name": u["name"], "from_avatar_bg": u["avatar_bg"], "from_avatar_letter": u["avatar_letter"], "from_avatar_photo": u.get("avatar_photo"), "to_user_id": to_user_id, "group_id": group_id, "call_type": call_type, "status": "ringing", "signals": [], "created_at": now().isoformat(), "ended_at": None}
        return {"call_id": call_id, "status": "ringing"}

    @api.get("/calls/{call_id}")
    async def get_call_state(call_id: str, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        return call

    @api.post("/calls/{call_id}/signal")
    async def add_call_signal(call_id: str, body: dict, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        call["signals"].append({"from_id": u["id"], "type": body.get("type"), "data": body.get("data"), "ts": now().isoformat()})
        if len(call["signals"]) > 200: call["signals"] = call["signals"][-200:]
        return {"ok": True}

    @api.get("/calls/{call_id}/signals")
    async def get_call_signals(call_id: str, since: int = 0, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        my_signals = [s for s in call["signals"][since:] if s["from_id"] != u["id"]]
        return {"signals": my_signals, "total": len(call["signals"])}

    @api.post("/calls/{call_id}/answer")
    async def answer_call(call_id: str, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        call["status"] = "active"
        return {"ok": True}

    @api.post("/calls/{call_id}/end")
    async def end_call(call_id: str, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        call["status"] = "ended"
        call["ended_at"] = now().isoformat()
        return {"ok": True}

    @api.post("/calls/{call_id}/decline")
    async def decline_call(call_id: str, u=Depends(current_user)):
        call = _call_state.get(call_id)
        if not call: raise HTTPException(404, "Call not found")
        call["status"] = "declined"
        return {"ok": True}

    @api.get("/calls/incoming/check")
    async def check_incoming_call(u=Depends(current_user)):
        for call_id, call in list(_call_state.items()):
            if call["to_user_id"] == u["id"] and call["status"] == "ringing":
                age = (now() - datetime.fromisoformat(call["created_at"])).total_seconds()
                if age > 60: call["status"] = "ended"
                else: return {"call": call}
        return {"call": None}


    # ── GIF proxy (Giphy) ─────────────────────────────────────────────────────
    @api.get("/gifs")
    async def gif_proxy(q: str = "", limit: int = 30):
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
    async def sticker_proxy(q: str = "", limit: int = 30):
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

    # Register all routes
    app.include_router(api)

    print("==> [DIAG] server.py loaded OK — app is ready", file=_sys.stderr, flush=True)

except Exception as _boot_err:
    print(f"==> [DIAG] FATAL BOOT ERROR: {type(_boot_err).__name__}: {_boot_err}", file=_sys.stderr, flush=True)
    _tb.print_exc(file=_sys.stderr)
    _sys.exit(1)

