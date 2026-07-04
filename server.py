import sys as _sys
import traceback as _tb

print('==> [DIAG] server.py starting load...', file=_sys.stderr, flush=True)

try:
    from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Query, Request
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
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
    TWILIO_SID     = os.environ.get("TWILIO_SID", "").strip()
    TWILIO_TOKEN   = os.environ.get("TWILIO_TOKEN", "").strip()
    TWILIO_PHONE   = os.environ.get("TWILIO_PHONE", "").strip()

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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], allow_credentials=True,
        allow_methods=["*"], allow_headers=["*"],
    )
    logging.basicConfig(level=logging.INFO)

    def now():
        return datetime.now(timezone.utc)

    # ── Password hashing (PBKDF2-HMAC-SHA256) ────────────────────
    _PBKDF2_ITER   = 100_000
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
                    iters  = int(parts[2])
                    salt, stored = parts[3], parts[4]
                else:
                    # Legacy format: ["", "pbkdf2", salt, digest] — always 260k
                    iters  = _PBKDF2_ITER_LEGACY
                    salt, stored = parts[2], parts[3]
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
            logging.info(f"[DEMO] SMS OTP for {phone}: {code}")
            return False
        try:
            from twilio.rest import Client
            twilio = Client(TWILIO_SID, TWILIO_TOKEN)
            twilio.messages.create(
                body=f"POST App verification code: {code}\nValid for 10 minutes.",
                from_=TWILIO_PHONE,
                to=phone,
            )
            logging.info(f"SMS sent to {phone}")
            return True
        except Exception as e:
            logging.warning(f"SMS failed: {e}")
            return False

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

    class CommentIn(BaseModel):
        text: str

    class LikeIn(BaseModel):
        color: Optional[str] = None

    class MessageIn(BaseModel):
        to_user_id: str; text: str = ""
        photo_url: Optional[str] = None; mood_color: Optional[str] = None

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
        u = await db.users.find_one({"email": p.email})
        if not u: raise HTTPException(400, "Invalid credentials")
        pw_hash = u.get("password_hash", "")
        if not await verifypw(p.password, pw_hash): raise HTTPException(400, "Invalid credentials")
        if not u.get("is_verified"): raise HTTPException(400, "Account not verified")
        if _is_bcrypt(pw_hash) or (pw_hash.startswith(_PBKDF2_PREFIX) and len(pw_hash.split("$")) == 4):
            asyncio.create_task(_migrate_hash(u["id"], p.password))  # upgrade legacy 260k → 100k
        asyncio.create_task(_migrate_prefs_defaults(u))  # background — don't block login
        resp = {"token": make_token(u["id"]), "user_id": u["id"]}
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
        user = await db.users.find_one({"$or": [{"email": identifier}, {"phone": identifier}]})
        if not user or not user.get("is_verified"):
            raise HTTPException(400, "No account found with this email or phone number")
        code = f"{random.randint(0,9999):04d}"
        await db.reset_otps.update_one(
            {"identifier": identifier},
            {"$set": {
                "identifier": identifier, "user_id": user["id"],
                "otp_hash": await hashpw(code),
                "otp_expires_at": now() + timedelta(minutes=10), "verified": False,
            }},
            upsert=True,
        )
        is_email = "@" in identifier
        if is_email:
            # Await email send so we can detect failure and surface OTP as fallback
            email_sent = await run_in_bg(send_otp_email, identifier, code)
            fallback_otp = code if not email_sent else None
            return {"message": "OTP sent", "demo_otp": fallback_otp, "method": "email",
                    "email_failed": not bool(email_sent)}
        else:
            sms_sent = await run_in_bg(send_otp_sms, identifier, code)
            return {"message": "OTP sent", "demo_otp": code if not sms_sent else None, "method": "sms"}

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
        sms_sent = await run_in_bg(send_otp_sms, p.phone, code)
        demo = code if not sms_sent else None
        if demo: await db.phone_otps.update_one({"phone": p.phone}, {"$set": {"_plain": demo}})
        return {"message": "OTP sent", "demo_otp": demo}

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
        u = await db.users.find_one({"phone": p.phone})
        pw_hash_p = u.get("password_hash", "") if u else ""
        if not u or not await verifypw(p.password, pw_hash_p):
            raise HTTPException(400, "Invalid phone or password")
        if u and (_is_bcrypt(pw_hash_p) or (pw_hash_p.startswith(_PBKDF2_PREFIX) and len(pw_hash_p.split("$")) == 4)):
            asyncio.create_task(_migrate_hash(u["id"], p.password))  # upgrade legacy 260k → 100k
        if not u.get("is_verified"): raise HTTPException(400, "Account not verified")
        asyncio.create_task(_migrate_prefs_defaults(u))  # background — don't block login
        resp = {"token": make_token(u["id"]), "user_id": u["id"]}
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
        sms_sent = await run_in_bg(send_otp_sms, p.phone, code)
        demo = code if not sms_sent else None
        if demo: await db.phone_otps.update_one({"phone": p.phone}, {"$set": {"_plain": demo}})
        return {"message": "OTP sent", "demo_otp": demo}

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
                "from_user_id": u["id"], "from_user_name": u["name"],
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
            "from_user_id": u["id"], "from_user_name": u["name"],
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
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": user_id,
            "from_user_id": u["id"], "from_user_name": u["name"],
            "type": "follow_accept", "created_at": now().isoformat(), "read": False,
        })
        asyncio.create_task(send_push(user_id, "Follow accepted", u["name"] + " accepted your follow request"))
        return {"ok": True}

    @api.post("/users/{user_id}/follow-request/decline")
    async def decline_follow_request(user_id: str, u=Depends(current_user)):
        await db.follow_requests.delete_one({"from_id": user_id, "to_id": u["id"]})
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

    # ── Posts ─────────────────────────────────────────────────────
    @api.post("/posts")
    async def create_post(p: PostIn, u=Depends(current_user)):
        doc = {
            "id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"],
            "user_handle": u["handle"], "avatar_bg": u["avatar_bg"],
            "avatar_letter": u["avatar_letter"], "avatar_photo": u.get("avatar_photo"),
            "content": p.content, "accent": p.accent, "location": p.location or "",
            "photo_url": p.photo_url or None,
            "user_location": u.get("location", ""),
            "likes": [], "comments": [], "views": [], "saves": [], "reposts": [],
            "created_at": now().isoformat(), "edited_at": None, "is_pinned": False,
        }
        await db.posts.insert_one(doc.copy())
        doc.pop("_id", None)
        return doc

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
            follower_query = (
                db.users.find(
                    {"id": {"$in": followers_ids},
                     "$or": [{"is_private": {"$ne": True}}, {"id": {"$in": can_see_list}}]},
                    {"id": 1, "_id": 0},
                ).to_list(None)
                if followers_ids else asyncio.coroutine(lambda: [])()
            )
            verified_query = db.users.find(
                {"is_badge_verified": True,
                 "$or": [{"is_private": {"$ne": True}}, {"id": {"$in": can_see_list}}]},
                {"id": 1, "_id": 0},
            ).to_list(None)
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
        posts = await db.posts.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
        unviewed_ids = [p["id"] for p in posts if u["id"] not in p.get("views", [])]
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
        upd = {"content": p.content, "accent": p.accent, "location": p.location or "", "edited_at": now().isoformat()}
        if p.photo_url is not None: upd["photo_url"] = p.photo_url
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
                "from_user_id": u["id"], "from_user_name": u["name"],
                "type": "like", "post_id": pid, "created_at": now().isoformat(), "read": False,
            })
            asyncio.create_task(send_push(post["user_id"], "New like ♥️", u["name"] + " liked your post"))
        return {"likes": likes, "total": len(likes)}

    @api.post("/posts/{pid}/comments")
    async def add_comment(pid: str, p: CommentIn, u=Depends(current_user)):
        post = await db.posts.find_one({"id": pid})
        if not post: raise HTTPException(404, "Post not found")
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
                "from_user_id": u["id"], "from_user_name": u["name"],
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
            "location": "", "photo_url": post.get("photo_url"),
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
                "from_user_id": u["id"], "from_user_name": u["name"],
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
            "from_user_id": u["id"], "from_user_name": u["name"],
            "type": "mention", "post_id": pid, "created_at": now().isoformat(), "read": False,
        })
        asyncio.create_task(send_push(target["id"], "Mention", u["name"] + " mentioned you in a post"))
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
            "from_user_id": u["id"], "from_user_name": u["name"],
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
        return {"ok": True}

    @api.post("/friends/decline")
    async def friend_decline(p: FriendIn, u=Depends(current_user)):
        await db.friend_requests.delete_one({"from_id": p.target_user_id, "to_id": u["id"]})
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

    # ── Messages ──────────────────────────────────────────────────
    _typing_state: dict = {}

    @api.post("/messages")
    async def send_message(p: MessageIn, u=Depends(current_user)):
        if not p.text.strip() and not p.photo_url:
            raise HTTPException(400, "Message cannot be empty")
        recipient = await db.users.find_one({"id": p.to_user_id})
        if not recipient: raise HTTPException(404, "Recipient not found")
        if u["id"] in recipient.get("blocked_users", []) or p.to_user_id in u.get("blocked_users", []):
            raise HTTPException(403, "Cannot message this user")
        if recipient.get("is_badge_verified"):
            raise HTTPException(403, "Cannot message verified public figures")
        same_continent = (
            (u.get("continent") or "").strip() == (recipient.get("continent") or "").strip()
            and bool(u.get("continent"))
        )
        if not same_continent:
            fr = await db.friend_requests.find_one({
                "status": "accepted",
                "$or": [
                    {"from_id": u["id"], "to_id": p.to_user_id},
                    {"from_id": p.to_user_id, "to_id": u["id"]},
                ],
            })
            if not fr:
                raise HTTPException(403, "Connect with this user first to message across countries")
        is_silent    = False
        recv_tz_offset = recipient.get("timezone_offset")
        if recv_tz_offset is not None:
            try:
                recv_hour = (now() + timedelta(hours=float(recv_tz_offset))).hour
                is_silent = (recv_hour >= 23 or recv_hour < 6)
            except Exception:
                pass
        m = {
            "id": str(uuid.uuid4()), "from_id": u["id"], "from_name": u["name"],
            "to_id": p.to_user_id, "text": p.text, "photo_url": p.photo_url,
            "mood_color": p.mood_color, "created_at": now().isoformat(),
            "status": "sent", "deleted_for": [], "deleted_for_everyone": False, "is_silent": is_silent,
        }
        await db.messages.insert_one(m.copy())
        m.pop("_id", None)
        return m

    @api.get("/messages/conversations")
    async def get_conversations(u=Depends(current_user)):
        pipeline = [
            {"$match": {"$or": [{"from_id": u["id"]}, {"to_id": u["id"]}], "deleted_for_everyone": {"$ne": True}}},
            {"$sort": {"created_at": -1}},
            {"$project": {
                "_id": 0,
                "other_id": {"$cond": [{"$eq": ["$from_id", u["id"]]}, "$to_id", "$from_id"]},
                "text": 1, "photo_url": 1, "created_at": 1, "status": 1, "from_id": 1, "mood_color": 1,
            }},
            {"$group": {
                "_id": "$other_id",
                "last_text":   {"$first": "$text"},
                "last_photo":  {"$first": "$photo_url"},
                "last_time":   {"$first": "$created_at"},
                "last_status": {"$first": "$status"},
                "last_from":   {"$first": "$from_id"},
                "last_mood":   {"$first": "$mood_color"},
            }},
        ]
        convs     = await db.messages.aggregate(pipeline).to_list(200)
        user_ids  = [c["_id"] for c in convs]
        pub = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
               "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1,
               "is_online": 1, "last_seen": 1}
        users_list = await db.users.find({"id": {"$in": user_ids}}, pub).to_list(200)
        users_map  = {uu["id"]: uu for uu in users_list}
        async def _unread(cid):
            return await db.messages.count_documents({
                "from_id": cid, "to_id": u["id"],
                "status": {"$ne": "seen"}, "deleted_for_everyone": {"$ne": True},
            })
        unread_counts = await asyncio.gather(*[_unread(c["_id"]) for c in convs])
        for c, uc in zip(convs, unread_counts):
            c["user"]   = users_map.get(c["_id"], {})
            c["unread"] = uc
        convs.sort(key=lambda x: x.get("last_time", ""), reverse=True)
        return {"conversations": convs}

    @api.get("/messages/typing")
    async def get_typing(with_user: str, u=Depends(current_user)):
        expires = _typing_state.get(with_user, {}).get(u["id"])
        if expires and now() < expires:
            return {"is_typing": True}
        return {"is_typing": False}

    @api.get("/messages/unread-count")
    async def get_msg_unread_count(u=Depends(current_user)):
        count = await db.messages.count_documents({
            "to_id": u["id"], "status": {"$ne": "seen"}, "deleted_for_everyone": {"$ne": True},
        })
        return {"unread_count": count}

    @api.get("/messages")
    async def list_messages(
        with_user: Optional[str] = None, skip: int = 0, limit: int = 50,
        u=Depends(current_user),
    ):
        if with_user:
            q = {"$or": [{"from_id": u["id"], "to_id": with_user}, {"from_id": with_user, "to_id": u["id"]}]}
        else:
            q = {"$or": [{"from_id": u["id"]}, {"to_id": u["id"]}]}
        msgs  = await db.messages.find(q, {"_id": 0}).sort("created_at", 1).skip(skip).limit(limit).to_list(limit)
        total = await db.messages.count_documents(q)
        if with_user:
            await db.messages.update_many(
                {"from_id": with_user, "to_id": u["id"], "status": "sent"},
                {"$set": {"status": "delivered"}},
            )
        msgs = [m for m in msgs if u["id"] not in m.get("deleted_for", []) and not m.get("deleted_for_everyone")]
        return {"messages": msgs, "total": total, "skip": skip, "limit": limit}

    @api.post("/messages/{msg_id}/seen")
    async def mark_message_seen(msg_id: str, u=Depends(current_user)):
        await db.messages.update_one(
            {"id": msg_id, "to_id": u["id"]},
            {"$set": {"status": "seen", "seen_at": now().isoformat()}},
        )
        return {"ok": True}

    @api.delete("/messages/{msg_id}")
    async def delete_message(msg_id: str, delete_for: str = "self", u=Depends(current_user)):
        msg = await db.messages.find_one({"id": msg_id})
        if not msg: raise HTTPException(404, "Message not found")
        if delete_for == "everyone":
            if msg["from_id"] != u["id"]: raise HTTPException(403, "Only sender can delete for everyone")
            await db.messages.update_one(
                {"id": msg_id},
                {"$set": {"deleted_for_everyone": True, "text": "", "photo_url": None}},
            )
        else:
            await db.messages.update_one({"id": msg_id}, {"$addToSet": {"deleted_for": u["id"]}})
        return {"ok": True}

    @api.post("/messages/typing")
    async def set_typing(p: TypingIn, u=Depends(current_user)):
        if u["id"] not in _typing_state:
            _typing_state[u["id"]] = {}
        if p.is_typing:
            _typing_state[u["id"]][p.to_user_id] = now() + timedelta(seconds=3)
        else:
            _typing_state[u["id"]].pop(p.to_user_id, None)
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

    # ── Health ────────────────────────────────────────────────────
    @api.get("/")
    async def root():
        return {"status": "ok", "demo_mode": DEMO_MODE, "twilio": bool(TWILIO_SID), "version": "5.0"}

    # ── Startup: indexes ──────────────────────────────────────────
    @app.on_event("startup")
    async def create_indexes():
        try:
            await db.users.create_index("id", unique=True, background=True)
            await db.users.create_index("username", background=True)
            await db.users.create_index("email", background=True)
            await db.users.create_index("phone", background=True)
            await db.users.create_index("handle", background=True)
            await db.posts.create_index("user_id", background=True)
            await db.posts.create_index([("created_at", -1)], background=True)
            await db.posts.create_index("id", unique=True, background=True)
            await db.messages.create_index([("from_id", 1), ("to_id", 1)], background=True)
            await db.messages.create_index([("created_at", 1)], background=True)
            await db.notifications.create_index("user_id", background=True)
            await db.notifications.create_index([("created_at", -1)], background=True)
            await db.follow_requests.create_index([("from_id", 1), ("to_id", 1)], background=True)
            await db.follow_requests.create_index("status", background=True)
            await db.friend_requests.create_index([("from_id", 1), ("to_id", 1)], background=True)
            await db.friend_requests.create_index("status", background=True)
            await db.email_otps.create_index("email", background=True)
            await db.phone_otps.create_index("phone", background=True)
            await db.account_deletions.create_index("identifier", background=True)
            # Feed query indexes
            await db.users.create_index("is_badge_verified", background=True)
            await db.users.create_index("is_private", background=True)
            await db.users.create_index("followers", background=True)
            logging.info("✅ MongoDB indexes created")
        except Exception as e:
            logging.warning(f"Index creation warning: {e}")

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
    @app.on_event("startup")
    async def keepalive_self_ping():
        async def _ping_loop():
            await asyncio.sleep(30)  # Let server fully boot first
            port = os.environ.get("PORT", "10000")
            ping_url = f"http://127.0.0.1:{port}/api/ping"
            logging.info(f"[KeepAlive] Self-ping started → {ping_url} every 4 min")
            import urllib.request as _ur2
            def _do_ping():
                with _ur2.urlopen(ping_url, timeout=10):
                    pass
            loop = asyncio.get_event_loop()
            while True:
                try:
                    # run_in_executor so urllib (sync) never blocks the async event loop
                    await loop.run_in_executor(None, _do_ping)
                    logging.info("[KeepAlive] ✅ Self-ping OK — server awake")
                except Exception as _pe:
                    logging.warning(f"[KeepAlive] ⚠️ Self-ping failed: {_pe}")
                await asyncio.sleep(4 * 60)   # every 4 minutes — keeps Render free tier awake
        asyncio.create_task(_ping_loop())

    # ── Shutdown ──────────────────────────────────────────────────
    @app.on_event("shutdown")
    async def shutdown():
        client.close()

    # ── Health / keep-alive ping ─────────────────────────────────
    @api.get("/ping")
    async def ping():
        return {"ok": True}

    # Register all routes
    app.include_router(api)

    print("==> [DIAG] server.py loaded OK — app is ready", file=_sys.stderr, flush=True)

except Exception as _boot_err:
    print(f"==> [DIAG] FATAL BOOT ERROR: {type(_boot_err).__name__}: {_boot_err}", file=_sys.stderr, flush=True)
    _tb.print_exc(file=_sys.stderr)
    _sys.exit(1)

