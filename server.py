from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Query
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

load_dotenv()

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME   = os.environ.get("DB_NAME", "postapp")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
TWILIO_SID   = os.environ.get("TWILIO_SID", "").strip()
TWILIO_TOKEN = os.environ.get("TWILIO_TOKEN", "").strip()
TWILIO_PHONE = os.environ.get("TWILIO_PHONE", "").strip()

DEMO_MODE = not bool(RESEND_API_KEY)

DELETE_GRACE_DAYS = 30
ABUSE_WINDOW_DAYS = 90
ABUSE_MAX_DELETIONS = 3
ABUSE_COOLDOWN_DAYS = 14

client = AsyncIOMotorClient(MONGO_URL, maxPoolSize=20, minPoolSize=5, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
db = client[DB_NAME]

app = FastAPI(title="POST App API")
api = APIRouter(prefix="/api")
bearer = HTTPBearer(auto_error=False)

app.add_middleware(GZipMiddleware, minimum_size=500)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
logging.basicConfig(level=logging.INFO)

def now(): return datetime.now(timezone.utc)
import hashlib as _hl, hmac as _hmac, os as _os

async def _run_sync(fn):
    """Run a sync callable in thread pool — keeps event loop free."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, fn)

async def run_in_bg(fn, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, fn, *args)

# ── Fast password hashing (PBKDF2-HMAC-SHA256, ~0.3s even on slow CPU) ───────
_PBKDF2_ITER = 260_000
_PBKDF2_PREFIX = "$pbkdf2$"

def _pbkdf2_hash(password: str, salt: str) -> str:
    return _hl.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITER).hex()

async def hashpw(p: str, rounds=None) -> str:
    """Hash a password with PBKDF2 (fast, runs in thread)."""
    salt = _os.urandom(16).hex()
    digest = await _run_sync(lambda: _pbkdf2_hash(p, salt))
    return f"{_PBKDF2_PREFIX}{salt}${digest}"

async def verifypw(p: str, h: str) -> bool:
    """Verify password. Supports both PBKDF2 (new, fast) and bcrypt (legacy, slow first time)."""
    if not h:
        return False
    if h.startswith(_PBKDF2_PREFIX):
        # Fast path: PBKDF2
        try:
            parts = h.split("$")  # ["", "pbkdf2", salt, digest]
            salt, stored = parts[2], parts[3]
            computed = await _run_sync(lambda: _pbkdf2_hash(p, salt))
            return _hmac.compare_digest(computed, stored)
        except Exception:
            return False
    else:
        # Legacy bcrypt path — run in thread so event loop stays free
        try:
            return await _run_sync(lambda: bcrypt.checkpw(p.encode(), h.encode()))
        except Exception:
            return False

def _is_bcrypt(h: str) -> bool:
    return h.startswith("$2b$") or h.startswith("$2a$")
def make_token(uid):
    return jwt.encode({"sub": uid, "exp": now() + timedelta(days=30)}, JWT_SECRET, algorithm="HS256")

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")

async def raw_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    """Get user from token without secondary contact check (for add-phone/add-email flows)."""
    if not creds: raise HTTPException(401, "Missing token")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
        uid = payload["sub"]
    except: raise HTTPException(401, "Invalid token")
    u = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0, "otp_hash": 0})
    if not u: raise HTTPException(401, "User not found")
    return u

async def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    u = await raw_user(creds)
    if u.get("signup_method") == "email" and not u.get("phone_verified", True):
        raise HTTPException(403, detail={"code": "SECONDARY_REQUIRED", "type": "phone"})
    if u.get("signup_method") == "phone" and not u.get("email_verified", True):
        raise HTTPException(403, detail={"code": "SECONDARY_REQUIRED", "type": "email"})
    return u

def send_otp_email(email, code):
    if DEMO_MODE:
        logging.info(f"[DEMO] Email OTP for {email}: {code}")
        return
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
            "from": "POST App <noreply@postbluom.online>",
            "to": [email],
            "subject": "Your POST App verification code",
            "html": html_body,
            "text": plain_text,
            "reply_to": "support@postbluom.online",
            "headers": {
                "X-Entity-Ref-ID": str(uuid.uuid4()),
            },
        })
        logging.info(f"✅ OTP email sent to {email}")
    except Exception as e:
        logging.warning(f"Email failed: {e}")

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
            to=phone
        )
        logging.info(f"SMS sent to {phone}")
        return True
    except Exception as e:
        logging.warning(f"SMS failed: {e}")
        return False

async def ensure_username_unique(username: str, exclude_uid: Optional[str] = None):
    """Usernames must be unique"""
    count = await db.users.count_documents({"username": username})
    if count > 0:
        if exclude_uid:
            user = await db.users.find_one({"username": username})
            if user["id"] != exclude_uid:
                raise ValueError("Username already taken")
        else:
            raise ValueError("Username already taken")

# ── Account deletion / restore / abuse-detection helpers ───────
def _aware(dt):
    if dt and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

async def permanently_delete_user(uid: str):
    """Hard-delete a user and all their data. Used once the 30-day grace period is over."""
    await db.posts.delete_many({"user_id": uid})
    await db.messages.delete_many({"$or": [{"from_id": uid}, {"to_id": uid}]})
    await db.notifications.delete_many({"$or": [{"user_id": uid}, {"from_user_id": uid}]})
    await db.friend_requests.delete_many({"$or": [{"from_id": uid}, {"to_id": uid}]})
    await db.users.update_many({}, {"$pull": {"followers": uid, "following": uid, "blocked_users": uid}})
    await db.users.delete_one({"id": uid})

async def purge_expired_deleted_account(field: str, value: str):
    """If a user with this phone/email is soft-deleted and past the 30-day grace period, hard-delete them now."""
    user = await db.users.find_one({field: value})
    if user and user.get("deleted_at"):
        deleted_at = _aware(user["deleted_at"])
        if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
            await permanently_delete_user(user["id"])
            return True
    return False

async def check_delete_recreate_abuse(identifier: str):
    """Block repeated delete-then-recreate cycles for the same phone/email."""
    since = now() - timedelta(days=ABUSE_WINDOW_DAYS)
    count = await db.account_deletions.count_documents({"identifier": identifier, "deleted_at": {"$gte": since}})
    if count >= ABUSE_MAX_DELETIONS:
        last = await db.account_deletions.find({"identifier": identifier}).sort("deleted_at", -1).limit(1).to_list(1)
        if last:
            cooldown_until = _aware(last[0]["deleted_at"]) + timedelta(days=ABUSE_COOLDOWN_DAYS)
            if now() < cooldown_until:
                raise HTTPException(
                    429,
                    f"Too many account deletions detected for this number/email. Please try again after "
                    f"{cooldown_until.strftime('%d %b %Y')}."
                )

# ── Models ───────────────────────────────────────────────────
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
    account_type: Optional[str] = None      # personal | politician | businessman | organisation
    is_badge_verified: Optional[bool] = None  # admin-granted verified badge

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if v is None: return v
        v = v.strip().lower()
        if not USERNAME_RE.match(v):
            raise ValueError("Username: 3-20 chars, only lowercase letters, numbers, underscore")
        return v

class AddPhoneInitIn(BaseModel):
    phone: str

class AddPhoneVerifyIn(BaseModel):
    phone: str
    otp: str

class AddEmailInitIn(BaseModel):
    email: EmailStr

class AddEmailVerifyIn(BaseModel):
    email: EmailStr
    otp: str

class NotificationsPrefsIn(BaseModel):
    likes: Optional[bool] = None
    comments: Optional[bool] = None
    friend_requests: Optional[bool] = None
    messages: Optional[bool] = None

class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str

class PostIn(BaseModel):
    content: str; accent: str = "#FFD600"; location: Optional[str] = None
    photo_url: Optional[str] = None

class CommentIn(BaseModel): 
    text: str

class LikeIn(BaseModel): 
    color: Optional[str] = None

class MessageIn(BaseModel):
    to_user_id: str
    text: str = ""
    photo_url: Optional[str] = None
    mood_color: Optional[str] = None

class TypingIn(BaseModel):
    to_user_id: str
    is_typing: bool = True

class FriendIn(BaseModel):
    target_user_id: str

class NotificationPrefs(BaseModel):
    likes: bool = True
    comments: bool = True
    friend_requests: bool = True
    messages: bool = True

# ── Auth Email ───────────────────────────────────────────────
@api.post("/auth/signup")
async def signup(p: SignupIn):
    existing = await db.users.find_one({"email": p.email})
    if existing and existing.get("is_verified"):
        raise HTTPException(400, "Email already registered")
    
    try:
        await ensure_username_unique(p.username, exclude_uid=existing["id"] if existing else None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    
    code = f"{random.randint(0,9999):04d}"
    uid = existing["id"] if existing else str(uuid.uuid4())
    colors = ["#FFD600","#00C853","#FF1744","#29B6F6"]
    doc = {
        "id": uid, "email": p.email, "name": p.name, "username": p.username,
        "handle": f"@{p.username}",
        "password_hash": await hashpw(p.password), "is_verified": False,
        "otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10),
        "avatar_bg": random.choice(colors), "avatar_letter": p.name[0].upper(),
        "avatar_photo": None, "profile_video": None, "cover_photo": None, "cover_video": None,
        "website": "", "location": "", "about": "", "language": "en",
        "continent": "Asia", "created_at": now(), "is_seed": False, "deleted_at": None,
        "is_online": False, "last_seen": None, "is_private": False, "theme": "dark",
        "chat_translation_enabled": True,
        "followers": [], "following": [], "blocked_users": [], "notifications_prefs": {
            "likes": True, "comments": True, "friend_requests": True, "messages": True
        }
    }
    if existing:
        await db.users.update_one({"id": uid}, {"$set": doc})
    else:
        await db.users.insert_one(doc)
    asyncio.create_task(run_in_bg(send_otp_email(p.email, code)))
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
    await db.users.update_one({"id": u["id"]}, {"$set": {"is_verified": True}, "$unset": {"otp_hash":"","otp_expires_at":""}})
    return {"token": make_token(u["id"]), "user_id": u["id"]}

@api.post("/auth/login")
async def login(p: LoginIn):
    u = await db.users.find_one({"email": p.email})
    if not u: raise HTTPException(400, "Invalid credentials")
    pw_hash = u.get("password_hash", "")
    ok = await verifypw(p.password, pw_hash)
    if not ok: raise HTTPException(400, "Invalid credentials")
    if not u.get("is_verified"): raise HTTPException(400, "Account not verified")
    # Auto-migrate legacy bcrypt hash → fast PBKDF2 hash in background
    if _is_bcrypt(pw_hash):
        asyncio.create_task(_migrate_hash(u["id"], p.password))
    resp = {"token": make_token(u["id"]), "user_id": u["id"]}
    if u.get("deleted_at"):
        deleted_at = _aware(u["deleted_at"])
        if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
            await permanently_delete_user(u["id"])
            raise HTTPException(400, "Invalid credentials")
        resp["pending_delete"] = True
        resp["restore_deadline"] = (deleted_at + timedelta(days=DELETE_GRACE_DAYS)).isoformat()
    return resp

@api.post("/auth/resend-otp")
async def resend_otp(body: dict):
    u = await db.users.find_one({"email": body.get("email")})
    if not u: raise HTTPException(400, "User not found")
    code = f"{random.randint(0,9999):04d}"
    await db.users.update_one({"id": u["id"]}, {"$set": {"otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10)}})
    asyncio.create_task(run_in_bg(send_otp_email(u["email"], code)))
    return {"message": "Resent", "demo_otp": code if DEMO_MODE else None}


# ── Forgot Password ──────────────────────────────────────────
class ForgotPasswordInitIn(BaseModel):
    identifier: str  # email or phone

class ForgotPasswordVerifyIn(BaseModel):
    identifier: str; otp: str

class ForgotPasswordResetIn(BaseModel):
    identifier: str; otp: str; new_password: str

@api.post("/auth/forgot-password-init")
async def forgot_password_init(p: ForgotPasswordInitIn):
    identifier = p.identifier.strip()
    user = await db.users.find_one({"$or": [{"email": identifier}, {"phone": identifier}]})
    if not user or not user.get("is_verified"):
        raise HTTPException(400, "No account found with this email or phone number")
    code = f"{random.randint(0,9999):04d}"
    await db.reset_otps.update_one(
        {"identifier": identifier},
        {"$set": {"identifier": identifier, "user_id": user["id"], "otp_hash": await hashpw(code),
                  "otp_expires_at": now() + timedelta(minutes=10), "verified": False}},
        upsert=True
    )
    is_email = "@" in identifier
    if is_email:
        asyncio.create_task(run_in_bg(send_otp_email(identifier, code)))
        return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None, "method": "email"}
    else:
        sms_sent = await run_in_bg(send_otp_sms(identifier, code))
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
    await db.users.update_one({"id": rec["user_id"]}, {"$set": {"password_hash": await hashpw(p.new_password)}})
    await db.reset_otps.delete_one({"identifier": p.identifier.strip()})
    return {"message": "Password reset successfully! Please log in."}

# ── Auth Email (OTP-first) ──────────────────────────────────────
@api.post("/auth/email-signup-init")
async def email_signup_init(p: EmailInitIn):
    await purge_expired_deleted_account("email", p.email)
    await check_delete_recreate_abuse(p.email)
    existing = await db.users.find_one({"email": p.email, "is_verified": True})
    if existing: raise HTTPException(400, "Email already registered")
    code = f"{random.randint(0,9999):04d}"
    await db.email_otps.update_one(
        {"email": p.email},
        {"$set": {"email": p.email, "otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10), "verified": False}},
        upsert=True
    )
    asyncio.create_task(run_in_bg(send_otp_email(p.email, code)))
    return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

@api.post("/auth/email-verify-init")
async def email_verify_init(p: EmailVerifyIn):
    rec = await db.email_otps.find_one({"email": p.email})
    if not rec: raise HTTPException(400, "Email not found")
    exp = rec["otp_expires_at"]
    if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if now() > exp: raise HTTPException(400, "OTP expired")
    if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
    await db.email_otps.update_one({"email": p.email}, {"$set": {"verified": True}})
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
    
    colors = ["#FFD600","#00C853","#FF1744","#29B6F6"]
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
        "is_online": False, "last_seen": None, "is_private": False, "theme": "dark",
        "chat_translation_enabled": True,
        "followers": [], "following": [], "blocked_users": [], "notifications_prefs": {
            "likes": True, "comments": True, "friend_requests": True, "messages": True
        }
    }
    await db.users.insert_one(doc)
    await db.email_otps.delete_one({"email": p.email})
    return {"token": make_token(uid), "user_id": uid, "requires_phone": True}

# ── Auth Phone ──────────────────────────────────────────────
@api.post("/auth/phone-signup-init")
async def phone_signup_init(p: PhoneInitIn):
    await purge_expired_deleted_account("phone", p.phone)
    await check_delete_recreate_abuse(p.phone)
    code = f"{random.randint(0,9999):04d}"
    await db.phone_otps.update_one(
        {"phone": p.phone},
        {"$set": {"phone": p.phone, "otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10), "verified": False}},
        upsert=True
    )
    sms_sent = await run_in_bg(send_otp_sms(p.phone, code))
    return {"message": "OTP sent", "demo_otp": code if not sms_sent else None}

@api.post("/auth/phone-verify-init")
async def phone_verify_init(p: PhoneVerifyIn):
    rec = await db.phone_otps.find_one({"phone": p.phone})
    if not rec: raise HTTPException(400, "Phone not found")
    exp = rec["otp_expires_at"]
    if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if now() > exp: raise HTTPException(400, "OTP expired")
    if not await verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
    await db.phone_otps.update_one({"phone": p.phone}, {"$set": {"verified": True}})
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
    
    colors = ["#FFD600","#00C853","#FF1744","#29B6F6"]
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
        "is_online": False, "last_seen": None, "is_private": False, "theme": "dark",
        "chat_translation_enabled": True,
        "followers": [], "following": [], "blocked_users": [], "notifications_prefs": {
            "likes": True, "comments": True, "friend_requests": True, "messages": True
        }
    }
    await db.users.insert_one(doc)
    await db.phone_otps.delete_one({"phone": p.phone})
    return {"token": make_token(uid), "user_id": uid, "requires_email": True}

@api.post("/auth/phone-login")
async def phone_login(p: PhoneLoginIn):
    u = await db.users.find_one({"phone": p.phone})
    pw_hash_p = u.get("password_hash", "") if u else ""
    if not u or not await verifypw(p.password, pw_hash_p): raise HTTPException(400, "Invalid phone or password")
    if u and _is_bcrypt(pw_hash_p):
        asyncio.create_task(_migrate_hash(u["id"], p.password))
    if not u.get("is_verified"): raise HTTPException(400, "Account not verified")
    resp = {"token": make_token(u["id"]), "user_id": u["id"]}
    if u.get("deleted_at"):
        deleted_at = _aware(u["deleted_at"])
        if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
            await permanently_delete_user(u["id"])
            raise HTTPException(400, "Invalid phone or password")
        resp["pending_delete"] = True
        resp["restore_deadline"] = (deleted_at + timedelta(days=DELETE_GRACE_DAYS)).isoformat()
    return resp

@api.get("/auth/me")
async def me(u=Depends(current_user)): return u

# ── Account deletion / restore ──────────────────────────────
@api.post("/account/delete-request")
async def request_account_delete(u=Depends(current_user)):
    """Soft-delete: account is hidden immediately, hard-deleted after DELETE_GRACE_DAYS unless restored."""
    if u.get("deleted_at"):
        raise HTTPException(400, "Account is already pending deletion")
    deleted_at = now()
    await db.users.update_one({"id": u["id"]}, {"$set": {"deleted_at": deleted_at}})
    identifier = u.get("phone") or u.get("email")
    await db.account_deletions.insert_one({
        "id": str(uuid.uuid4()), "user_id": u["id"], "identifier": identifier, "deleted_at": deleted_at
    })
    restore_deadline = deleted_at + timedelta(days=DELETE_GRACE_DAYS)
    return {
        "message": f"Account will be permanently deleted in {DELETE_GRACE_DAYS} days unless you log back in and restore it.",
        "restore_deadline": restore_deadline.isoformat()
    }

@api.post("/account/restore")
async def restore_account(u=Depends(current_user)):
    if not u.get("deleted_at"):
        raise HTTPException(400, "Account is not pending deletion")
    deleted_at = _aware(u["deleted_at"])
    if now() >= deleted_at + timedelta(days=DELETE_GRACE_DAYS):
        raise HTTPException(400, "Restore window has expired; account was permanently deleted")
    await db.users.update_one({"id": u["id"]}, {"$set": {"deleted_at": None}})
    await db.account_deletions.delete_many({"user_id": u["id"], "deleted_at": u["deleted_at"]})
    return {"message": "Account restored successfully"}

@api.get("/account/deletion-status")
async def deletion_status(u=Depends(current_user)):
    if not u.get("deleted_at"):
        return {"pending_delete": False}
    deleted_at = _aware(u["deleted_at"])
    deadline = deleted_at + timedelta(days=DELETE_GRACE_DAYS)
    return {"pending_delete": True, "restore_deadline": deadline.isoformat(), "days_left": max(0, (deadline - now()).days)}

# ── Profile ──────────────────────────────────────────────────
@api.patch("/profile")
async def update_profile(p: ProfileUpdate, u=Depends(current_user)):
    upd = {k: v for k,v in p.dict().items() if v is not None}
    if "username" in upd:
        try:
            await ensure_username_unique(upd["username"], exclude_uid=u["id"])
        except ValueError as e:
            raise HTTPException(400, str(e))
        upd["handle"] = f"@{upd['username']}"
    if upd:
        await db.users.update_one({"id": u["id"]}, {"$set": upd})
        # Sync identity fields to posts
        post_upd = {}
        if "name" in upd: post_upd["user_name"] = upd["name"]
        if "handle" in upd: post_upd["user_handle"] = upd["handle"]
        if "avatar_bg" in upd: post_upd["avatar_bg"] = upd["avatar_bg"]
        if "avatar_letter" in upd: post_upd["avatar_letter"] = upd["avatar_letter"]
        if "avatar_photo" in upd: post_upd["avatar_photo"] = upd["avatar_photo"]
        if post_upd:
            await db.posts.update_many({"user_id": u["id"]}, {"$set": post_upd})
        # Sync identity fields to comments inside posts
        comment_upd = {}
        if "name" in upd: comment_upd["comments.$[c].user_name"] = upd["name"]
        if "handle" in upd: comment_upd["comments.$[c].user_handle"] = upd["handle"]
        if "avatar_bg" in upd: comment_upd["comments.$[c].avatar_bg"] = upd["avatar_bg"]
        if "avatar_letter" in upd: comment_upd["comments.$[c].avatar_letter"] = upd["avatar_letter"]
        if "avatar_photo" in upd: comment_upd["comments.$[c].avatar_photo"] = upd["avatar_photo"]
        if comment_upd:
            await db.posts.update_many(
                {"comments.user_id": u["id"]},
                {"$set": comment_upd},
                array_filters=[{"c.user_id": u["id"]}]
            )
        # Sync name/avatar to messages sent by user
        msg_upd = {}
        if "name" in upd: msg_upd["from_name"] = upd["name"]
        if "avatar_bg" in upd: msg_upd["avatar_bg"] = upd["avatar_bg"]
        if "avatar_photo" in upd: msg_upd["avatar_photo"] = upd["avatar_photo"]
        if msg_upd:
            await db.messages.update_many({"from_user_id": u["id"]}, {"$set": msg_upd})
    return await db.users.find_one({"id": u["id"]}, {"_id": 0, "password_hash": 0, "otp_hash": 0})

@api.patch("/profile/online")
async def update_online_status(body: dict, u=Depends(current_user)):
    """Mark user online or offline; updates last_seen timestamp"""
    is_online = body.get("is_online", True)
    await db.users.update_one(
        {"id": u["id"]},
        {"$set": {"is_online": is_online, "last_seen": now().isoformat()}}
    )
    return {"ok": True}

# ── Users ────────────────────────────────────────────────────
@api.get("/users")
async def list_users(continent: Optional[str] = None, q: Optional[str] = None, skip: int = 0, limit: int = 50, u=Depends(current_user)):
    excluded_ids = list(set([u["id"]] + (u.get("following") or [])))
    query = {"id": {"$nin": excluded_ids}, "is_verified": True, "deleted_at": None}
    if continent and continent != "All": query["continent"] = continent
    if q:
        query["$or"] = [
            {"name": {"$regex": q, "$options": "i"}}, 
            {"handle": {"$regex": q, "$options": "i"}}, 
            {"username": {"$regex": q, "$options": "i"}}, 
            {"location": {"$regex": q, "$options": "i"}}
        ]
    users = await db.users.find(query, {"_id": 0, "password_hash": 0, "otp_hash": 0}).skip(skip).limit(limit).to_list(limit)
    total = await db.users.count_documents(query)
    return {"users": users, "total": total, "skip": skip, "limit": limit}

@api.get("/users/{user_id}")
async def get_user(user_id: str, u=Depends(current_user)):
    """Get user profile with stats"""
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0, "otp_hash": 0})
    if not user: raise HTTPException(404, "User not found")

    is_self = user_id == u["id"]
    is_follower = u["id"] in user.get("followers", [])
    is_private = user.get("is_private", False)

    # Private account: viewer is not a follower and not self → locked profile
    is_private_locked = is_private and not is_follower and not is_self

    # Check if viewer has a pending follow request to this private account
    pending_req = None
    if is_private_locked:
        pending_req = await db.follow_requests.find_one(
            {"from_id": u["id"], "to_id": user_id, "status": "pending"}
        )

    # Parallelize DB calls
    posts_count_task = db.posts.count_documents({"user_id": user_id})
    follow_req_task = (
        db.follow_requests.find_one({"from_id": u["id"], "to_id": user_id, "status": "pending"})
        if is_private_locked else None
    )
    if follow_req_task is not None:
        posts_count, pending_req = await asyncio.gather(posts_count_task, follow_req_task)
    else:
        posts_count = await posts_count_task
    is_mutual = user_id in u.get("following", []) and u["id"] in (user.get("following") or [])
    is_following_you = u["id"] in user.get("following", [])
    followers_count = len(user.get("followers", []))
    following_count = len(user.get("following", []))

    base = {
        "id": user["id"],
        "name": user.get("name"),
        "handle": user.get("handle"),
        "username": user.get("username"),
        "avatar_bg": user.get("avatar_bg"),
        "avatar_letter": user.get("avatar_letter"),
        "avatar_photo": user.get("avatar_photo"),
        "is_private": is_private,
        "account_type": user.get("account_type"),
        "is_badge_verified": user.get("is_badge_verified"),
        "category": user.get("category"),
        "is_mutual": is_mutual,
        "is_following_you": is_following_you,
        "is_private_locked": is_private_locked,
        "has_pending_request": bool(pending_req),
        "stats": {
            "posts": posts_count,
            "followers": followers_count,
            "following": following_count
        }
    }

    if is_private_locked:
        # Return only basic info — no about, location, website, posts
        return base

    # Full profile for public accounts or approved followers
    return {
        **user,
        "is_mutual": is_mutual,
        "is_following_you": is_following_you,
        "is_private_locked": False,
        "has_pending_request": False,
        "stats": {
            "posts": posts_count,
            "followers": followers_count,
            "following": following_count
        }
    }

# ── Posts ────────────────────────────────────────────────────
@api.post("/posts")
async def create_post(p: PostIn, u=Depends(current_user)):
    doc = {
        "id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"],
        "user_handle": u["handle"], "avatar_bg": u["avatar_bg"],
        "avatar_letter": u["avatar_letter"], "avatar_photo": u.get("avatar_photo"),
        "content": p.content, "accent": p.accent, "location": p.location or "",
        "photo_url": p.photo_url or None,
        "user_location": u.get("location", ""),
        "likes": [], "comments": [], "views": [], "created_at": now().isoformat(),
        "edited_at": None, "is_pinned": False
    }
    await db.posts.insert_one(doc.copy())
    doc.pop("_id", None)
    return doc

@api.get("/posts")
async def list_posts(q: Optional[str] = None, user_id: Optional[str] = None, skip: int = 0, limit: int = 20, feed: bool = False, u=Depends(current_user)):
    query = {}
    following_ids = u.get("following", [])

    if user_id:
        # Private account check — only followers can see posts
        target_user = await db.users.find_one({"id": user_id}, {"is_private": 1, "followers": 1})
        if target_user and target_user.get("is_private") and user_id != u["id"]:
            if u["id"] not in target_user.get("followers", []):
                return {"posts": [], "total": 0, "skip": skip, "limit": limit, "private_locked": True}
        query["user_id"] = user_id
    elif feed:
        # Feed mode: posts from followed users + self only
        feed_ids = list(set(following_ids + [u["id"]]))
        query["user_id"] = {"$in": feed_ids}
        # No private-account scan needed — we already only show followed users
    else:
        if q:
            query["$or"] = [
                {"content": {"$regex": q, "$options": "i"}},
                {"user_name": {"$regex": q, "$options": "i"}},
                {"location": {"$regex": q, "$options": "i"}}
            ]
        # Discover mode: hide private accounts the viewer doesn't follow
        viewer_can_see = set(following_ids + [u["id"]])
        priv_cursor = db.users.find(
            {"is_private": True, "id": {"$nin": list(viewer_can_see)}},
            {"id": 1, "_id": 0}
        )
        private_ids = [p["id"] async for p in priv_cursor]
        if private_ids:
            query["user_id"] = {"$nin": private_ids}

    if q and user_id:
        query["$or"] = [
            {"content": {"$regex": q, "$options": "i"}},
            {"user_name": {"$regex": q, "$options": "i"}},
            {"location": {"$regex": q, "$options": "i"}}
        ]

    posts = await db.posts.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)

    # Background view tracking — don't block the response
    unviewed_ids = [p["id"] for p in posts if u["id"] not in p.get("views", [])]
    if unviewed_ids:
        asyncio.create_task(db.posts.update_many(
            {"id": {"$in": unviewed_ids}},
            {"$addToSet": {"views": u["id"]}}
        ))

    return {"posts": posts, "has_more": len(posts) == limit, "skip": skip, "limit": limit}

@api.get("/posts/{pid}")
async def get_post(pid: str, u=Depends(current_user)):
    """Get single post with details"""
    post = await db.posts.find_one({"id": pid})
    if not post: raise HTTPException(404, "Post not found")
    
    # Track view
    if u["id"] not in post.get("views", []):
        await db.posts.update_one({"id": pid}, {"$push": {"views": u["id"]}})
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
    # Note: photo_url is also updated if provided
    """Edit post content"""
    post = await db.posts.find_one({"id": pid})
    if not post: raise HTTPException(404, "Post not found")
    if post["user_id"] != u["id"]: raise HTTPException(403, "Not your post")
    
    upd = {"content": p.content, "accent": p.accent, "location": p.location or "", "edited_at": now().isoformat()}
    if p.photo_url is not None: upd["photo_url"] = p.photo_url
    await db.posts.update_one({"id": pid}, {"$set": upd})
    return await db.posts.find_one({"id": pid})

@api.post("/posts/{pid}/like")
async def like_post(pid: str, p: LikeIn, u=Depends(current_user)):
    post = await db.posts.find_one({"id": pid})
    if not post: raise HTTPException(404, "Not found")
    likes = [l for l in post.get("likes", []) if l["user_id"] != u["id"]]
    if p.color: likes.append({"user_id": u["id"], "color": p.color, "liked_at": now().isoformat()})
    await db.posts.update_one({"id": pid}, {"$set": {"likes": likes}})
    
    # Create notification
    if p.color and post["user_id"] != u["id"]:
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": post["user_id"],
            "from_user_id": u["id"],
            "from_user_name": u["name"],
            "type": "like",
            "post_id": pid,
            "created_at": now().isoformat(),
            "read": False
        })
    
    return {"likes": likes, "total": len(likes)}

@api.post("/posts/{pid}/comments")
async def add_comment(pid: str, p: CommentIn, u=Depends(current_user)):
    post = await db.posts.find_one({"id": pid})
    if not post: raise HTTPException(404, "Post not found")
    
    c = {
        "id": str(uuid.uuid4()), 
        "user_id": u["id"], 
        "user_name": u["name"], 
        "user_handle": u["handle"],
        "avatar_bg": u["avatar_bg"],
        "avatar_letter": u["avatar_letter"],
        "text": p.text, 
        "created_at": now().isoformat()
    }
    await db.posts.update_one({"id": pid}, {"$push": {"comments": c}})
    
    # Create notification
    if post["user_id"] != u["id"]:
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": post["user_id"],
            "from_user_id": u["id"],
            "from_user_name": u["name"],
            "type": "comment",
            "post_id": pid,
            "created_at": now().isoformat(),
            "read": False
        })
    
    return c

@api.delete("/posts/{pid}/comments/{cid}")
async def delete_comment(pid: str, cid: str, u=Depends(current_user)):
    """Delete comment"""
    post = await db.posts.find_one({"id": pid})
    if not post: raise HTTPException(404, "Post not found")
    
    comment = next((c for c in post.get("comments", []) if c["id"] == cid), None)
    if not comment: raise HTTPException(404, "Comment not found")
    if comment["user_id"] != u["id"] and post["user_id"] != u["id"]: 
        raise HTTPException(403, "Cannot delete")
    
    await db.posts.update_one({"id": pid}, {"$pull": {"comments": {"id": cid}}})
    return {"ok": True}

# ── Followers/Following ──────────────────────────────────────
@api.post("/users/{user_id}/follow")
async def follow_user(user_id: str, u=Depends(current_user)):
    """Follow a user. If target has private account, creates a pending follow_request instead."""
    if user_id == u["id"]: raise HTTPException(400, "Can't follow yourself")
    
    target = await db.users.find_one({"id": user_id})
    if not target: raise HTTPException(404, "User not found")

    # Block if either side blocked the other
    if u["id"] in target.get("blocked_users", []):
        raise HTTPException(403, "Action not allowed")
    if user_id in u.get("blocked_users", []):
        raise HTTPException(403, "Action not allowed")

    # Private account → create pending follow request instead of direct follow
    if target.get("is_private"):
        existing = await db.follow_requests.find_one({"from_id": u["id"], "to_id": user_id})
        if existing:
            return {"ok": True, "pending": True}
        await db.follow_requests.insert_one({
            "id": str(uuid.uuid4()),
            "from_id": u["id"],
            "to_id": user_id,
            "status": "pending",
            "created_at": now().isoformat()
        })
        # Notify the private-account owner
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "from_user_id": u["id"],
            "from_user_name": u["name"],
            "type": "follow_request",
            "created_at": now().isoformat(),
            "read": False
        })
        return {"ok": True, "pending": True}

    # Public account → direct follow
    if u["id"] not in target.get("followers", []):
        await db.users.update_one({"id": user_id}, {"$push": {"followers": u["id"]}})
    if user_id not in u.get("following", []):
        await db.users.update_one({"id": u["id"]}, {"$push": {"following": user_id}})
    
    # Notify
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "from_user_id": u["id"],
        "from_user_name": u["name"],
        "type": "follow",
        "created_at": now().isoformat(),
        "read": False
    })
    
    return {"ok": True, "pending": False}

@api.post("/users/{user_id}/unfollow")
async def unfollow_user(user_id: str, u=Depends(current_user)):
    """Unfollow a user"""
    await db.users.update_one({"id": user_id}, {"$pull": {"followers": u["id"]}})
    await db.users.update_one({"id": u["id"]}, {"$pull": {"following": user_id}})
    return {"ok": True}

@api.get("/users/{user_id}/followers")
async def get_followers(user_id: str, u=Depends(current_user)):
    """Get user followers"""
    user = await db.users.find_one({"id": user_id})
    if not user: raise HTTPException(404, "User not found")
    
    followers = await db.users.find(
        {"id": {"$in": user.get("followers", [])}},
        {"_id": 0, "password_hash": 0, "otp_hash": 0}
    ).to_list(500)
    return followers

@api.get("/users/{user_id}/following")
async def get_following(user_id: str, u=Depends(current_user)):
    """Get users being followed"""
    user = await db.users.find_one({"id": user_id})
    if not user: raise HTTPException(404, "User not found")
    
    following = await db.users.find(
        {"id": {"$in": user.get("following", [])}},
        {"_id": 0, "password_hash": 0, "otp_hash": 0}
    ).to_list(500)
    return following

@api.post("/users/me/remove-follower/{follower_id}")
async def remove_follower(follower_id: str, u=Depends(current_user)):
    """Remove a follower from your own followers list"""
    await db.users.update_one({"id": u["id"]}, {"$pull": {"followers": follower_id}})
    await db.users.update_one({"id": follower_id}, {"$pull": {"following": u["id"]}})
    return {"ok": True}

# ── Follow Requests (private accounts) ────────────────────────
@api.post("/users/{user_id}/follow-request/cancel")
async def cancel_follow_request(user_id: str, u=Depends(current_user)):
    """Cancel outgoing follow request (for private accounts)"""
    await db.follow_requests.delete_one({"from_id": u["id"], "to_id": user_id})
    return {"ok": True}

@api.post("/users/{user_id}/follow-request/accept")
async def accept_follow_request(user_id: str, u=Depends(current_user)):
    """Accept incoming follow request (private account owner calls this)"""
    req = await db.follow_requests.find_one({"from_id": user_id, "to_id": u["id"], "status": "pending"})
    if not req: raise HTTPException(404, "Follow request not found")
    # Add to followers/following
    await db.users.update_one({"id": u["id"]}, {"$addToSet": {"followers": user_id}})
    await db.users.update_one({"id": user_id}, {"$addToSet": {"following": u["id"]}})
    await db.follow_requests.delete_one({"from_id": user_id, "to_id": u["id"]})
    # Notify requester
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "from_user_id": u["id"],
        "from_user_name": u["name"],
        "type": "follow_accept",
        "created_at": now().isoformat(),
        "read": False
    })
    return {"ok": True}

@api.post("/users/{user_id}/follow-request/decline")
async def decline_follow_request(user_id: str, u=Depends(current_user)):
    """Decline incoming follow request (private account owner calls this)"""
    await db.follow_requests.delete_one({"from_id": user_id, "to_id": u["id"]})
    return {"ok": True}

@api.get("/users/me/follow-requests")
async def my_follow_requests(u=Depends(current_user)):
    """Get incoming pending follow requests (for private account owners)"""
    pending = await db.follow_requests.find({"to_id": u["id"], "status": "pending"}, {"_id": 0}).to_list(500)
    from_ids = [r["from_id"] for r in pending]
    PUBLIC = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
              "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1, "location": 1, "about": 1}
    users_list = await db.users.find({"id": {"$in": from_ids}}, PUBLIC).to_list(500) if from_ids else []
    users_map = {u2["id"]: u2 for u2 in users_list}
    for r in pending:
        r["from_user"] = users_map.get(r["from_id"], {})
    # Outgoing (requests I sent to private accounts)
    outgoing = await db.follow_requests.find({"from_id": u["id"], "status": "pending"}, {"_id": 0}).to_list(500)
    return {"incoming": pending, "outgoing": outgoing}

# ── Friends ──────────────────────────────────────────────────
@api.post("/friends/request")
async def friend_request(p: FriendIn, u=Depends(current_user)):
    if p.target_user_id == u["id"]: raise HTTPException(400, "Can't friend yourself")
    target = await db.users.find_one({"id": p.target_user_id})
    if not target: raise HTTPException(404, "User not found")
    # Organisation accounts cannot be connected — only followed
    if target.get("account_type") == "organisation":
        raise HTTPException(400, "You can only follow organisation accounts, not connect")
    # Badge-verified accounts (politicians/businessmen) cannot receive connect/chat requests
    if target.get("is_badge_verified"):
        raise HTTPException(400, "Verified public figures can only be followed, not connected")
    # Block duplicate outgoing request
    existing = await db.friend_requests.find_one({"from_id": u["id"], "to_id": p.target_user_id})
    if existing: return {"status": existing["status"]}
    # Block if already accepted (friends)
    already_accepted = await db.friend_requests.find_one({
        "$or": [
            {"from_id": u["id"], "to_id": p.target_user_id, "status": "accepted"},
            {"from_id": p.target_user_id, "to_id": u["id"], "status": "accepted"},
        ]
    })
    if already_accepted: return {"status": "accepted"}
    await db.friend_requests.insert_one({
        "id": str(uuid.uuid4()), 
        "from_id": u["id"], 
        "to_id": p.target_user_id, 
        "status": "pending", 
        "created_at": now().isoformat()
    })
    
    # Create notification
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": p.target_user_id,
        "from_user_id": u["id"],
        "from_user_name": u["name"],
        "type": "friend_request",
        "created_at": now().isoformat(),
        "read": False
    })
    
    return {"status": "pending"}

@api.post("/friends/accept")
async def friend_accept(p: FriendIn, u=Depends(current_user)):
    await db.friend_requests.update_one(
        {"from_id": p.target_user_id, "to_id": u["id"], "status": "pending"}, 
        {"$set": {"status": "accepted"}}
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
        {"_id": 0}
    ).to_list(500)
    friend_ids = [r["to_id"] if r["from_id"] == u["id"] else r["from_id"] for r in accepted]
    pending_in = await db.friend_requests.find({"to_id": u["id"], "status": "pending"}, {"_id": 0}).to_list(500)
    pending_out = await db.friend_requests.find({"from_id": u["id"], "status": "pending"}, {"_id": 0}).to_list(500)

    # Public profile fields only — no PII (email, phone, otp, etc.)
    PUBLIC_FIELDS = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
                     "avatar_photo": 1, "avatar_bg": 1, "avatar_letter": 1,
                     "category": 1, "location": 1, "about": 1, "cover_photo": 1,
                     "stats": 1, "following": 1}

    friends = await db.users.find({"id": {"$in": friend_ids}}, PUBLIC_FIELDS).to_list(500)

    # Populate user info for pending incoming / outgoing requests
    in_from_ids  = [r["from_id"] for r in pending_in]
    out_to_ids   = [r["to_id"]   for r in pending_out]

    in_users_list  = await db.users.find({"id": {"$in": in_from_ids}},  PUBLIC_FIELDS).to_list(500) if in_from_ids  else []
    out_users_list = await db.users.find({"id": {"$in": out_to_ids}},   PUBLIC_FIELDS).to_list(500) if out_to_ids   else []

    in_users  = {usr["id"]: usr for usr in in_users_list}
    out_users = {usr["id"]: usr for usr in out_users_list}

    for r in pending_in:
        r["from_user"] = in_users.get(r["from_id"], {})
    for r in pending_out:
        r["to_user"] = out_users.get(r["to_id"], {})

    return {"friends": friends, "pending_incoming": pending_in, "pending_outgoing": pending_out}

# ── In-memory typing state ────────────────────────────────────
_typing_state: dict = {}  # {from_id -> {to_id -> expires_at}}

# ── Messages ─────────────────────────────────────────────────
@api.post("/messages")
async def send_message(p: MessageIn, u=Depends(current_user)):
    if not p.text.strip() and not p.photo_url:
        raise HTTPException(400, "Message cannot be empty")
    recipient = await db.users.find_one({"id": p.to_user_id})
    if not recipient:
        raise HTTPException(404, "Recipient not found")
    if u["id"] in recipient.get("blocked_users", []) or p.to_user_id in u.get("blocked_users", []):
        raise HTTPException(403, "Cannot message this user")
    if recipient.get("is_badge_verified"):
        raise HTTPException(403, "Cannot message verified public figures")
    same_continent = (u.get("continent") or "").strip() == (recipient.get("continent") or "").strip() and bool(u.get("continent"))
    if not same_continent:
        fr = await db.friend_requests.find_one({
            "status": "accepted",
            "$or": [{"from_id": u["id"], "to_id": p.to_user_id}, {"from_id": p.to_user_id, "to_id": u["id"]}]
        })
        if not fr:
            raise HTTPException(403, "Connect with this user first to message across countries")

    # Segment 9: Timezone-aware silent delivery
    # Check receiver's local hour using their timezone offset (if stored)
    is_silent = False
    recv_tz_offset = recipient.get("timezone_offset")  # hours offset, e.g. +5.5
    if recv_tz_offset is not None:
        try:
            recv_hour = (now() + timedelta(hours=float(recv_tz_offset))).hour
            is_silent = (recv_hour >= 23 or recv_hour < 6)
        except Exception:
            pass

    m = {
        "id": str(uuid.uuid4()),
        "from_id": u["id"],
        "from_name": u["name"],
        "to_id": p.to_user_id,
        "text": p.text,
        "photo_url": p.photo_url,
        "mood_color": p.mood_color,
        "created_at": now().isoformat(),
        "status": "sent",       # sent → delivered → seen
        "deleted_for": [],      # list of user_ids who deleted for self
        "deleted_for_everyone": False,
        "is_silent": is_silent,
    }
    await db.messages.insert_one(m.copy())
    m.pop("_id", None)
    return m

@api.get("/messages")
async def list_messages(with_user: Optional[str] = None, skip: int = 0, limit: int = 50, u=Depends(current_user)):
    if with_user:
        q = {"$or": [{"from_id": u["id"], "to_id": with_user}, {"from_id": with_user, "to_id": u["id"]}]}
    else:
        q = {"$or": [{"from_id": u["id"]}, {"to_id": u["id"]}]}
    msgs = await db.messages.find(q, {"_id": 0}).sort("created_at", 1).skip(skip).limit(limit).to_list(limit)
    total = await db.messages.count_documents(q)
    # Segment 2: Mark delivered when receiver fetches
    if with_user:
        await db.messages.update_many(
            {"from_id": with_user, "to_id": u["id"], "status": "sent"},
            {"$set": {"status": "delivered"}}
        )
    # Filter out messages deleted for this user
    msgs = [m for m in msgs if u["id"] not in m.get("deleted_for", []) and not m.get("deleted_for_everyone")]
    return {"messages": msgs, "total": total, "skip": skip, "limit": limit}

@api.post("/messages/{msg_id}/seen")
async def mark_message_seen(msg_id: str, u=Depends(current_user)):
    """Segment 2: Mark a message as seen by the receiver"""
    await db.messages.update_one(
        {"id": msg_id, "to_id": u["id"]},
        {"$set": {"status": "seen", "seen_at": now().isoformat()}}
    )
    return {"ok": True}

@api.delete("/messages/{msg_id}")
async def delete_message(msg_id: str, delete_for: str = "self", u=Depends(current_user)):
    """Segment 4: Delete message for self or for everyone"""
    msg = await db.messages.find_one({"id": msg_id})
    if not msg: raise HTTPException(404, "Message not found")
    if delete_for == "everyone":
        if msg["from_id"] != u["id"]: raise HTTPException(403, "Only sender can delete for everyone")
        await db.messages.update_one({"id": msg_id}, {"$set": {"deleted_for_everyone": True, "text": "", "photo_url": None}})
    else:
        await db.messages.update_one({"id": msg_id}, {"$addToSet": {"deleted_for": u["id"]}})
    return {"ok": True}

@api.get("/messages/conversations")
async def get_conversations(u=Depends(current_user)):
    """Segment 5: Get chat list with last message preview and unread count"""
    pipeline = [
        {"$match": {"$or": [{"from_id": u["id"]}, {"to_id": u["id"]}], "deleted_for_everyone": {"$ne": True}}},
        {"$sort": {"created_at": -1}},
        {"$project": {
            "_id": 0,
            "other_id": {"$cond": [{"$eq": ["$from_id", u["id"]]}, "$to_id", "$from_id"]},
            "text": 1, "photo_url": 1, "created_at": 1, "status": 1, "from_id": 1, "mood_color": 1
        }},
        {"$group": {
            "_id": "$other_id",
            "last_text": {"$first": "$text"},
            "last_photo": {"$first": "$photo_url"},
            "last_time": {"$first": "$created_at"},
            "last_status": {"$first": "$status"},
            "last_from": {"$first": "$from_id"},
            "last_mood": {"$first": "$mood_color"},
        }}
    ]
    convs = await db.messages.aggregate(pipeline).to_list(200)
    user_ids = [c["_id"] for c in convs]
    pub = {"_id": 0, "id": 1, "name": 1, "handle": 1, "username": 1,
           "avatar_bg": 1, "avatar_letter": 1, "avatar_photo": 1,
           "is_online": 1, "last_seen": 1}
    users_list = await db.users.find({"id": {"$in": user_ids}}, pub).to_list(200)
    users_map = {uu["id"]: uu for uu in users_list}
    # Parallel unread counts (all at once instead of sequentially)
    async def _unread(cid):
        return await db.messages.count_documents({
            "from_id": cid, "to_id": u["id"],
            "status": {"$ne": "seen"}, "deleted_for_everyone": {"$ne": True}
        })
    unread_counts = await asyncio.gather(*[_unread(c["_id"]) for c in convs])
    for c, uc in zip(convs, unread_counts):
        c["user"] = users_map.get(c["_id"], {})
        c["unread"] = uc
    convs.sort(key=lambda x: x.get("last_time", ""), reverse=True)
    return {"conversations": convs}

@api.post("/messages/typing")
async def set_typing(p: TypingIn, u=Depends(current_user)):
    """Segment 3: Set typing indicator (stored in memory, expires in 5s)"""
    if u["id"] not in _typing_state:
        _typing_state[u["id"]] = {}
    if p.is_typing:
        _typing_state[u["id"]][p.to_user_id] = now() + timedelta(seconds=5)
    else:
        _typing_state[u["id"]].pop(p.to_user_id, None)
    return {"ok": True}

@api.get("/messages/typing")
async def get_typing(with_user: str, u=Depends(current_user)):
    """Segment 3: Check if a user is typing to me"""
    expires = _typing_state.get(with_user, {}).get(u["id"])
    if expires and now() < expires:
        return {"is_typing": True}
    return {"is_typing": False}

@api.patch("/users/me/timezone")
async def update_timezone(body: dict, u=Depends(current_user)):
    """Segment 9: Store user's timezone offset for silent night delivery"""
    offset = body.get("offset")
    if offset is None: raise HTTPException(400, "offset required")
    await db.users.update_one({"id": u["id"]}, {"$set": {"timezone_offset": float(offset)}})
    return {"ok": True}

# ── Notifications ────────────────────────────────────────────
@api.get("/notifications")
async def get_notifications(u=Depends(current_user)):
    """Get user notifications"""
    notifs = await db.notifications.find(
        {"user_id": u["id"]}, 
        {"_id": 0}
    ).sort("created_at", -1).limit(100).to_list(100)
    
    unread_count = await db.notifications.count_documents({"user_id": u["id"], "read": False})
    return {"notifications": notifs, "unread_count": unread_count}

@api.post("/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: str, u=Depends(current_user)):
    """Mark notification as read"""
    await db.notifications.update_one(
        {"id": notif_id, "user_id": u["id"]},
        {"$set": {"read": True}}
    )
    return {"ok": True}

@api.post("/notifications/read-all")
async def mark_all_notifications_read(u=Depends(current_user)):
    """Mark all notifications as read"""
    await db.notifications.update_many(
        {"user_id": u["id"], "read": False},
        {"$set": {"read": True}}
    )
    return {"ok": True}


@api.get("/notifications/unread-count")
async def get_notif_unread_count(u=Depends(current_user)):
    """Lightweight polling endpoint: just the unread notification count."""
    count = await db.notifications.count_documents({"user_id": u["id"], "read": False})
    return {"unread_count": count}

@api.get("/messages/unread-count")
async def get_msg_unread_count(u=Depends(current_user)):
    """Lightweight polling endpoint: just the total unread message count."""
    count = await db.messages.count_documents({
        "to_id": u["id"],
        "status": {"$ne": "seen"},
        "deleted_for_everyone": {"$ne": True}
    })
    return {"unread_count": count}

# ── Block Users ──────────────────────────────────────────────
@api.post("/users/{user_id}/block")
async def block_user(user_id: str, u=Depends(current_user)):
    """Block a user"""
    if user_id == u["id"]: raise HTTPException(400, "Can't block yourself")
    await db.users.update_one({"id": u["id"]}, {"$addToSet": {"blocked_users": user_id}})
    return {"ok": True}

@api.post("/users/{user_id}/unblock")
async def unblock_user(user_id: str, u=Depends(current_user)):
    """Unblock a user"""
    await db.users.update_one({"id": u["id"]}, {"$pull": {"blocked_users": user_id}})
    return {"ok": True}

@api.get("/users/me/blocked")
async def get_blocked_users(u=Depends(current_user)):
    """List full profile details for users the current user has blocked"""
    ids = u.get("blocked_users", [])
    if not ids: return []
    return await db.users.find(
        {"id": {"$in": ids}}, {"_id": 0, "password_hash": 0, "otp_hash": 0}
    ).to_list(len(ids))

# ── Settings: notifications, security ────────────────────────
@api.patch("/settings/notifications")
async def update_notifications_prefs(p: NotificationsPrefsIn, u=Depends(current_user)):
    """Merge-update the current user's notification preferences"""
    upd = {k: v for k, v in p.dict().items() if v is not None}
    if upd:
        await db.users.update_one(
            {"id": u["id"]},
            {"$set": {f"notifications_prefs.{k}": v for k, v in upd.items()}}
        )
    fresh = await db.users.find_one({"id": u["id"]}, {"_id": 0, "notifications_prefs": 1})
    return fresh.get("notifications_prefs", {})

@api.post("/settings/change-password")
async def change_password(p: ChangePasswordIn, u=Depends(current_user)):
    """Verify the current password and set a new one"""
    # current_user excludes password_hash for security — re-fetch it for verification
    user_with_hash = await db.users.find_one({"id": u["id"]}, {"_id": 0, "password_hash": 1})
    if not user_with_hash or not await verifypw(p.current_password, user_with_hash.get("password_hash", "")):
        raise HTTPException(400, "Current password is incorrect")
    if len(p.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    await db.users.update_one({"id": u["id"]}, {"$set": {"password_hash": await hashpw(p.new_password)}})
    return {"message": "Password updated successfully"}

# ── Username availability check ──────────────────────────────
@api.get("/check-username")
async def check_username(username: str, u=Depends(current_user)):
    """Check if a username is available (excluding current user)"""
    import re
    if not re.match(r'^[a-z0-9_]{3,30}$', username):
        return {"available": False, "reason": "3-30 chars, only a-z 0-9 _"}
    existing = await db.users.find_one({"username": username})
    if existing and existing["id"] != u["id"]:
        return {"available": False, "reason": "Already taken"}
    return {"available": True, "reason": "Available!"}

# ── Translation (POST own, no Google dependency) ─────────
TRANSLATE_LANG_MAP = {
    "zh": "zh-CN", "en": "en", "hi": "hi", "ur": "ur", "es": "es",
    "fr": "fr", "ar": "ar", "pt": "pt", "de": "de", "ja": "ja",
    "ru": "ru", "bn": "bn", "id": "id", "tr": "tr",
}

# Segment 8: Cultural tone analysis — simple heuristic, no AI key needed
def _detect_tone_hint(text: str) -> Optional[str]:
    t = text.lower()
    if any(w in t for w in ["please", "kindly", "would you", "could you", "sir", "ma'am", "madam", "dear"]):
        return "Formal tone — polite phrasing used"
    if any(w in t for w in ["hey", "yo", "sup", "lol", "haha", "bruh", "bro", "sis", "wanna", "gonna", "kinda"]):
        return "Informal tone — casual/slang phrasing"
    if any(w in t for w in ["urgent", "asap", "immediately", "now", "hurry", "quickly"]):
        return "Urgent tone — time-sensitive message"
    if text.endswith("?") or text.count("?") > 1:
        return "Questioning tone — expecting a reply"
    if any(w in t for w in ["sorry", "apolog", "forgive", "excuse me", "pardon"]):
        return "Apologetic tone — expressing regret"
    return None

@api.post("/translate")
async def translate_endpoint(body: dict):
    """POST App's own translation endpoint — uses MyMemory (free, no key needed)."""
    text   = (body.get("text") or "").strip()
    target = body.get("target", "en")
    include_tone = body.get("tone", False)
    if not text:
        return {"translated": text, "tone_hint": None}
    tl = TRANSLATE_LANG_MAP.get(target, target)

    cache_key = tl + "||" + text
    cached = _cache_get(cache_key)
    if cached:
        return {"translated": cached, "tone_hint": _detect_tone_hint(text) if include_tone else None}

    translated = None
    # Primary: MyMemory free API (no key, 1000 words/day anonymous)
    try:
        url = (
            "https://api.mymemory.translated.world/get"
            f"?q={urllib.parse.quote(text)}&langpair=autodetect|{tl}"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "PostApp/1.0"})
        def _fetch():
            with urllib.request.urlopen(req, timeout=6) as resp:
                return _json.loads(resp.read().decode())
        data = await asyncio.to_thread(_fetch)
        t_result = (data.get("responseData") or {}).get("translatedText", "")
        if t_result and "MYMEMORY WARNING" not in t_result and t_result != text:
            translated = t_result
    except Exception as e:
        logging.warning(f"MyMemory translation failed: {e}")

    if not translated:
        # Fallback: LibreTranslate public instance
        try:
            lt_body = _json.dumps({"q": text, "source": "auto", "target": tl, "format": "text"}).encode()
            lt_req  = urllib.request.Request(
                "https://libretranslate.com/translate",
                data=lt_body,
                headers={"Content-Type": "application/json", "User-Agent": "PostApp/1.0"},
                method="POST"
            )
            def _fetch_lt():
                with urllib.request.urlopen(lt_req, timeout=6) as resp:
                    return _json.loads(resp.read().decode())
            lt_data = await asyncio.to_thread(_fetch_lt)
            t_result = lt_data.get("translatedText", "")
            if t_result and t_result != text:
                translated = t_result
        except Exception as e:
            logging.warning(f"LibreTranslate fallback failed: {e}")

    if not translated:
        translated = text

    tone_hint = _detect_tone_hint(text) if include_tone else None
    _cache_set(cache_key, translated)
    return {"translated": translated, "tone_hint": tone_hint}

# ── Health ───────────────────────────────────────────────────

async def _migrate_hash(uid: str, password: str):
    """Background task: replace bcrypt hash with fast PBKDF2 hash after successful login."""
    try:
        new_hash = await hashpw(password)
        await db.users.update_one({"id": uid}, {"$set": {"password_hash": new_hash}})
        logging.info(f"✅ Migrated password hash for {uid}")
    except Exception as e:
        logging.warning(f"Hash migration failed for {uid}: {e}")

@api.get("/")
async def root(): 
    return {
        "status": "ok", 
        "demo_mode": DEMO_MODE, 
        "twilio": bool(TWILIO_SID),
        "version": "5.0"
    }

# ── Add Secondary Contact (Anti-Fake-Account) ───────────────
@api.post("/auth/add-phone-init")
async def add_phone_init(p: AddPhoneInitIn, u=Depends(raw_user)):
    """Send SMS OTP to add phone (required for email-registered users)."""
    if u.get("signup_method") != "email": raise HTTPException(403, "This endpoint is only for email-registered accounts")
    if u.get("phone_verified"): raise HTTPException(400, "Phone already verified")
    existing = await db.users.find_one({"phone": p.phone, "is_verified": True, "id": {"$ne": u["id"]}})
    if existing: raise HTTPException(400, "This phone is already registered to another account")
    code = f"{random.randint(0,9999):04d}"
    await db.phone_otps.update_one(
        {"phone": p.phone},
        {"$set": {"phone": p.phone, "otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10), "verified": False, "user_id": u["id"]}},
        upsert=True
    )
    sms_sent = await run_in_bg(send_otp_sms(p.phone, code))
    return {"message": "OTP sent", "demo_otp": code if not sms_sent else None}

@api.post("/auth/add-phone-verify")
async def add_phone_verify(p: AddPhoneVerifyIn, u=Depends(raw_user)):
    """Verify SMS OTP and save phone."""
    if u.get("signup_method") != "email": raise HTTPException(403, "This endpoint is only for email-registered accounts")
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
    """Send email OTP to add email (required for phone-registered users)."""
    if u.get("signup_method") != "phone": raise HTTPException(403, "This endpoint is only for phone-registered accounts")
    if u.get("email_verified"): raise HTTPException(400, "Email already verified")
    existing = await db.users.find_one({"email": p.email, "is_verified": True, "id": {"$ne": u["id"]}})
    if existing: raise HTTPException(400, "This email is already registered to another account")
    code = f"{random.randint(0,9999):04d}"
    await db.email_otps.update_one(
        {"email": p.email},
        {"$set": {"email": p.email, "otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10), "verified": False, "user_id": u["id"]}},
        upsert=True
    )
    asyncio.create_task(run_in_bg(send_otp_email(p.email, code)))
    return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

@api.post("/auth/add-email-verify")
async def add_email_verify(p: AddEmailVerifyIn, u=Depends(raw_user)):
    """Verify email OTP and save email."""
    if u.get("signup_method") != "phone": raise HTTPException(403, "This endpoint is only for phone-registered accounts")
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



# ── Translation Cache (in-memory, TTL 1 hour) ─────────────────
import time as _time
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
        for k in oldest: del _trans_cache[k]
    _trans_cache[key] = (value, _time.monotonic())

# ── DB Indexes (performance) ─────────────────────────────────
@app.on_event('startup')
async def create_indexes():
    try:
        # Users
        await db.users.create_index('id', unique=True, background=True)
        await db.users.create_index('username', background=True)
        await db.users.create_index('email', background=True)
        await db.users.create_index('phone', background=True)
        await db.users.create_index('handle', background=True)
        # Posts
        await db.posts.create_index('user_id', background=True)
        await db.posts.create_index([('created_at', -1)], background=True)
        await db.posts.create_index('id', unique=True, background=True)
        # Messages
        await db.messages.create_index([('from_id', 1), ('to_id', 1)], background=True)
        await db.messages.create_index([('created_at', 1)], background=True)
        # Notifications
        await db.notifications.create_index('to_id', background=True)
        await db.notifications.create_index([('created_at', -1)], background=True)
        # Follow / Friend requests
        await db.follow_requests.create_index([('from_id', 1), ('to_id', 1)], background=True)
        await db.follow_requests.create_index('status', background=True)
        await db.friend_requests.create_index([('from_id', 1), ('to_id', 1)], background=True)
        await db.friend_requests.create_index('status', background=True)
        # OTPs
        await db.email_otps.create_index('email', background=True)
        await db.phone_otps.create_index('phone', background=True)
        # Account deletions
        await db.account_deletions.create_index('identifier', background=True)
        logging.info('✅ MongoDB indexes created')
    except Exception as e:
        logging.warning(f'Index creation warning: {e}')

# ── Seed ─────────────────────────────────────────────────────
@app.on_event("startup")
async def seed():
    if await db.users.count_documents({"is_seed": True}) > 0: return
    WORLD = [
        ("Aryan","@aryan_world","Mumbai, India","Photographer & traveller 📷","Asia","#FFD600"),
        ("Bella","@bella_creates","London, UK","Designer. Coffee lover ☕","Europe","#00C853"),
        ("Carlos","@carlos_global","Mexico City","Entrepreneur 🚀","Americas","#29B6F6"),
        ("Yuki","@yuki_jp","Tokyo, Japan","Manga artist 🎨","Asia","#00C853"),
        ("Fatima","@fatima_sa","Riyadh, Saudi Arabia","Writer & poet ✍️","Asia","#FF1744"),
        ("Pierre","@pierre_fr","Paris, France","Chef & food blogger 🥐","Europe","#FF1744"),
        ("Lucas","@lucas_br","São Paulo, Brazil","Carnaval organizer 🎉","Americas","#00C853"),
        ("Chioma","@chioma_ng","Lagos, Nigeria","Fashion designer 👗","Africa","#29B6F6"),
        ("Jack","@jack_au","Sydney, Australia","Surfer & barista ☕","Oceania","#00C853"),
        ("Soo-Jin","@soojin_kr","Seoul, South Korea","K-pop enthusiast 🎵","Asia","#FF1744"),
        ("Anna","@anna_se","Stockholm, Sweden","Environmentalist 🌿","Europe","#29B6F6"),
        ("Amara","@amara_ke","Nairobi, Kenya","Safari guide 🦁","Africa","#FFD600"),
    ]
    for name, handle, loc, about, continent, color in WORLD:
        uid = str(uuid.uuid4())
        await db.users.insert_one({
            "id": uid, 
            "email": f"{handle[1:]}@post.demo", 
            "username": handle[1:], 
            "name": name, 
            "handle": handle, 
            "is_verified": True, 
            "is_seed": True, 
            "avatar_bg": color,
            "avatar_letter": name[0], 
            "location": loc, 
            "about": about, 
            "continent": continent,
            "created_at": now(),
            "followers": [],
            "following": [],
            "blocked_users": [],
            "notifications_prefs": {
                "likes": True,
                "comments": True,
                "friend_requests": True,
                "messages": True
            }
        })
    logging.info("✅ World users seeded")


app.include_router(api)

@app.on_event("shutdown")
async def shutdown(): client.close()

# ── Health ───────────────────────────────────────────────────

async def _migrate_hash(uid: str, password: str):
    """Background task: replace bcrypt hash with fast PBKDF2 hash after successful login."""
    try:
        new_hash = await hashpw(password)
        await db.users.update_one({"id": uid}, {"$set": {"password_hash": new_hash}})
        logging.info(f"✅ Migrated password hash for {uid}")
    except Exception as e:
        logging.warning(f"Hash migration failed for {uid}: {e}")

@api.get("/")
async def root(): 
    return {
        "status": "ok", 
        "demo_mode": DEMO_MODE, 
        "twilio": bool(TWILIO_SID),
        "version": "5.0"
    }

# ── Add Secondary Contact (Anti-Fake-Account) ───────────────
@api.post("/auth/add-phone-init")
async def add_phone_init(p: AddPhoneInitIn, u=Depends(raw_user)):
    """Send SMS OTP to add phone (required for email-registered users)."""
    if u.get("signup_method") != "email": raise HTTPException(403, "This endpoint is only for email-registered accounts")
    if u.get("phone_verified"): raise HTTPException(400, "Phone already verified")
    existing = await db.users.find_one({"phone": p.phone, "is_verified": True, "id": {"$ne": u["id"]}})
    if existing: raise HTTPException(400, "This phone is already registered to another account")
    code = f"{random.randint(0,9999):04d}"
    await db.phone_otps.update_one(
        {"phone": p.phone},
        {"$set": {"phone": p.phone, "otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10), "verified": False, "user_id": u["id"]}},
        upsert=True
    )
    sms_sent = await run_in_bg(send_otp_sms(p.phone, code))
    return {"message": "OTP sent", "demo_otp": code if not sms_sent else None}

@api.post("/auth/add-phone-verify")
async def add_phone_verify(p: AddPhoneVerifyIn, u=Depends(raw_user)):
    """Verify SMS OTP and save phone."""
    if u.get("signup_method") != "email": raise HTTPException(403, "This endpoint is only for email-registered accounts")
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
    """Send email OTP to add email (required for phone-registered users)."""
    if u.get("signup_method") != "phone": raise HTTPException(403, "This endpoint is only for phone-registered accounts")
    if u.get("email_verified"): raise HTTPException(400, "Email already verified")
    existing = await db.users.find_one({"email": p.email, "is_verified": True, "id": {"$ne": u["id"]}})
    if existing: raise HTTPException(400, "This email is already registered to another account")
    code = f"{random.randint(0,9999):04d}"
    await db.email_otps.update_one(
        {"email": p.email},
        {"$set": {"email": p.email, "otp_hash": await hashpw(code), "otp_expires_at": now() + timedelta(minutes=10), "verified": False, "user_id": u["id"]}},
        upsert=True
    )
    asyncio.create_task(run_in_bg(send_otp_email(p.email, code)))
    return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

@api.post("/auth/add-email-verify")
async def add_email_verify(p: AddEmailVerifyIn, u=Depends(raw_user)):
    """Verify email OTP and save email."""
    if u.get("signup_method") != "phone": raise HTTPException(403, "This endpoint is only for phone-registered accounts")
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

# ── Seed ─────────────────────────────────────────────────────
@app.on_event("startup")
async def seed():
    if await db.users.count_documents({"is_seed": True}) > 0: return
    WORLD = [
        ("Aryan","@aryan_world","Mumbai, India","Photographer & traveller 📷","Asia","#FFD600"),
        ("Bella","@bella_creates","London, UK","Designer. Coffee lover ☕","Europe","#00C853"),
        ("Carlos","@carlos_global","Mexico City","Entrepreneur 🚀","Americas","#29B6F6"),
        ("Yuki","@yuki_jp","Tokyo, Japan","Manga artist 🎨","Asia","#00C853"),
        ("Fatima","@fatima_sa","Riyadh, Saudi Arabia","Writer & poet ✍️","Asia","#FF1744"),
        ("Pierre","@pierre_fr","Paris, France","Chef & food blogger 🥐","Europe","#FF1744"),
        ("Lucas","@lucas_br","São Paulo, Brazil","Carnaval organizer 🎉","Americas","#00C853"),
        ("Chioma","@chioma_ng","Lagos, Nigeria","Fashion designer 👗","Africa","#29B6F6"),
        ("Jack","@jack_au","Sydney, Australia","Surfer & barista ☕","Oceania","#00C853"),
        ("Soo-Jin","@soojin_kr","Seoul, South Korea","K-pop enthusiast 🎵","Asia","#FF1744"),
        ("Anna","@anna_se","Stockholm, Sweden","Environmentalist 🌿","Europe","#29B6F6"),
        ("Amara","@amara_ke","Nairobi, Kenya","Safari guide 🦁","Africa","#FFD600"),
    ]
    for name, handle, loc, about, continent, color in WORLD:
        uid = str(uuid.uuid4())
        await db.users.insert_one({
            "id": uid, 
            "email": f"{handle[1:]}@post.demo", 
            "username": handle[1:], 
            "name": name, 
            "handle": handle, 
            "is_verified": True, 
            "is_seed": True, 
            "avatar_bg": color,
            "avatar_letter": name[0], 
            "location": loc, 
            "about": about, 
            "continent": continent,
            "created_at": now(),
            "followers": [],
            "following": [],
            "blocked_users": [],
            "notifications_prefs": {
                "likes": True,
                "comments": True,
                "friend_requests": True,
                "messages": True
            }
        })
    logging.info("✅ World users seeded")


app.include_router(api)

@app.on_event("shutdown")
async def shutdown(): client.close()

