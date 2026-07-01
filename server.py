from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os, uuid, random, logging, bcrypt, jwt, re, io
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import base64

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

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="POST App API")
api = APIRouter(prefix="/api")
bearer = HTTPBearer(auto_error=False)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
logging.basicConfig(level=logging.INFO)

def now(): return datetime.now(timezone.utc)
def hashpw(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
def verifypw(p, h):
    try: return bcrypt.checkpw(p.encode(), h.encode())
    except: return False
def make_token(uid):
    return jwt.encode({"sub": uid, "exp": now() + timedelta(days=30)}, JWT_SECRET, algorithm="HS256")

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")

async def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds: raise HTTPException(401, "Missing token")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
        uid = payload["sub"]
    except: raise HTTPException(401, "Invalid token")
    u = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0, "otp_hash": 0})
    if not u: raise HTTPException(401, "User not found")
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

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if v is None: return v
        v = v.strip().lower()
        if not USERNAME_RE.match(v):
            raise ValueError("Username: 3-20 chars, only lowercase letters, numbers, underscore")
        return v

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

class CommentIn(BaseModel): 
    text: str

class LikeIn(BaseModel): 
    color: Optional[str] = None

class MessageIn(BaseModel):
    to_user_id: str; text: str

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
        "password_hash": hashpw(p.password), "is_verified": False,
        "otp_hash": hashpw(code), "otp_expires_at": now() + timedelta(minutes=10),
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
    send_otp_email(p.email, code)
    return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

@api.post("/auth/verify-otp")
async def verify_otp(p: OtpIn):
    u = await db.users.find_one({"email": p.email})
    if not u: raise HTTPException(400, "User not found")
    if u.get("is_verified"): raise HTTPException(400, "Already verified")
    exp = u["otp_expires_at"]
    if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if now() > exp: raise HTTPException(400, "Code expired")
    if not verifypw(p.otp, u["otp_hash"]): raise HTTPException(400, "Incorrect code")
    await db.users.update_one({"id": u["id"]}, {"$set": {"is_verified": True}, "$unset": {"otp_hash":"","otp_expires_at":""}})
    return {"token": make_token(u["id"]), "user_id": u["id"]}

@api.post("/auth/login")
async def login(p: LoginIn):
    u = await db.users.find_one({"email": p.email})
    if not u or not verifypw(p.password, u.get("password_hash","")): raise HTTPException(400, "Invalid credentials")
    if not u.get("is_verified"): raise HTTPException(400, "Account not verified")
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
    await db.users.update_one({"id": u["id"]}, {"$set": {"otp_hash": hashpw(code), "otp_expires_at": now() + timedelta(minutes=10)}})
    send_otp_email(u["email"], code)
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
        {"$set": {"identifier": identifier, "user_id": user["id"], "otp_hash": hashpw(code),
                  "otp_expires_at": now() + timedelta(minutes=10), "verified": False}},
        upsert=True
    )
    is_email = "@" in identifier
    if is_email:
        send_otp_email(identifier, code)
        return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None, "method": "email"}
    else:
        sms_sent = send_otp_sms(identifier, code)
        return {"message": "OTP sent", "demo_otp": code if not sms_sent else None, "method": "sms"}

@api.post("/auth/forgot-password-verify")
async def forgot_password_verify(p: ForgotPasswordVerifyIn):
    rec = await db.reset_otps.find_one({"identifier": p.identifier.strip()})
    if not rec: raise HTTPException(400, "Request not found. Please start again.")
    exp = rec["otp_expires_at"]
    if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if now() > exp: raise HTTPException(400, "OTP expired. Please request a new one.")
    if not verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
    await db.reset_otps.update_one({"identifier": p.identifier.strip()}, {"$set": {"verified": True}})
    return {"message": "OTP verified"}

@api.post("/auth/forgot-password-reset")
async def forgot_password_reset(p: ForgotPasswordResetIn):
    rec = await db.reset_otps.find_one({"identifier": p.identifier.strip(), "verified": True})
    if not rec: raise HTTPException(400, "Not verified. Please verify OTP first.")
    if len(p.new_password) < 6: raise HTTPException(400, "Password must be at least 6 characters")
    await db.users.update_one({"id": rec["user_id"]}, {"$set": {"password_hash": hashpw(p.new_password)}})
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
        {"$set": {"email": p.email, "otp_hash": hashpw(code), "otp_expires_at": now() + timedelta(minutes=10), "verified": False}},
        upsert=True
    )
    send_otp_email(p.email, code)
    return {"message": "OTP sent", "demo_otp": code if DEMO_MODE else None}

@api.post("/auth/email-verify-init")
async def email_verify_init(p: EmailVerifyIn):
    rec = await db.email_otps.find_one({"email": p.email})
    if not rec: raise HTTPException(400, "Email not found")
    exp = rec["otp_expires_at"]
    if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if now() > exp: raise HTTPException(400, "OTP expired")
    if not verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
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
        "password_hash": hashpw(p.password), "is_verified": True,
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
    return {"token": make_token(uid), "user_id": uid}

# ── Auth Phone ──────────────────────────────────────────────
@api.post("/auth/phone-signup-init")
async def phone_signup_init(p: PhoneInitIn):
    await purge_expired_deleted_account("phone", p.phone)
    await check_delete_recreate_abuse(p.phone)
    code = f"{random.randint(0,9999):04d}"
    await db.phone_otps.update_one(
        {"phone": p.phone},
        {"$set": {"phone": p.phone, "otp_hash": hashpw(code), "otp_expires_at": now() + timedelta(minutes=10), "verified": False}},
        upsert=True
    )
    sms_sent = send_otp_sms(p.phone, code)
    return {"message": "OTP sent", "demo_otp": code if not sms_sent else None}

@api.post("/auth/phone-verify-init")
async def phone_verify_init(p: PhoneVerifyIn):
    rec = await db.phone_otps.find_one({"phone": p.phone})
    if not rec: raise HTTPException(400, "Phone not found")
    exp = rec["otp_expires_at"]
    if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if now() > exp: raise HTTPException(400, "OTP expired")
    if not verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Incorrect OTP")
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
        "id": uid, "phone": p.phone, "email": f"{p.phone.replace('+','')}@phone.post",
        "name": p.name, "username": p.username, "handle": f"@{p.username}", "dob": p.dob,
        "password_hash": hashpw(p.password), "is_verified": True,
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
    return {"token": make_token(uid), "user_id": uid}

@api.post("/auth/phone-login")
async def phone_login(p: PhoneLoginIn):
    u = await db.users.find_one({"phone": p.phone})
    if not u or not verifypw(p.password, u.get("password_hash","")): raise HTTPException(400, "Invalid phone or password")
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
    query = {"id": {"$ne": u["id"]}, "is_verified": True, "deleted_at": None}
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
    
    posts_count = await db.posts.count_documents({"user_id": user_id})
    followers_count = len(user.get("followers", []))
    following_count = len(user.get("following", []))
    
    return {
        **user,
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
        "likes": [], "comments": [], "views": [], "created_at": now().isoformat(),
        "edited_at": None, "is_pinned": False
    }
    await db.posts.insert_one(doc.copy())
    doc.pop("_id", None)
    return doc

@api.get("/posts")
async def list_posts(q: Optional[str] = None, skip: int = 0, limit: int = 50, u=Depends(current_user)):
    query = {}
    if q:
        query["$or"] = [
            {"content": {"$regex": q, "$options": "i"}}, 
            {"user_name": {"$regex": q, "$options": "i"}}, 
            {"location": {"$regex": q, "$options": "i"}}
        ]
    posts = await db.posts.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.posts.count_documents(query)
    
    # Add view tracking
    for post in posts:
        if u["id"] not in post.get("views", []):
            await db.posts.update_one({"id": post["id"]}, {"$push": {"views": u["id"]}})
    
    return {"posts": posts, "total": total, "skip": skip, "limit": limit}

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
    """Edit post content"""
    post = await db.posts.find_one({"id": pid})
    if not post: raise HTTPException(404, "Post not found")
    if post["user_id"] != u["id"]: raise HTTPException(403, "Not your post")
    
    await db.posts.update_one({"id": pid}, {"$set": {
        "content": p.content,
        "accent": p.accent,
        "location": p.location or "",
        "edited_at": now().isoformat()
    }})
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
    """Follow a user"""
    if user_id == u["id"]: raise HTTPException(400, "Can't follow yourself")
    
    target = await db.users.find_one({"id": user_id})
    if not target: raise HTTPException(404, "User not found")
    
    # Add to following
    if u["id"] not in target.get("followers", []):
        await db.users.update_one({"id": user_id}, {"$push": {"followers": u["id"]}})
    if user_id not in u.get("following", []):
        await db.users.update_one({"id": u["id"]}, {"$push": {"following": user_id}})
    
    # Create notification
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "from_user_id": u["id"],
        "from_user_name": u["name"],
        "type": "follow",
        "created_at": now().isoformat(),
        "read": False
    })
    
    return {"ok": True}

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

# ── Friends ──────────────────────────────────────────────────
@api.post("/friends/request")
async def friend_request(p: FriendIn, u=Depends(current_user)):
    if p.target_user_id == u["id"]: raise HTTPException(400, "Can't friend yourself")
    existing = await db.friend_requests.find_one({"from_id": u["id"], "to_id": p.target_user_id})
    if existing: return {"status": existing["status"]}
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
    friends = await db.users.find(
        {"id": {"$in": friend_ids}}, 
        {"_id": 0, "password_hash": 0, "otp_hash": 0}
    ).to_list(500)
    return {"friends": friends, "pending_incoming": pending_in, "pending_outgoing": pending_out}

# ── Messages ─────────────────────────────────────────────────
@api.post("/messages")
async def send_message(p: MessageIn, u=Depends(current_user)):
    m = {
        "id": str(uuid.uuid4()), 
        "from_id": u["id"], 
        "from_name": u["name"], 
        "to_id": p.to_user_id, 
        "text": p.text, 
        "created_at": now().isoformat(),
        "read": False
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
    
    msgs = await db.messages.find(q, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.messages.count_documents(q)
    
    # Mark as read
    if with_user:
        await db.messages.update_many(
            {"from_id": with_user, "to_id": u["id"], "read": False},
            {"$set": {"read": True}}
        )
    
    return {"messages": msgs, "total": total, "skip": skip, "limit": limit}

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
    if not verifypw(p.current_password, u.get("password_hash", "")):
        raise HTTPException(400, "Current password is incorrect")
    if len(p.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    await db.users.update_one({"id": u["id"]}, {"$set": {"password_hash": hashpw(p.new_password)}})
    return {"message": "Password updated successfully"}

# ── Health ───────────────────────────────────────────────────
@api.get("/")
async def root(): 
    return {
        "status": "ok", 
        "demo_mode": DEMO_MODE, 
        "twilio": bool(TWILIO_SID),
        "version": "2.0"
    }

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
