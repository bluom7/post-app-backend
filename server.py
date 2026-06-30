from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os, uuid, random, logging, bcrypt, jwt, re
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime, timezone, timedelta

load_dotenv()

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME   = os.environ.get("DB_NAME", "postapp")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
TWILIO_SID   = os.environ.get("TWILIO_SID", "").strip()
TWILIO_TOKEN = os.environ.get("TWILIO_TOKEN", "").strip()
TWILIO_PHONE = os.environ.get("TWILIO_PHONE", "").strip()

DEMO_MODE = not bool(RESEND_API_KEY)

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
        resend.Emails.send({
            "from": "POST App <noreply@postbluom.online>",
            "to": [email],
            "subject": "Your POST verification code",
            "html": f"<div style='font-family:sans-serif;max-width:400px;margin:auto;padding:24px;background:#111;color:#fff;border-radius:16px;'><h1 style='color:#FFD600;letter-spacing:6px;'>POST</h1><p>Your verification code:</p><div style='font-size:36px;font-weight:900;letter-spacing:10px;color:#FFD600;padding:16px 0;'>{code}</div><p style='color:#666;font-size:13px;'>Valid for 10 minutes.</p></div>"
        })
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
    """Disabled: usernames no longer need to be unique."""
    return

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
    avatar_bg: Optional[str] = None
    avatar_letter: Optional[str] = None
    avatar_photo: Optional[str] = None
    language: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if v is None: return v
        v = v.strip().lower()
        if not USERNAME_RE.match(v):
            raise ValueError("Username: 3-20 chars, only lowercase letters, numbers, underscore")
        return v

class PostIn(BaseModel):
    content: str; accent: str = "#FFD600"; location: Optional[str] = None

class CommentIn(BaseModel): text: str
class LikeIn(BaseModel): color: Optional[str] = None
class MessageIn(BaseModel):
    to_user_id: str; text: str
class FriendIn(BaseModel):
    target_user_id: str

# ── Auth Email ───────────────────────────────────────────────
@api.post("/auth/signup")
async def signup(p: SignupIn):
    existing = await db.users.find_one({"email": p.email})
    if existing and existing.get("is_verified"):
        raise HTTPException(400, "Email already registered")
    await ensure_username_unique(p.username, exclude_uid=existing["id"] if existing else None)
    code = f"{random.randint(0,9999):04d}"
    uid = existing["id"] if existing else str(uuid.uuid4())
    colors = ["#FFD600","#00C853","#FF1744","#2979FF"]
    doc = {
        "id": uid, "email": p.email, "name": p.name, "username": p.username,
        "handle": f"@{p.username}",
        "password_hash": hashpw(p.password), "is_verified": False,
        "otp_hash": hashpw(code), "otp_expires_at": now() + timedelta(minutes=10),
        "avatar_bg": random.choice(colors), "avatar_letter": p.name[0].upper(),
        "avatar_photo": None, "location": "", "about": "", "language": "en",
        "continent": "Asia", "created_at": now(), "is_seed": False,
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
    return {"token": make_token(u["id"]), "user_id": u["id"]}

@api.post("/auth/resend-otp")
async def resend_otp(body: dict):
    u = await db.users.find_one({"email": body.get("email")})
    if not u: raise HTTPException(400, "User not found")
    code = f"{random.randint(0,9999):04d}"
    await db.users.update_one({"id": u["id"]}, {"$set": {"otp_hash": hashpw(code), "otp_expires_at": now() + timedelta(minutes=10)}})
    send_otp_email(u["email"], code)
    return {"message": "Resent", "demo_otp": code if DEMO_MODE else None}

# ── Auth Email (OTP-first, phone jaisa flow) ──────────────────
@api.post("/auth/email-signup-init")
async def email_signup_init(p: EmailInitIn):
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
    if not rec: raise HTTPException(400, "Email not found — pehle OTP bhejo")
    exp = rec["otp_expires_at"]
    if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if now() > exp: raise HTTPException(400, "OTP expire ho gaya")
    if not verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Galat OTP")
    await db.email_otps.update_one({"email": p.email}, {"$set": {"verified": True}})
    return {"message": "Email verified"}

@api.post("/auth/email-signup")
async def email_signup(p: EmailSignupIn):
    rec = await db.email_otps.find_one({"email": p.email, "verified": True})
    if not rec: raise HTTPException(400, "Email verified nahi hai")
    existing = await db.users.find_one({"email": p.email, "is_verified": True})
    if existing: raise HTTPException(400, "Email already registered")
    await ensure_username_unique(p.username)
    colors = ["#FFD600","#00C853","#FF1744","#2979FF"]
    uid = str(uuid.uuid4())
    doc = {
        "id": uid, "email": p.email, "name": p.name, "username": p.username,
        "handle": f"@{p.username}", "dob": p.dob,
        "password_hash": hashpw(p.password), "is_verified": True,
        "avatar_bg": random.choice(colors), "avatar_letter": p.name[0].upper(),
        "avatar_photo": None, "location": "", "about": "", "language": "en",
        "continent": "Asia", "created_at": now(), "is_seed": False,
    }
    await db.users.insert_one(doc)
    await db.email_otps.delete_one({"email": p.email})
    return {"token": make_token(uid), "user_id": uid}

# ── Auth Phone (Twilio) ──────────────────────────────────────
@api.post("/auth/phone-signup-init")
async def phone_signup_init(p: PhoneInitIn):
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
    if not rec: raise HTTPException(400, "Phone not found — pehle OTP bhejo")
    exp = rec["otp_expires_at"]
    if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if now() > exp: raise HTTPException(400, "OTP expire ho gaya")
    if not verifypw(p.otp, rec["otp_hash"]): raise HTTPException(400, "Galat OTP")
    await db.phone_otps.update_one({"phone": p.phone}, {"$set": {"verified": True}})
    return {"message": "Phone verified"}

@api.post("/auth/phone-signup")
async def phone_signup(p: PhoneSignupIn):
    rec = await db.phone_otps.find_one({"phone": p.phone, "verified": True})
    if not rec: raise HTTPException(400, "Phone verified nahi hai")
    existing = await db.users.find_one({"phone": p.phone, "is_verified": True})
    if existing: raise HTTPException(400, "Phone already registered")
    await ensure_username_unique(p.username)
    colors = ["#FFD600","#00C853","#FF1744","#2979FF"]
    uid = str(uuid.uuid4())
    doc = {
        "id": uid, "phone": p.phone, "email": f"{p.phone.replace('+','')}@phone.post",
        "name": p.name, "username": p.username, "handle": f"@{p.username}", "dob": p.dob,
        "password_hash": hashpw(p.password), "is_verified": True,
        "avatar_bg": random.choice(colors), "avatar_letter": p.name[0].upper(),
        "avatar_photo": None, "location": "", "about": "", "language": "en",
        "continent": "Asia", "created_at": now(), "is_seed": False,
    }
    await db.users.insert_one(doc)
    await db.phone_otps.delete_one({"phone": p.phone})
    return {"token": make_token(uid), "user_id": uid}

@api.post("/auth/phone-login")
async def phone_login(p: PhoneLoginIn):
    u = await db.users.find_one({"phone": p.phone})
    if not u or not verifypw(p.password, u.get("password_hash","")): raise HTTPException(400, "Galat phone ya password")
    if not u.get("is_verified"): raise HTTPException(400, "Account verified nahi")
    return {"token": make_token(u["id"]), "user_id": u["id"]}

@api.get("/auth/me")
async def me(u=Depends(current_user)): return u

# ── Profile ──────────────────────────────────────────────────
@api.patch("/profile")
async def update_profile(p: ProfileUpdate, u=Depends(current_user)):
    upd = {k: v for k,v in p.dict().items() if v is not None}
    if "username" in upd:
        await ensure_username_unique(upd["username"], exclude_uid=u["id"])
        upd["handle"] = f"@{upd['username']}"
    if upd:
        await db.users.update_one({"id": u["id"]}, {"$set": upd})
        post_upd = {}
        if "name" in upd: post_upd["user_name"] = upd["name"]
        if "handle" in upd: post_upd["user_handle"] = upd["handle"]
        if "avatar_bg" in upd: post_upd["avatar_bg"] = upd["avatar_bg"]
        if "avatar_letter" in upd: post_upd["avatar_letter"] = upd["avatar_letter"]
        if "avatar_photo" in upd: post_upd["avatar_photo"] = upd["avatar_photo"]
        if post_upd:
            await db.posts.update_many({"user_id": u["id"]}, {"$set": post_upd})
    return await db.users.find_one({"id": u["id"]}, {"_id": 0, "password_hash": 0, "otp_hash": 0})

# ── Users ────────────────────────────────────────────────────
@api.get("/users")
async def list_users(continent: Optional[str] = None, q: Optional[str] = None, u=Depends(current_user)):
    query = {"id": {"$ne": u["id"]}, "is_verified": True}
    if continent and continent != "All": query["continent"] = continent
    if q:
        query["$or"] = [{"name": {"$regex": q, "$options": "i"}}, {"handle": {"$regex": q, "$options": "i"}}, {"username": {"$regex": q, "$options": "i"}}, {"location": {"$regex": q, "$options": "i"}}]
    users = await db.users.find(query, {"_id": 0, "password_hash": 0, "otp_hash": 0}).limit(200).to_list(200)
    return users

# ── Posts ────────────────────────────────────────────────────
@api.post("/posts")
async def create_post(p: PostIn, u=Depends(current_user)):
    doc = {
        "id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"],
        "user_handle": u["handle"], "avatar_bg": u["avatar_bg"],
        "avatar_letter": u["avatar_letter"], "avatar_photo": u.get("avatar_photo"),
        "content": p.content, "accent": p.accent, "location": p.location or "",
        "likes": [], "comments": [], "created_at": now().isoformat()
    }
    await db.posts.insert_one(doc.copy())
    doc.pop("_id", None)
    return doc

@api.get("/posts")
async def list_posts(q: Optional[str] = None, u=Depends(current_user)):
    query = {}
    if q:
        query["$or"] = [{"content": {"$regex": q, "$options": "i"}}, {"user_name": {"$regex": q, "$options": "i"}}, {"location": {"$regex": q, "$options": "i"}}]
    posts = await db.posts.find(query, {"_id": 0}).sort("created_at", -1).limit(200).to_list(200)
    return posts

@api.delete("/posts/{pid}")
async def delete_post(pid: str, u=Depends(current_user)):
    post = await db.posts.find_one({"id": pid})
    if not post: raise HTTPException(404, "Not found")
    if post["user_id"] != u["id"]: raise HTTPException(403, "Not your post")
    await db.posts.delete_one({"id": pid})
    return {"ok": True}

@api.post("/posts/{pid}/like")
async def like_post(pid: str, p: LikeIn, u=Depends(current_user)):
    post = await db.posts.find_one({"id": pid})
    if not post: raise HTTPException(404, "Not found")
    likes = [l for l in post.get("likes", []) if l["user_id"] != u["id"]]
    if p.color: likes.append({"user_id": u["id"], "color": p.color})
    await db.posts.update_one({"id": pid}, {"$set": {"likes": likes}})
    return {"likes": likes}

@api.post("/posts/{pid}/comments")
async def add_comment(pid: str, p: CommentIn, u=Depends(current_user)):
    c = {"id": str(uuid.uuid4()), "user_id": u["id"], "user_name": u["name"], "text": p.text, "created_at": now().isoformat()}
    await db.posts.update_one({"id": pid}, {"$push": {"comments": c}})
    return c

# ── Friends ──────────────────────────────────────────────────
@api.post("/friends/request")
async def friend_request(p: FriendIn, u=Depends(current_user)):
    if p.target_user_id == u["id"]: raise HTTPException(400, "Can't friend yourself")
    existing = await db.friend_requests.find_one({"from_id": u["id"], "to_id": p.target_user_id})
    if existing: return {"status": existing["status"]}
    await db.friend_requests.insert_one({"id": str(uuid.uuid4()), "from_id": u["id"], "to_id": p.target_user_id, "status": "pending", "created_at": now().isoformat()})
    return {"status": "pending"}

@api.post("/friends/accept")
async def friend_accept(p: FriendIn, u=Depends(current_user)):
    await db.friend_requests.update_one({"from_id": p.target_user_id, "to_id": u["id"], "status": "pending"}, {"$set": {"status": "accepted"}})
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
    accepted = await db.friend_requests.find({"$or": [{"from_id": u["id"], "status": "accepted"}, {"to_id": u["id"], "status": "accepted"}]}, {"_id": 0}).to_list(500)
    friend_ids = [r["to_id"] if r["from_id"] == u["id"] else r["from_id"] for r in accepted]
    pending_in = await db.friend_requests.find({"to_id": u["id"], "status": "pending"}, {"_id": 0}).to_list(500)
    pending_out = await db.friend_requests.find({"from_id": u["id"], "status": "pending"}, {"_id": 0}).to_list(500)
    friends = await db.users.find({"id": {"$in": friend_ids}}, {"_id": 0, "password_hash": 0, "otp_hash": 0}).to_list(500)
    return {"friends": friends, "pending_incoming": pending_in, "pending_outgoing": pending_out}

# ── Messages ─────────────────────────────────────────────────
@api.post("/messages")
async def send_message(p: MessageIn, u=Depends(current_user)):
    m = {"id": str(uuid.uuid4()), "from_id": u["id"], "from_name": u["name"], "to_id": p.to_user_id, "text": p.text, "created_at": now().isoformat()}
    await db.messages.insert_one(m.copy())
    m.pop("_id", None)
    return m

@api.get("/messages")
async def list_messages(with_user: Optional[str] = None, u=Depends(current_user)):
    if with_user:
        q = {"$or": [{"from_id": u["id"], "to_id": with_user}, {"from_id": with_user, "to_id": u["id"]}]}
    else:
        q = {"$or": [{"from_id": u["id"]}, {"to_id": u["id"]}]}
    msgs = await db.messages.find(q, {"_id": 0}).sort("created_at", 1).limit(500).to_list(500)
    return msgs

# ── Health ───────────────────────────────────────────────────
@api.get("/")
async def root(): return {"status": "ok", "demo_mode": DEMO_MODE, "twilio": bool(TWILIO_SID)}

# ── Seed ─────────────────────────────────────────────────────
@app.on_event("startup")
async def seed():
    if await db.users.count_documents({"is_seed": True}) > 0: return
    WORLD = [
        ("Aryan","@aryan_world","Mumbai, India","Photographer & traveller 📷","Asia","#FFD600"),
        ("Bella","@bella_creates","London, UK","Designer. Coffee lover ☕","Europe","#00C853"),
        ("Carlos","@carlos_global","Mexico City","Entrepreneur 🚀","Americas","#2979FF"),
        ("Yuki","@yuki_jp","Tokyo, Japan","Manga artist 🎨","Asia","#00C853"),
        ("Fatima","@fatima_sa","Riyadh, Saudi Arabia","Writer & poet ✍️","Asia","#FF1744"),
        ("Pierre","@pierre_fr","Paris, France","Chef & food blogger 🥐","Europe","#FF1744"),
        ("Lucas","@lucas_br","São Paulo, Brazil","Carnaval organizer 🎉","Americas","#00C853"),
        ("Chioma","@chioma_ng","Lagos, Nigeria","Fashion designer 👗","Africa","#2979FF"),
        ("Jack","@jack_au","Sydney, Australia","Surfer & barista ☕","Oceania","#00C853"),
        ("Soo-Jin","@soojin_kr","Seoul, South Korea","K-pop enthusiast 🎵","Asia","#FF1744"),
        ("Anna","@anna_se","Stockholm, Sweden","Environmentalist 🌿","Europe","#2979FF"),
        ("Amara","@amara_ke","Nairobi, Kenya","Safari guide 🦁","Africa","#FFD600"),
    ]
    for name, handle, loc, about, continent, color in WORLD:
        uid = str(uuid.uuid4())
        await db.users.insert_one({"id": uid, "email": f"{handle[1:]}@post.demo", "username": handle[1:], "name": name, "handle": handle, "is_verified": True, "is_seed": True, "avatar_bg": color, "avatar_letter": name[0], "avatar_photo": None, "location": loc, "about": about, "continent": continent, "language": "en", "created_at": now()})
    logging.info("✅ World users seeded")

app.include_router(api)

@app.on_event("shutdown")
async def shutdown(): client.close()
