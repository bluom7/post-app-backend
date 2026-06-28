# POST App — Backend Deployment Guide

## Files in this folder
- `server.py` — FastAPI backend (all APIs)
- `requirements.txt` — Python dependencies
- `render.yaml` — Render deployment config
- `.env.example` — Environment variables template

---

## STEP 1 — MongoDB Atlas Setup

1. Go to https://mongodb.com/atlas → Create free account
2. Create cluster → M0 Free tier
3. Click "Connect" → "Drivers" → Copy connection string:
   `mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/`
4. Network Access → Add IP → Allow from Anywhere (0.0.0.0/0)

---

## STEP 2 — Resend Email Setup

1. Go to https://resend.com → Create free account
2. Dashboard → API Keys → Create key → Copy it
3. Free plan: 3000 emails/month

---

## STEP 3 — Deploy on Render

1. Push this folder to GitHub (create new repo)
2. Go to https://render.com → New Web Service
3. Connect your GitHub repo
4. Settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn server:app --host 0.0.0.0 --port $PORT`
   - Environment: Python 3
5. Add Environment Variables:
   - `MONGO_URL` = your Atlas connection string
   - `DB_NAME` = postapp
   - `JWT_SECRET` = any random string
   - `RESEND_API_KEY` = your Resend key (optional, leave empty for demo)
6. Deploy → Wait 2-3 minutes
7. Copy your URL: `https://post-app-backend.onrender.com`

---

## STEP 4 — Update Frontend

In your React JSX file, change line:
```js
const API_BASE = "";
```
to:
```js
const API_BASE = "https://YOUR-RENDER-URL.onrender.com/api";
```

---

## STEP 5 — Mobile App (Expo)

1. Install: `npm install -g expo-cli`
2. Create app: `npx create-expo-app PostApp`
3. Copy the JSX code into `App.js`
4. Add API_BASE with your Render URL
5. Run: `npx expo start`
6. Scan QR code with Expo Go app (Android/iOS)

For Play Store:
- `npx expo build:android`
- Upload to Google Play Console

For App Store:
- `npx expo build:ios`
- Upload to App Store Connect

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/auth/signup | No | Register |
| POST | /api/auth/verify-otp | No | Verify email |
| POST | /api/auth/login | No | Login |
| POST | /api/auth/resend-otp | No | Resend OTP |
| GET | /api/auth/me | Yes | Get profile |
| PATCH | /api/profile | Yes | Update profile |
| GET | /api/users | Yes | Discover users |
| GET | /api/posts | Yes | Get posts |
| POST | /api/posts | Yes | Create post |
| DELETE | /api/posts/:id | Yes | Delete post |
| POST | /api/posts/:id/like | Yes | Like post |
| POST | /api/posts/:id/comments | Yes | Comment |
| GET | /api/friends | Yes | Friends list |
| POST | /api/friends/request | Yes | Send request |
| POST | /api/friends/accept | Yes | Accept request |
| POST | /api/friends/decline | Yes | Decline request |
| POST | /api/friends/cancel | Yes | Cancel request |
| GET | /api/messages | Yes | Get messages |
| POST | /api/messages | Yes | Send message |
