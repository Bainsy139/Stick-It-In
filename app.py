"""
Stick It In (SII) – Flask app (learning notes)

This file powers the web edition of SII. I’m documenting decisions as I go so reviewers can see how I’m thinking:
- Use environment variables via python-dotenv for secrets (never hardcode).
- Prefer Firebase Admin ADC on Cloud Run; fall back locally.
- Keep sessions cookie-based for Cloud Run (stateless containers).
- Add small, testable routes before big refactors; commit in small slices.
"""
# -----------------------------------
# 0 - Imports
# -----------------------------------

# operating 
# it utilises my computer OS 
import os

# this is the environment variables that rely on secrets, 
# load dot env is the file in which my secrets are stored?
from dotenv import load_dotenv

import requests  
import base64

# Runs a function once after a delay
from threading import Timer

# -----------------------------------
# Flask
# -----------------------------------
# flask creates the app
# render template returns HTML from jinja templates
# requests reads the data, forms and json files 
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Blueprint, send_from_directory

# access to my firebase account 
# credentials and auth for verification
# firestore for the database itself
import firebase_admin
from firebase_admin import credentials, auth, firestore

# this was used to create random string tokens
# i don't think i was successful with this 
import random

# used in conjuction with creating random strings - or at least i thought so. 
import string

# this was for sending emails, still currently not working, but still a WIP.
# dont hard code the secrets!!!
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# I have a different file called userModel to define the DB fields each user needs in firestore
# I want to import the function UserModel to use for new user functions
from userModel import UserModel


# should this ne directly under import datetime? 
from datetime import datetime, timedelta, timezone

# simple regex validation for usernames
import re

import json

# Firebase Storage + image header validation
from google.cloud import storage
import imghdr

# rounds up to the neartest integer, useful for page counts, price tiers or probability rounding.
from math import ceil

# counter tallies items (great for 'most picked' teams)
# default dict creates dicts - perfect for community insights.
from collections import defaultdict, Counter

# What: read/write CSVs.
# Where: exports/imports.
# Why: simple reports.
import csv

import logging
# loads all secrets from .env
load_dotenv()

# Developer note:
# load_dotenv() reads .env when developing locally. In production (Cloud Run)
# I set real env vars on the service. This keeps secrets out of the repo.
# I try to access everything through os.getenv(...) below to avoid surprises.

# --- Firebase key strategy ---
# Use two keys when possible:
#  - FIREBASE_WEB_API_KEY          → browser key (referrer restricted)
#  - FIREBASE_WEB_API_KEY_SERVER   → server key (no referrer restriction; API-restricted)
# During local dev with only a browser key, we send a Referer header that matches an allowed origin.




# -----------------------------------------------------
# 1 - Firebase Admin Initialization
#     Use Application Default Credentials (ADC) on Cloud Run
#     and fall back to local ADC when developing.
# -----------------------------------------------------
# Learning note:
# Firebase Admin prefers "Application Default Credentials" (ADC). On Cloud Run,
# ADC is provided automatically via Workload Identity. Locally I let it discover
# credentials if available, but I don't commit any JSON keyfiles.
# If project_id is discoverable, I pass it; otherwise I let the SDK infer it.

if not firebase_admin._apps:
    # Hint Cloud Run/local which project to bind to, if discoverable.
    project_id = (
        os.getenv("GOOGLE_CLOUD_PROJECT")
        or os.getenv("GCLOUD_PROJECT")
        or os.getenv("FIREBASE_PROJECT_ID")
    )
    try:
        if project_id:
            firebase_admin.initialize_app(options={"projectId": project_id})
        else:
            firebase_admin.initialize_app()
        print(f"✅ Firebase Admin initialized (ADC). project_id={project_id or 'auto'}")
    except Exception as e:
        # One last gentle retry without options
        try:
            firebase_admin.initialize_app()
            print("✅ Firebase Admin initialized (ADC, no explicit projectId).")
        except Exception as e2:
            raise RuntimeError(f"🔥 Failed to initialize Firebase Admin via ADC: {e2}")

db = firestore.client()

app = Flask(__name__)
# Sessions in Flask are signed with a secret key (HMAC). I pull it from env so
# I never commit secrets. If it's missing, I fail fast to avoid debugging ghosts.
app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY not set in environment")

# -----------------------------------------------------
# 2) Cookie-based Session Configuration (Cloud Run safe)
# -----------------------------------------------------
# Why cookie sessions?
# Cloud Run instances are ephemeral; filesystem sessions could disappear on swap.
# Signed cookies avoid that problem and are fine for small payloads (IDs, flags).
app.permanent_session_lifetime = timedelta(days=365)

# Use signed cookies (Flask default) instead of filesystem-backed sessions.
# This avoids Cloud Run instance swaps wiping your session files.

# Allow overriding cookie security via env. Default: secure in prod, not in dev.
_secure_env = os.getenv("SESSION_COOKIE_SECURE", "").lower()
_secure_flag = True if _secure_env in ("1", "true", "yes") else False
if not _secure_env:
    # If not explicitly set, infer from FLASK_ENV/ENV
    _secure_flag = os.getenv("FLASK_ENV", "").lower() == "production" or os.getenv("ENV", "").lower() == "production"

app.config.update(
    SESSION_COOKIE_SECURE=_secure_flag,      # only sent over HTTPS in prod
    SESSION_COOKIE_HTTPONLY=True,            # not accessible to JS
    SESSION_COOKIE_SAMESITE="Lax",           # good default for normal nav
    # Set in prod to share between apex + www (e.g. ".stickitin.co.uk")
    SESSION_COOKIE_DOMAIN=os.getenv("SESSION_COOKIE_DOMAIN")
)

# Refresh cookie expiry on each request while the user is active
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

# Optional: set a canonical host (e.g., "stickitin.co.uk") to prevent cookie
# fragmentation between www / apex. Only enforced if env var is present.
app.config["CANONICAL_HOST"] = os.getenv("CANONICAL_HOST")

if not app.secret_key:
    print("⚠️ FLASK_SECRET_KEY is not set; sessions may not persist reliably.")

@app.before_request
def _set_permanent_and_canonical():
    """Ensure sessions persist and redirect to the canonical host to avoid cookie splits."""
    # Ensure sessions are permanent (use above lifetime)
    session.permanent = True
    # Enforce canonical host if configured (prevents www/apex cookie split)
    ch = app.config.get("CANONICAL_HOST")
    if ch:
        host = request.host.split(":")[0]
        if host != ch:
            return redirect(request.url.replace(host, ch, 1), code=301)


# -----------------------------------------------------
# Session guard for protected pages (NO Firebase token check)
# -----------------------------------------------------
@app.before_request
def _require_session_for_protected_pages():
    """Very simple gate: redirect to /login if a page needs a user session."""
    # Only guard app pages that need login; allow auth endpoints and static
    open_paths = {"/login", "/signup", "/", "/static/"}
    p = request.path
    if any(p == op or p.startswith(op) for op in open_paths):
        return  # allow
    if "user_id" not in session:
        return redirect(url_for("login"))


# -----------------------------------------------------
# 3) Firebase Web API Key (same as in your HTML's firebaseConfig)
#    Typically found in your Firebase project settings.
#    For a real production app, keep this somewhere safer (like an env variable).
# -----------------------------------------------------
FIREBASE_WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY")

'''verification_codes = {}'''

# -----------------------------------------------------
# User doc schema (defaults used at signup/bootstrap)
# -----------------------------------------------------
def build_default_user_doc(uid: str, email: str, username: str = "") -> dict:
    """Return a complete user document with sensible defaults for V3."""
    # Username can be blank at signup; managerName too. Users fill these in Profile.
    return {
        "uid": uid,
        "email": email,
        "username": (username or "").strip().lower(),
        "managerName": "",
        "clubImageUrl": "",

        # Game state counters
        "predictionCount": 10,
        "bttsCount": 10,
        "totalPredictions": 0,
        "totalBTTS": 0,
        "correctPredictions": 0,
        "correctBTTS": 0,

        # Cards & penalties
        "yellowCardsAvailable": 0,
        "redCardsAvailable": 0,
        "injuriesAvailable": 0,
        "yellowCardsReceived": 0,
        "redCardsReceived": 0,
        "injuriesReceived": 0,

        # Misc league/app fields
        "coinBalance": 0,
        "clubID": None,
        "isAdmin": False,

        # Metadata
        "created_at": firestore.SERVER_TIMESTAMP,
        "updated_at": firestore.SERVER_TIMESTAMP
    }

'''
# ✅ Email Configuration
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))  # make sure to cast as int
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
if not all([SMTP_SERVER, SMTP_EMAIL, SMTP_PASSWORD]):
    print("⚠️ Warning: SMTP settings incomplete. Email functions may fail.")

def send_email(to_email, subject, body):
    """ Sends an email using Gmail SMTP """
    msg = MIMEMultipart()
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        server.quit()
        print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Email failed: {e}")

def send_verification_email(email):
    """
    Generates and sends a Firebase email verification link to the user.
    """
    try:
        link = auth.generate_email_verification_link(email)
        subject = "Verify your Stick It In Account"
        body = f"Hi,\n\nPlease verify your email address by clicking the link below:\n\n{link}\n\nThanks,\nStick It In Team"
        send_email(email, subject, body)
        print(f"✅ Verification email sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send verification email to {email}: {e}")

# -----------------------------------------------------
# 4) Helper Function to Verify Email + Password w/ Firebase
# -----------------------------------------------------
def verify_password_with_firebase(email, password, api_key):
    """
    Calls Firebase's signInWithPassword endpoint to verify user's password.
    Returns a dict with user info (localId, idToken, etc.) if valid; otherwise None.

    Notes:
    - If you have referrer restrictions on your browser key, you must either
      (a) use an unrestricted *server* key (recommended) by setting the env var
          FIREBASE_WEB_API_KEY_SERVER, or
      (b) supply a Referer header that matches an allowed origin (temporary dev hack).
    """
    # Reviewer note:
    # This uses the REST Identity Toolkit. For local dev I may send a Referer header
    # to satisfy browser-key restrictions. In production I'd prefer a server-restricted key.
    # Prefer a dedicated server key if available
    server_key = os.getenv("FIREBASE_WEB_API_KEY_SERVER") or api_key
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={server_key}"

    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    # Temporary local-dev workaround for referrer-restricted keys:
    # allow overriding the Referer header; default to localhost.
    ref_header = os.getenv("FIREBASE_ALLOWED_REFERRER", "http://127.0.0.1:5001")
    headers = {"Referer": ref_header}

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
    except Exception as e:
        print(f"❌ signInWithPassword request error: {e}")
        return None

    if resp.status_code == 200:
        return resp.json()  # Contains localId, idToken, refreshToken, etc.
    else:
        # More explicit diagnostics without dumping the whole key
        key_tail = server_key[-6:] if server_key else "None"
        print("❌ signInWithPassword failed",
              {"status": resp.status_code, "key_tail": key_tail, "body": resp.text[:400]})
        return None
'''
# -----------------------------------------------------
# Creates user session
# -----------------------------------------------------
@app.route("/session", methods=["POST"])
def create_session():
    """Create a lightweight cookie session after verifying the user exists in Firestore."""
    try:
        data = request.get_json()
        email = data.get("email")

        print(f"📨 Received session request for {email}")

        user_query = db.collection("users").where("email", "==", email).limit(1).stream()
        user_data = None
        user_id = None

        for user_doc in user_query:
            user_data = user_doc.to_dict()
            user_id = user_doc.id  

        if not user_data:
            print("❌ User not found in Firestore")
            return jsonify({"success": False, "message": "User not found"}), 400

        session["user_id"] = user_id
        session["email"] = email
        session["username"] = user_data.get("username", "Unknown")
        session.permanent = True
        session.modified = True  

        print(f"✅ Session set for {email}")
        return jsonify({"success": True})

    except Exception as e:
        print(f"🔥 Error setting session: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

# -----------------------------------------------------
# Sign Up Route
# -----------------------------------------------------
from userModel import UserModel

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Minimal sign-up flow: create Firebase Auth user, send verification, seed Firestore doc."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']

        try:
            # ✅ Create Firebase Authentication user
            user = auth.create_user(email=email, password=password)
            auth.update_user(user.uid, password=password)
            auth.update_user(user.uid, email_verified=True)  # Optional: auto-verification

            # ✅ Send verification email anyway (can still be useful)
            send_verification_email(email)
            print("📧 Verification email queued via Admin SDK.")

            # ✅ Create full Firestore user with all required/default fields
            user_doc = build_default_user_doc(uid=user.uid, email=email, username=username)
            db.collection("users").document(user.uid).set(user_doc, merge=True)

            print(f"✅ Firestore user created or updated for {email}")
            flash("✅ Account created successfully! You can now log in.")
            return redirect(url_for('login'))

        except Exception as e:
            print(f"🔥 Signup Error: {e}")
            flash("❌ Sign up failed. Please check your details and try again.")

    return render_template('signup.html')

# -----------------------------------------------------
# Login Route 
# -----------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Form-based login: verify creds via Firebase REST, enforce email_verified, then set session."""
    if request.method == 'GET':
        return render_template('login.html')

    try:
        # ✅ Extract form data (NOT JSON)
        email = request.form.get("email")
        password = request.form.get("password")

        print(f"🧪 Login attempt for {email}")

        # ✅ Step 1: Verify password with Firebase REST
        auth_result = verify_password_with_firebase(email, password, FIREBASE_WEB_API_KEY)

        # Ensure auth_result is valid
        if not isinstance(auth_result, dict):
            flash("❌ Login failed. Invalid response from authentication.")
            return redirect(url_for("login"))

        # ✅ Step 2: Verify email is confirmed in Firebase
        firebase_user = auth.get_user_by_email(email)
        if not firebase_user.email_verified:
            flash("❌ Please verify your email before logging in.")
            return redirect(url_for("login"))

        # ✅ Step 3: Fetch or create Firestore user document
        user_uid = auth_result.get("localId")
        user_ref = db.collection("users").document(user_uid)
        user_doc = user_ref.get()

        if not user_doc.exists:
            # 🚀 Auto-create missing Firestore user document
            user_ref.set({
                "email": email,
                "username": email.split("@")[0],
                "created_at": firestore.SERVER_TIMESTAMP,
                "isAdmin": False,
                "predictionCount": 10,
                "bttsCount": 10,
                "correctPredictions": 0,
                "correctBTTS": 0,
                "clubID": None
            })
            print(f"👤 Created new Firestore user doc for {email}")
            user_doc = user_ref.get()  # Refresh it

        user_data = user_doc.to_dict()

        # ✅ Step 4: Set session
        session['user_id']  = user_uid
        session['email']    = email
        session['username'] = user_data.get("username", "Unknown")
        session['is_admin'] = user_data.get("isAdmin", False)
        session.modified    = True
        session.permanent = True

        print("✅ Session Set:", dict(session))

        return redirect(url_for("home"))

    except Exception as e:
        print(f"🔥 Exception in /login: {e}")
        flash("❌ Login failed. Please try again.")
        return redirect(url_for("login"))


# -----------------------------------------------------
# Logout Route
# -----------------------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    flash("👋 You have been logged out.")
    return redirect(url_for('login'))

# -----------------------------------------------------
# Client auth bridge: mint a Firebase custom token
# -----------------------------------------------------
@app.get("/auth/custom_token")
def auth_custom_token():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Not signed in"}), 401
    try:
        token = auth.create_custom_token(uid)
        return jsonify({"token": token.decode("utf-8")})
    except Exception as e:
        print("custom_token error:", e)
        return jsonify({"error": "Could not create token"}), 500
    

# ============================
# S26/27 ROUTES (NEW SEASON)
# ============================
@app.route("/s2627/home")
def s2627_home():
    return render_template("season2627home.html")


# -----------------------------------------------------
# Profile (view + update) – user-doc native
# -----------------------------------------------------
@app.route('/profile', methods=['GET'])
def profile():
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    uid = session["user_id"]
    snap = db.collection("users").document(uid).get()
    data = snap.to_dict() if snap.exists else {}

    return render_template(
        "profile.html",

        # Identity
        username=data.get("username", ""),
        managerName=data.get("managerName", ""),
        clubImageUrl=data.get("clubImageUrl", ""),
        teamValue=data.get("teamValue", 0.0),

        # Prediction stats (raw counts)
        totalPredictions=data.get("totalPredictions", 0),
        correctPredictions=data.get("correctPredictions", 0),
        predictionCount=data.get("predictionCount", 0),

        totalBTTS=data.get("totalBTTS", 0),
        correctBTTS=data.get("correctBTTS", 0),
        bttsCount=data.get("bttsCount", 0),

        # Discipline / cards (read‑only)
        yellowCardsReceived=data.get("yellowCardsReceived", 0),
        yellowCardsAvailable=data.get("yellowCardsAvailable", 0),

        redCardsReceived=data.get("redCardsReceived", 0),
        redCardsAvailable=data.get("redCardsAvailable", 0),

        injuriesReceived=data.get("injuriesReceived", 0),
        injuriesAvailable=data.get("injuriesAvailable", 0),
    )


@app.route('/profile/update', methods=['POST'])
def profile_update():
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    uid = session["user_id"]
    username = (request.form.get("username") or "").strip()
    managerName = (request.form.get("managerName") or "").strip()

    # Keep validations lightweight to match your Firestore Rules
    if len(username) > 40:
        flash("❌ Username too long (max 40 characters).")
        return redirect(url_for("profile"))

    if not (2 <= len(managerName) <= 40):
        flash("❌ Manager name must be 2–40 characters.")
        return redirect(url_for("profile"))

    try:
        db.collection("users").document(uid).set({
            "username": username,  # allow '' while transitioning away from pre-made clubs
            "managerName": managerName,
            "updated_at": firestore.SERVER_TIMESTAMP
        }, merge=True)
        flash("✅ Saved")
    except Exception as e:
        print(f"🔥 profile_update error: {e}")
        flash("⚠️ Failed to save changes. Please try again.")

    return redirect(url_for("profile"))

# -----------------------------------------------------
# Profile Avatar Upload → Firebase Storage (public read)
# -----------------------------------------------------
@app.route('/profile/upload_avatar', methods=['POST'])
def upload_avatar():
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    file = request.files.get('avatar')
    if not file or file.filename == '':
        flash("⚠️ No file selected.")
        return redirect(url_for('profile'))

    # Enforce small-ish uploads (2 MB)
    try:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
    except Exception:
        size = 0
    if size > 2 * 1024 * 1024:
        flash("⚠️ Image too large (max 2MB).")
        return redirect(url_for('profile'))

    # Validate image type by header sniffing
    head = file.read(512)
    file.seek(0)
    kind = imghdr.what(None, head)
    if kind not in ('jpeg', 'png', 'webp'):
        flash("⚠️ Please upload a JPEG, PNG, or WEBP image.")
        return redirect(url_for('profile'))

    uid = session["user_id"]
    ext = 'jpg' if kind == 'jpeg' else kind
    blob_path = f"avatars/{uid}/profile.{ext}"

    try:
        bucket_name = os.getenv("FIREBASE_STORAGE_BUCKET")
        if not bucket_name:
            raise RuntimeError("FIREBASE_STORAGE_BUCKET not set")
        print(f"[avatar] uploading to bucket: {bucket_name}")
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_path)

        # Cache for a day; browsers will revalidate on URL change
        blob.cache_control = "public, max-age=86400"
        blob.upload_from_file(file, content_type=f"image/{ext}")

        # Make the image publicly accessible (matches your Storage rules read:true)
        blob.make_public()
        public_url = blob.public_url

        # Save URL to user doc
        db.collection("users").document(uid).set({
            "clubImageUrl": public_url,
            "updated_at": firestore.SERVER_TIMESTAMP
        }, merge=True)

        flash("✅ Profile picture updated.")
    except Exception as e:
        print(f"avatar upload error: {e}")
        flash("⚠️ Failed to upload image.")

    return redirect(url_for('profile'))

# -----------------------------------------------------
# V3 routes here
# -----------------------------------------------------
'''@app.route("/quiz")
def quiz():
    with open("quiz_bank.json") as f:
        questions = json.load(f)
    selected_questions = random.sample(questions, 10)
    session["quiz"] = selected_questions  # ✅ store in session
    return render_template("quiz.html", questions=selected_questions)

@app.route("/submit_quiz", methods=["POST"])
def submit_quiz():
    questions = session.get("quiz", [])  # ✅ retrieve original 10

    score = 0
    for i in range(10):
        user_answer = request.form.get(f"q{i}")
        correct_answer = questions[i]["answer"]
        if user_answer == correct_answer:
            score += 1

    if score >= 8:
        return redirect(url_for("interest_form"))
    else:
        return render_template("result.html", score=score)


@app.route("/interest_form")
def interest_form():
    return render_template("interest_form.html")


@app.route("/submit_interest", methods=["POST"])
def submit_interest():
    name = request.form.get("name")
    email = request.form.get("email")
    club = request.form.get("club")

    data = {
        "name": name,
        "email": email,
        "club": club,
        "status": "pending",
        "timestamp": firestore.SERVER_TIMESTAMP
    }

    db.collection("quiz_passes").add(data)

    return render_template("confirmation.html", name=name) '''

@app.route("/home")
def home():
    """User dashboard: shows weekly timer state, leaderboard position, quick stats, and public pot graph."""
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    user_id = session["user_id"]


    # ---------------------------
    # Timer window (Mon 00:01 → Fri 23:58 UTC) vs weekend lockout
    # ---------------------------
    now = datetime.now(timezone.utc)
    weekday = now.weekday()
    monday_start = now - timedelta(days=weekday, hours=now.hour, minutes=now.minute,
                                   seconds=now.second, microseconds=now.microsecond) + timedelta(minutes=1)
    friday_end = monday_start + timedelta(days=4, hours=23, minutes=58)
    if monday_start <= now <= friday_end:
        mode = "prediction_window"
        time_left = friday_end - now
        days = time_left.days
        hours, remainder = divmod(time_left.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        time_left_str = f"{days}d {hours}h {minutes}m"
    else:
        mode = "weekend_lockout"
        time_left_str = None

    # ---------------------------
    # Defaults
    # ---------------------------
    username = ""
    manager_name = ""
    club_image_url = ""
    club_data = None
    club_name = None
    club_id = None
    league_position = None
    prediction_count = None
    btts_count = None
    team_value = None
    available_cards = []
    news = []
    season_number, week_number = 2025, 1
    pot_labels, pot_values = [], []
    all_users = []

    # ---------------------------
    # User & leaderboard
    # ---------------------------
    try:
        user_doc = db.collection("users").document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict() or {}

            # Identity from USER doc
            username = user_data.get("username", "") or ""
            manager_name = user_data.get("managerName", "") or ""
            club_image_url = user_data.get("clubImageUrl", "") or ""  # used for synthetic badge
            club_id = user_data.get("clubID")

            # Counts & stats
            prediction_count = user_data.get("predictionCount", 0)
            btts_count = user_data.get("bttsCount", 0)
            correct_btts = user_data.get("correctBTTS", 0)
            correct_predictions = user_data.get("correctPredictions", 0)
            total_predictions = user_data.get("totalPredictions", 0)
            total_btts = user_data.get("totalBTTS", 0)
            yellow_cards = user_data.get("yellowCardsReceived", 0)
            red_cards = user_data.get("redCardsReceived", 0)
            injuries = user_data.get("injuriesReceived", 0)

            total_games = total_predictions + total_btts

            if user_data.get("yellowCardsAvailable", 0) > 0:
                available_cards.append("yellow")
            if user_data.get("redCardsAvailable", 0) > 0:
                available_cards.append("red")
            if user_data.get("injuriesAvailable", 0) > 0:
                available_cards.append("injury")

            # Your adjusted points & accuracy
            _adjusted_points = (correct_predictions + correct_btts) - (
                yellow_cards + (3 * red_cards) + (2 * injuries)
            )
            _accuracy = round(
                ((correct_predictions + correct_btts) / total_games) * 100, 1
            ) if total_games > 0 else 0.0

            # Leaderboard (rank by adjusted points, then accuracy)
            leaderboard = []
            for u in db.collection("users").stream():
                u_data = u.to_dict() or {}
                u_points = u_data.get("correctPredictions", 0) + u_data.get("correctBTTS", 0)
                u_total = u_data.get("totalPredictions", 0) + u_data.get("totalBTTS", 0)
                if u_total < 2:
                    continue
                u_yellow = u_data.get("yellowCardsReceived", 0)
                u_red = u_data.get("redCardsReceived", 0)
                u_injury = u_data.get("injuriesReceived", 0)
                u_adjusted = u_points - (u_yellow + (3 * u_red) + (2 * u_injury))
                u_accuracy = round((u_points / u_total) * 100, 1) if u_total > 0 else 0.0
                leaderboard.append({
                    "id": u.id,
                    "adjusted_points": u_adjusted,
                    "accuracy": u_accuracy
                })

            leaderboard.sort(key=lambda x: (-x["adjusted_points"], -x["accuracy"]))
            for idx, u in enumerate(leaderboard):
                if u["id"] == user_id:
                    league_position = idx + 1
                    break

            # Value & naming from USER doc
            team_value = user_data.get("teamValue", 0.0)
            club_name = user_data.get("clubName") or (user_data.get("username", "") or None)

            # Synthesise a minimal club dict for {{ club.badgeUrl }}
            club_data = {"badgeUrl": club_image_url, "clubName": club_name}

    except Exception as e:
        print("🔥 Error fetching user/leaderboard data:", e)
        flash("Error loading your dashboard.")

    # ---------------------------
    # Season & announcements
    # ---------------------------
    try:
        season_doc = db.collection("state").document("seasonTracking").get()
        if season_doc.exists:
            season_data = season_doc.to_dict() or {}
            season_number = season_data.get("seasonYear", 2025)
            week_number = season_data.get("weekNumber", 1)
    except Exception as e:
        print("ℹ️ Season fallback:", e)

    try:
        news_doc = db.collection("state").document("announcements").get()
        if news_doc.exists:
            news = (news_doc.to_dict() or {}).get("news", []) or []
    except Exception as e:
        print("ℹ️ Announcements fallback:", e)

    # ---------------------------
    # Public pot graph (communityPotHistory collection)
    # ---------------------------
    try:
        pot_labels, pot_values = [], []
        q = db.collection("communityPotHistory").order_by(
            "week", direction=firestore.Query.ASCENDING
        )
        for doc in q.stream():
            d = doc.to_dict() or {}
            wk = d.get("week")
            if wk is None:
                try:
                    wk = int(doc.id)
                except Exception:
                    continue
            val = d.get("value")
            if val is None:
                continue
            pot_labels.append(wk)
            pot_values.append(float(val))

        # Sort by week
        zipped = sorted(zip(pot_labels, pot_values), key=lambda x: x[0])
        if zipped:
            pot_labels, pot_values = map(list, zip(*zipped))
        else:
            pot_labels, pot_values = [], []

    except Exception as e:
        print("ℹ️ Pot history read error:", e)
        pot_labels, pot_values = [], []

    # ---------------------------
    # Other users (for future dropdowns, actions, etc.)
    # ---------------------------
    try:
        for doc in db.collection("users").stream():
            uid = doc.id
            if uid == user_id:
                continue
            other = doc.to_dict() or {}
            club_name_target = other.get("clubName") or other.get("username") or "Unknown"
            username_target = other.get("username") or other.get("clubName") or "Unknown"
            all_users.append({
                "user_id": uid,
                "club_name": club_name_target,
                "clubID": other.get("clubID"),
                "teamValue": other.get("teamValue", 0.0),
                "username": username_target
            })
    except Exception as e:
        print("ℹ️ All users fetch fallback:", e)

    # ---------------------------
    # Render
    # ---------------------------
    return render_template(
        "home.html",
        username=username,
        managerName=manager_name,
        clubImageUrl=club_image_url,
        prediction_count=prediction_count,
        btts_count=btts_count,
        league_position=league_position,
        team_value=team_value,
        club_name=club_name,
        club=club_data,
        club_id=club_id,
        season_number=season_number,
        week_number=week_number,
        news=news,
        mode=mode,
        time_left_str=time_left_str,
        all_users=all_users,
        available_cards=available_cards,
        current_user_id=user_id,
        pot_labels=pot_labels,
        pot_values=pot_values
    )

# -----------------------------------------------------
# Reporting Page Route
# -----------------------------------------------------
@app.route("/reporting")
def reporting():
    # Load latest 25 press reports
    reports = []
    try:
        query = db.collection("press_reports").order_by("ts", direction=firestore.Query.DESCENDING).limit(25)
        snaps = query.stream()
        for snap in snaps:
            d = snap.to_dict() or {}
            rid = snap.id

            # Load first 10 comments oldest-first
            comments = []
            try:
                c_snaps = (
                    db.collection("press_reports")
                      .document(rid)
                      .collection("comments")
                      .order_by("ts")
                      .limit(10)
                      .stream()
                )
                for c in c_snaps:
                    cd = c.to_dict() or {}
                    comments.append({
                        "author_username": cd.get("author_username", "Unknown"),
                        "text": cd.get("text", ""),
                        "ts": cd.get("ts")
                    })
            except Exception as e:
                print(f"⚠️ reporting: failed to load comments for {rid}: {e}")

            reports.append({
                "id": rid,
                "ts": d.get("ts"),
                "weekNumber": d.get("weekNumber", 0),
                "cardType": d.get("cardType", "yellow"),
                "actor_uid": d.get("actor_uid"),
                "actor_username": d.get("actor_username", "Unknown"),
                "target_uid": d.get("target_uid"),
                "target_username": d.get("target_username", "Unknown"),
                "message": d.get("message", ""),
                "comments_count": d.get("comments_count", 0),
                "hidden": d.get("hidden", False),
                "comments": comments
            })
    except Exception as e:
        print(f"⚠️ reporting: failed to load reports: {e}")

    return render_template("reporting.html", press_reports=reports)
'''
@app.route("/reporting/<report_id>/comment", methods=["POST"])
def add_press_comment(report_id):
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    text = (request.form.get("text") or "").strip()
    if not (1 <= len(text) <= 280):
        flash("⚠️ Comment must be 1–280 characters.")
        return redirect(url_for("reporting") + f"#report-{report_id}")

    uid = session["user_id"]
    user_snap = db.collection("users").document(uid).get()
    author_username = (user_snap.to_dict() or {}).get("username", "Unknown") if user_snap.exists else "Unknown"

    try:
        parent_ref = db.collection("press_reports").document(report_id)
        comment_ref = parent_ref.collection("comments").document()
        batch = db.batch()
        batch.set(comment_ref, {
            "ts": firestore.SERVER_TIMESTAMP,
            "author_uid": uid,
            "author_username": author_username,
            "text": text,
            "hidden": False
        })
        batch.update(parent_ref, {"comments_count": firestore.Increment(1)})
        batch.commit()
        flash("✅ Comment posted.")
    except Exception as e:
        print(f"⚠️ add_press_comment error: {e}")
        flash("⚠️ Failed to post comment.")

    return redirect(url_for("reporting") + f"#report-{report_id}")
'''
# -----------------------------------------------------
# Admin Page Functions
# -----------------------------------------------------
@app.route("/admin")
def admin_home():
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    # 🔐 Admin check
    user_id = session["user_id"]
    user_doc = db.collection("users").document(user_id).get()
    if not user_doc.exists or not user_doc.to_dict().get("isAdmin", False):
        flash("⚠️ Admin access only.")
        return redirect(url_for("home"))

    # ✅ Users overview (replace clubs list with users_list)
    users_list = []
    for user_doc in db.collection("users").stream():
        user_data = user_doc.to_dict()
        users_list.append({
            "id": user_doc.id,
            "username": user_data.get("username", "Unknown"),
            "manager": user_data.get("managerName", "Unassigned"),
            "totalPredictions": user_data.get("totalPredictions", 0),
            "totalBTTS": user_data.get("totalBTTS", 0),
            "teamValue": user_data.get("teamValue", 0.0),
            "strikes": user_data.get("strikes", 0),
            "status": user_data.get("status", "Active")
        })

    # ✅ Load latest pot
    pot_doc = db.collection("state").document("latestPot").get()
    last_pot = pot_doc.to_dict() if pot_doc.exists else None

    # ✅ Load incomplete clubs
    incomplete_clubs = []
    for user in db.collection("users").stream():
        data = user.to_dict()
        club_name   = data.get("clubName", "Unknown Club")
        manager     = data.get("managerName", "Unassigned")
        predictions = data.get("predictionCount", 0)
        if predictions < 10:
            incomplete_clubs.append({
                "name": club_name,
                "manager": manager,
                "predictions": predictions
            })

    # ✅ Load HotPicks from /communityInsights/{weekNumber}
    hotpicks = {"topPicks": [], "btts": []}
    try:
        season_doc = db.collection("state").document("seasonTracking").get()
        week_number = season_doc.to_dict().get("weekNumber", 1)
        hot_doc = db.collection("communityInsights").document(str(week_number)).get()
        if hot_doc.exists:
            hot_data = hot_doc.to_dict()
            hotpicks["topPicks"] = hot_data.get("topPicks", [])
            hotpicks["btts"]     = hot_data.get("btts", [])
    except Exception as e:
        print("⚠️ Failed to load community picks:", e)

    # ✅ Load Weighted HotPicks from /communityInsightsWeighted/{weekNumber}
    hotpicks_weighted = None
    try:
        weighted_doc = db.collection("communityInsightsWeighted").document(str(week_number)).get()
        if weighted_doc.exists:
            hotpicks_weighted = weighted_doc.to_dict()
    except Exception as e:
        print("⚠️ Failed to load weighted community picks:", e)

    # ✅ Load pot history for graph
    pot_history = []
    try:
        for doc in db.collection("communityPotHistory").stream():
            d = doc.to_dict()
            pot_history.append({
                "week":  d.get("week", 0),
                "value": d.get("value", 0.0)
            })
        pot_history.sort(key=lambda x: x["week"])
    except Exception as e:
        print("⚠️ Failed to load pot history:", e)

    '''# 🔄 Load TikTok game state for toggle button
    tiktok_state = db.collection("state") \
                     .document("tiktokGameState") \
                     .get().to_dict() or {}
    active_game_day = tiktok_state.get("activeGameDay")
    locked          = tiktok_state.get("locked", False) '''

    return render_template(
        "admin_dashboard.html",
        users=users_list,
        last_pot=last_pot,
        incomplete_clubs=incomplete_clubs,
        hotpicks=hotpicks,
        pot_history=pot_history,
        hotpicks_weighted=hotpicks_weighted
    )


# -----------------------------------------------------
# Admin: Update User (strikes, status)
# -----------------------------------------------------
@app.route("/admin/update_user/<user_id>", methods=["POST"])
def update_user(user_id):
    if "user_id" not in session or not session.get("is_admin"):
        flash("⚠️ Admin access only.")
        return redirect(url_for("login"))

    try:
        strikes = int(request.form.get("strikes", 0))
        status = request.form.get("status", "Active")

        db.collection("users").document(user_id).update({
            "strikes": strikes,
            "status": status
        })

        flash(f"✅ Updated {user_id} successfully.")
    except Exception as e:
        flash(f"⚠️ Error updating user: {e}")

    return redirect(url_for("admin_home"))


@app.route("/admin/update_club_values", methods=["POST"])
def update_club_values():
    if "user_id" not in session or not session.get("is_admin"):
        return jsonify({"success": False, "error": "Admin access only"}), 403

    data = request.get_json()
    pot_value = data.get("pot")

    if not pot_value or pot_value <= 0:
        return jsonify({"success": False, "error": "Invalid pot value"}), 400

    try:
        # 🔢 Get current week number and max predictions
        season_doc = db.collection("state").document("seasonTracking").get()
        week_number = season_doc.to_dict().get("weekNumber", 1)
        max_predictions = week_number * 10

        # 🧮 Loop through users to calculate effective accuracy
        users = db.collection("users").stream()
        user_accuracies = {}
        total_effective_accuracy = 0

        for user in users:
            user_data = user.to_dict()
            uid = user.id
            club_id = user_data.get("clubID")
            if not club_id:
                continue  # Only consider users who are linked to a club (still our gate)

            correct = user_data.get("correctPredictions", 0)
            effective_accuracy = (correct / max_predictions) if max_predictions > 0 else 0

            user_accuracies[uid] = {
                "club_id": club_id,
                "effective_accuracy": effective_accuracy
            }
            total_effective_accuracy += effective_accuracy

        if total_effective_accuracy == 0:
            return jsonify({"success": False, "error": "No valid prediction data found."}), 400

        # 💰 Calculate and assign values to user docs (users/{uid}.teamValue)
        batch = db.batch()
        updates = []

        for uid, info in user_accuracies.items():
            accuracy = info["effective_accuracy"]
            weight = accuracy / total_effective_accuracy
            user_value = round(weight * pot_value, 2)

            user_ref = db.collection("users").document(uid)
            batch.set(user_ref, {"teamValue": user_value}, merge=True)

            updates.append({
                "user_id": uid,
                "club_id": info["club_id"],
                "effective_accuracy": round(accuracy, 4),
                "value_assigned": user_value
            })

        batch.commit()

        return jsonify({"success": True, "message": "User team values updated.", "updates": updates}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# 🔧 Reusable club value updater
def update_club_values_internal(pot_value):
    season_doc = db.collection("state").document("seasonTracking").get()
    week_number = season_doc.to_dict().get("weekNumber", 1)
    max_predictions = week_number * 10

    users = db.collection("users").stream()
    user_accuracies = {}
    total_effective_accuracy = 0

    for user in users:
        user_data = user.to_dict()
        uid = user.id
        club_id = user_data.get("clubID")
        if not club_id:
            continue

        correct = user_data.get("correctPredictions", 0)
        effective_accuracy = (correct / max_predictions) if max_predictions > 0 else 0

        user_accuracies[uid] = {
            "club_id": club_id,
            "effective_accuracy": effective_accuracy
        }
        total_effective_accuracy += effective_accuracy

    if total_effective_accuracy == 0:
        return {"success": False, "error": "No valid prediction data found."}

    batch = db.batch()
    updates = []

    for uid, info in user_accuracies.items():
        accuracy = info["effective_accuracy"]
        weight = accuracy / total_effective_accuracy
        user_value = round(weight * pot_value, 2)

        user_ref = db.collection("users").document(uid)
        batch.set(user_ref, {"teamValue": user_value}, merge=True)

        updates.append({
            "user_id": uid,
            "club_id": info["club_id"],
            "effective_accuracy": round(accuracy, 4),
            "value_assigned": user_value
        })

    batch.commit()
    return {"success": True, "message": "User team values updated.", "updates": updates}


@app.route("/admin/distribute-pot", methods=["GET", "POST"])
def distribute_pot():
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    user_doc = db.collection("users").document(session["user_id"]).get()
    if not user_doc.exists or not user_doc.to_dict().get("isAdmin", False):
        flash("⚠️ Admin access only.")
        return redirect(url_for("home"))

    if request.method == "POST":
        try:
            pot = float(request.form.get("pot", 0.0))
            now = datetime.now(timezone.utc)

            # 🔄 Update latest pot state
            db.collection("state").document("latestPot").set({
                "value": pot,
                "timestamp": now
            }, merge=True)

            # 🔢 Get current week number from season state
            season_doc = db.collection("state").document("seasonTracking").get()
            week_number = season_doc.to_dict().get("weekNumber", 0)

            # 📈 Log this week's pot snapshot to history
            db.collection("communityPotHistory").document(str(week_number)).set({
                "week": week_number,
                "value": pot,
                "timestamp": now
            })

            # ✅ Call club value calculation logic
            result = update_club_values_internal(pot)
            if result.get("success"):
                flash("✅ Pot and user team values updated successfully.")
            else:
                flash(f"⚠️ User team value update failed: {result.get('error')}")

        except Exception as e:
            flash(f"⚠️ Failed to update pot: {e}")

        return redirect(url_for("distribute_pot"))

    # GET method – render the dashboard with context
    pot_doc = db.collection("state").document("latestPot").get()
    last_pot = pot_doc.to_dict() if pot_doc.exists else None

    users_ref = db.collection("users").stream()
    incomplete_clubs = []

    for user in users_ref:
        data = user.to_dict()
        club_name = data.get("clubName", "Unknown Club")
        manager = data.get("managerName", "Unknown Manager")
        predictions = data.get("predictionCount", 0)

        if predictions < 10:
            incomplete_clubs.append({
                "name": club_name,
                "manager": manager,
                "predictions": predictions
            })

    # Load Hot Picks
    season_doc = db.collection("state").document("seasonTracking").get()
    week_number = season_doc.to_dict().get("weekNumber", 0)
    hotpicks_doc = db.collection("communityInsights").document(str(week_number)).get()
    hotpicks = hotpicks_doc.to_dict() if hotpicks_doc.exists else {}

    # ✅ Load Weighted HotPicks for current week
    hotpicks_weighted = None
    try:
        weighted_doc = db.collection("communityInsightsWeighted").document(str(week_number)).get()
        if weighted_doc.exists:
            hotpicks_weighted = weighted_doc.to_dict()
    except Exception as e:
        print("⚠️ Failed to load weighted community picks:", e)

    return render_template("admin_dashboard.html",
                           last_pot=last_pot,
                           incomplete_clubs=incomplete_clubs,
                           hotpicks=hotpicks,
                           hotpicks_weighted=hotpicks_weighted)

# -----------------------------------------------------
# V3 shop / marketplace
# -----------------------------------------------------

# --- PayPal order helper and routes ---
def _paypal_get_access_token():
    client_id = os.getenv("PAYPAL_CLIENT_ID")
    client_secret = os.getenv("PAYPAL_CLIENT_SECRET")
    env = os.getenv("PAYPAL_ENV", "sandbox")

    if not client_id or not client_secret:
        raise RuntimeError("PayPal credentials not set")

    base = "https://api-m.sandbox.paypal.com" if env == "sandbox" else "https://api-m.paypal.com"
    auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

    resp = requests.post(
        f"{base}/v1/oauth2/token",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data={"grant_type": "client_credentials"},
        timeout=20
    )
    resp.raise_for_status()
    return base, resp.json()["access_token"]


@app.route("/paypal/create-order", methods=["POST"])
def paypal_create_order():
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    try:
        base, token = _paypal_get_access_token()

        order_payload = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "amount": {
                    "currency_code": "GBP",
                    "value": "1.00"
                },
                "description": "250 SII Coins"
            }],
            "application_context": {
                "brand_name": "Stick It In",
                "landing_page": "NO_PREFERENCE",
                "user_action": "PAY_NOW",
                "return_url": url_for("paypal_capture_order", _external=True),
                "cancel_url": url_for("marketplace", _external=True)
            }
        }

        resp = requests.post(
            f"{base}/v2/checkout/orders",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json=order_payload,
            timeout=20
        )
        resp.raise_for_status()
        data = resp.json()

        # Store pending order for audit
        db.collection("coin_purchases").document(data["id"]).set({
            "user_id": session["user_id"],
            "status": "created",
            "amount_gbp": 1.00,
            "coins": 250,
            "created_at": firestore.SERVER_TIMESTAMP
        })

        for link in data.get("links", []):
            if link.get("rel") == "approve":
                return redirect(link["href"])

        flash("PayPal approval link not found.")
        return redirect(url_for("marketplace"))

    except Exception as e:
        print("paypal_create_order error:", e)
        flash("Payment could not be started.")
        return redirect(url_for("marketplace"))


@app.route("/paypal/capture-order")
def paypal_capture_order():
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    order_id = request.args.get("token")
    if not order_id:
        flash("Missing PayPal order reference.")
        return redirect(url_for("marketplace"))

    try:
        base, token = _paypal_get_access_token()

        resp = requests.post(
            f"{base}/v2/checkout/orders/{order_id}/capture",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            timeout=20
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "COMPLETED":
            flash("Payment not completed.")
            return redirect(url_for("marketplace"))

        # Credit coins (Firestore user docs are keyed by Firebase UID)
        uid = session.get("user_id")
        if not uid:
            flash("User session invalid.")
            return redirect(url_for("marketplace"))

        user_ref = db.collection("users").document(uid)
        batch = db.batch()
        batch.update(user_ref, {
            "coinBalance": firestore.Increment(250),
            "updated_at": firestore.SERVER_TIMESTAMP
        })

        purchase_ref = db.collection("coin_purchases").document(order_id)
        batch.set(purchase_ref, {
            "status": "completed",
            "captured_at": firestore.SERVER_TIMESTAMP
        }, merge=True)

        batch.commit()

        flash("✅ 250 coins added to your balance.")
        return redirect(url_for("marketplace"))

    except Exception as e:
        print("paypal_capture_order error:", e)
        flash("Payment verification failed.")
        return redirect(url_for("marketplace"))
@app.route("/marketplace")
def marketplace():
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user_doc = db.collection("users").document(user_id).get()
    user_data = user_doc.to_dict() if user_doc.exists else {}
    coin_balance = user_data.get("coinBalance", 0)

    # Only unassigned clubs
    clubs = []
    for doc in db.collection("clubs").where("manager", "==", None).stream():
        d = doc.to_dict()
        clubs.append({
            "id": doc.id,
            "name": d.get("clubName", "Unknown"),
            "manager": None,
            "value": d.get("value", 0),
            "badgeUrl": d.get("badgeUrl", "/static/images/default_badge.png"),
            "status": "unassigned"
        })

    # 2️⃣ Card Items from Firestore
    items = []
    card_docs = db.collection("marketplace_items").stream()
    for doc in card_docs:
        d = doc.to_dict()
        items.append({
            "id": doc.id,
            "name": d.get("name", "Mystery Card"),
            "description": d.get("description", ""),
            "price": d.get("price", 0),
            "quantity": d.get("quantity", 0),
            "can_afford": coin_balance >= d.get("price", 0)
        })

    return render_template("marketplace.html", clubs=clubs, items=items, coin_balance=coin_balance)


# -----------------------------------------------------
# the info page
# -----------------------------------------------------
@app.route("/about")
def about():
    return render_template("about.html")

# -----------------------------------------------------
# default link to stop www.stickitin.co.uk from breaking
# -----------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for('home'))

'''# -----------------------------------------------------
# Serve Firebase Messaging service worker at origin root
# -----------------------------------------------------
@app.route('/firebase-messaging-sw.js')
def firebase_sw():
    # This file lives in /static/firebase-messaging-sw.js but must be served at /
    # so the service worker can control the whole origin.
    return send_from_directory('static', 'firebase-messaging-sw.js', mimetype='application/javascript') '''

# -----------------------------------------------------
# Game Entry Route
# -----------------------------------------------------
web_leagueIDs = [
    "39",  # English Premier League
    "40",  # English Championship
    "41",  # English League 1
    "42",  # English League 2
    "45",  # FA Cup
    "46",  # EFL Trophy
    "47",  # FA Trophy
    "48",  # League Cup
    "179", # Scottish Premiership
    "180", # Scottish Championship
    "181", # Scottish FA Cup
    "182", # Scottish Challenge Cup
    "183", # Scottish League 1
    "184", # Scottish League 2
    "185", # Scottish League Cup
    #"15",  # FIFA Club World Cup - pre-season only  - comment this out on August 2nd
    #"10",  # World Friendlies                       - comment this out on August 2nd
    #"32",  # World Cup Quals (Europe)               - comment this out on August 2nd
    "1",   # FIFA World Cup
    "2",   # UEFA Champions League
    "3"   # UEFA Europa League
    #"4",   # UEFA Euro Championship                 - comment this out on August 2nd
    #"960", # UEFA Euro Qualifiers                   - comment this out on August 2nd
    #"253"  # MLS - fine for pre-season              - comment this out on August 2nd
]

LEAGUE_NAME_MAP = {
    "39":  "Premier League",
    "40":  "Championship",
    "41":  "League One",
    "42":  "League Two",
    "45":  "FA Cup",
    "46":  "EFL Trophy",
    "47":  "FA Trophy",
    "48":  "League Cup (EFL Cup)",
    "179": "Scottish Premiership",
    "180": "Scottish Championship",
    "181": "Scottish FA Cup",
    "182": "Scottish Challenge Cup",
    "183": "Scottish League One",
    "184": "Scottish League Two",
    "185": "Scottish League Cup",
    "1":   "FIFA World Cup",
    "2":   "UEFA Champions League",
    "3":   "UEFA Europa League",
}

@app.route("/GameEntry")
def game_entry():
    """Game Entry: pull Firestore fixtures per league and merge with the user's predictions."""
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    # Lockout logic: block access on Saturday (5) or Sunday (6)
    today = datetime.utcnow().weekday()
    if today in [5, 6]:  # Saturday or Sunday
        flash("⚠️ Game Entry is locked during match weekends.")
        return redirect(url_for("home"))

    user_id = session["user_id"]
    prediction_count = None
    btts_count = None
    # Map of fixture_id (string) -> { 'prediction': 'Home/Away/Draw'|None, 'btts': 'Yes/No'|None }
    user_predictions = {}

    try:
        user_ref = db.collection("users").document(user_id)
        user_doc = user_ref.get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            prediction_count = user_data.get("predictionCount", 10)
            btts_count = user_data.get("bttsCount", 10)

        predictions_ref = user_ref.collection("predictions")
        predictions = predictions_ref.stream()
        for pred in predictions:
            p = pred.to_dict() or {}
            fid = str(pred.id)
            user_predictions[fid] = {
                "prediction": p.get("prediction"),
                "btts": p.get("btts")
            }

    except Exception as e:
        print(f"🔥 Firestore Error: {e}")
        flash("⚠️ Error fetching prediction data.")

    fixtures = []
    for leagueID in web_leagueIDs:
        league_ref = db.collection(f"web_fixtures/{leagueID}/matches")
        matches = league_ref.stream()

        for match in matches:
            match_data = match.to_dict()
            fixture_id = match_data.get("fixture_id", "")
            raw_date = match_data.get("date", "")
            try:
                dt = datetime.fromisoformat(raw_date).replace(tzinfo=timezone.utc)
                formatted_date = dt.strftime("%b %d, %Y %I:%M %p UTC")
            except ValueError:
                dt = None
                formatted_date = "Invalid Date"

            def extract_percentage(value):
                try:
                    return float(value.replace("%", "").strip()) if isinstance(value, str) else float(value)
                except Exception:
                    return 0.0

            home_win_prob = extract_percentage(match_data.get("home_win_prob", "0%"))
            draw_prob = extract_percentage(match_data.get("draw_prob", "0%"))
            away_win_prob = extract_percentage(match_data.get("away_win_prob", "0%"))

            total = home_win_prob + draw_prob + away_win_prob
            if total > 0:
                home_win_prob = round((home_win_prob / total) * 100, 1)
                draw_prob = round((draw_prob / total) * 100, 1)
                away_win_prob = round((away_win_prob / total) * 100, 1)

            fixtures.append({
                "fixtureID": match.id,
                "fixture_id": fixture_id,

                # NEW: league fields used by filters
                "league_id": leagueID,
                "league_name": LEAGUE_NAME_MAP.get(leagueID, leagueID),

                "team1": match_data.get("team1", "Unknown"),
                "team2": match_data.get("team2", "Unknown"),
                "team1_logo": match_data.get("team1_logo", ""),
                "team2_logo": match_data.get("team2_logo", ""),
                "venue": match_data.get("venue", "Unknown"),

                # Keep the pretty string for display…
                "date": formatted_date,
                # …but also pass the actual datetime + a numeric epoch for filtering
                "datetime": dt,
                "ts": int(dt.timestamp() * 1000) if dt else None,

                # User prediction state for this fixture
                "user_prediction": user_predictions.get(match.id, {}).get("prediction"),
                "user_btts": user_predictions.get(match.id, {}).get("btts"),
                # legacy boolean (true if either side chosen)
                "predicted": (match.id in user_predictions),
                # granular state used by UI (none | partial | predicted)
                "pred_state": (
                    "predicted" if (
                        user_predictions.get(match.id, {}).get("prediction") and
                        user_predictions.get(match.id, {}).get("btts")
                    ) else (
                        "partial" if (
                            user_predictions.get(match.id, {}).get("prediction") or
                            user_predictions.get(match.id, {}).get("btts")
                        ) else None
                    )
                ),
                "home_win_prob": home_win_prob,
                "draw_prob": draw_prob,
                "away_win_prob": away_win_prob
            })

    fixtures = sorted(fixtures, key=lambda x: x["datetime"] or datetime.max)

    return render_template(
        "GameEntry.html",
        fixtures=fixtures,
        prediction_count=prediction_count,
        btts_count=btts_count,
        user_prediction_map=user_predictions
    )

@app.route("/submit_prediction", methods=["POST"])
def submit_prediction():
    """Save a prediction without a transaction (simplified). Counts only decrement on first set."""
    # Simplified, non-transactional save to avoid the 'str has no attribute exists' crash
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "User not logged in"}), 403

    data = request.get_json(silent=True) or {}

    fixture_id = str(data.get("fixtureID", "")).strip()
    prediction = data.get("prediction")  # 'Home' | 'Away' | 'Draw' | None
    btts = data.get("btts")              # 'Yes' | 'No' | None

    team1 = (data.get("team1") or "").strip() or "Unknown"
    team2 = (data.get("team2") or "").strip() or "Unknown"
    venue = (data.get("venue") or "").strip() or "Unknown"
    raw_date = (data.get("date") or "").strip() or "Invalid Date"

    if not fixture_id or (not prediction and not btts):
        return jsonify({"error": "Invalid data – must provide at least one prediction"}), 400

    # Parse match datetime (best-effort)
    try:
        dt = datetime.strptime(raw_date, "%b %d, %Y %I:%M %p UTC").replace(tzinfo=timezone.utc)
    except Exception:
        dt = None

    user_ref = db.collection("users").document(user_id)
    pred_ref = user_ref.collection("predictions").document(fixture_id)

    try:
        # Read current user and prior prediction without a transaction
        user_snap = user_ref.get()
        if not user_snap.exists:
            return jsonify({"error": "User not found"}), 404
        user_data = user_snap.to_dict() or {}

        prior_snap = pred_ref.get()
        prior = prior_snap.to_dict() if prior_snap.exists else {}

        # Current remaining counts (clamped to >= 0)
        pred_left = max(0, int(user_data.get("predictionCount", 0)))
        btts_left = max(0, int(user_data.get("bttsCount", 0)))

        # Determine if we're adding new fields (to adjust counters)
        adding_pred = bool(prediction) and not prior.get("prediction")
        adding_btts = (btts in ("Yes", "No")) and not prior.get("btts")

        # Hard stop: do not allow going below 0
        if adding_pred and pred_left <= 0:
            return jsonify({
                "error": "No result predictions left this week.",
                "ok": False,
                "counts": {
                    "predictionCount": pred_left,
                    "bttsCount": btts_left
                }
            }), 400

        if adding_btts and btts_left <= 0:
            return jsonify({
                "error": "No BTTS predictions left this week.",
                "ok": False,
                "counts": {
                    "predictionCount": pred_left,
                    "bttsCount": btts_left
                }
            }), 400

        # Build merged document
        new_doc = {
            **prior,
            "fixture_id": fixture_id,
            "team1": team1,
            "team2": team2,
            "venue": venue,
            "date": dt if dt else (prior.get("date") or raw_date),
            "timestamp": datetime.utcnow().replace(tzinfo=timezone.utc)
        }
        if prediction:
            new_doc["prediction"] = prediction
        if btts in ("Yes", "No"):
            new_doc["btts"] = btts

        batch = db.batch()
        batch.set(pred_ref, new_doc, merge=True)

        # Update counters only when adding new info (no hard gatekeeping)
        updates = {}
        if adding_pred:
            updates["predictionCount"] = max(0, pred_left - 1)
            updates["totalPredictions"] = user_data.get("totalPredictions", 0) + 1
        if adding_btts:
            updates["bttsCount"] = max(0, btts_left - 1)
            updates["totalBTTS"] = user_data.get("totalBTTS", 0) + 1
        if updates:
            batch.update(user_ref, updates)

        batch.commit()

        final_counts = {
            "predictionCount": updates.get("predictionCount", pred_left),
            "bttsCount": updates.get("bttsCount", btts_left),
            "totalPredictions": updates.get("totalPredictions", user_data.get("totalPredictions", 0)),
            "totalBTTS": updates.get("totalBTTS", user_data.get("totalBTTS", 0))
        }

        return jsonify({
            "message": "Prediction saved successfully!",
            "ok": True,
            "counts": final_counts,
            "applied": {"prediction": prediction, "btts": btts}
        }), 200

    except Exception as e:
        print(f"🔥 submit_prediction error (simplified): {e}")
        return jsonify({"error": "Failed to save prediction."}), 500


'''
# -----------------------------------------------------
# FCM token registration
# -----------------------------------------------------

def _resolve_token_for_uid(uid: str) -> str:
    """Try hard to find a usable FCM token for this user.
    Checks multiple legacy field names and optional subcollections.
    Returns an empty string if nothing is found.
    """
    try:
        user_ref = db.collection("users").document(uid)
        snap = user_ref.get()
        if not snap.exists:
            print(f"[fcm] no user doc for {uid}")
            return ""
        d = snap.to_dict() or {}

        # 1) Flat, common field names (new → old)
        for key in [
            "fcmToken",            # current flat
            "fcm_token",           # snake case
            "webToken",            # some early experiments
            "web_token",
        ]:
            t = (d.get(key) or "").strip()
            if t:
                return t

        # 2) Arrays we may have stored historically
        array_candidates = [
            (d.get("fcmTokens"), False),                # e.g., [t1, t2, ...]
            ((d.get("fcm") or {}).get("web_tokens"), True),
            ((d.get("fcm") or {}).get("ios_tokens"), True),
            ((d.get("fcm") or {}).get("android_tokens"), True),
        ]
        best = ""
        for arr, is_list in array_candidates:
            if isinstance(arr, list) and arr:
                best = (arr[-1] or "").strip()  # newest last
                if best:
                    return best

        # 3) Subcollection under the user: users/{uid}/fcm_tokens or fcmTokens
        for subname in ("fcm_tokens", "fcmTokens"):
            try:
                q = (
                    user_ref.collection(subname)
                    .order_by("ts", direction=firestore.Query.DESCENDING)
                    .limit(1)
                )
                sub = list(q.stream())
                if sub:
                    doc = sub[0].to_dict() or {}
                    t = (doc.get("token") or "").strip()
                    if t:
                        return t
            except Exception as ie:
                # collection may not exist; ignore
                pass

        # 4) As a last resort: collection group query (if user writes elsewhere)
        try:
            cg = (
                db.collection_group("fcm_tokens")
                .where("uid", "==", uid)
                .order_by("ts", direction=firestore.Query.DESCENDING)
                .limit(1)
            )
            sub = list(cg.stream())
            if sub:
                doc = sub[0].to_dict() or {}
                t = (doc.get("token") or "").strip()
                if t:
                    return t
        except Exception:
            pass

        return ""
    except Exception as e:
        print(f"⚠️ _resolve_token_for_uid error: {e}")
        return ""
@app.route("/fcm/register", methods=["POST"])
def fcm_register():
    """Store FCM token across flat field, array mirror, and a subcollection for discovery."""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    payload = request.get_json(silent=True) or {}
    token = (payload.get("token") or "").strip()
    platform = (payload.get("platform") or "web").strip().lower()

    if not token:
        return jsonify({"success": False, "message": "Missing token"}), 400

    try:
        uid = session["user_id"]
        user_ref = db.collection("users").document(uid)

        update = {
            "fcmToken": token,  # flat latest
            "fcmTokens": firestore.ArrayUnion([token]),  # legacy array mirror
            "fcm": {
                "last_registered": firestore.SERVER_TIMESTAMP
            }
        }
        # Use ArrayUnion to avoid duplicates per platform
        if platform == "web":
            update["fcm"]["web_tokens"] = firestore.ArrayUnion([token])
        else:
            update["fcm"][f"{platform}_tokens"] = firestore.ArrayUnion([token])

        batch = db.batch()
        batch.set(user_ref, update, merge=True)
        # Optional subcollection record for newest-first discovery
        sub = user_ref.collection("fcm_tokens").document()
        batch.set(sub, {"token": token, "uid": uid, "platform": platform, "ts": firestore.SERVER_TIMESTAMP})
        batch.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(f"🔥 fcm_register error: {e}")
        return jsonify({"success": False, "message": "Failed to save token"}), 500


# -----------------------------------------------------
# FCM test notification (public endpoint)
# -----------------------------------------------------
@app.route("/fcm/send_test", methods=["POST"])
def fcm_send_test():
    """Send an immediate WebPush test notification. Public for now; will lock down later."""
    try:
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()
        uid = (data.get("uid") or "").strip()

        if not token and uid:
            token = _resolve_token_for_uid(uid)

        print(f"[fcm] resolved uid={uid or '-'} token={(token[:12] + '…') if token else ''}")
        if not token:
            return jsonify({"success": False, "message": "No FCM token provided (and none could be found for uid)."}), 400

        message = messaging.Message(
            webpush=messaging.WebpushConfig(
                headers={"TTL": "300"},
                notification=messaging.WebpushNotification(
                    title="Stick It In 🚨",
                    body="This is a test push notification!",
                    icon="/static/icons/icon-192.png",
                    badge="/static/icons/badge-72.png",
                    tag="sii-test",
                    require_interaction=True
                ),
                fcm_options=messaging.WebpushFCMOptions(
                    link="https://www.stickitin.co.uk/home"
                )
            ),
            data={
                "source": "send_test",
                "sent_at": datetime.utcnow().isoformat() + "Z"
            },
            token=token
        )
        response = messaging.send(message)
        return jsonify({"success": True, "response": response}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# -----------------------------------------------------
# FCM delayed notification for testing
# -----------------------------------------------------
@app.route("/fcm/send_delayed", methods=["POST"])
def fcm_send_delayed():
    """Schedule a delayed WebPush via a background Timer. Dev only; replace with Cloud Tasks."""
    try:
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()
        uid = (data.get("uid") or "").strip()
        delay = int(data.get("delay", 30))

        if not token and uid:
            token = _resolve_token_for_uid(uid)

        print(f"[fcm] resolved uid={uid or '-'} token={(token[:12] + '…') if token else ''}")
        if not token:
            return jsonify({"success": False, "message": "No FCM token provided (and none could be found for uid)."}), 400

        def send_later():
            try:
                message = messaging.Message(
                    webpush=messaging.WebpushConfig(
                        headers={"TTL": "600"},
                        notification=messaging.WebpushNotification(
                            title="Stick It In ⏰",
                            body=f"This reminder fired after {delay} seconds!",
                            icon="/static/icons/icon-192.png",
                            badge="/static/icons/badge-72.png",
                            tag="sii-delayed",
                            require_interaction=True
                        ),
                        fcm_options=messaging.WebpushFCMOptions(
                            link="https://www.stickitin.co.uk/home"
                        )
                    ),
                    data={
                        "source": "send_delayed",
                        "delay_secs": str(delay)
                    },
                    token=token
                )
                response = messaging.send(message)
                print(f"✅ Delayed push sent: {response}")
            except Exception as e:
                print(f"❌ Delayed push failed: {e}")

        Timer(delay, send_later).start()
        return jsonify({"success": True, "scheduled_in": delay}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# -----------------------------------------------------
# FCM debug: inspect tokens for a uid
# -----------------------------------------------------
@app.route("/fcm/tokens", methods=["GET"])
def fcm_list_tokens():
    """Inspect token shapes for a uid. Helpful during the migration to a single token model."""
    uid = (request.args.get("uid") or "").strip()
    if not uid:
        return jsonify({"success": False, "message": "Provide ?uid="}), 400
    try:
        snap = db.collection("users").document(uid).get()
        if not snap.exists:
            return jsonify({"success": False, "message": "User not found"}), 404
        d = snap.to_dict() or {}
        fcm = d.get("fcm") or {}
        return jsonify({
            "success": True,
            "resolved_token": _resolve_token_for_uid(uid),
            "flat_token": d.get("fcmToken"),
            "web_tokens": fcm.get("web_tokens"),
            "ios_tokens": fcm.get("ios_tokens"),
            "android_tokens": fcm.get("android_tokens"),
            "last_registered": fcm.get("last_registered")
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500 '''

# -----------------------------------------------------
# Action Cards - now a single function for V3
# -----------------------------------------------------
@app.route("/issue_card", methods=["POST"])
def issue_card():
    """Apply a card effect from one user to another and log a press report (best-effort)."""
    if "user_id" not in session:
        return jsonify({"message": "⚠️ Please log in first."}), 403

    data = request.get_json()
    giver_id = session["user_id"]
    receiver_id = data.get("target_user")
    card_type = data.get("card_type")

    if not receiver_id or not card_type:
        return jsonify({"message": "⚠️ Missing card type or target user."}), 400

    if receiver_id == giver_id:
        return jsonify({"message": "⚠️ You cannot target yourself."}), 400

    giver_ref = db.collection("users").document(giver_id)
    receiver_ref = db.collection("users").document(receiver_id)

    try:
        giver_doc = giver_ref.get()
        receiver_doc = receiver_ref.get()

        if not giver_doc.exists or not receiver_doc.exists:
            return jsonify({"message": "⚠️ User not found."}), 404

        giver = giver_doc.to_dict()
        receiver = receiver_doc.to_dict()

        # Card-specific logic
        update_fields = {
            "yellow": {
                "available_key": "yellowCardsAvailable",
                "received_key": "yellowCardsReceived",
                "label": "Yellow Card"
            },
            "red": {
                "available_key": "redCardsAvailable",
                "received_key": "redCardsReceived",
                "label": "Red Card"
            },
            "injury": {
                "available_key": "injuriesAvailable",
                "received_key": "injuriesReceived",
                "label": "Injury"
            }
        }

        if card_type not in update_fields:
            return jsonify({"message": "⚠️ Invalid card type."}), 400

        keys = update_fields[card_type]
        giver_available = giver.get(keys["available_key"], 0)
        receiver_received = receiver.get(keys["received_key"], 0)

        if giver_available <= 0:
            return jsonify({"message": f"⚠️ No {keys['label']}s available!"}), 400

        # Firestore transaction
        batch = db.batch()

        batch.update(giver_ref, {
            keys["available_key"]: giver_available - 1
        })

        batch.update(receiver_ref, {
            keys["received_key"]: receiver_received + 1
        })

        batch.commit()

                # 🗞️ Create Press Conference report (best-effort; won't block response)
        try:
            # Pull usernames for nicer copy
            actor_username = (giver.get("username") or giver.get("managerName") or "Unknown").strip()
            target_username = (receiver.get("username") or receiver.get("managerName") or "Unknown").strip()

            # Get current week number (optional)
            try:
                season_doc = db.collection("state").document("seasonTracking").get()
                week_number = (season_doc.to_dict() or {}).get("weekNumber", 0)
            except Exception:
                week_number = 0

            # Normalise cardType and label
            ctype = card_type.lower()
            c_label = {"yellow": "Yellow", "red": "Red", "injury": "Injury"}.get(ctype, ctype.capitalize())

            msg = f"{actor_username} issued a {c_label.upper()} to {target_username}"

            db.collection("press_reports").add({
                "ts": firestore.SERVER_TIMESTAMP,
                "weekNumber": week_number,
                "cardType": ctype,
                "actor_uid": giver_id,
                "actor_username": actor_username,
                "target_uid": receiver_id,
                "target_username": target_username,
                "message": msg,
                "comments_count": 0,
                "hidden": False
            })
        except Exception as e:
            print(f"⚠️ Failed to write press report: {e}")

        return jsonify({"message": f"✅ {keys['label']} issued successfully!"}), 200

    except Exception as e:
        return jsonify({"message": f"⚠️ Error: {str(e)}"}), 500

# -----------------------------------------------------
# globalleague updated for V3
# -----------------------------------------------------
@app.route("/globalleague")
def global_league():
    """Compute a simple global ranking by adjusted points, using penalties for cards/injuries."""
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user_doc = db.collection("users").document(user_id).get()
    current_username = user_doc.to_dict().get("username", "Unknown") if user_doc.exists else "Unknown"

    users_ref = db.collection("users")
    users = users_ref.stream()

    all_users = []

    for user in users:
        data = user.to_dict()

        total_predictions = data.get("totalPredictions", 0)
        total_btts = data.get("totalBTTS", 0)
        total_games = total_predictions + total_btts

        correct_predictions = data.get("correctPredictions", 0)
        correct_btts = data.get("correctBTTS", 0)
        total_points = correct_predictions + correct_btts

        accuracy = round((total_points / total_games) * 100, 1) if total_games > 0 else 0.0

        yellow_cards = data.get("yellowCardsReceived", 0)
        red_cards = data.get("redCardsReceived", 0)
        injuries = data.get("injuriesReceived", 0)

        adjusted_points = total_points - (yellow_cards + (3 * red_cards) + (2 * injuries))
        injury_status = "✅" if injuries == 0 else "❌"

        all_users.append({
            "id": user.id, 
            "username": data.get("username", "Unknown"),
            "managerName": data.get("managerName", ""),
            "clubImageUrl": data.get("clubImageUrl", ""),
            "games_predicted": total_games,
            "points": total_points,
            "accuracy": accuracy,
            "yellow_cards": yellow_cards,
            "red_cards": red_cards,
            "injury_status": injury_status,
            "adjusted_points": adjusted_points,
            "rank": 0
        })

    all_users.sort(key=lambda x: (-x["adjusted_points"], -x["accuracy"]))
    for index, user in enumerate(all_users):
        user["rank"] = index + 1

    return render_template(
        "globalleague.html",
        all_users=all_users,
        current_user={"username": current_username},
        show_empty_msg=(len(all_users) == 0)
    )

# -----------------------------------------------------
# Media page for V3
# -----------------------------------------------------
@app.route('/media')
def media():
    return render_template("media.html")


# -----------------------------------------------------
# v2 - yet to be determined for V3
# -----------------------------------------------------
@app.route("/marketplace/buy-item/<item_id>", methods=["POST"])
def buy_marketplace_item(item_id):
    """Purchase flow for marketplace items. Legacy cards increase *Available*; new items self-heal *Received*."""
    if "user_id" not in session:
        flash("⚠️ Please log in first.")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user_ref = db.collection("users").document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        flash("⚠️ User not found.")
        return redirect(url_for("marketplace"))

    user_data = user_doc.to_dict()
    coin_balance = user_data.get("coinBalance", 0)

    item_ref = db.collection("marketplace_items").document(item_id)
    item_doc = item_ref.get()

    if not item_doc.exists:
        flash("⚠️ Item not found.")
        return redirect(url_for("marketplace"))

    item_data = item_doc.to_dict()
    price = item_data.get("price", 0)
    quantity = item_data.get("quantity", 0)

    if quantity <= 0:
        flash("⚠️ Item is out of stock.")
        return redirect(url_for("marketplace"))

    if coin_balance < price:
        flash("⚠️ Not enough coins.")
        return redirect(url_for("marketplace"))

    # Deduct coins and increment card count atomically OR apply self-heal
    update_field = None  # for legacy card purchases (adds to *Available*)
    self_heal_field = None  # for new antidote purchases (reduces *Received*)

    if item_id == "yellow_card":
        update_field = "yellowCardsAvailable"
    elif item_id == "red_card":
        update_field = "redCardsAvailable"
    elif item_id == "injury":
        update_field = "injuriesAvailable"
    elif item_id == "hire_physio":
        self_heal_field = "injuriesReceived"
    elif item_id == "bribe_ref":
        self_heal_field = "redCardsReceived"
    elif item_id == "appeal_decision":
        self_heal_field = "yellowCardsReceived"
    else:
        flash("⚠️ Invalid item.")
        return redirect(url_for("marketplace"))

    try:
        batch = db.batch()

        # Decrement stock
        batch.update(item_ref, {
            "quantity": quantity - 1
        })

        if update_field:
            # Legacy: buying a card to add to available pool
            batch.update(user_ref, {
                "coinBalance": coin_balance - price,
                update_field: firestore.Increment(1)
            })
        elif self_heal_field:
            # New: buying an antidote that reduces a *Received* counter (floor at 0)
            current_val = int(user_data.get(self_heal_field, 0))
            new_val = max(current_val - 1, 0)
            batch.update(user_ref, {
                "coinBalance": coin_balance - price,
                self_heal_field: new_val
            })

        batch.commit()
        # Optional: log a press report for self-heal purchases
        try:
            if self_heal_field:
                actor_username = user_data.get("username", "Unknown")
                label_map = {
                    "injuriesReceived": ("injury", "hired a Physio. One injury removed."),
                    "redCardsReceived": ("red", "bribed the Ref. One red removed."),
                    "yellowCardsReceived": ("yellow", "appealed the decision. One yellow removed.")
                }
                ctype, tail = label_map.get(self_heal_field, ("yellow", "used a self-heal."))
                msg = f"{actor_username} {tail}"
                db.collection("press_reports").add({
                    "ts": firestore.SERVER_TIMESTAMP,
                    "weekNumber": 0,
                    "cardType": ctype,
                    "actor_uid": user_id,
                    "actor_username": actor_username,
                    "target_uid": user_id,
                    "target_username": actor_username,
                    "message": msg,
                    "comments_count": 0,
                    "hidden": False,
                })
        except Exception as e:
            print(f"[press] self-heal report failed: {e}")
        flash(f"✅ Purchased {item_data.get('name', 'item')} successfully!")
    except Exception as e:
        print("🔥 Error during purchase:", e)
        flash("⚠️ An error occurred during purchase.")

    return redirect(url_for("marketplace"))

# -----------------------------------------------------
# Season Winners Archive
# -----------------------------------------------------
@app.route('/archive')
def archive():
    return render_template('archive.html')


# -----------------------------------------------------
# Live Scores
# -----------------------------------------------------
@app.route('/live-scores')
def live_scores_page():
    return render_template('live_scores.html')

# -----------------------------------------------------
# Live‑Scores (ALL predictions)
# -----------------------------------------------------

MAX_BATCH = 20
API_KEY = os.getenv("API_FOOTBALL_KEY")
if not API_KEY:
    raise RuntimeError("API_FOOTBALL_KEY not set in environment")
HEADERS = {"x-apisports-key": API_KEY}

@app.route("/api/live-scores")
def api_live_scores():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "User not logged in"}), 401

    # 1) Pull the user’s predictions
    preds_snap = db.collection("users").document(uid).collection("predictions").stream()
    predictions = {}
    missing_id_docs = 0
    bad_id_docs = 0

    for doc in preds_snap:
        d = doc.to_dict() or {}

        # Prefer field, but fall back to the document id (legacy data)
        raw_id = d.get("fixture_id", doc.id)

        try:
            fid = int(str(raw_id).strip())
        except Exception:
            bad_id_docs += 1
            continue

        predictions[fid] = {
            "prediction": d.get("prediction"),
            "btts": d.get("btts"),  # 'Yes' / 'No' / None
            "date": d.get("date")
        }

        if "fixture_id" not in d:
            missing_id_docs += 1

    print(f"🔎 live-scores: uid={uid}, preds={len(predictions)}, "
          f"missing_field={missing_id_docs}, bad_ids={bad_id_docs}")

    if not predictions:
        return jsonify({"fixtures": []})

    # 2) Fetch fixtures in batches from API
    fixture_ids = list(predictions.keys())
    batches = [fixture_ids[i:i + MAX_BATCH] for i in range(0, len(fixture_ids), MAX_BATCH)]
    fixtures = []

    for chunk in batches:
        url = "https://v3.football.api-sports.io/fixtures"
        params = {"ids": "-".join(map(str, chunk))}  # API expects dash-separated ids
        try:
            resp = requests.get(url, headers=HEADERS, params=params, timeout=15)
        except Exception as e:
            print(f"⚠️ API request failed for ids={chunk}: {e}")
            continue

        if resp.status_code != 200:
            print(f"⚠️ API error [{resp.status_code}] for ids={chunk}: {resp.text[:300]}")
            continue

        data = (resp.json() or {}).get("response", [])
        if not data:
            print(f"ℹ️ API returned no fixtures for ids={chunk}")

        for item in data:
            fixture = item["fixture"]
            teams = item["teams"]
            goals = item["goals"]
            fid = fixture["id"]

            ts = fixture.get("timestamp")
            if ts:
                dt = datetime.fromtimestamp(ts)
                date_key = dt.strftime("%Y-%m-%d")
                date_label = dt.strftime("%a %d %b %Y")
                kickoff_str = dt.strftime("%Y-%m-%d %H:%M")
            else:
                date_key = "unknown"
                date_label = "Unknown date"
                kickoff_str = "TBC"

            home_goals = goals.get("home") or 0
            away_goals = goals.get("away") or 0
            status = fixture["status"]["short"]  # e.g. NS, 1H, 2H, FT

            pick = predictions.get(fid, {}).get("prediction")
            btts_pick = predictions.get(fid, {}).get("btts")

            # Evaluate correctness only when the game is live/finished
            correct = None
            btts_correct = None
            if status in ("FT", "AET", "PEN", "LIVE", "1H", "2H", "ET", "P"):
                if home_goals > away_goals:
                    correct = (pick == "Home")
                elif home_goals < away_goals:
                    correct = (pick == "Away")
                else:
                    correct = (pick == "Draw")

                both_scored = (home_goals > 0 and away_goals > 0)
                if btts_pick == "Yes":
                    btts_correct = both_scored
                elif btts_pick == "No":
                    btts_correct = not both_scored

            fixtures.append({
                "fixtureID": fid,
                "team1": teams["home"]["name"],
                "team2": teams["away"]["name"],
                "score1": home_goals,
                "score2": away_goals,
                "time": status,
                "kickoff": kickoff_str,
                "dateKey": date_key,
                "dateLabel": date_label,
                "prediction": pick,
                "bttsPick": btts_pick,
                "isCorrectPrediction": correct,
                "isCorrectBTTS": btts_correct
            })

    order = {"NS": 0, "TBD": 0, "1H": 1, "2H": 1, "LIVE": 1, "ET": 1, "P": 1, "FT": 2, "AET": 2, "PEN": 2}
    fixtures.sort(key=lambda f: (order.get(f["time"], 99), f["kickoff"]))

    return jsonify({"fixtures": fixtures})

# -----------------------------------------------------
# Hot Picks V2
# -----------------------------------------------------

@app.route('/hot-picks')
def hot_picks():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user_doc = db.collection("users").document(user_id).get()
    prediction_count = user_doc.to_dict().get("predictionCount", 10)
    access_granted = prediction_count == 0

    # Fetch all predictions from all users, grouped by fixture, sorted by popularity
    # Then calculate pick outcomes based on match results (W/L/Live/Future)
    picks, top3_accuracy, top3_streak, avg_win_rate = build_community_picks()  # You’ll need to implement this

    return render_template("hot_picks.html",
                           week=6,
                           access_granted=access_granted,
                           picks=picks if access_granted else [],
                           top3_accuracy=top3_accuracy,
                           top3_streak=top3_streak,
                           avg_win_rate=avg_win_rate)

def build_community_picks():
    # Replace this with Firestore access
    predictions = db.collection_group("predictions").stream()

    fixture_votes = defaultdict(lambda: {"home": 0, "away": 0, "draw": 0, "team1": "", "team2": "", "results": []})

    for doc in predictions:
        data = doc.to_dict()
        fixture_id = str(data.get("fixture_id"))
        prediction = data.get("prediction", "").lower()
        result = data.get("result", "future").lower()  # You’ll need to store this result in Firestore
        team1 = data.get("team1")
        team2 = data.get("team2")

        if not all([fixture_id, prediction, team1, team2]):
            continue

        fixture_votes[fixture_id][prediction] += 1
        fixture_votes[fixture_id]["team1"] = team1
        fixture_votes[fixture_id]["team2"] = team2
        fixture_votes[fixture_id]["results"].append(result)

    picks = []
    top_correct = 0
    total_top = 0

    for fid, data in fixture_votes.items():
        most_common = max(["home", "away", "draw"], key=lambda x: data[x])
        votes = data[most_common]
        result_summary = Counter(data["results"])

        if "future" in result_summary:
            color = "grey"
        elif "live" in result_summary:
            color = "yellow"
        elif most_common in result_summary:
            color = "green"
            top_correct += 1
        else:
            color = "red"

        total_top += 1
        picks.append({
            "team1": data["team1"],
            "team2": data["team2"],
            "prediction": most_common.capitalize(),
            "user_agreement": votes,
            "color": color
        })

    picks = sorted(picks, key=lambda x: x["user_agreement"], reverse=True)

    top3_accuracy = f"{top_correct}/{total_top}" if total_top else "0/0"
    top3_streak = random.randint(1, 4)  # Replace with real streak logic later
    avg_win_rate = round((top_correct / total_top) * 100, 1) if total_top else 0.0

    return picks, top3_accuracy, top3_streak, avg_win_rate


@app.route("/tiktoklivegame")
def tiktoklivegame():
    # 1) Load the current game state
    state_doc = db.collection("state").document("tiktokGameState").get()
    state = state_doc.to_dict() if state_doc.exists else {}

    today = state.get("activeGameDay", datetime.now().strftime("%Y-%m-%d"))
    goal_count = state.get("goalCount", 0)
    game_over = state.get("gameOver", False)
    is_locked = state.get("locked", False)

    # 2) Fetch fixtures
    fixtures_doc = db.collection("tiktokLiveFixtures").document(today).get()
    fixture_data = fixtures_doc.to_dict().get("matches", []) if fixtures_doc.exists else []

    live_fixtures = []

    # ✅ FIX: Use int for fixture IDs, match the API return structure
    if fixture_data and isinstance(fixture_data[0], dict) and "fixture_id" in fixture_data[0]:
        fixture_ids = [int(m["fixture_id"]) for m in fixture_data]

        # 3) Fetch live scores from API
        try:
            url = "https://v3.football.api-sports.io/fixtures"
            params = {"ids": "-".join(map(str, fixture_ids))}  # Convert to comma-separated string
            response = requests.get(url, headers=HEADERS, params=params)

            print(f"📡 API Status: {response.status_code}")
            print(f"📦 API Response Text: {response.text[:500]}")

            api_data = response.json().get("response", [])
            id_map = {f["fixture"]["id"]: f for f in api_data}  # IDs are integers
            print(f"🧩 API ID Map Keys: {list(id_map.keys())}")

            # Merge API data with local match info
            for match in fixture_data:
                fid = int(match["fixture_id"])
                api = id_map.get(fid)
                if not api:
                    print(f"⚠️ No match found for fixture ID: {fid}")
                    continue

                home = api["teams"]["home"]["name"]
                away = api["teams"]["away"]["name"]
                score1 = api["goals"]["home"] if api["goals"]["home"] is not None else "-"
                score2 = api["goals"]["away"] if api["goals"]["away"] is not None else "-"
                status = api["fixture"]["status"]["short"]  # e.g. "1H", "HT", "FT", "NS"

                timestamp = api["fixture"].get("timestamp")
                kickoff = datetime.fromtimestamp(timestamp).strftime("%H:%M") if timestamp else "TBC"

                live_fixtures.append({
                    "home": home,
                    "away": away,
                    "score1": score1,
                    "score2": score2,
                    "status": status,
                    "kickoff": kickoff,
                    "total_goals": (score1 if isinstance(score1, int) else 0) + (score2 if isinstance(score2, int) else 0)
                })
        except Exception as e:
            print(f"❌ Error fetching live scores: {e}")
    else:
        # fallback to basic strings
        live_fixtures = fixture_data  # list of plain strings like "St Mirren vs Annan (15:00)"

    # 4) Fetch and sort leaderboard
    guesses = db.collection("tiktokLiveGuesses").where("date", "==", today).stream()
    leaderboard = sorted([g.to_dict() for g in guesses], key=lambda x: -x["guess"])

    # ---- Add total_goals calculation here ----
    total_goals = sum(
        int(match.get("score1", 0)) + int(match.get("score2", 0))
        for match in live_fixtures
        if str(match.get("score1", "")).isdigit() and str(match.get("score2", "")).isdigit()
    )

    # 5) Render template
    return render_template(
        "tiktoklivegame.html",
        fixtures=live_fixtures,
        leaderboard=leaderboard,
        goal_count=goal_count,
        game_over=game_over,
        is_locked=is_locked,
        total_goals=total_goals
    )


# -----------------------------------------------------
# API: TikTok Live Fixtures (JSON)
# -----------------------------------------------------
@app.route("/api/tiktok-live-fixtures")
def api_tiktok_live_fixtures():
    today = db.collection("state") \
              .document("tiktokGameState") \
              .get().to_dict() \
              .get("activeGameDay", datetime.now().strftime("%Y-%m-%d"))

    goal_count = db.collection("state") \
                 .document("tiktokGameState") \
                 .get().to_dict() \
                 .get("goalCount", 0)

    fixtures_doc = db.collection("tiktokLiveFixtures").document(today).get()
    fixture_data = fixtures_doc.to_dict().get("matches", []) if fixtures_doc.exists else []

    live_fixtures = []

    if fixture_data and isinstance(fixture_data[0], dict) and "fixture_id" in fixture_data[0]:
        fixture_ids = [int(m["fixture_id"]) for m in fixture_data]
        try:
            url = "https://v3.football.api-sports.io/fixtures"
            params = {"ids": "-".join(map(str, fixture_ids))}
            response = requests.get(url, headers=HEADERS, params=params)
            api_data = response.json().get("response", [])
            id_map = {f["fixture"]["id"]: f for f in api_data}

            for match in fixture_data:
                fid = int(match["fixture_id"])
                api = id_map.get(fid)
                if not api:
                    continue

                home = api["teams"]["home"]["name"]
                away = api["teams"]["away"]["name"]
                score1 = api["goals"]["home"] if api["goals"]["home"] is not None else "-"
                score2 = api["goals"]["away"] if api["goals"]["away"] is not None else "-"
                status = api["fixture"]["status"]["short"]
                timestamp = api["fixture"].get("timestamp")
                kickoff = datetime.fromtimestamp(timestamp).strftime("%H:%M") if timestamp else "TBC"

                live_fixtures.append({
                    "home": home,
                    "away": away,
                    "score1": score1,
                    "score2": score2,
                    "status": status,
                    "kickoff": kickoff,
                    "total_goals": (score1 if isinstance(score1, int) else 0) + (score2 if isinstance(score2, int) else 0)
                })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        live_fixtures = fixture_data

    return jsonify({
        "fixtures": live_fixtures,
        "goal_count": goal_count
    })


@app.route("/submit_tiktok_guess", methods=["POST"])
def submit_tiktok_guess():
    name  = request.form.get("name", "").strip()
    guess = int(request.form.get("guess", 0))

    if not name or guess <= 0:
        return redirect(url_for("tiktoklivegame"))

    today = db.collection("state") \
              .document("tiktokGameState") \
              .get().to_dict() \
              .get("activeGameDay",
                   datetime.now().strftime("%Y-%m-%d"))

    # Prevent duplicate
    existing = db.collection("tiktokLiveGuesses") \
                 .where("date", "==", today) \
                 .where("name", "==", name) \
                 .stream()
    if any(existing):
        return redirect(url_for("tiktoklivegame"))

    db.collection("tiktokLiveGuesses").add({
        "name": name,
        "guess": guess,
        "eliminated": False,
        "date": today
    })

    return redirect(url_for("tiktoklivegame"))

@app.route("/admin/add_tiktok_guess", methods=["POST"])
def add_tiktok_guess():
    name = request.form.get("tt_name", "").strip()
    guess = int(request.form.get("tt_guess", 0))

    if not name or guess <= 0:
        return redirect(url_for("admin_home"))  # or flash an error

    # Get active TikTok game day
    state_doc = db.collection("state").document("tiktokGameState").get()
    game_day = state_doc.to_dict().get("activeGameDay", datetime.now().strftime("%Y-%m-%d"))

    # Prevent duplicates
    existing = db.collection("tiktokLiveGuesses") \
                 .where("date", "==", game_day) \
                 .where("name", "==", name) \
                 .stream()

    if any(existing):
        return redirect(url_for("admin_home"))  # Already exists

    # Add guess to Firestore
    db.collection("tiktokLiveGuesses").add({
        "name": name,
        "guess": guess,
        "eliminated": False,
        "date": game_day
    })

    return redirect(url_for("admin_home"))


@app.route("/set_goals/<int:count>")
def set_goals(count):
    state_ref = db.collection("state").document("tiktokGameState")
    state_doc = state_ref.get()
    if not state_doc.exists:
        return "❌ No game state found", 404

    game_day = state_doc.to_dict().get("activeGameDay")
    state_ref.update({"goalCount": count})

    # LIVE elimination: kill off guesses lower than current total
    guesses = db.collection("tiktokLiveGuesses") \
                .where("date", "==", game_day) \
                .where("eliminated", "==", False) \
                .stream()

    for g in guesses:
        if g.to_dict().get("guess", 0) < count:
            g.reference.update({"eliminated": True})

    return f"✅ Goal count set to {count}. Updated eliminations for under-guesses."

@app.route("/end_tiktok_game", methods=["POST"])
def end_tiktok_game():
    goal_count = int(request.form["goalCount"])
    state_ref = db.collection("state").document("tiktokGameState")

    # Set game over + final score
    state_ref.update({
        "goalCount": goal_count,
        "gameOver": True
    })

    # FINAL elimination: eliminate guesses over final total if still in
    game_day = state_ref.get().to_dict().get("activeGameDay")
    guesses = db.collection("tiktokLiveGuesses") \
                .where("date", "==", game_day) \
                .stream()

    for doc in guesses:
        g = doc.to_dict()
        if not g.get("eliminated", False) and g.get("guess", 0) > goal_count:
            doc.reference.update({"eliminated": True})

    return redirect(url_for("admin_home"))

@app.route("/toggle_lock")
def toggle_lock():
    state_ref   = db.collection("state").document("tiktokGameState")
    current     = state_ref.get().to_dict().get("locked", False)
    state_ref.update({"locked": not current})
    return f"🔒 Submissions now {'locked' if not current else 'unlocked'}."


# -----------------------------------------------------
# User Stats (lifetime) – view page
# -----------------------------------------------------
@app.route('/me/stats')
def user_stats_view():
    """Render the logged-in user's lifetime prediction stats with processed
    team hit-rate table. Looks for Firestore doc at: users/{uid}/stats/lifetime.
    Supports query params: ?sort=adj|acc|attempts & ?min=<int>."""

    # --- helpers ---
    def wilson_lb(ci_correct: int, n_att: int, z: float = 1.96) -> float:
        """Wilson score lower bound for binomial proportion; returns 0..1."""
        if n_att <= 0:
            return 0.0
        p = ci_correct / n_att
        z2 = z * z
        denom = 1 + z2 / n_att
        centre = p + z2 / (2 * n_att)
        margin = z * ((p * (1 - p) + z2 / (4 * n_att)) / n_att) ** 0.5
        return max(0.0, (centre - margin) / denom)

    # --- choose user ---
    uid = session.get('user_id') or session.get('uid')
    override = request.args.get('uid')
    if override:
        uid = override
    if not uid:
        return render_template('user_stats.html',
                               stats=None,
                               teams_sorted=[],
                               sort_key='adj',
                               min_attempts=1,
                               error_msg='No user in session. Append ?uid=<USER_ID> while testing.')

    # --- read base stats doc ---
    try:
        snap = db.collection('users').document(uid).collection('stats').document('lifetime').get()
        if not snap.exists:
            return render_template('user_stats.html',
                                   stats=None,
                                   teams_sorted=[],
                                   sort_key='adj',
                                   min_attempts=1,
                                   error_msg='No stats yet. Run userStats.py to generate your lifetime stats.')
        stats = snap.to_dict() or {}
    except Exception as e:
        return render_template('user_stats.html',
                               stats=None,
                               teams_sorted=[],
                               sort_key='adj',
                               min_attempts=1,
                               error_msg=f'Failed to load stats: {e}')

    # --- build team hit-rate rows ---
    team_map = stats.get('team_hit_rate', {}) or {}

    # parse controls
    sort_key = request.args.get('sort', 'adj')  # 'adj' | 'acc' | 'attempts'
    try:
        min_attempts = int(request.args.get('min', 1))
    except Exception:
        min_attempts = 1

    rows = []
    for team, rec in team_map.items():
        attempts = int(rec.get('attempts', 0) or 0)
        correct  = int(rec.get('correct', 0) or 0)
        if attempts < min_attempts:
            continue
        accuracy = round((correct / attempts) * 100, 1) if attempts > 0 else 0.0
        adj_acc  = round(wilson_lb(correct, attempts) * 100, 1) if attempts > 0 else 0.0
        rows.append({
            'team': team,
            'attempts': attempts,
            'correct': correct,
            'accuracy': accuracy,
            'adj_accuracy': adj_acc,
        })

    # sort rows
    if sort_key == 'acc':
        teams_sorted = sorted(rows, key=lambda r: (-r['accuracy'], -r['attempts']))
    elif sort_key == 'attempts':
        teams_sorted = sorted(rows, key=lambda r: (-r['attempts'], -r['accuracy']))
    else:  # default 'adj'
        teams_sorted = sorted(rows, key=lambda r: (-r['adj_accuracy'], -r['attempts']))

    return render_template('user_stats.html',
                           stats=stats,
                           teams_sorted=teams_sorted,
                           sort_key=sort_key,
                           min_attempts=min_attempts,
                           error_msg=None)
# -----------------------------------------------------
# App entrypoint (local dev / simple hosting)
# -----------------------------------------------------
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)

    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5001))
    debug = os.getenv("FLASK_DEBUG", "1").lower() in ("1", "true", "yes")

    print(f"\n🚀 Starting SII web on http://{host}:{port} (debug={debug})\n")
    app.run(host=host, port=port, debug=debug)