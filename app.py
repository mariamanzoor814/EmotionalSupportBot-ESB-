# app.py
# Standard Library Imports
import os
import re
import random
import smtplib
import traceback
import time
from uuid import uuid4
from datetime import datetime, timedelta, timezone, date
from collections import Counter
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from markupsafe import escape, Markup
from werkzeug.utils import secure_filename
import base64, json, time

# Third-party Imports
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_session import Session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length
import firebase_admin
import requests
from google.cloud.firestore_v1 import FieldFilter
from firebase_admin import auth as firebase_auth
from firebase_admin import credentials, auth, firestore
import markdown as md 
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from urllib.parse import quote_plus


# Local Imports
from forms import ResetPasswordForm, LoginForm, SignupForm, ForgotPasswordForm, ChatForm, FeedbackForm, ProfileForm
from models import ( save_chat_session, save_chat_message, get_user_sessions, save_chat_session, 
                    analyze_sentiment, smart_mood_label)
from firebase_setup import db
from main import generate_bot_response
from llm_setup import generate_mood_explanation, generate_mood_recommendations
from mood_questions import get_random_questions

# Environment Setup
load_dotenv()

# Initialize Flask Application
app = Flask(__name__, static_folder='static', template_folder='templates')
# Load from .env
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

app.logger.info("GOOGLE_CLIENT_ID env var: %s", GOOGLE_CLIENT_ID)

# Config dict instead of client_secret.json
client_config = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris": [GOOGLE_REDIRECT_URI],
        "javascript_origins": [
            "http://127.0.0.1:5000",
            "http://localhost:5000"
        ]
    }
}
flow = Flow.from_client_config(
    client_config,
    scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_uri=GOOGLE_REDIRECT_URI
)



# Application Configuration
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "default_secret_key"),
    SESSION_COOKIE_NAME='esb_session',
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    SESSION_PERMANENT=False,
    SESSION_TYPE='filesystem',
    WTF_CSRF_SECRET_KEY=os.getenv("SECRET_KEY"),
    RECAPTCHA_PUBLIC_KEY=os.getenv('RECAPTCHA_SITE_KEY'),
    RECAPTCHA_PRIVATE_KEY=os.getenv('RECAPTCHA_SECRET_KEY')
)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # optional: limit file size (2MB)

# Initialize Extensions
Session(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Firebase Initialization
if not firebase_admin._apps:
    cred = credentials.Certificate(os.getenv("FIREBASE_CREDENTIALS_PATH"))
    firebase_admin.initialize_app(cred)

# Authentication Setup
class User(UserMixin):
    """Custom User class integrating Firebase UID with Flask-Login"""
    def __init__(self, uid, email):
        self.id = uid  # Using Firebase UID as primary identifier
        self.email = email
        self.uid = uid

@login_manager.user_loader
def load_user(uid):
    """Load user from Firebase UID"""
    try:
        user = auth.get_user(uid)
        return User(uid=user.uid, email=user.email)
    except auth.UserNotFoundError:
        return None

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Forms
class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[
        DataRequired(),
        Length(min=6, max=6, message='OTP must be 6 digits')
    ])
    submit = SubmitField('Verify OTP')

# Middleware
# Put this after you create `app` and configure logging, and BEFORE route definitions finish.
# Single, robust before_request & after_request

from flask import current_app

@app.before_request
def require_login():
    """
    Global auth middleware.
    - Allows listed endpoints (function names).
    - Allows certain request.path prefixes (e.g. /static, /auth) for safety.
    - Uses .split('.')[-1] so blueprint.function_name matches the simple name.
    """
    try:
        # safe list of function names (use the view function name)
        allowed_endpoints = {
            'home',
            'landing_page',
            'login',
            'signup',
            'verify_otp',
            'forgot_password',
            'password_reset_success',
            'google_login', 
            'submit_suggestion',# <-- IMPORTANT: whitelist your google-login endpoint
        }

        # safe path prefixes (allow entire prefix)
        allowed_path_prefixes = (
            '/static',
            '/auth',       # allow /auth/google-login and other auth callbacks
            '/favicon.ico',
            '/.well-known', # devtools/other well-known requests
        )

        # If endpoint is None (e.g., 404 before endpoint resolution), be conservative
        endpoint = request.endpoint or ''
        endpoint_name = endpoint.split('.')[-1]  # handles blueprints: bp.endpoint -> endpoint

        # Allow if endpoint is in allowed list
        if endpoint_name in allowed_endpoints:
            return

        # Allow if path starts with allowed prefix
        for pfx in allowed_path_prefixes:
            if request.path.startswith(pfx):
                return

        # Allow if user logged in (Flask-Login current_user)
        if getattr(current_user, "is_authenticated", False):
            return

        # Also allow if session-based login present (your app stores user_id in session)
        if 'user_id' in session:
            return

        # Not allowed -> log reason and redirect to login
        app.logger.debug(
            "Blocking access to endpoint='%s' (name='%s'), path='%s'; not authenticated",
            endpoint, endpoint_name, request.path
        )
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))

    except Exception as exc:
        # If anything goes wrong in the middleware, log and allow request to continue
        # (avoid locking yourself out during a bug)
        app.logger.exception("Error in require_login middleware: %s", exc)
        return  # allow the request (safer than crashing the app)

@app.after_request
def set_coop_header(response):
    """
    Set Cross-Origin-Opener-Policy so GSI popup can postMessage back.
    Keep this single and do not set Cross-Origin-Embedder-Policy unless required.
    """
    try:
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    except Exception:
        app.logger.exception("Failed to set COOP header")
    return response



@app.template_filter('markdown')
def markdown_filter(s):
    if not s:
        return ""
    import re
    html = md.markdown(
        s,
        extensions=[
            'fenced_code',
            'tables',
            'codehilite',
            'attr_list'
        ],
        extension_configs={
            'codehilite': {
                'guess_lang': False,
                'use_pygments': False
            }
        }
    )
    # Ensure class="hljs language-xyz"
    html = re.sub(r'<code class="([^"]+)"', r'<code class="hljs \1"', html)
    html = re.sub(r'<code>', r'<code class="hljs">', html)
    return Markup(html)

# def require_login():
#     allowed_routes = ['login', 'signup', 'verify_otp', 'forgot_password', 'static']
#     if 'user_id' not in session and request.endpoint not in allowed_routes:
#         return redirect(url_for('login'))

def decode_jwt_unverified(token):
    """Return JWT payload as dict without verifying signature."""
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return {}
        payload = parts[1]
        # add padding if necessary
        rem = len(payload) % 4
        if rem:
            payload += '=' * (4 - rem)
        decoded = base64.urlsafe_b64decode(payload.encode('utf-8'))
        return json.loads(decoded)
    except Exception:
        return {}

def generate_otp():
    return str(random.randint(100000, 999999))  # Generate a 6-digit OTP

def send_otp_email(user_email, otp, flow_type):
    try:
        print(f"📩 Sending OTP to: {user_email}")

        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = user_email
        
        # Adjust subject based on flow type (reset or signup)
        subject = "Your OTP for Password Reset" if flow_type == 'reset' else "Your OTP for Signup"
        msg["Subject"] = subject

        email_body = f"""
        <p>Hello,</p>
        <p>Your OTP for {subject.lower()} is: <strong>{otp}</strong></p>
        <p>This OTP is valid for 5 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
        """
        msg.attach(MIMEText(email_body, "html"))

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                response = server.sendmail(EMAIL_SENDER, user_email, msg.as_string())
                print("✅ OTP email sent successfully!", response)  # Log the response to verify success
        except Exception as e:
            print(f"🚨 Email Sending Error: {e}")
            raise  # Raise the error so it can be handled by the outer exception block

    except Exception as e:
        print(f"🚨 Error in send_otp_email: {e}")
        raise  # Raise to the caller
@app.route('/')
def home():
    return redirect(url_for('landing_page'))  # Or you can serve a home page if you prefer


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data.strip()

        try:
            user = auth.get_user_by_email(email)  # Check if user exists

            otp = generate_otp()
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(minutes=10)

            db.collection("reset_otps").document(email).set({
                "otp": otp,
                "timestamp": now,
                "expires_at": expires_at
            })

            send_otp_email(email, otp, flow_type="reset")
            session['reset_email'] = email
            flash("OTP sent to your email!", "success")
            return redirect(url_for('verify_otp'))

        except firebase_admin.auth.UserNotFoundError:
            flash("No account found with this email.", "danger")
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")

    return render_template('forgot-password.html', form=form)


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    flow_type = None
    email = None
    signup_data = None
    collection_name = None

    # Session flow checking
    if 'reset_email' in session:
        flow_type = 'reset'
        email = session['reset_email']
        collection_name = 'reset_otps'
    elif 'signup_data' in session:
        flow_type = 'signup'
        signup_data = session.get('signup_data')
        email = signup_data.get('email') if signup_data else None
        collection_name = 'signup_otps'
    else:
        flash("Session expired or invalid. Please try again.", "danger")
        return redirect(url_for('login'))

    if form.validate_on_submit():
        entered_otp = form.otp.data.strip()

        try:
            otp_doc = db.collection(collection_name).document(email).get()

            if not otp_doc.exists:
                flash("OTP expired or invalid. Request a new one.", "danger")
                return redirect(url_for('forgot_password' if flow_type == 'reset' else 'signup'))

            otp_data = otp_doc.to_dict()
            stored_otp = otp_data.get('otp')
            expires_at = otp_data.get('expires_at')

            if not expires_at or datetime.now(timezone.utc) > expires_at:
                # Delete expired OTP doc (best-effort)
                try:
                    db.collection(collection_name).document(email).delete()
                except Exception:
                    pass
                flash("OTP expired. Request a new one.", "danger")
                return redirect(url_for('forgot_password' if flow_type == 'reset' else 'signup'))

            if entered_otp != stored_otp:
                flash("Incorrect OTP. Please try again.", "danger")
                return render_template(
                    'verify_otp.html' if flow_type == 'reset' else 'verify_otp_signup.html',
                    form=form
                )

            # OTP valid
            if flow_type == 'reset':
                flash("OTP verified. You may reset your password.", "success")
                return redirect(url_for('reset_password'))

            elif flow_type == 'signup':
                if not signup_data:
                    flash("Signup session expired. Start again.", "danger")
                    return redirect(url_for('signup'))

                username = signup_data.get('username')
                password = signup_data.get('password')

                try:
                    # Create Firebase user
                    user = auth.create_user(
                        email=email,
                        password=password,
                        display_name=username
                    )

                    # Prepare default avatar (UI Avatars) if none provided
                    safe_name = quote_plus(username or (email.split('@')[0] if email else "User"))
                    default_avatar = f"https://ui-avatars.com/api/?name={safe_name}&background=random"

                    # Create Firestore user document with UID as key (include profile_picture)
                    user_ref = db.collection("users").document(user.uid)
                    user_ref.set({
                        "username": username,
                        "email": email,
                        "created_at": firestore.SERVER_TIMESTAMP,
                        "status": "active",
                        "profile_picture": default_avatar
                    }, merge=True)

                    # Delete OTP data (cleanup)
                    try:
                        db.collection("signup_otps").document(email).delete()
                    except Exception:
                        pass

                    # Log user in immediately with Flask-Login
                    user_obj = User(uid=user.uid, email=email)
                    login_user(user_obj)
                    session['user_id'] = user.uid
                    session['user_email'] = email
                    session['username'] = username
                    session['profile_picture'] = default_avatar

                    # Cleanup signup session data
                    session.pop('signup_data', None)

                    flash("Signup successful! Welcome to our platform.", "success")
                    return redirect(url_for('dashboard'))

                except Exception as user_creation_err:
                    print(f"🔥 User creation failed: {str(user_creation_err)}")
                    # Cleanup Firebase user if created partially
                    try:
                        if 'user' in locals() and getattr(user, 'uid', None):
                            auth.delete_user(user.uid)
                    except Exception:
                        pass
                    flash("Account creation failed. Please try again.", "danger")
                    return redirect(url_for('signup'))

        except Exception as e:
            traceback.print_exc()
            flash("OTP verification failed. Try again.", "danger")
            return redirect(url_for('forgot_password' if flow_type == 'reset' else 'signup'))

    # Render appropriate verify page
    return render_template(
        'verify_otp.html' if flow_type == 'reset' else 'verify_otp_signup.html',
        form=form
    )

@csrf.exempt
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    print("Session keys:", list(session.keys()))
    print("Session dict:", dict(session))
    reset_email = session.get('reset_email')
    signup_data = session.get('signup_data')

    print("Session keys:", list(session.keys()))
    print(f"Session data for reset_email: {reset_email}")
    print(f"Session data for signup_data: {signup_data}")

    if signup_data:
        email = signup_data.get('email')
        collection = 'signup_otps'
        flow_type = 'signup'
    elif reset_email:
        email = reset_email
        collection = 'reset_otps'
        flow_type = 'reset'
    else:
        return jsonify({"error": "Session expired. Restart the process."}), 400

    try:
        now = datetime.now(timezone.utc)
        new_otp = generate_otp()
        expires_at = now + timedelta(minutes=10)

        # USE set(..., merge=True) INSTEAD OF update()
        db.collection(collection).document(email).set({
            "otp": new_otp,
            "timestamp": now,
            "expires_at": expires_at
        }, merge=True)

        send_otp_email(email, new_otp, flow_type)
        return jsonify({"message": "OTP resent successfully."}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "OTP resend failed. Try again."}), 500

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email:
        flash("Session expired. Request a new OTP.", "danger")
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        new_password = form.password.data.strip()
        try:
            user = auth.get_user_by_email(email)
            auth.update_user(user.uid, password=new_password)
            session.pop('reset_email', None)
            flash("Password reset successful!", "success")
            return redirect(url_for('password_reset_success'))

        except Exception as e:
            flash(f"Error: {str(e)}", "danger")

    return render_template('reset-password.html', form=form)


@app.route('/password-reset-success')
def password_reset_success():
    return render_template('password-reset-success.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            username = escape(form.username.data.strip())  # Safe for later use
            password = form.password.data.strip()

            try:
                # Check if user already exists
                auth.get_user_by_email(email)
                flash("Email already registered. Please log in.", "danger")
                return redirect(url_for('login'))

            except firebase_admin.auth.UserNotFoundError:
                otp = generate_otp()
                now = datetime.now(timezone.utc)
                expires_at = now + timedelta(minutes=10)

                try:
                    print("📝 Storing OTP in Firestore for signup...")

                    # Store OTP in Firestore
                    db.collection("signup_otps").document(email).set({
                        "email": email,
                        "username": username,
                        "otp": otp,
                        "timestamp": now,
                        "expires_at": expires_at
                    })

                    print("✅ OTP stored in Firestore successfully.")
                    
                    # Send OTP via Email
                    try:
                        send_otp_email(email, otp, flow_type="signup")
                        print(f"📨 OTP email sent to {email}.")
                    except Exception as email_err:
                        print("❌ Failed to send OTP email:", str(email_err))
                        flash("Failed to send OTP. Please try again later.", "danger")
                        return redirect(url_for('signup'))

                    # Store signup session
                    session["signup_data"] = {
                        "email": email,
                        "username": username,
                        "password": password
                    }

                    flash("OTP sent to your email. Please verify to complete registration.", "success")
                    return redirect(url_for('verify_otp'))

                except Exception as firestore_err:
                    print("🔥 Firestore write failed:", str(firestore_err))
                    flash("An error occurred while processing your request. Try again later.", "danger")
                    return redirect(url_for('signup'))
        else:
            print("⚠️ Signup form not validated")
            print(form.errors)
            flash("Please fill in all fields correctly.", "warning")

    # Always pass form (and GOOGLE_CLIENT_ID for GSI) when rendering template
    return render_template('signup.html', form=form, GOOGLE_CLIENT_ID=os.getenv('GOOGLE_CLIENT_ID'))


# ===========================
# GOOGLE LOGIN
# ===========================
# place this in your main app file (replace existing route)
@app.route("/auth/google-login", methods=["POST"])
@csrf.exempt
def google_login():
    """
    Accepts JSON { idToken: "<google-id-token>" }.
    Verifies Google token, ensures Firebase Auth + Firestore user,
    logs in via Flask-Login, returns JSON. No redirects.
    """
    try:
        payload = request.get_json(silent=True) or {}
        id_token_str = payload.get("idToken") or payload.get("token")
        if not id_token_str:
            return jsonify({"error": "Missing ID token"}), 400

        client_id = os.getenv("GOOGLE_CLIENT_ID")
        if not client_id:
            return jsonify({"error": "Server misconfigured: missing GOOGLE_CLIENT_ID"}), 500

        # Verify the Google token
        try:
            id_info = google_id_token.verify_oauth2_token(
                id_token_str,
                google_requests.Request(),
                client_id
            )
        except ValueError as ve:
            return jsonify({"error": "Invalid Google token", "details": str(ve)}), 401

        email = id_info.get("email")
        name = id_info.get("name") or (email.split("@")[0] if email else None)
        picture = id_info.get("picture")
        if not email:
            return jsonify({"error": "Google token missing email"}), 400

        # Ensure Firebase Auth user exists
        try:
            existing = firebase_auth.get_user_by_email(email)
            firebase_uid = existing.uid
        except firebase_auth.UserNotFoundError:
            created = firebase_auth.create_user(
                email=email,
                display_name=name,
                photo_url=picture,
                email_verified=True
            )
            firebase_uid = created.uid

        # Ensure Firestore doc exists/updates
        user_doc_ref = db.collection("users").document(firebase_uid)
        snap = user_doc_ref.get()
        if not snap.exists:
            user_doc_ref.set({
                "uid": firebase_uid,
                "email": email,
                "username": name,
                "profile_picture": picture,
                "login_provider": "google",   # ✅ always set login_provider
                "created_at": firestore.SERVER_TIMESTAMP if 'firestore' in globals() else datetime.utcnow()
            }, merge=True)
        else:
            updates = {"login_provider": "google"}  # ✅ refresh login_provider
            data = snap.to_dict()
            if not data.get("profile_picture") and picture:
                updates["profile_picture"] = picture
            if not data.get("username") and name:
                updates["username"] = name
            if updates:
                user_doc_ref.update(updates)

        # Flask-Login session
        user_obj = User(uid=firebase_uid, email=email)
        login_user(user_obj)
        session["user_id"] = firebase_uid
        session["user_email"] = email
        session["username"] = name
        session["profile_picture"] = picture

        return jsonify({
            "message": "Google signup/login successful",
            "uid": firebase_uid,
            "email": email,
            "name": name,
            "profile_picture": picture
        }), 200

    except Exception as e:
        app.logger.exception("Unhandled exception in google_login")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/auth/callback")
def auth_callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        id_info = google_id_token.verify_oauth2_token(
            credentials._id_token,
            google_requests.Request(),
            os.getenv("GOOGLE_CLIENT_ID")
        )

        user_id = id_info["sub"]
        email = id_info.get("email")
        name = id_info.get("name")
        picture = id_info.get("picture")

        # Save/Update Firestore
        db.collection("users").document(user_id).set({
            "email": email,
            "username": name,
            "profile_picture": picture,
            "login_provider": "google"
        }, merge=True)

        # Log user in
        user = User(id=user_id, email=email, username=name)
        login_user(user)

        return redirect(url_for("dashboard"))

    except Exception as e:
        app.logger.error(f"Google login failed: {e}")
        return jsonify({"error": "Google login failed", "details": str(e)}), 400

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        remember = form.remember.data

        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={os.getenv('FIREBASE_WEB_API_KEY')}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            response = requests.post(url, json=payload)
            data = response.json()

            if "idToken" in data:
                uid = data['localId']  # Firebase UID

                # Get Firestore user doc
                user_ref = db.collection("users").document(uid)
                user_data = user_ref.get().to_dict()

                # If missing, create/update doc
                if not user_data:
                    user_ref.set({
                        "uid": uid,
                        "email": email,
                        "username": email.split("@")[0],
                        "profile_picture": None,
                        "created_at": firestore.SERVER_TIMESTAMP if 'firestore' in globals() else datetime.utcnow()
                    })
                    user_data = user_ref.get().to_dict()

                # Flask-Login user object
                user = User(uid=uid, email=email)
                login_user(user, remember=remember)

                # Save in session
                session['user_id'] = uid
                session['user_email'] = user_data.get('email')
                session['username'] = user_data.get('username')
                session['profile_picture'] = user_data.get('profile_picture')

                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                error_message = data.get("error", {}).get("message", "Invalid email or password.")
                flash(f"Login failed: {error_message}", "danger")

        except Exception as e:
            app.logger.exception("Login error")
            flash(f"Login failed: {str(e)}", "danger")

    return render_template('login.html', form=form, GOOGLE_CLIENT_ID=os.getenv("GOOGLE_CLIENT_ID"))


@app.route('/dashboard')
@login_required
def dashboard():
    user_id = current_user.id

    # Fetch user from Firestore
    user_ref = db.collection("users").document(user_id)
    user_doc = user_ref.get()
    if not user_doc.exists:
        flash("Your profile data is missing! Please contact support.", "danger")
        return redirect(url_for('logout'))

    user_data = user_doc.to_dict()

    # Determine profile avatar:
    if user_data.get("login_provider") == "google" and user_data.get("profile_picture"):
        profile_avatar = user_data["profile_picture"]
        is_initials = False
    else:
        # generate initials fallback
        username = user_data.get("username", "User")
        initials = "".join([part[0].upper() for part in username.split()[:2]])
        profile_avatar = initials
        is_initials = True

    # Fetch latest mood
    latest_mood_query = (
        db.collection('moods')
        .where(filter=FieldFilter("user_id", "==", user_id))
        .order_by('timestamp', direction=firestore.Query.DESCENDING)
        .limit(1)
        .stream()
    )
    latest_mood_data = next(latest_mood_query, None)
    if latest_mood_data:
        mood_doc = latest_mood_data.to_dict()
        latest_mood_score = mood_doc.get('confidence_score')
        latest_sentiment = mood_doc.get('mood_label')
    else:
        latest_mood_score = None
        latest_sentiment = None

    # Build mood history
    mood_history = []
    history_query = (
        db.collection('moods')
        .where(filter=FieldFilter("user_id", "==", user_id))
        .order_by('timestamp', direction=firestore.Query.DESCENDING)
        .stream()
    )
    for doc in history_query:
        data = doc.to_dict()
        if "timestamp" in data:
            data['timestamp'] = data['timestamp'].strftime('%Y-%m-%d %H:%M')
        mood_history.append(data)

    return render_template(
        "dashboard.html",
        latest_mood_score=latest_mood_score,
        latest_sentiment=latest_sentiment,
        mood_history=mood_history,
        user_email=user_data.get("email"),
        username=user_data.get("username"),
        profile_avatar=profile_avatar,
        is_initials=is_initials
    )


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = current_user.id
    user_doc = db.collection('users').document(user_id).get()
    user_data = user_doc.to_dict() if user_doc.exists else {}

    # Avatar logic (same as mood_analysis)
    if user_data.get("login_provider") == "google" and user_data.get("profile_picture"):
        profile_avatar = user_data["profile_picture"]
        is_initials = False
    else:
        username = user_data.get("username") or session.get("name") or current_user.email or ""
        # Build initials from up to the first two name parts
        initials = "".join([part[0].upper() for part in username.split()[:2] if part])
        # If initials empty (e.g., email only), fall back to first two letters of email local-part
        if not initials and "@" in username:
            initials = username.split("@", 1)[0][:2].upper()
        profile_avatar = initials or "?"  # safe fallback
        is_initials = True

    name = user_data.get("username") or session.get("name") or current_user.email or ""
    form = ProfileForm()

    # Handle form submission
    if form.validate_on_submit():
        updates = {}
        # Update first_name if provided
        if 'first_name' in form and form.first_name.data is not None:
            updates['first_name'] = form.first_name.data.strip()
        # Optionally update username if you include it in the form (uncomment if needed)
        # if 'username' in form and form.username.data:
        #     updates['username'] = form.username.data.strip()

        try:
            if updates:
                db.collection('users').document(user_id).update(updates)
            flash("Profile updated successfully!", "success")
        except Exception as e:
            # Be explicit about failure so user can act
            flash(f"Failed to update profile: {str(e)}", "danger")

        # Refresh local copy after update
        user_doc = db.collection('users').document(user_id).get()
        user_data = user_doc.to_dict() if user_doc.exists else {}
        # Recompute avatar in case name or picture changed
        if user_data.get("login_provider") == "google" and user_data.get("profile_picture"):
            profile_avatar = user_data["profile_picture"]
            is_initials = False
        else:
            username = user_data.get("username") or session.get("name") or current_user.email or ""
            initials = "".join([part[0].upper() for part in username.split()[:2] if part])
            if not initials and "@" in username:
                initials = username.split("@", 1)[0][:2].upper()
            profile_avatar = initials or "?"
            is_initials = True

        return redirect(url_for('settings'))

    # Pre-fill the form on GET (or when not POST)
    if request.method == 'GET':
        form.first_name.data = user_data.get('first_name', '')
        form.email.data = user_data.get('email', '')

    # Compute profile_pic for template consistency (nicer naming)
    profile_pic = profile_avatar if not is_initials else None

    return render_template(
        'settings.html',
        form=form,
        user=user_data,
        profile_pic=profile_pic,    # URL when image exists, otherwise None
        initials=profile_avatar,    # initials string when using initials (or "?")
        is_initials=is_initials,
        user_name=name
    )

@app.route('/feedback_form', methods=['GET', 'POST'])
@login_required
def feedback_form():
    form = FeedbackForm()
    if form.validate_on_submit():
        user_id = current_user.id
        name = form.name.data.strip()
        email = form.email.data.strip()
        experience = form.experience.data
        comments = form.comments.data.strip()
        timestamp = datetime.now(timezone.utc)

        try:
            save_user_feedback(user_id, name, email, experience, comments, timestamp)
            flash("Thank you for your feedback!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Error saving feedback: {e}", "danger")
            return redirect(url_for('feedback_form'))

    # For GET request or if form is not valid
    return render_template(
        'feedback_form.html',
        form=form,
        name='',
        email=getattr(current_user, 'email', '')
    )

def save_user_feedback(user_id, name, email, experience, comments, timestamp):
    feedback_data = {
        "name": name,
        "email": email,
        "experience": experience,
        "comments": comments,
        "timestamp": timestamp
    }
    # Save feedback under users/<user_id>/feedback/<auto_id>
    db.collection("users").document(str(user_id)).collection("feedback").add(feedback_data)
    
# helper to save to Firestore
def save_user_suggestion(user_id, name, email, suggestion, timestamp):
    doc = {
        "user_id": str(user_id) if user_id is not None else None,
        "name": name,
        "email": email,
        "suggestion": suggestion,
        "timestamp": timestamp
    }
    # top-level collection "user_suggestions"
    db.collection("user_suggestions").add(doc)

# public route (no @login_required)
@csrf.exempt 
@app.route("/submit_suggestion", methods=["POST"])
def submit_suggestion():
    # Accept JSON or form-encoded POSTs
    current_app.logger.debug("submit_suggestion content-type: %s", request.content_type)
    data = {}
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = {
            "first_name": request.form.get("first_name", ""),
            "last_name": request.form.get("last_name", ""),
            "name": request.form.get("name", ""),
            "email": request.form.get("email", ""),
            "suggestion": request.form.get("suggestion", "")
        }

    first = (data.get("first_name") or "").strip()
    last = (data.get("last_name") or "").strip()
    name = (data.get("name") or "").strip() or (first + " " + last).strip()
    email = (data.get("email") or "").strip()
    suggestion = (data.get("suggestion") or "").strip()

    # validation
    if not suggestion:
        return jsonify({"status": "error", "message": "Suggestion cannot be empty."}), 400
    if email and "@" not in email:
        return jsonify({"status": "error", "message": "Please provide a valid email address."}), 400

    # no login required; optional user_id = None
    user_id = None
    timestamp = datetime.now(timezone.utc)

    try:
        save_user_suggestion(user_id, name or None, email or None, suggestion, timestamp)
        return jsonify({"status": "success", "message": "Thanks — suggestion saved."}), 200
    except Exception as exc:
        current_app.logger.exception("Error saving suggestion")
        return jsonify({"status": "error", "message": f"Server error: {str(exc)}"}), 500
    
    
@app.route('/help')
def help_page():
    return render_template('help.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))



# Fetch past mood session history (internal)
def fetch_mood_history(session_id):
    """Pulls Q&A, summary, and free chats for a completed mood session."""
    history = []

    # 1) Q&A pairs from moodAnalysis
    for doc in db.collection('moodAnalysis') \
                 .where('session_id','==',session_id) \
                 .order_by('timestamp') \
                 .stream():
        d = doc.to_dict()
        ts = d['timestamp'].strftime('%Y-%m-%d %H:%M')
        history.append({'sender':'bot',  'message':d['question'], 'timestamp':ts})
        history.append({'sender':'user', 'message':d['answer'],   'timestamp':ts})

    # 2) Summary from MoodSessions
    sess = db.collection('MoodSessions').document(session_id).get()
    if sess.exists:
        d = sess.to_dict()
        ts = d['timestamp'].strftime('%Y-%m-%d %H:%M')
        recs = d.get('recommendations') or []
        if isinstance(recs, str):
            recs = [r.strip('-*• ').strip() for r in recs.split('\n') if r.strip()]
        mood_summary = {
            'sender': 'bot',
            'type': 'mood_summary',
            'mood_label': d.get('mood_label'),
            'sentiment': d.get('sentiment'),
            'confidence': d.get('confidence', 0),
            'explanation': d.get('explanation'),
            'recommendations': recs,
            'timestamp': ts
        }
        history.append(mood_summary)

    # 3) Free-chat logs from MoodChats
    for c in db.collection('MoodChats') \
               .where('session_id','==',session_id) \
               .order_by('timestamp') \
               .stream():
        d = c.to_dict()
        ts = d['timestamp'].strftime('%Y-%m-%d %H:%M')
        history.append({
            'sender':    d['sender'],
            'message':   d['message'],
            'timestamp': ts
        })

    return history


def save_free_chat(session_id, user_id, sender, message):
    db.collection('MoodChats').add({
        'session_id': session_id,
        'user_id':    user_id,
        'sender':     sender,
        'message':    message,
        'timestamp':  datetime.now(timezone.utc)
    })


def get_user_mood_sessions(user_id):
    """
    Returns a list of the user's mood-analysis sessions for the sidebar.
    Each item has:
      - id: the Firestore document ID
      - type: 'mood' (so you can pick the brain icon)
      - topic: a label to display
      - time: the timestamp (useful if you want to show dates)
    """
    sessions = []
    for doc in (
        db.collection('MoodSessions')
          .where('user_id', '==', user_id)
          .order_by('timestamp', direction=firestore.Query.DESCENDING)
          .stream()
    ):
        d = doc.to_dict()
        sessions.append({
            'id':    doc.id,
            'type':  'mood',
            'topic': f"Mood: {d.get('mood_label','')}",
            'time':  d.get('timestamp')
        })
    return sessions



# ——— Route ———
@app.route('/mood-analysis', methods=['GET'])
@login_required
def mood_analysis():
    user_id = current_user.id
    user_doc = db.collection('users').document(user_id).get()
    user_data = user_doc.to_dict() if user_doc.exists else {}

    # Avatar logic (same as chat)
    if user_data.get("login_provider") == "google" and user_data.get("profile_picture"):
        profile_avatar = user_data["profile_picture"]
        is_initials = False
    else:
        username = user_data.get("username") or session.get("name") or current_user.email
        initials = "".join([part[0].upper() for part in username.split()[:2]])
        profile_avatar = initials
        is_initials = True

    name = user_data.get("username") or session.get("name") or current_user.email
    sid = request.args.get('session_id')

    # View past session (read-only)
    if sid:
        return render_template(
            'mood_analysis.html',
            profile_avatar=profile_avatar,
            is_initials=is_initials,
            user_name=name,
            question=None,
            question_index=0,
            total_questions=0,
            mood_result=None,
            chat_history=fetch_mood_history(sid),
            session_list=get_user_mood_sessions(user_id),
            chat_session_id=sid,
            allow_chat=False
        )

    # Start new session (if not present)
    if 'questions' not in session:
        session['questions'] = get_random_questions()
        session['answers'] = []
        session['chat_history'] = []
        session['q_index'] = 0
        session['mood_done'] = False

    idx = session['q_index']
    current_q = (
        session['questions'][idx]
        if not session['mood_done'] and idx < len(session['questions'])
        else None
    )
    mood_result = session.get('mood_result')
    chat_history = session.get('chat_history', [])

    return render_template(
        'mood_analysis.html',
        profile_avatar=profile_avatar,
        is_initials=is_initials,
        user_name=name,
        question=current_q,
        question_index=idx,
        total_questions=len(session['questions']),
        mood_result=mood_result,
        chat_history=chat_history,
        session_list=get_user_mood_sessions(user_id),
        chat_session_id=None,
        allow_chat=True
    )

@csrf.exempt
@app.route('/ajax/mood-analysis', methods=['POST'])
@login_required
def ajax_mood_analysis():
    user_id = current_user.id
    data = request.get_json()
    answer = data.get('answer', '').strip()
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if 'questions' not in session:
        session['questions'] = get_random_questions()
        session['answers'] = []
        session['chat_history'] = []
        session['q_index'] = 0
        session['mood_done'] = False

    idx = session['q_index']
    questions = session['questions']

    # Q&A Flow
    if not session['mood_done']:
        if answer:
            q = questions[idx]
            session['chat_history'].append({'sender': 'bot', 'message': q, 'timestamp': ts})
            session['chat_history'].append({'sender': 'user', 'message': answer, 'timestamp': ts})
            session['answers'].append(answer)
            session['q_index'] += 1

        if session['q_index'] >= len(questions):
            # ---- sentiment & label pipeline (new) ----
            try:
                # 1) Let the LLM (or your classifier) produce an initial label/confidence/sentiment
                model_label, model_conf, model_sent = analyze_sentiment(session['questions'], session['answers'])
            except Exception as e:
                app.logger.exception("analyze_sentiment failed")
                model_label, model_conf, model_sent = "unclear", 0.0, "neutral"

            try:
                # 2) Apply heuristics / normalization to produce the final label/confidence/sentiment
                final_label, final_conf, final_sent = smart_mood_label(session['questions'], session['answers'], model_label, model_conf)
            except Exception as e:
                app.logger.exception("smart_mood_label failed")
                final_label, final_conf, final_sent = model_label or "unclear", float(model_conf or 0.0), model_sent or "neutral"

            # 3) Generate human-friendly explanation & recommendations (text outputs)
            combined = " ".join(session['answers'])
            try:
                expl = generate_mood_explanation(final_label, combined)
            except Exception as e:
                app.logger.exception("generate_mood_explanation failed")
                expl = "Let's explore this feeling together."

            try:
                recs = generate_mood_recommendations(final_label, combined)
            except Exception as e:
                app.logger.exception("generate_mood_recommendations failed")
                recs = ["Practice mindful breathing", "Write your thoughts in a journal", "Talk to someone you trust"]

            # Normalize recommendations to a list
            if isinstance(recs, str):
                recs_list = [r.strip('-*• ').strip() for r in recs.split('\n') if r.strip()]
            else:
                recs_list = recs

            # Use the final label/confidence/sentiment for saving & returning
            label, conf, sent = final_label, final_conf, final_sent

            new_sid = str(uuid4())

            # Save Q&A entries
            for q_text, a_text in zip(questions, session['answers']):
                db.collection('moodAnalysis').add({
                    'user_id': user_id,
                    'session_id': new_sid,
                    'question': q_text,
                    'answer': a_text,
                    'timestamp': datetime.now(timezone.utc)
                })

            # Save session summary
            db.collection('MoodSessions').document(new_sid).set({
                'user_id': user_id,
                'session_id': new_sid,
                'mood_label': label,
                'confidence': conf,
                'sentiment': sent,
                'recommendations': recs_list,
                'explanation': expl,
                'timestamp': datetime.now(timezone.utc)
            })

            result = {
                'mood_label': label,
                'confidence': conf,
                'sentiment': sent,
                'recommendations': recs_list,
                'explanation': expl,
                'timestamp': ts
            }
            session['mood_result'] = result
            session['mood_session_id'] = new_sid
            session['mood_done'] = True
            session['chat_history'].append({
                'sender': 'bot',
                'type': 'mood_summary',
                'mood_label': label,
                'confidence': conf,
                'sentiment': sent,
                'recommendations': recs_list,
                'explanation': expl,
                'timestamp': ts
            })
            return jsonify({'done': True, 'mood_result': result, 'chat_history': session['chat_history']})

        # If still questions left
        idx = session['q_index']
        next_q = questions[idx] if idx < len(questions) else None
        return jsonify({'done': False, 'next_question': next_q, 'chat_history': session['chat_history']})

    # Free chat after mood analysis is done
    elif session['mood_done']:
        if answer:
            sid = session['mood_session_id']
            session['chat_history'].append({'sender': 'user', 'message': answer, 'timestamp': ts})
            save_free_chat(sid, user_id, 'user', answer)
            context = session['chat_history'][-8:]
            bot_msg = generate_bot_response(context, answer)
            session['chat_history'].append({'sender': 'bot', 'message': bot_msg, 'timestamp': ts})
            save_free_chat(sid, user_id, 'bot', bot_msg)
            return jsonify({'reply': bot_msg, 'chat_history': session['chat_history']})
        return jsonify({'reply': '', 'chat_history': session['chat_history']})

@app.route('/api/mood-session-list')
@login_required
def api_mood_sessions():
    sessions = get_user_mood_sessions(current_user.id)
    for sess in sessions:
        sess['time'] = sess['time'].strftime('%Y-%m-%d %H:%M')
    return jsonify({'sessions': sessions})
@app.route('/get-mood-history/<session_id>', methods=['GET'])
@csrf.exempt
def get_mood_history(session_id):
    try:
        user_id = current_user.id
        msgs = db.collection('moodAnalysis')\
                 .where('session_id', '==', session_id)\
                 .order_by('timestamp')\
                 .stream()
        history = [{'question': m.to_dict().get('question'), 'answer': m.to_dict().get('answer'),
                    'timestamp': m.to_dict().get('timestamp').strftime('%Y-%m-%d %H:%M')} for m in msgs]
        return jsonify({'history': history}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete-mood/<session_id>', methods=['DELETE'])
@csrf.exempt
@login_required
def delete_mood(session_id):
    try:
        user_id = current_user.id
        # Remove Q&A docs
        qa_docs = db.collection('moodAnalysis').where('session_id', '==', session_id).stream()
        for doc in qa_docs:
            doc.reference.delete()
        # Remove session summary
        sess_ref = db.collection('MoodSessions').document(session_id)
        if sess_ref.get().exists:
            sess_ref.delete()
        return jsonify({'success': True}), 200
    except Exception:
        return jsonify({'error': 'Failed to delete mood session'}), 500

@app.route('/reanalyze-mood', methods=['POST'])
@csrf.exempt
@login_required
def reanalyze_mood():
    for key in ['questions', 'answers', 'q_index', 'mood_completed', 'chat_history', 'mood_result']:
        session.pop(key, None)
    return redirect(url_for('mood_analysis'))

@app.route('/save-mood-analysis', methods=['POST'])
@csrf.exempt
def save_mood_analysis_api():
    data = request.get_json()
    user_id = data.get('user_id')
    session_id = data.get('session_id') or str(uuid4())
    questions = data.get('questions') or []
    answers = data.get('answers') or []
    if not user_id or not questions or not answers:
        return jsonify({'error': 'Missing fields'}), 400
    combined = " ".join(answers)
    label, conf, sent = analyze_sentiment(questions, answers)
    label, conf, sent = smart_mood_label(questions, answers, label, conf)
    recs = generate_mood_recommendations(label, combined)
    expl = generate_mood_explanation(label, combined)
    # Save QA
    for q, a in zip(questions, answers):
        db.collection('moodAnalysis').document().set({
            'user_id': user_id,
            'session_id': session_id,
            'question': q,
            'answer': a,
            'timestamp': datetime.utcnow()
        })
    # Save summary
    db.collection('MoodSessions').document(session_id).set({
        'user_id': user_id,
        'session_id': session_id,
        'mood_label': label,
        'confidence': conf,
        'sentiment': sent,
        'recommendations': recs,
        'explanation': expl,
        'timestamp': datetime.utcnow()
    })
    return jsonify({'session_id': session_id, 'mood_label': label,
                    'confidence': conf, 'sentiment': sent,
                    'recommendations': recs}), 200


    
@csrf.exempt
@app.route('/mood_trends', methods=['GET'])
@login_required
def mood_trends():
    user_id = current_user.id
    if not user_id:
        flash("You must be logged in to view mood trends.", "error")
        return redirect(url_for('login'))

    user_doc = db.collection("users").document(user_id).get()
    user_data = user_doc.to_dict() if user_doc.exists else {}

    # --- Avatar logic: prefer Google profile picture if present (adjust field names if needed)
    # If your user doc stores the provider or field name differently, change these keys.
    if user_data.get("login_provider") == "google" and user_data.get("profile_picture"):
        profile_avatar = user_data["profile_picture"]
        is_initials = False
    else:
        # fallback to initials from username/email
        username = user_data.get("username") or session.get("name") or current_user.email or ""
        initials = "".join([part[0].upper() for part in username.split()[:2] if part])
        profile_avatar = initials or "U"
        is_initials = True

    # --- existing logic (unchanged except variable names) ---
    today = datetime.utcnow().date()
    days = [(today - timedelta(days=i)) for i in reversed(range(7))]
    mood_days = [{"label": d.strftime("%a"), "day": d.day, "date": d.strftime("%Y-%m-%d")} for d in days]

    start_of_week = days[0]
    moods_query = db.collection('MoodSessions') \
        .where('user_id', '==', user_id) \
        .where('timestamp', '>=', datetime.combine(start_of_week, datetime.min.time())) \
        .where('timestamp', '<', datetime.combine(today + timedelta(days=1), datetime.min.time())) \
        .order_by('timestamp')

    mood_entries = [mood.to_dict() for mood in moods_query.stream()]
    print("MoodSessions found:", mood_entries)

    mood_score_by_day = {d["date"]: 0 for d in mood_days}
    mood_label_by_day = {d["date"]: "" for d in mood_days}
    for entry in mood_entries:
        # guard if timestamp missing
        if not entry.get('timestamp'):
            continue
        entry_date = entry['timestamp'].date().strftime("%Y-%m-%d")
        if entry_date in mood_score_by_day:
            mood_score_by_day[entry_date] = entry.get("confidence", 0)
            mood_label_by_day[entry_date] = entry.get("mood_label", "")

    mood_trends = [mood_score_by_day[d["date"]] * 18 for d in mood_days]
    mood_trends_labels = [d["label"] for d in mood_days]

    # Calculate mood percentages
    label_counts = {}
    for entry in mood_entries:
        lbl = entry.get("mood_label", "Unknown")
        label_counts[lbl] = label_counts.get(lbl, 0) + 1
    total = sum(label_counts.values())
    label_colors = {
        'Happy': 'swatch-happy',
        'Stressed': 'swatch-stressed',
        'Relaxed': 'swatch-relaxed',
        'Angry': 'swatch-angry'
    }
    overall_mood = []
    for label, count in label_counts.items():
        overall_mood.append({
            "color": label_colors.get(label, 'swatch-happy'),
            "label": label,
            "percent": int((count / total) * 100) if total else 0
        })
    donut_data = []
    donut_order = ['Happy', 'Stressed', 'Relaxed', 'Angry']
    for lbl in donut_order:
        percent = next((m["percent"] for m in overall_mood if m["label"] == lbl), 0)
        donut_data.append({"class": lbl.lower(), "percent": percent})

    latest_entry = mood_entries[-1] if mood_entries else None
    mood_label = latest_entry.get("mood_label") if latest_entry else "No Data"
    confidence_score = latest_entry.get("confidence") if latest_entry else "N/A"
    mood_summary = [latest_entry.get("explanation")] if latest_entry and latest_entry.get("explanation") else []
    tips = latest_entry.get("recommendations", [
        "Break tasks into smaller steps to reduce stress.",
        "Prioritize rest and balance study with short breaks.",
        "Reach out to friends/family for support.",
        "Focus on small wins to boost confidence.",
        "Stay present—take it one step at a time."
    ]) if latest_entry else []
    donut_label = "Improved<br>By 20%"

    return render_template(
        'mood_trends.html',
        profile_avatar=profile_avatar,
        is_initials=is_initials,
        user_name=(user_data.get("username") or session.get("name") or current_user.email),
        mood_days=mood_days,
        selected_day=days[-1].day,
        mood_label=mood_label,
        confidence_score=confidence_score,
        mood_summary=mood_summary,
        tips=tips,
        mood_trends=mood_trends,
        mood_trends_labels=mood_trends_labels,
        overall_mood=overall_mood,
        donut_data=donut_data,
        donut_label=donut_label
    )


# helper to parse YYYY-MM-DD -> date
def parse_ymd(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None

@app.route('/get-mood-trends', methods=['POST'])
@csrf.exempt
@login_required
def get_mood_trends():
    user_id = current_user.id
    data = request.get_json() or {}
    view_type = (data.get('view_type') or 'week').lower()
    date_str = data.get('date')

    today = datetime.utcnow().date()

    # determine window and labels
    if view_type == 'day' and date_str:
        d = parse_ymd(date_str) or today
        range_start = datetime.combine(d, datetime.min.time())
        range_end = range_start + timedelta(days=1)
        labels = [d.strftime("%a")]
        day_list = [d.strftime("%Y-%m-%d")]
    elif view_type == 'month':
        d = parse_ymd(date_str) or today
        first = d.replace(day=1)
        next_month = (first + timedelta(days=32)).replace(day=1)
        range_start = datetime.combine(first, datetime.min.time())
        range_end = datetime.combine(next_month, datetime.min.time())
        days = []
        cur = first
        while cur < next_month:
            days.append(cur)
            cur += timedelta(days=1)
        labels = [dt.strftime("%d") for dt in days]
        day_list = [dt.strftime("%Y-%m-%d") for dt in days]
    elif view_type == 'year':
        d = parse_ymd(date_str) or today
        first = date(d.year, 1, 1)
        next_year = date(d.year + 1, 1, 1)
        range_start = datetime.combine(first, datetime.min.time())
        range_end = datetime.combine(next_year, datetime.min.time())
        labels = [date(d.year, m, 1).strftime("%b") for m in range(1,13)]
        day_list = None
    else:
        # default: week ending on date (or today)
        d = parse_ymd(date_str) or today
        start_d = d - timedelta(days=6)
        range_start = datetime.combine(start_d, datetime.min.time())
        range_end = datetime.combine(d + timedelta(days=1), datetime.min.time())
        day_list = [(start_d + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
        labels = [(start_d + timedelta(days=i)).strftime("%a") for i in range(7)]

    # query Firestore
    sessions_ref = db.collection('MoodSessions') \
        .where('user_id', '==', user_id) \
        .where('timestamp', '>=', range_start) \
        .where('timestamp', '<', range_end) \
        .order_by('timestamp')

    entries = [doc.to_dict() for doc in sessions_ref.stream()]

    resp = {
        'mood_trends': [],
        'mood_trends_labels': labels,
        'mood_label': 'No Data',
        'confidence_score': 'N/A',
        'mood_summary': [],
        'tips': [],
        'overall_mood': [],
        'donut_data': [],
        'donut_label': ''
    }

    # aggregate values for chart
    if view_type == 'year':
        months_vals = [0]*12
        months_counts = [0]*12
        for e in entries:
            ts = e.get('timestamp')
            if not ts: continue
            m = ts.month - 1
            conf = e.get('confidence') or 0
            months_vals[m] += conf
            months_counts[m] += 1
        for i in range(12):
            avg = (months_vals[i] / months_counts[i]) if months_counts[i] else 0
            resp['mood_trends'].append(avg * 18)
    elif view_type == 'month' and day_list:
        by_day = {d: {'sum':0, 'count':0} for d in day_list}
        for e in entries:
            ts = e.get('timestamp')
            if not ts: continue
            key = ts.date().strftime("%Y-%m-%d")
            if key in by_day:
                by_day[key]['sum'] += (e.get('confidence') or 0)
                by_day[key]['count'] += 1
        for d in day_list:
            rec = by_day[d]
            avg = (rec['sum'] / rec['count']) if rec['count'] else 0
            resp['mood_trends'].append(avg * 18)
    else:
        # week/day
        if day_list:
            by_day = {d: {'sum':0, 'count':0} for d in day_list}
            for e in entries:
                ts = e.get('timestamp')
                if not ts: continue
                key = ts.date().strftime("%Y-%m-%d")
                if key in by_day:
                    by_day[key]['sum'] += (e.get('confidence') or 0)
                    by_day[key]['count'] += 1
            for d in day_list:
                rec = by_day[d]
                avg = (rec['sum'] / rec['count']) if rec['count'] else 0
                resp['mood_trends'].append(avg * 18)

    # build overall mood and donut
    label_counts = {}
    for e in entries:
        lbl = e.get('mood_label') or 'Unknown'
        label_counts[lbl] = label_counts.get(lbl, 0) + 1
    total = sum(label_counts.values())
    label_colors = {
        'Happy': 'swatch-happy',
        'Stressed': 'swatch-stressed',
        'Relaxed': 'swatch-relaxed',
        'Angry': 'swatch-angry'
    }
    overall = []
    for label, count in label_counts.items():
        overall.append({
            "color": label_colors.get(label, 'swatch-happy'),
            "label": label,
            "percent": int((count / total) * 100) if total else 0
        })
    resp['overall_mood'] = overall
    donut_order = ['Happy', 'Stressed', 'Relaxed', 'Angry']
    donut = []
    for lbl in donut_order:
        pct = next((m["percent"] for m in overall if m["label"] == lbl), 0)
        donut.append({"class": lbl.lower(), "percent": pct})
    resp['donut_data'] = donut

    latest = entries[-1] if entries else None
    if latest:
        resp['mood_label'] = latest.get('mood_label') or resp['mood_label']
        resp['confidence_score'] = latest.get('confidence') or resp['confidence_score']
        expl = latest.get('explanation')
        if expl: resp['mood_summary'] = [expl]
        recs = latest.get('recommendations') or []
        resp['tips'] = recs if isinstance(recs, list) else ([r.strip('-*• ').strip() for r in str(recs).split('\n') if r.strip()])
        resp['donut_label'] = latest.get('donut_label') or ''
    else:
        resp['tips'] = []

    return jsonify(resp)



@csrf.exempt
def save_recommendation(user_id, chat_session_id, mood_label, recommendation_text):
    recommendation_data = {
        "user_id": user_id,
        "chat_session_id": chat_session_id,
        "mood": mood_label,
        "recommendation": recommendation_text,
        "timestamp": datetime.datetime.utcnow()
    }
    db.collection("Recommendations").add(recommendation_data)
    
@app.route('/get_recommendations', methods=['GET'])
@login_required
def get_recommendations():
    user_id = current_user.id
    recommendations_ref = db.collection('Recommendations').where('user_id', '==', user_id).order_by('timestamp', direction=firestore.Query.DESCENDING)
    docs = recommendations_ref.stream()
    rec_list = [{
        "mood": doc.to_dict().get("mood"),
        "recommendation": doc.to_dict().get("recommendation"),
        "timestamp": doc.to_dict().get("timestamp").isoformat()
    } for doc in docs]
    return jsonify(rec_list)


@app.route('/start-chat', methods=['GET'])
def start_chat():
    if 'user_id' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))

    chat_session_id = str(uuid4())  # NEW SESSION ID
    session['chat_session_id'] = chat_session_id
    session['chat_start_time'] = datetime.now(timezone.utc)

    # Optionally store it in Firestore
    db.collection('users').document(session['user_id']).collection('chats').document(chat_session_id).set({
        'start_time': firestore.SERVER_TIMESTAMP,
        'active': True
    })

    flash("🔵 New chat session started!", "info")
    return redirect(url_for('chat', chat_session_id=chat_session_id))

@app.route('/end-chat', methods=['GET'])
def end_chat():
    if 'user_id' not in session or 'chat_session_id' not in session or 'chat_start_time' not in session:
        flash("No active chat session found.", "error")
        return redirect(url_for('dashboard'))

    user_id = session['user_id']
    chat_session_id = session['chat_session_id']
    session_start = session['chat_start_time']
    session_end = datetime.utcnow()

    try:
        # Fetch first user message as topic
        first_msg = db.collection('users').document(user_id)\
            .collection('chats').document(chat_session_id)\
            .collection('messages')\
            .order_by('timestamp').limit(1).stream()
        
        topic = "Untitled Chat"
        for msg in first_msg:
            msg_data = msg.to_dict()
            if msg_data.get("sender") == "user":
                topic = msg_data.get("message", "").strip()[:40] or "Untitled Chat"
                break

        # Update session with topic and end_time
        db.collection('users').document(user_id)\
            .collection('chats').document(chat_session_id)\
            .update({
                'end_time': firestore.SERVER_TIMESTAMP,
                'active': False,
                'topic': topic
            })

        save_chat_session(
            user_id=user_id,
            session_start=session_start,
            session_end=session_end
        )

        flash("✅ Chat session saved successfully.", "success")

    except Exception as e:
        print(f"[ERROR] Failed to end chat session: {e}")
        flash(f"❌ Failed to save chat session: {str(e)}", "error")

    # Clear session data
    session.pop('chat_session_id', None)
    session.pop('chat_start_time', None)

    return redirect(url_for('dashboard'))


# @csrf.exempt
# @app.route('/get-chat-history/<chat_session_id>', methods=['GET'])
# def get_chat_history_route(chat_session_id):
#     try:
#         # Get user ID from both session and current_user for compatibility
#         user_id = session.get('user_id') or current_user.id
        
#         messages_ref = db.collection('users').document(user_id)\
#             .collection('chats').document(chat_session_id)\
#             .collection('messages')
            
#         chat_history = [{
#             'id': msg.id,
#             'sender': msg.get('sender'),
#             'message': msg.get('message'),
#             'timestamp': msg.get('timestamp').strftime('%Y-%m-%d %H:%M')
#         } for msg in messages_ref.order_by("timestamp").stream()]
        
#         return jsonify({'history': chat_history}), 200
        
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

@csrf.exempt
@app.route('/delete-chat/<chat_session_id>', methods=['DELETE'])
@login_required
def delete_chat(chat_session_id):
    try:
        user_id = current_user.id
        
        # Delete chat messages and document
        chat_ref = db.collection('users').document(user_id)\
            .collection('chats').document(chat_session_id)
        # Delete messages subcollection
        messages = chat_ref.collection('messages').stream()
        for msg in messages:
            msg.reference.delete()
        chat_ref.delete()

        # Delete MoodAnalysis entries
        mood_analysis_query = db.collection('MoodAnalysis')\
            .where('chat_session_id', '==', chat_session_id)
        for doc in mood_analysis_query.stream():
            doc.reference.delete()

        # Delete MoodSessions entry
        mood_session_ref = db.collection('MoodSessions').document(chat_session_id)
        if mood_session_ref.get().exists:
            mood_session_ref.delete()

        return jsonify({'success': True}), 200

    except Exception as e:
        print(f"Deletion failed: {str(e)}")
        return jsonify({'error': 'Failed to delete chat'}), 500
    
@app.route('/chat/', defaults={'chat_session_id': None}, methods=['GET'])
@app.route('/chat', defaults={'chat_session_id': None}, methods=['GET'])
@app.route('/chat/<chat_session_id>', methods=['GET'])
@login_required
def chat(chat_session_id):
    form = ChatForm()
    user_id = current_user.id

    # ✅ Fetch user profile from Firestore
    user_ref = db.collection("users").document(user_id)
    user_doc = user_ref.get()
    if not user_doc.exists:
        flash("Your profile data is missing! Please contact support.", "danger")
        return redirect(url_for('logout'))

    user_data = user_doc.to_dict()

    # ✅ Determine profile avatar (Google profile picture OR initials)
    if user_data.get("login_provider") == "google" and user_data.get("profile_picture"):
        profile_avatar = user_data["profile_picture"]
        is_initials = False
    else:
        username = user_data.get("username", "User")
        initials = "".join([part[0].upper() for part in username.split()[:2]])
        profile_avatar = initials
        is_initials = True

    # ✅ Handle chat session
    if not chat_session_id:
        chat_session_id = session.get('chat_session_id')
        if not chat_session_id:
            return redirect(url_for('start_chat'))

    chat_doc_ref = db.collection('users').document(user_id).collection('chats').document(chat_session_id)
    if not chat_doc_ref.get().exists:
        chat_doc_ref.set({
            'created_at': firestore.SERVER_TIMESTAMP,
            'user_id': user_id,
            'topic': f"Chat from {datetime.now().strftime('%b %d')}"
        })
    session['chat_session_id'] = chat_session_id

    # ✅ Fetch messages
    messages_ref = chat_doc_ref.collection('messages')
    chat_history = [msg.to_dict() for msg in messages_ref.order_by("timestamp").stream()]

    return render_template(
        'chat.html',
        form=form,
        chat_history=chat_history,
        chat_session_id=chat_session_id,
        session_list=get_user_sessions(user_id),
        # 🆕 User profile data
        user_email=user_data.get("email"),
        username=user_data.get("username"),
        profile_avatar=profile_avatar,
        is_initials=is_initials
    )


from datetime import datetime, timezone

def _serialize_doc_to_iso(doc_snapshot_or_dict):
    """
    Return a dict with 'timestamp' as an ISO8601 UTC string (Z suffix).
    Accepts either DocumentSnapshot or plain dict.
    """
    try:
        doc = doc_snapshot_or_dict.to_dict() if hasattr(doc_snapshot_or_dict, "to_dict") else dict(doc_snapshot_or_dict)
    except Exception:
        doc = dict(doc_snapshot_or_dict)

    ts_iso = ""
    # 1) prefer explicit numeric ms stored on doc (timestamp_ms)
    if "timestamp_ms" in doc and isinstance(doc["timestamp_ms"], (int, float)):
        dt = datetime.fromtimestamp(doc["timestamp_ms"] / 1000.0, tz=timezone.utc)
        ts_iso = dt.isoformat().replace("+00:00", "Z")
    else:
        ts = doc.get("timestamp")
        if ts:
            try:
                # Firestore python Timestamp-like / datetime
                if hasattr(ts, "to_datetime"):
                    dt = ts.to_datetime().astimezone(timezone.utc)
                    ts_iso = dt.isoformat().replace("+00:00", "Z")
                elif hasattr(ts, "strftime"):
                    # Python datetime (maybe naive) — force to UTC if tzinfo missing
                    if ts.tzinfo is None:
                        dt = ts.replace(tzinfo=timezone.utc)
                    else:
                        dt = ts.astimezone(timezone.utc)
                    ts_iso = dt.isoformat().replace("+00:00", "Z")
                elif isinstance(ts, dict) and "seconds" in ts:
                    dt = datetime.fromtimestamp(ts["seconds"], tz=timezone.utc)
                    ts_iso = dt.isoformat().replace("+00:00", "Z")
                else:
                    ts_iso = str(ts)
            except Exception:
                ts_iso = ""
    doc["timestamp"] = ts_iso
    return doc


@csrf.exempt
@app.route('/ajax/chat/send', methods=['POST'])
@login_required
def ajax_chat_send():
    user_id = current_user.id
    data = request.get_json(silent=True) or {}
    chat_session_id = data.get('chat_session_id')
    user_message = (data.get('message') or '').strip()

    if not chat_session_id or not user_message:
        return jsonify({'error': 'Missing chat_session_id or message'}), 400

    chat_doc_ref = db.collection('users').document(user_id).collection('chats').document(chat_session_id)
    messages_ref = chat_doc_ref.collection('messages')

    try:
        # server-side epoch ms (guaranteed numeric instant)
        now_ms = int(time.time() * 1000)

        # Add user message with server timestamp + explicit ms
        messages_ref.add({
            'sender': 'user',
            'message': user_message,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'timestamp_ms': now_ms
        })

        # Ensure chat doc exists and set topic from first user message if missing/placeholder
        chat_snapshot = chat_doc_ref.get()
        chat_data = chat_snapshot.to_dict() if chat_snapshot.exists else {}
        topic = chat_data.get('topic') if chat_data else None
        if not topic or topic.startswith('Chat from'):
            snippet = user_message.split('\n', 1)[0].strip()
            if len(snippet) > 60:
                snippet = snippet[:57].rsplit(' ', 1)[0] + '…'
            if not snippet:
                snippet = f"Chat {datetime.utcfromtimestamp(now_ms / 1000.0).strftime('%b %d')}"
            chat_doc_ref.set({'topic': snippet}, merge=True)
            topic = snippet

        # Read messages (order by Firestore timestamp) — server ordering still correct
        final_snapshots = list(messages_ref.order_by('timestamp').stream())

        # generate bot response from current chat_history
        bot_response = generate_bot_response([s.to_dict() for s in final_snapshots], user_message)

        # add bot response with its own server timestamp + ms
        bot_now_ms = int(time.time() * 1000)
        messages_ref.add({
            'sender': 'bot',
            'message': bot_response,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'timestamp_ms': bot_now_ms
        })

        # fetch latest messages and serialize to ISO timestamps
        latest = list(messages_ref.order_by('timestamp').stream())
        chat_history = [_serialize_doc_to_iso(s) for s in latest]

        return jsonify({'reply': bot_response, 'chat_history': chat_history, 'topic': topic}), 200

    except Exception as e:
        app.logger.exception("Chat send failed")
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/ajax/chat/rename', methods=['POST'])
@login_required
def ajax_chat_rename():
    data = request.get_json(silent=True) or {}
    chat_session_id = data.get('chat_session_id')
    new_title = (data.get('title') or '').strip()

    if not chat_session_id or not new_title:
        return jsonify({'error': 'Missing chat_session_id or title'}), 400

    try:
        chat_doc_ref = db.collection('users').document(current_user.id).collection('chats').document(chat_session_id)
        if not chat_doc_ref.get().exists:
            return jsonify({'error': 'Chat not found'}), 404

        chat_doc_ref.update({'topic': new_title})
        return jsonify({'success': True, 'title': new_title}), 200
    except Exception as e:
        app.logger.exception("Rename failed")
        return jsonify({'error': str(e)}), 500


@csrf.exempt
@app.route('/ajax/chat/history/<chat_session_id>', methods=['GET'])
@login_required
def ajax_chat_history(chat_session_id):
    user_id = current_user.id
    chat_doc_ref = db.collection('users').document(user_id).collection('chats').document(chat_session_id)
    messages_ref = chat_doc_ref.collection('messages')

    def _serialize_doc_to_iso(item):
        """
        Accept either a DocumentSnapshot or a plain dict and return a JSON-friendly dict.
        Produces 'timestamp' as ISO8601 UTC (e.g. "2025-08-18T12:34:56.789Z").
        Prefer explicit numeric 'timestamp_ms' if present.
        """
        try:
            doc = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        except Exception:
            doc = dict(item)

        # Ensure we don't mutate original dict in Firestore snapshot
        out = dict(doc)

        ts_iso = ""
        # 1) prefer explicit numeric ms stored on doc (timestamp_ms)
        ts_ms = out.get("timestamp_ms")
        if isinstance(ts_ms, (int, float)):
            try:
                dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
                ts_iso = dt.isoformat().replace("+00:00", "Z")
            except Exception:
                ts_iso = ""
        else:
            ts = out.get("timestamp")
            if ts:
                try:
                    # Firestore Timestamp-like (python library sometimes exposes to_datetime)
                    if hasattr(ts, "to_datetime"):
                        dt = ts.to_datetime().astimezone(timezone.utc)
                        ts_iso = dt.isoformat().replace("+00:00", "Z")
                    # Python datetime
                    elif hasattr(ts, "strftime"):
                        if ts.tzinfo is None:
                            dt = ts.replace(tzinfo=timezone.utc)
                        else:
                            dt = ts.astimezone(timezone.utc)
                        ts_iso = dt.isoformat().replace("+00:00", "Z")
                    # dict-like {'seconds':..., 'nanoseconds':...}
                    elif isinstance(ts, dict) and "seconds" in ts:
                        dt = datetime.fromtimestamp(ts["seconds"], tz=timezone.utc)
                        ts_iso = dt.isoformat().replace("+00:00", "Z")
                    else:
                        ts_iso = str(ts)
                except Exception:
                    ts_iso = ""
        out["timestamp"] = ts_iso
        # Keep original timestamp_ms if present (useful clientside)
        if "timestamp_ms" in out and isinstance(out["timestamp_ms"], (int, float)):
            out["timestamp_ms"] = int(out["timestamp_ms"])
        return out

    try:
        snapshots = list(messages_ref.order_by("timestamp").stream())
        chat_history = [_serialize_doc_to_iso(s) for s in snapshots]
        return jsonify({"chat_history": chat_history}), 200
    except Exception as e:
        app.logger.exception("Failed to fetch chat history")
        return jsonify({"error": "Failed to fetch chat history", "details": str(e)}), 500



@csrf.exempt
@app.route('/save-chat-message', methods=['POST'])
def save_chat_message_route():
    try:
        data = request.get_json()
        user_id = session.get('user_id')
        chat_session_id = data.get('chat_session_id')
        message = data.get('message')
        sender = data.get('sender')

        if not user_id or not chat_session_id:
            return jsonify({'error': 'Missing user_id or chat_session_id'}), 400

        success = save_chat_message(user_id, chat_session_id, message, sender)
        if success:
            return jsonify({'message': 'Message saved successfully'}), 200
        else:
            return jsonify({'error': 'Failed to save message'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# If you use chat sessions (e.g., multiple chat histories), add session_id:
@app.route('/delete-message/<chat_session_id>/<int:message_index>', methods=['DELETE'])
@login_required
@csrf.exempt
def delete_message_firestore(chat_session_id, message_index):
    user_id = current_user.id
    chat_doc_ref = db.collection('users').document(user_id)\
                    .collection('chats').document(chat_session_id)
    messages_ref = chat_doc_ref.collection('messages')

    # Fetch messages in order
    messages_query = messages_ref.order_by("timestamp").stream()
    messages = [msg for msg in messages_query]
    chat_history = [msg.to_dict() for msg in messages]

    if not (0 <= message_index < len(messages)):
        return jsonify({'error': 'Message not found'}), 404

    deleted_msg = chat_history[message_index]
    deleted_doc = messages[message_index]

    # Helper: delete a message by doc reference
    def delete_doc(doc):
        doc.reference.delete()

    if deleted_msg.get('sender') == 'user':
        # Delete user message
        delete_doc(deleted_doc)
        # If next message is bot, delete it
        if message_index+1 < len(messages):
            next_msg = chat_history[message_index+1]
            if next_msg.get('sender') == 'bot':
                delete_doc(messages[message_index+1])
    elif deleted_msg.get('sender') == 'bot':
        # If previous is user, regenerate bot reply
        if message_index > 0 and chat_history[message_index-1].get('sender') == 'user':
            user_msg = chat_history[message_index-1]['message']
            # Delete bot message
            delete_doc(deleted_doc)
            # Regenerate bot reply for last user message
            # Re-fetch messages after deletion
            messages_query = messages_ref.order_by("timestamp").stream()
            chat_history_new = [msg.to_dict() for msg in messages_query]
            bot_response = generate_bot_response(chat_history_new[:message_index-1], user_msg)
            messages_ref.add({
                'sender': 'bot',
                'message': bot_response,
                'timestamp': firestore.SERVER_TIMESTAMP
            })
        else:
            delete_doc(deleted_doc)

    return '', 204

def get_chat_history_for_session(session_id):
    chat_sessions = session.get('chat_sessions', {})
    return chat_sessions.get(session_id, [])

def save_chat_history_for_session(session_id, chat_history):
    chat_sessions = session.get('chat_sessions', {})
    chat_sessions[session_id] = chat_history
    session['chat_sessions'] = chat_sessions
    
@app.route('/calendar', methods=['GET'])
def calendar_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('calendar.html')

@app.route('/landingpage', methods=['GET'])
def landing_page():
    
    return render_template('landingpage.html')

@app.template_filter('nl2br')
def nl2br(s):
    return s.replace('\n','<br>\n')



if __name__ == '__main__':
    app.run(debug=True)
