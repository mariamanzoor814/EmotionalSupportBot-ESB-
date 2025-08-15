# app.py
# Standard Library Imports
import os
import re
import random
import smtplib
import traceback
import time
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from collections import Counter
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from markupsafe import escape, Markup
from werkzeug.utils import secure_filename

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
from firebase_admin import credentials, auth, firestore
import markdown as md 

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
@app.before_request
def require_login():
    """Authentication middleware for route protection"""
    allowed_routes = [
        'home',
        'landing_page', 
        'login', 
        'signup', 
        'verify_otp', 
        'forgot_password', 
        'static',
        'password_reset_success'
    ]
    
    if not current_user.is_authenticated and request.endpoint not in allowed_routes:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))

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

def require_login():
    allowed_routes = ['login', 'signup', 'verify_otp', 'forgot_password', 'static']
    if 'user_id' not in session and request.endpoint not in allowed_routes:
        return redirect(url_for('login'))


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
                flash("OTP expired. Request a new one.", "danger")
                return redirect(url_for('forgot_password' if flow_type == 'reset' else 'signup'))

            if entered_otp != stored_otp:
                flash("Incorrect OTP. Please try again.", "danger")
                return render_template(
                    'verify_otp.html' if flow_type == 'reset' else 'verify_otp_signup.html',
                    form=form
                )

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

                    # Create Firestore user document with UID as key
                    user_ref = db.collection("users").document(user.uid)
                    user_ref.set({
                        "username": username,
                        "email": email,
                        "created_at": firestore.SERVER_TIMESTAMP,
                        "status": "active"
                    }, merge=True)

                    # Delete OTP data
                    db.collection("signup_otps").document(email).delete()

                    # Log user in immediately
                    user_obj = User(uid=user.uid, email=email)
                    login_user(user_obj)
                    session['user_id'] = user.uid  # Set session variable

                    # Cleanup session data
                    session.pop('signup_data', None)

                    flash("Signup successful! Welcome to our platform.", "success")
                    return redirect(url_for('dashboard'))

                except Exception as user_creation_err:
                    print(f"🔥 User creation failed: {str(user_creation_err)}")
                    # Cleanup Firebase user if created
                    if 'user' in locals():
                        auth.delete_user(user.uid)
                    flash("Account creation failed. Please try again.", "danger")
                    return redirect(url_for('signup'))

        except Exception as e:
            traceback.print_exc()
            flash("OTP verification failed. Try again.", "danger")
            return redirect(url_for('forgot_password' if flow_type == 'reset' else 'signup'))

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

    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        remember = form.remember.data  # <-- this is True if checked

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
                user = User(uid=uid, email=email)
                # THIS LINE IS THE IMPORTANT ONE:
                login_user(user, remember=remember)
            
                user_ref = db.collection("users").document(uid)
                user_data = user_ref.get().to_dict()
                
                session['user_id'] = uid
                session['user_email'] = user_data.get('email')
                session['username'] = user_data.get('username')
                
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                error_message = data.get("error", {}).get("message", "Invalid email or password.")
                flash(f"Login failed: {error_message}", "danger")

        except Exception as e:
            flash(f"Login failed: {str(e)}", "danger")

    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    
    user_id = current_user.id
    
    # Get user document with error handling
    user_ref = db.collection("users").document(user_id)
    user_doc = user_ref.get()
    
    if not user_doc.exists:
        flash("Your profile data is missing! Please contact support.", "danger")
        return redirect(url_for('logout'))
    
    user_data = user_doc.to_dict()

    if not user_id:
        flash("You must be logged in to access the dashboard.", "error")
        return redirect(url_for('login'))

    # === Fetch the latest mood entry ===
    latest_mood_query = db.collection('moods') \
        .where(filter=FieldFilter("user_id", "==", user_id)) \
        .order_by('timestamp', direction=firestore.Query.DESCENDING) \
        .limit(1) \
        .stream()

    latest_mood_data = next(latest_mood_query, None)

    if latest_mood_data:
        mood_doc = latest_mood_data.to_dict()
        latest_mood_score = mood_doc.get('confidence_score')  # FIXED
        latest_sentiment = mood_doc.get('mood_label')         # FIXED
    else:
        latest_mood_score = None
        latest_sentiment = None

    # === Fetch full mood history for this user ===
    mood_history_query = db.collection('moods') \
    .where(filter=FieldFilter("user_id", "==", user_id)) \
    .order_by('timestamp', direction=firestore.Query.DESCENDING) \
    .stream()

    mood_history = []
    for doc in mood_history_query:
        data = doc.to_dict()
        data['timestamp'] = data['timestamp'].strftime('%Y-%m-%d %H:%M')
        mood_history.append(data)

    return render_template(
        'dashboard.html',
        latest_mood_score=latest_mood_score,
        latest_sentiment=latest_sentiment,
        mood_history=mood_history,
        user_email=user_data.get('email'),
        username=user_data.get('username')
    )
import hashlib
def gravatar_url(email, size=128, default='identicon'):
    """Return the gravatar URL for the given email."""
    email = email.strip().lower().encode('utf-8')
    email_hash = hashlib.md5(email).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d={default}"

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_ref = db.collection('users').document(current_user.id)
    user_data = user_ref.get().to_dict() if user_ref.get().exists else {}

    form = ProfileForm()

    # Handle form submission
    if form.validate_on_submit():
        # Get updated data
        new_first_name = form.first_name.data

        # Save to Firestore
        user_ref.update({
            'first_name': new_first_name
        })

        flash("Profile updated successfully!", "success")
        return redirect(url_for('settings'))  # Refresh page with updated data

    # Pre-fill the form on GET
    if request.method == 'GET':
        form.first_name.data = user_data.get('first_name', '')
        form.email.data = user_data.get('email', '')

    gravatar = gravatar_url(user_data.get('email', '')) if user_data.get('email') else url_for('static', filename='images/esb-logo.jpg')

    return render_template('settings.html', form=form, user=user_data, gravatar=gravatar)


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
    avatar = user_doc.to_dict().get('profile_picture') if user_doc.exists else None
    name = session.get('name', current_user.email)
    sid = request.args.get('session_id')

    # View past session (read-only)
    if sid:
        return render_template('mood_analysis.html',
            avatar_url=avatar,
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
    current_q = session['questions'][idx] if not session['mood_done'] and idx < len(session['questions']) else None
    mood_result = session.get('mood_result')
    chat_history = session.get('chat_history',[])

    return render_template(
        'mood_analysis.html',
        avatar_url=avatar,
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
            label, conf, sent = analyze_sentiment(session['questions'], session['answers'])
            label, conf, sent = smart_mood_label(session['questions'], session['answers'], label, conf)
            expl = generate_mood_explanation(label, " ".join(session['answers']))
            recs = generate_mood_recommendations(label, " ".join(session['answers']))

            # >>>> PUT THIS BLOCK HERE <<<<
            if isinstance(recs, str):
                recs_list = [r.strip('-*• ').strip() for r in recs.split('\n') if r.strip()]
            else:
                recs_list = recs

            new_sid = str(uuid4())

            # Save to DB
            for q_text, a_text in zip(questions, session['answers']):
                db.collection('moodAnalysis').add({
                    'user_id': user_id,
                    'session_id': new_sid,
                    'question': q_text,
                    'answer': a_text,
                    'timestamp': datetime.now(timezone.utc)
                })
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
    profile_img = user_doc.to_dict().get("profile_img") if user_doc.exists else "https://randomuser.me/api/portraits/men/1.jpg"

    today = datetime.utcnow().date()
    days = [(today - timedelta(days=i)) for i in reversed(range(7))]
    mood_days = [{"label": d.strftime("%a"), "day": d.day, "date": d.strftime("%Y-%m-%d")} for d in days]

    start_of_week = days[0]
    moods_query = db.collection('MoodSessions') \
        .where('user_id', '==', user_id) \
        .where('timestamp', '>=', datetime.combine(start_of_week, datetime.min.time())) \
        .where('timestamp', '<', datetime.combine(today + timedelta(days=1), datetime.min.time())) \
        .order_by('timestamp')

    # DEBUG: Print what you get from Firestore!
    mood_entries = [mood.to_dict() for mood in moods_query.stream()]
    print("MoodSessions found:", mood_entries)

    mood_score_by_day = {d["date"]: 0 for d in mood_days}
    mood_label_by_day = {d["date"]: "" for d in mood_days}
    for entry in mood_entries:
        entry_date = entry['timestamp'].date().strftime("%Y-%m-%d")
        if entry_date in mood_score_by_day:
            mood_score_by_day[entry_date] = entry.get("confidence", 0)
            mood_label_by_day[entry_date] = entry.get("mood_label", "")

    mood_trends = [mood_score_by_day[d["date"]]*18 for d in mood_days]
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
        profile_img=profile_img,
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

@csrf.exempt
@app.route('/get-mood-trends', methods=['POST'])
@login_required
def get_mood_trends():
    from collections import defaultdict, Counter
    import calendar

    try:
        data = request.get_json(force=True)
        user_id = current_user.id
        view_type = data.get('view_type', 'week')
        date_str = data.get('date')
        now = datetime.now(timezone.utc)
        today = now.date()

        # Helper to get period keys
        def get_period_key(dt, vtype):
            if vtype == 'week':
                return dt.strftime('%Y-%m-%d')
            elif vtype == 'month':
                ws = dt - timedelta(days=dt.weekday())
                return ws.strftime('%Y-%m-%d')
            elif vtype == 'year':
                return dt.strftime('%Y-%m')
            else:
                return dt.strftime('%Y-%m-%d')

        # Define periods and labels
        if view_type == 'week':
            bar_periods = [(today - timedelta(days=i)) for i in reversed(range(7))]
            bar_labels = [d.strftime("%a") for d in bar_periods]
            bar_keys = [d.strftime("%Y-%m-%d") for d in bar_periods]
            start_time = now - timedelta(days=7)
            end_time = now
            detail_type = "day"
            detail_value = date_str or bar_keys[-1]
        elif view_type == 'month':
            week_starts = []
            for i in range(4, -1, -1):
                ws = (today - timedelta(days=today.weekday())) - timedelta(weeks=i)
                week_starts.append(ws)
            bar_periods = week_starts
            bar_labels = [f"{ws.strftime('%b %d')}" for ws in week_starts]
            bar_keys = [ws.strftime('%Y-%m-%d') for ws in week_starts]
            start_time = now - timedelta(days=30)
            end_time = now
            detail_type = "week"
            detail_value = date_str or bar_keys[-1]
        elif view_type == 'year':
            months = [datetime(now.year, m, 1, tzinfo=timezone.utc).date() for m in range(1, now.month+1)]
            bar_periods = months
            bar_labels = [calendar.month_abbr[m] for m in range(1, now.month+1)]
            bar_keys = [d.strftime('%Y-%m') for d in months]
            start_time = datetime(now.year, 1, 1, tzinfo=timezone.utc)
            end_time = now
            detail_type = "month"
            detail_value = date_str or bar_keys[-1]
        else:
            bar_periods = [(today - timedelta(days=i)) for i in reversed(range(7))]
            bar_labels = [d.strftime("%a") for d in bar_periods]
            bar_keys = [d.strftime("%Y-%m-%d") for d in bar_periods]
            start_time = now - timedelta(days=7)
            end_time = now
            detail_type = "day"
            detail_value = date_str or bar_keys[-1]

        # Fetch all moods in range
        moods_query = db.collection('MoodSessions') \
            .where('user_id', '==', user_id) \
            .where('timestamp', '>=', start_time) \
            .where('timestamp', '<', end_time) \
            .order_by('timestamp')
        mood_entries = [mood.to_dict() for mood in moods_query.stream() if 'timestamp' in mood.to_dict()]

        # Find the most recent mood per period
        period_latest = {}
        for entry in mood_entries:
            dt = entry['timestamp'].date()
            key = get_period_key(dt, view_type)
            # If this is the latest so far, store it
            if key not in period_latest or entry['timestamp'] > period_latest[key]['timestamp']:
                period_latest[key] = entry

        # Chart bars: use the most recent mood's confidence in each period, 0 if missing
        mood_trends = []
        for k in bar_keys:
            ent = period_latest.get(k)
            mood_trends.append(int(ent.get("confidence", 0)*18) if ent else 0)

        mood_trends_labels = bar_labels

        # --- PERIOD SUMMARY ---
        # Find all entries for the selected period
        if detail_type == 'day':
            period_entry = period_latest.get(detail_value)
            period_entries = [period_entry] if period_entry else []
        elif detail_type == 'week':
            ws = datetime.strptime(detail_value, '%Y-%m-%d').date()
            period_entries = [e for e in mood_entries if ws <= e['timestamp'].date() <= ws + timedelta(days=6)]
        elif detail_type == 'month':
            ym = detail_value.split('-')
            y, m = int(ym[0]), int(ym[1])
            period_entries = [e for e in mood_entries if e['timestamp'].date().year == y and e['timestamp'].date().month == m]
        else:
            period_entries = []

        # For summary, use most recent in period
        if not period_entries:
            mood_label = "No Data"
            confidence_score = "N/A"
            mood_summary = []
            tips = [
                "No mood data for this period.",
                "Try analyzing your mood to see insights here!"
            ]
            recommendations = []
        else:
            period_entry = sorted(period_entries, key=lambda e: e['timestamp'])[-1]
            mood_label = period_entry.get("mood_label") or "No Data"
            confidence_score = round(period_entry.get("confidence", 0), 2)
            mood_summary = [period_entry.get("explanation")] if period_entry.get("explanation") else []
            # recommendations in quick tips
            recs = period_entry.get("recommendations")
            if isinstance(recs, list):
                tips = recs
            elif isinstance(recs, str):
                # split by newline/bullet if needed
                tips = [l.strip('*- ') for l in recs.splitlines() if l.strip()]
            else:
                tips = []
            recommendations = tips

        # Mood distribution donut for this period
        label_counts = Counter(e.get("mood_label", "Unknown") for e in period_entries)
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

        # Calculate "real progress" for week/month/year
        progress = None
        if view_type in ['month', 'year', 'week']:
            # Compare last 2 periods' average confidence
            idx = bar_keys.index(detail_value) if detail_value in bar_keys else len(bar_keys) - 1
            curr_val = mood_trends[idx] / 18 if mood_trends[idx] else 0
            prev_val = mood_trends[idx-1] / 18 if idx > 0 and mood_trends[idx-1] else 0
            if prev_val:
                prog = ((curr_val - prev_val) / prev_val) * 100
                progress = round(prog, 1)
            elif curr_val:
                progress = 100.0  # just started, all progress
            else:
                progress = 0.0

        donut_label = f"Improved<br>By {progress}%" if progress is not None and progress > 0 else \
                      f"Down<br>{abs(progress)}%" if progress is not None and progress < 0 else \
                      "No change" if progress == 0 else "No Data"

        return jsonify({
            "mood_trends": mood_trends,
            "mood_trends_labels": mood_trends_labels,
            "mood_label": mood_label,
            "confidence_score": confidence_score,
            "mood_summary": mood_summary,
            "tips": recommendations,
            "overall_mood": overall_mood,
            "donut_data": donut_data,
            "donut_label": donut_label,
            "progress": progress,
            "show_progress": view_type in ['month', 'year', 'week']  # only show below donut for non-daily
        }), 200

    except Exception as e:
        import traceback
        print(f"Error in /get-mood-trends: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500


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

    # Initialize or validate session ID
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
    messages_ref = chat_doc_ref.collection('messages')
    chat_history = [msg.to_dict() for msg in messages_ref.order_by("timestamp").stream()]

    return render_template('chat.html',
                         form=form,
                         chat_history=chat_history,
                         chat_session_id=chat_session_id,
                         session_list=get_user_sessions(user_id))

@csrf.exempt
@app.route('/ajax/chat/send', methods=['POST'])
@login_required
def ajax_chat_send():
    user_id = current_user.id
    data = request.get_json()
    chat_session_id = data.get('chat_session_id')
    user_message = data.get('message')

    chat_doc_ref = db.collection('users').document(user_id).collection('chats').document(chat_session_id)
    messages_ref = chat_doc_ref.collection('messages')

    # Add user message
    messages_ref.add({
        'sender': 'user',
        'message': user_message,
        'timestamp': firestore.SERVER_TIMESTAMP
    })

    # Generate and add bot response
    chat_history = [msg.to_dict() for msg in messages_ref.order_by("timestamp").stream()]
    bot_response = generate_bot_response(chat_history, user_message)
    messages_ref.add({
        'sender': 'bot',
        'message': bot_response,
        'timestamp': firestore.SERVER_TIMESTAMP
    })

    chat_history = [msg.to_dict() for msg in messages_ref.order_by("timestamp").stream()]
    return jsonify({'reply': bot_response, 'chat_history': chat_history})

@csrf.exempt
@app.route('/ajax/chat/history/<chat_session_id>', methods=['GET'])
@login_required
def ajax_chat_history(chat_session_id):
    user_id = current_user.id
    chat_doc_ref = db.collection('users').document(user_id).collection('chats').document(chat_session_id)
    messages_ref = chat_doc_ref.collection('messages')
    chat_history = [msg.to_dict() for msg in messages_ref.order_by("timestamp").stream()]
    return jsonify({'chat_history': chat_history})


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
