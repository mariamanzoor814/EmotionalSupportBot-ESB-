import os
from flask import Blueprint, request, jsonify
from firebase_admin import auth as firebase_auth, firestore
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Create Blueprint
auth_bp = Blueprint("auth", __name__)

# Firestore client
db = firestore.client()

# --------------------------------
# Email/Password Sign Up
# --------------------------------
@auth_bp.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        name = data.get("name")

        if not email or not password or not name:
            return jsonify({"error": "Missing required fields"}), 400

        user_record = firebase_auth.create_user(
            email=email,
            password=password,
            display_name=name
        )

        db.collection("users").document(user_record.uid).set({
            "name": name,
            "email": email,
            "profile_picture": None
        })

        return jsonify({"message": "User created successfully", "uid": user_record.uid}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --------------------------------
# Email/Password Login
# --------------------------------
@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        # Firebase Admin SDK can't directly check password
        # This should be handled in frontend using Firebase Auth JS SDK
        return jsonify({"message": "Use frontend Firebase Auth to sign in"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --------------------------------
# Google Sign-In
# --------------------------------
@auth_bp.route("/google-login", methods=["POST"])
def google_login():
    """
    Accepts a Google ID token from frontend,
    verifies it, stores/updates user in Firestore,
    returns user info.
    """
    try:
        data = request.get_json()
        id_token = data.get("idToken")

        if not id_token:
            return jsonify({"error": "Missing Google ID token"}), 400

        # Verify ID token with Google
        id_info = google_id_token.verify_oauth2_token(
            id_token,
            google_requests.Request(),
            os.getenv("GOOGLE_CLIENT_ID")
        )

        uid = id_info.get("sub")
        name = id_info.get("name")
        email = id_info.get("email")
        picture = id_info.get("picture")

        if not uid or not email:
            return jsonify({"error": "Invalid Google token data"}), 400

        # Save/update user in Firestore
        db.collection("users").document(uid).set({
            "name": name,
            "email": email,
            "profile_picture": picture
        }, merge=True)

        return jsonify({
            "uid": uid,
            "name": name,
            "email": email,
            "profile_picture": picture
        }), 200

    except ValueError as ve:
        return jsonify({"error": f"Invalid token: {str(ve)}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
