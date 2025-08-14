from flask import Blueprint, request, jsonify
from firebase_setup import auth, db
from google.cloud import firestore
import firebase_admin.auth as firebase_auth  # Correct Firebase Auth Import
from firebase_admin.exceptions import FirebaseError

auth_bp = Blueprint("auth", __name__)

# Signup API
@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    name = data.get("name")

    if not email or not password or not name:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # Check if email already exists
        firebase_auth.get_user_by_email(email)
        return jsonify({"error": "Email already in use. Please use another email."}), 400
    except firebase_auth.UserNotFoundError:
        pass  # No user found, so proceed
    except FirebaseError as e:
        return jsonify({"error": f"Error checking email: {str(e)}"}), 500

    try:
        # Create user in Firebase Authentication
        user = firebase_auth.create_user(email=email, password=password, display_name=name)
        
        # Store user details in Firestore
        user_ref = db.collection("Users").document(user.uid)
        user_ref.set({
            "name": name,
            "email": email,
            "registration_date": firestore.SERVER_TIMESTAMP,
            "profile_picture": "https://ui-avatars.com/api/?name=" + name.replace(" ", "+")  # 🧠 auto-generate avatar
        })

        return jsonify({"message": "User registered successfully!", "user_id": user.uid}), 201

    except FirebaseError as e:
        error_message = str(e)
        if "EMAIL_EXISTS" in error_message or "email already in use" in error_message.lower():
            return jsonify({"error": "Email already in use. Please use another email."}), 400
        return jsonify({"error": f"Signup failed: {error_message}"}), 500
@auth_bp.route("/google-login", methods=["POST"])
def google_login():
    data = request.json
    email = data.get("email")
    name = data.get("name")
    uid = data.get("uid")  # Google UID
    avatar = data.get("profile_picture")

    if not email or not uid:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # Store or update user
        db.collection("Users").document(uid).set({
            "email": email,
            "name": name,
            "profile_picture": avatar,
            "login_method": "google",
            "last_login": firestore.SERVER_TIMESTAMP
        }, merge=True)

        return jsonify({"message": "Google login success", "user_id": uid}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Login API
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        # Verify user exists in Firebase Authentication
        user = firebase_auth.get_user_by_email(email)
        
        # Retrieve user details from Firestore
        user_ref = db.collection("Users").document(user.uid).get()
        if not user_ref.exists:
            return jsonify({"error": "User data not found in database"}), 404

        user_data = user_ref.to_dict()
        return jsonify({
            "message": "Login successful",
            "user": {
                "id": user.uid,
                "name": user_data.get("name"),
                "email": user_data.get("email")
            }
        }), 200

    except firebase_auth.UserNotFoundError:
        return jsonify({"error": "User not found"}), 404
    except FirebaseError as e:
        return jsonify({"error": f"Login failed: {str(e)}"}), 500 