import firebase_admin
from firebase_admin import credentials, firestore
import os

# Absolute path to the service account key (not firebase_config.json)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVICE_ACCOUNT_PATH = os.path.join(BASE_DIR, "firebase_admin_key.json")  # <- make sure this is the downloaded key

# Initialize Firebase app only once
if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
    firebase_admin.initialize_app(cred)

# Firestore database reference
db = firestore.client()
# Optionally, you can print a confirmation to verify
print("Firestore client initialized successfully.")