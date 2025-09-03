# test.py
import os
from pathlib import Path
from firebase_admin import credentials, initialize_app, firestore

BASE_DIR = Path(__file__).resolve().parent
SERVICE_ACCOUNT_PATH = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH") or (BASE_DIR / "firebase_admin_key.json")

if not Path(SERVICE_ACCOUNT_PATH).exists():
    raise SystemExit(f"Missing service account at: {SERVICE_ACCOUNT_PATH}\nSet FIREBASE_SERVICE_ACCOUNT_PATH or place file in project folder.")

cred = credentials.Certificate(str(SERVICE_ACCOUNT_PATH))
initialize_app(cred)
db = firestore.client()

print("Firestore client ready. Collections:", [c.id for c in db.collections()])
