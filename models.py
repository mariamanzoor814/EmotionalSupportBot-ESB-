from firebase_setup import db
from google.cloud.firestore import SERVER_TIMESTAMP
from datetime import datetime, timedelta
from google.cloud import firestore
from flask import session, current_app
from flask_login import current_user
import uuid
import random
from transformers import pipeline
from llm_setup import generate_content

import os
import requests
from tenacity import retry, stop_after_attempt, wait_fixed



@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def get_recommendations(mood_label):
    recs = {
        "Happy": ["Keep up your routines!", "Express gratitude daily."],
        "Sad": ["Try going for a walk in nature.", "Reach out to someone you trust."],
        "Neutral": ["Journal your thoughts tonight.", "Try a new hobby this week."]
    }
    return recs.get(mood_label, ["Stay mindful."])

# User Model
def create_user(user_id, name, email):
    user_ref = db.collection("users").document(user_id)
    user_ref.set({
        "name": name,
        "email": email,
        "registration_date": SERVER_TIMESTAMP
    })
    return "User Registered!"

def save_chat_message(user_id, chat_session_id, message, sender):
    try:
        doc_ref = db.collection('users').document(user_id)\
            .collection('chats').document(chat_session_id)\
            .collection('messages').document()
        doc_ref.set({
            'message': message,
            'sender': sender,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return doc_ref.id
    except Exception as e:
        print(f"[ERROR] Failed to save message: {e}")
        return None

def save_chat_session(user_id, session_start, session_end):
    db.collection('users').document(user_id)\
        .collection('sessions_summary').add({
            'start_time': session_start,
            'end_time': session_end,
            'duration_seconds': (session_end - session_start).total_seconds()
        })

from google.cloud.firestore_v1.base_query import FieldFilter

def get_user_sessions(user_id):
    try:
        chat_sessions = []
        chat_ref = db.collection('users').document(user_id).collection('chats')
        for doc in chat_ref.order_by('start_time', direction=firestore.Query.DESCENDING).stream():
            data = doc.to_dict()
            chat_sessions.append({
                'id': doc.id,
                'topic': data.get('topic', 'Untitled Chat'),
                'start_time': data.get('start_time'),
                'type': 'chat',
                'message_count': data.get('message_count', 0)
            })

        mood_sessions = []
        mood_ref = db.collection('MoodSessions')
        for doc in mood_ref.where(filter=FieldFilter('user_id', '==', user_id))\
                           .order_by('timestamp', direction=firestore.Query.DESCENDING).stream():
            data = doc.to_dict()
            mood_sessions.append({
                'id': doc.id,
                'topic': f"Mood: {data.get('mood_label', 'Analysis')}",
                'start_time': data.get('timestamp'),
                'type': 'mood',
                'confidence': round(float(data.get('confidence', 0)) * 100, 1)
            })

        return sorted(chat_sessions + mood_sessions, key=lambda x: x.get('start_time') or datetime.min, reverse=True)

    except Exception as e:
        print(f"[ERROR] Session fetch failed: {e}")
        return []

def get_active_chat_session_id(user_id):
    if 'chat_session_id' not in session:
        session_start = session.get('chat_start_time', datetime.utcnow())
        chat_session_id = save_chat_session(user_id, session_start, datetime.utcnow())
        session['chat_session_id'] = chat_session_id
    return session['chat_session_id']

import json
def analyze_sentiment(questions, answers):
    combined_text = " ".join([f"Q: {q} A: {a}" for q, a in zip(questions, answers)])
    prompt = (
        f"Analyze the emotional tone of the following text and return:\n"
        f"1. The specific mood label (like anxious, content, burned out).\n"
        f"2. A confidence score from 0 to 1.\n"
        f"3. The sentiment (positive, negative, neutral).\n\n"
        f"Text: \"{combined_text}\"\n\n"
        "Return your answer in plain text or JSON. If plain text, use this format:\n"
        "mood: <label>\nconfidence: <float>\nsentiment: <sentiment>\n\n"
        "If you return JSON, it should be an object with keys: mood, confidence, sentiment."
    )

    try:
        raw = generate_content(prompt)  # use your wrapper
        text = (raw or "").strip()
        # Try JSON first
        m = re.search(r'(\{[\s\S]*\})', text)
        if m:
            try:
                payload = json.loads(m.group(1))
                mood_label = str(payload.get("mood") or payload.get("label") or payload.get("mood_label") or "unknown")
                confidence = float(payload.get("confidence", 0.0) or 0.0)
                sentiment = str(payload.get("sentiment", "neutral") or "neutral")
                return mood_label, max(0.0, min(1.0, confidence)), sentiment.lower()
            except Exception:
                pass

        # Fallback: parse lines like "mood: ...", "confidence: ...", "sentiment: ..."
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        mood_label = "unknown"
        confidence = 0.0
        sentiment = "neutral"
        for line in lines:
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            key, val = parts[0].strip().lower(), parts[1].strip()
            if key.startswith("mood"):
                mood_label = val
            elif key.startswith("confidence"):
                try:
                    confidence = float(re.findall(r"[-+]?\d*\.?\d+|\d+", val)[0])
                except Exception:
                    confidence = 0.0
            elif key.startswith("sentiment"):
                sentiment = val.lower()
        return mood_label, max(0.0, min(1.0, confidence)), sentiment
    except Exception as e:
        print(f"LLM Sentiment Analysis Error: {e}")
        return "unclear", 0.0, "neutral"
    
import re
def smart_mood_label(questions, answers, model_label, confidence):
    """
    Return (final_label, final_confidence, sentiment)
    """
    positive_words = ["good", "yes", "energetic", "productive", "happy", "mostly", "fine", "great", "okay", "ok"]
    negative_words = ["no", "sad", "tired", "overwhelmed", "not really", "bad", "lonely", "depressed", "anxious", "stressed"]

    # Normalize inputs
    ml = (model_label or "").strip().lower()
    try:
        confidence = float(confidence or 0.0)
    except Exception:
        confidence = 0.0

    def contains_any(text, words):
        if not text:
            return False
        t = text.lower()
        for w in words:
            if re.search(r'\b' + re.escape(w) + r'\b', t):
                return True
        return False

    positive_count = sum(1 for a in answers if contains_any(a, positive_words)) if answers else 0
    negative_count = sum(1 for a in answers if contains_any(a, negative_words)) if answers else 0

    # Heuristic overrides when model is neutral/surprised/empty
    if ml in ("surprise", "neutral", ""):
        if positive_count > negative_count + 2:
            return "content", max(confidence, 0.7), "positive"
        if negative_count > positive_count + 2:
            return "sadness", max(confidence, 0.7), "negative"

    # Map common labels to sentiment
    positive_labels = {"content", "happy", "joy", "positive", "optimistic", "satisfied", "calm", "relieved"}
    negative_labels = {"sadness", "sad", "depressed", "angry", "fear", "anxious", "negative", "stressed", "overwhelmed", "burnout"}

    if ml in positive_labels:
        sentiment = "positive"
    elif ml in negative_labels:
        sentiment = "negative"
    else:
        # fallback to counts
        if positive_count > negative_count:
            sentiment = "positive"
        elif negative_count > positive_count:
            sentiment = "negative"
        else:
            sentiment = "neutral"

    final_label = model_label or ("content" if sentiment == "positive" else ("sadness" if sentiment == "negative" else "neutral"))
    return final_label, confidence, sentiment


class FirestoreModels:
    def __init__(self):
        pass