import google.generativeai as genai
import os
from google.api_core.exceptions import InvalidArgument

# Debug API key
print("🔑 API Key:", os.getenv("GEMINI_API_KEY")[:6] + "..." if os.getenv("GEMINI_API_KEY") else "❌ Missing API Key")

# Configure with explicit endpoint
genai.configure(
    api_key=os.getenv("GEMINI_API_KEY"),
    client_options={
        "api_endpoint": "generativelanguage.googleapis.com"
    }
)

# Initialize model
gemini_pro = genai.GenerativeModel('gemini-2.0-flash') # Correct model name

def generate_content(prompt):
    try:
        response = gemini_pro.generate_content(
            contents=[{"role":"user","parts":[{"text": prompt}]}],
            # optional: temperature=0.0 for deterministic outputs
        )
        return getattr(response, "text", str(response))
    except InvalidArgument as e:
        print(f"API Error: {e}")
        return ""
    except Exception as e:
        print(f"General Error: {e}")
        return ""


def generate_mood_explanation(mood_label, combined_text):
    prompt = (
        f"The user has completed a mood questionnaire.\n"
        f"Mood label: {mood_label}\n"
        f"Summary of answers: {combined_text}\n\n"
        "Write a short, empathetic summary (2-4 sentences) explaining why the user might be feeling this way, "
        "using their answers as context. Avoid simply repeating the mood label. Be supportive and positive, "
        "and use plain language the user will understand."
    )
    try:
        response_text = generate_content(prompt)
        return (response_text or "").strip()
    except Exception as e:
        print(f"[generate_mood_explanation] Error: {e}")
        return "Let's explore this feeling together."


def generate_mood_recommendations(mood_label, combined_text):
    prompt = f"""The user feels {mood_label}. Context: {combined_text}

Suggest 3 practical coping strategies. Format as bullet points (one per line, no numbering).
Keep each under 15 words. Use empathetic language."""
    try:
        response_text = generate_content(prompt)
        # optionally split lines into a list for DB storage
        lines = [ln.strip('-*• \t') for ln in (response_text or "").splitlines() if ln.strip()]
        return lines if lines else ["Practice mindful breathing", "Write your thoughts in a journal", "Talk to someone you trust"]
    except Exception as e:
        print(f"generate_mood_recommendations error: {e}")
        return ["Practice mindful breathing", "Write your thoughts in a journal", "Talk to someone you trust"]
