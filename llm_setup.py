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
    """Universal content generator for all Gemini requests"""
    try:
        response = gemini_pro.generate_content(
            contents=[{
                "role": "user",
                "parts": [{"text": prompt}]
            }]
        )
        return response.text
    except InvalidArgument as e:
        print(f"API Error: {e}")
        return "I'm having trouble connecting to the AI service."
    except Exception as e:
        print(f"General Error: {e}")
        return "Something went wrong. Please try again."

def generate_mood_explanation(mood_label, combined_text):
    prompt = (
        f"The user has completed a mood questionnaire.\n"
        f"Mood label: {mood_label}\n"
        f"Summary of answers: {combined_text}\n\n"
        "Write a short, empathetic summary explaining why the user might be feeling this way, "
        "using their answers as context. Avoid simply repeating the mood label. Be supportive and positive, "
        "and use plain language the user will understand."
    )
    print(f"[DEBUG] Mood explanation prompt: {prompt}")
    try:
        response = gemini_pro.generate_content(prompt)
        print(f"[DEBUG] Gemini response: {response.text}")
        return response.text
    except InvalidArgument as e:
        print(f"API Error: {e.message}")
        return "Let's explore this feeling together."
    except Exception as e:
        print(f"Unexpected Error: {str(e)}")
        return "Let's explore this feeling together."

def generate_mood_recommendations(mood_label, combined_text):
    prompt = f"""The user feels {mood_label}. Context: {combined_text}
    
    Suggest 3 practical coping strategies. Format as bullet points.
    Keep each under 15 words. Use empathetic language."""
    
    try:
        response = gemini_pro.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini Error: {e}")
        return "- Practice mindful breathing\n- Journal your thoughts\n- Reach out to a friend"