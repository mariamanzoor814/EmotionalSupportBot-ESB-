# main.py
from llm_setup import generate_content

def generate_bot_response(chat_history, user_input):
    # Prepare context
    context = "\n".join([f"{msg['sender']}: {msg['message']}" for msg in chat_history[-10:]])
    
    # Add instruction for Markdown formatting
    prompt = f"""You're an emotional support assistant. Be kind and non-judgmental.

Format all your responses using Markdown. Use bold for headings, bullet points for lists, italics for emphasis, and code blocks for code.

Conversation History:
{context}

User: {user_input}
Assistant:"""

    try:
        return generate_content(prompt)
    except Exception as e:
        print(f"Response Error: {e}")
        return "I'm here to listen. Could you share more?"
