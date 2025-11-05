# Use official lightweight Python image
FROM python:3.10-slim

# Prevent Python from writing .pyc files and buffering output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory inside the container
WORKDIR /app

# Install system dependencies (for Firebase + email + Google libs)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency file first to leverage Docker caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your app code
COPY . .

# Expose Hugging Face default port
EXPOSE 7860

# Environment variables (placeholders, use Hugging Face “Secrets” for real values)
ENV PORT=7860
ENV HOST=0.0.0.0

# Run the Flask app with Gunicorn (production server)
# If your entry file is app.py, use: app:app (format: filename:Flask_instance)
CMD ["gunicorn", "--bind", "0.0.0.0:7860", "app:app"]
