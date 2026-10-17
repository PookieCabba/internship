# Production Dockerfile for PhishGuard AI API Backend
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and models
COPY features.py .
COPY api.py .
COPY models/ ./models/

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PORT=8000 \
    MODEL_PATH=models/phishing_model.joblib \
    SCALER_PATH=models/feature_scaler.joblib \
    METADATA_PATH=models/model_metadata.json

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Start uvicorn
CMD exec uvicorn api:app --host 0.0.0.0 --port ${PORT}
