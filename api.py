"""
============================================================
api.py — FastAPI Backend for Phishing URL Detection
============================================================
This script serves the trained ML model as a RESTful API.

Endpoints:
    POST /predict     — Classify a single URL
    POST /predict/batch — Classify multiple URLs at once
    GET  /health      — Health check / model status
    GET  /model/info  — Model metadata and feature list

The API extracts features in real-time using the same shared
feature extraction module used during training, ensuring
perfect feature parity.

Usage:
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload

Author:  Senior AI & Cybersecurity Engineer
Version: 1.0.0
============================================================
"""

import os
import json
import logging
import time
from datetime import datetime
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

import numpy as np
# pyrefly: ignore[missing-import]
import joblib
# pyrefly: ignore[missing-import]
from fastapi import FastAPI, HTTPException, Request
# pyrefly: ignore[missing-import]
from fastapi.middleware.cors import CORSMiddleware
# pyrefly: ignore[missing-import]
from fastapi.responses import JSONResponse
# pyrefly: ignore[missing-import]
from pydantic import BaseModel, Field, field_validator

# Import the shared feature extraction module
from features import (
    extract_features,
    get_feature_warnings,
    FEATURE_NAMES,
)

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────
MODEL_PATH = os.getenv("MODEL_PATH", "models/phishing_model.joblib")
SCALER_PATH = os.getenv("SCALER_PATH", "models/feature_scaler.joblib")
METADATA_PATH = os.getenv("METADATA_PATH", "models/model_metadata.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Global state for loaded model artifacts
# ──────────────────────────────────────────────────────────────
model_state: Dict[str, Any] = {
    "model": None,
    "scaler": None,
    "metadata": None,
    "loaded_at": None,
    "prediction_count": 0,
}


# ──────────────────────────────────────────────────────────────
# Lifespan: load model on startup
# ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ML model and scaler when the API starts up."""
    logger.info("=" * 50)
    logger.info("  Loading model artifacts...")

    # Load the trained model
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Model file not found: {MODEL_PATH}")
        logger.error("Run `python train_model.py` first.")
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

    model_state["model"] = joblib.load(MODEL_PATH)
    logger.info(f"  ✓ Model loaded from: {MODEL_PATH}")

    # Load the feature scaler
    if not os.path.exists(SCALER_PATH):
        logger.error(f"Scaler file not found: {SCALER_PATH}")
        raise FileNotFoundError(f"Scaler file not found: {SCALER_PATH}")

    model_state["scaler"] = joblib.load(SCALER_PATH)
    logger.info(f"  ✓ Scaler loaded from: {SCALER_PATH}")

    # Load model metadata (optional but useful)
    if os.path.exists(METADATA_PATH):
        with open(METADATA_PATH, "r") as f:
            model_state["metadata"] = json.load(f)
        logger.info(f"  ✓ Metadata loaded from: {METADATA_PATH}")

    model_state["loaded_at"] = datetime.now().isoformat()
    logger.info("  Model artifacts loaded successfully!")
    logger.info("=" * 50)

    yield  # Application runs here

    # Cleanup on shutdown
    logger.info("Shutting down API server...")


# ──────────────────────────────────────────────────────────────
# FastAPI app initialization
# ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Phishing URL Detection API",
    description=(
        "A machine-learning-powered API that classifies URLs as "
        "legitimate or phishing. The model extracts 27 lexical "
        "features from the URL and returns a probability score."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for the Streamlit frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # In production, restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────
# Request / Response schemas
# ──────────────────────────────────────────────────────────────

class URLRequest(BaseModel):
    """Schema for a single URL prediction request."""
    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="The URL to classify.",
        json_schema_extra={"examples": ["http://suspicious-site.xyz/login"]},
    )

    @field_validator("url")
    @classmethod
    def url_must_not_be_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("URL cannot be empty or whitespace.")
        return stripped


class BatchURLRequest(BaseModel):
    """Schema for batch URL prediction requests."""
    urls: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of URLs to classify (max 100).",
    )


class PredictionResponse(BaseModel):
    """Schema for a single prediction response."""
    url: str
    is_phishing: bool
    phishing_probability: float = Field(
        ..., ge=0.0, le=1.0,
        description="Probability that the URL is phishing (0.0–1.0)."
    )
    risk_level: str = Field(
        ...,
        description="Risk category: Safe, Low, Medium, High, or Critical."
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Model confidence in the prediction."
    )
    features: Dict[str, float]
    warnings: List[str]
    inference_time_ms: float


class BatchPredictionResponse(BaseModel):
    """Schema for batch prediction responses."""
    predictions: List[PredictionResponse]
    total_urls: int
    total_phishing: int
    total_legitimate: int


class HealthResponse(BaseModel):
    """Schema for health check response."""
    status: str
    model_loaded: bool
    model_version: Optional[str]
    loaded_at: Optional[str]
    total_predictions: int
    uptime_info: str


# ──────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────

def classify_risk(probability: float) -> str:
    """
    Map a phishing probability to a human-readable risk level.

    Thresholds are calibrated based on the model's precision-recall
    characteristics:
        0.0 – 0.2  →  Safe
        0.2 – 0.4  →  Low Risk
        0.4 – 0.6  →  Medium Risk
        0.6 – 0.8  →  High Risk
        0.8 – 1.0  →  Critical
    """
    if probability < 0.2:
        return "Safe"
    elif probability < 0.4:
        return "Low Risk"
    elif probability < 0.6:
        return "Medium Risk"
    elif probability < 0.8:
        return "High Risk"
    else:
        return "Critical"


def predict_url(url: str) -> PredictionResponse:
    """
    Run the full prediction pipeline for a single URL.

    Steps:
        1. Extract features using the shared module
        2. Scale features using the fitted scaler
        3. Get probability from the trained model
        4. Classify risk level
        5. Generate human-readable warnings

    Args:
        url: The URL string to classify.

    Returns:
        A PredictionResponse with all prediction details.

    Raises:
        HTTPException: If feature extraction or prediction fails.
    """
    start = time.perf_counter()

    try:
        # Step 1: Extract features
        features = extract_features(url)

        # Step 2: Build the feature vector in correct order
        feature_vector = np.array(
            [features[name] for name in FEATURE_NAMES]
        ).reshape(1, -1)

        # Step 3: Scale features
        feature_vector_scaled = model_state["scaler"].transform(
            feature_vector
        )

        # Step 4: Get prediction probability
        probabilities = model_state["model"].predict_proba(
            feature_vector_scaled
        )[0]
        phishing_prob = float(probabilities[1])

        # Step 5: Determine prediction and risk
        is_phishing = phishing_prob >= 0.5
        risk_level = classify_risk(phishing_prob)
        confidence = max(phishing_prob, 1.0 - phishing_prob)

        # Step 6: Generate warnings
        warnings = get_feature_warnings(features)

        # Track prediction count
        model_state["prediction_count"] += 1

        elapsed_ms = (time.perf_counter() - start) * 1000

        return PredictionResponse(
            url=url,
            is_phishing=is_phishing,
            phishing_probability=round(phishing_prob, 4),
            risk_level=risk_level,
            confidence=round(confidence, 4),
            features=features,
            warnings=warnings,
            inference_time_ms=round(elapsed_ms, 2),
        )

    except Exception as e:
        logger.error(f"Prediction failed for URL '{url}': {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}",
        )


# ──────────────────────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────────────────────

@app.post(
    "/predict",
    response_model=PredictionResponse,
    summary="Classify a single URL",
    tags=["Predictions"],
)
async def predict_single(request: URLRequest):
    """
    Classify a single URL as legitimate or phishing.

    The endpoint extracts 27 lexical features from the URL,
    scales them using the pre-fitted scaler, and returns the
    model's phishing probability along with risk indicators.

    **Example request:**
    ```json
    {"url": "http://192.168.1.1/login/secure-account"}
    ```
    """
    logger.info(f"Prediction request: {request.url}")
    result = predict_url(request.url)
    logger.info(
        f"  → {result.risk_level} "
        f"(prob={result.phishing_probability:.4f}, "
        f"time={result.inference_time_ms:.1f}ms)"
    )
    return result


@app.post(
    "/predict/batch",
    response_model=BatchPredictionResponse,
    summary="Classify multiple URLs",
    tags=["Predictions"],
)
async def predict_batch(request: BatchURLRequest):
    """
    Classify up to 100 URLs in a single request.

    Returns individual predictions for each URL along with
    aggregate statistics.
    """
    logger.info(f"Batch prediction request: {len(request.urls)} URLs")

    predictions = []
    for url in request.urls:
        try:
            pred = predict_url(url)
            predictions.append(pred)
        except HTTPException:
            # Include a failed prediction marker
            predictions.append(PredictionResponse(
                url=url,
                is_phishing=False,
                phishing_probability=0.0,
                risk_level="Error",
                confidence=0.0,
                features={},
                warnings=["⚠️ Feature extraction failed for this URL."],
                inference_time_ms=0.0,
            ))

    total_phishing = sum(1 for p in predictions if p.is_phishing)

    return BatchPredictionResponse(
        predictions=predictions,
        total_urls=len(predictions),
        total_phishing=total_phishing,
        total_legitimate=len(predictions) - total_phishing,
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    tags=["System"],
)
async def health_check():
    """
    Check API health and model status.

    Returns model version, loading timestamp, and total
    prediction count since startup.
    """
    metadata = model_state.get("metadata", {})
    return HealthResponse(
        status="healthy" if model_state["model"] is not None else "degraded",
        model_loaded=model_state["model"] is not None,
        model_version=metadata.get("model_version", "unknown"),
        loaded_at=model_state.get("loaded_at"),
        total_predictions=model_state["prediction_count"],
        uptime_info=f"Model loaded at {model_state.get('loaded_at', 'N/A')}",
    )


@app.get(
    "/model/info",
    summary="Model information",
    tags=["System"],
)
async def model_info():
    """
    Return detailed model metadata including algorithm,
    hyperparameters, training metrics, and feature list.
    """
    if model_state["metadata"] is None:
        return {"message": "No metadata available."}
    return model_state["metadata"]


# ──────────────────────────────────────────────────────────────
# Error handlers
# ──────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all error handler for unexpected exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
        },
    )


# ──────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # pyrefly: ignore[missing-import]
    import uvicorn
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
