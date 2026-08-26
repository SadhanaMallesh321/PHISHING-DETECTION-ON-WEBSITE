import os
from pathlib import Path
import sys

import joblib
import numpy as np
import requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from explanation_service import generate_explanation, generate_summary
from page_analysis import analyze_public_url


def extract_url_features(url: str) -> list[int]:
    """Build the 48-feature vector expected by the trained phishing model."""
    features = [0] * EXPECTED_FEATURE_COUNT
    if not url:
        return features

    try:
        parsed = urlparse(url)
    except Exception:
        return features

    full_url = url.lower()
    hostname = (parsed.hostname or "").lower()
    path_text = parsed.path or ""
    query = parsed.query or ""
    hostname_parts = [part for part in hostname.split(".") if part]

    if hostname:
        features[0] = hostname.count(".")
        features[1] = max(0, len(hostname_parts) - 2)
        features[5] = hostname.count("-")
        features[16] = 1 if re.fullmatch(r"\d+(?:\.\d+){3}", hostname) else 0
        features[19] = 1 if "https" in hostname else 0
        features[20] = len(hostname)

    features[2] = len([segment for segment in path_text.split("/") if segment])
    features[3] = len(url)
    features[4] = full_url.count("-")
    features[6] = 1 if "@" in url else 0
    features[7] = 1 if "~" in url else 0
    features[8] = full_url.count("_")
    features[9] = full_url.count("%")
    features[10] = len(query.split("&")) if query else 0
    features[11] = query.count("&")
    features[12] = 1 if "#" in url else 0
    features[13] = sum(char.isdigit() for char in url)
    features[14] = 0 if parsed.scheme.lower() == "https" else 1
    features[17] = 1 if hostname and hostname in path_text.lower() else 0
    features[18] = 1 if hostname and hostname in parsed.path.lower() else 0
    features[21] = len(path_text)
    features[22] = len(query)
    features[23] = 1 if "//" in path_text[1:] else 0

    suspicious_keywords = [
        "login", "verify", "secure", "account", "update", "bank",
        "confirm", "invoice", "password", "pay", "signin", "security",
        "webmail", "wallet", "alert", "claim", "urgent",
    ]
    features[24] = 1 if any(keyword in full_url for keyword in suspicious_keywords) else 0
    brand_names = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "bank", "dropbox", "github", "facebook"]
    features[25] = 1 if any(brand in full_url for brand in brand_names) else 0

    return features


def apply_page_features(features: list[int], page_features: dict) -> list[float]:
    """Add bounded DOM-derived signals to the trained 48-feature schema."""
    numeric = {}
    for key, value in page_features.items():
        try:
            numeric[key] = float(value)
        except (TypeError, ValueError):
            continue

    def bounded(name: str, minimum: float = 0.0, maximum: float = 1.0) -> float:
        return max(minimum, min(maximum, numeric.get(name, 0.0)))

    features = list(features)
    features[24] = bounded("sensitive_words", 0.0, 20.0)
    features[25] = 1 if bounded("embedded_brand") else 0
    features[26] = bounded("external_link_ratio")
    features[27] = bounded("external_resource_ratio")
    features[28] = 1 if bounded("external_favicon") else 0
    features[29] = 1 if bounded("insecure_forms") else 0
    features[30] = 1 if bounded("relative_form_action") else 0
    features[31] = 1 if bounded("external_form_action") else 0
    features[32] = 1 if bounded("abnormal_form_action") else 0
    features[33] = bounded("null_self_redirect", 0.0, 20.0)
    features[39] = 1 if bounded("iframe") else 0
    features[40] = 1 if bounded("missing_title") else 0
    features[41] = 1 if bounded("images_only_form") else 0
    features[46] = bounded("meta_script_link_ratio")
    return features


def build_domain_reputation(features: list[float], prediction: str) -> dict:
    signals = []
    risk_score = 0
    if features[14] == 1:
        risk_score += 1
        signals.append("The page is not using HTTPS.")
    if features[24] >= 2:
        risk_score += 1
        signals.append("The page contains multiple sensitive words.")
    if features[25] == 1:
        risk_score += 1
        signals.append("A brand name appears in the page content.")
    if features[29] == 1 or features[31] == 1:
        risk_score += 2
        signals.append("A form sends information to an insecure or external destination.")
    if features[39] == 1:
        risk_score += 1
        signals.append("The page embeds content in a frame.")

    verdict = "Phishing Website" if prediction == "Phishing Website" or risk_score >= 2 else "Legitimate Website"
    if not signals:
        signals.append("No strong phishing indicators were found in the available page content.")
    return {"verdict": verdict, "risk_score": risk_score, "signals": signals}

app = Flask(__name__)

MODEL_PATH = ROOT_DIR / "model" / "phishing_model.pkl"
EXPECTED_FEATURE_COUNT = 48

if not MODEL_PATH.exists():
    raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

model = joblib.load(MODEL_PATH)


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}

    features = data.get("features")
    if features is None:
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "Request JSON must include a 'features' list or 'url' string."}), 400

        features = extract_url_features(url)
    elif not isinstance(features, list):
        return jsonify({"error": "'features' must be a list of numeric values."}), 400

    page_features = data.get("page_features")
    if isinstance(page_features, dict):
        features = apply_page_features(features, page_features)

    if len(features) != EXPECTED_FEATURE_COUNT:
        return jsonify({"error": f"Expected {EXPECTED_FEATURE_COUNT} feature values, got {len(features)}."}), 400

    try:
        features_array = np.array(features, dtype=float).reshape(1, -1)
    except ValueError:
        return jsonify({"error": "All feature values must be numeric."}), 400

    prediction = model.predict(features_array)
    result = "Phishing Website" if int(prediction[0]) == 1 else "Legitimate Website"

    confidence = None
    try:
        probabilities = model.predict_proba(features_array)
        confidence = float(np.max(probabilities))
    except Exception:
        confidence = None

    summary = generate_summary(features, result, confidence)
    explanation = generate_explanation(features, result)
    domain_reputation = build_domain_reputation(features, result)

    return jsonify({
        "prediction": result,
        "confidence": confidence,
        "summary": summary,
        "explanation": explanation,
        "domain_reputation": domain_reputation,
    })


@app.route("/analyze-url", methods=["POST"])
def analyze_url():
    data = request.get_json(silent=True) or {}
    try:
        url = data.get("url", "")
        final_url, page_features, metadata = analyze_public_url(url)
        features = apply_page_features(extract_url_features(final_url), page_features)
        features_array = np.array(features, dtype=float).reshape(1, -1)
        prediction = model.predict(features_array)
        result = "Phishing Website" if int(prediction[0]) == 1 else "Legitimate Website"
        probabilities = model.predict_proba(features_array)
        confidence = float(np.max(probabilities))
        reputation = build_domain_reputation(features, result)
        model_risk = confidence * 100 if result == "Phishing Website" else (1 - confidence) * 100
        risk_score = min(100, round(model_risk + reputation["risk_score"] * 10))
        reasons = list(reputation["signals"])
        if metadata["password_field_count"]:
            reasons.append("Password input detected on the page.")
        if metadata["login_form_count"]:
            reasons.append("Login form detected on the page.")
        if metadata["redirect_count"]:
            reasons.append("The URL redirected before returning the page.")
        return jsonify({
            "url": url,
            "final_url": final_url,
            "prediction": result,
            "risk_score": risk_score,
            "reasons": reasons[:8],
            "confidence": confidence,
            "domain_reputation": reputation,
            "page": metadata,
        })
    except (ValueError, requests.RequestException) as error:
        return jsonify({"error": str(error)}), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Flask app on port: {port}")
    app.run(host="0.0.0.0", port=port)