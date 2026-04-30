from pathlib import Path

from flask import Flask, jsonify, request
import joblib
import numpy as np

app = Flask(__name__)

MODEL_PATH = Path(__file__).resolve().parent / "model" / "phishing_model.pkl"
EXPECTED_FEATURE_COUNT = 48

if not MODEL_PATH.exists():
    raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

model = joblib.load(MODEL_PATH)

@app.route("/")
def home():
    return "Phishing Detection API Running"

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not data or "features" not in data:
        return jsonify({"error": "Request JSON must include a 'features' list."}), 400

    features = data["features"]
    if not isinstance(features, list):
        return jsonify({"error": "'features' must be a list of numeric values."}), 400

    if len(features) != EXPECTED_FEATURE_COUNT:
        return (
            jsonify(
                {
                    "error": f"Expected {EXPECTED_FEATURE_COUNT} feature values, got {len(features)}."
                }
            ),
            400,
        )

    try:
        features_array = np.array(features, dtype=float).reshape(1, -1)
    except ValueError:
        return jsonify({"error": "All feature values must be numeric."}), 400

    prediction = model.predict(features_array)
    result = "Phishing Website" if int(prediction[0]) == 1 else "Legitimate Website"

    return jsonify({"prediction": result})

if __name__ == "__main__":
    import os
    from waitress import serve
    port = int(os.environ.get("PORT", 5000))
    serve(app, host="0.0.0.0", port=port)
