import os
import pandas as pd
import joblib
import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import socket
import re

# Setup logging
logging.basicConfig(
    filename=os.path.join(os.path.expanduser("~"), "Desktop", "logs", "predict.log"),
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("predict")

def extract_features(data):
    """Extract features from domain or IP."""
    try:
        # Resolve domain to IP if not an IP
        try:
            ip = socket.gethostbyname(data) if not re.match(r"^\d+\.\d+\.\d+\.\d+$", data) else data
        except socket.gaierror:
            logger.error(f"Failed to resolve domain {data}")
            return {}

        # Mock features (replace with real feature extraction if available)
        features = {
            'ip.len': len(data),
            'ip.proto': 6,  # TCP
            'ip.ttl': 64,
            'tcp.window_size': 65535,
            'port': 80
        }
        logger.debug(f"Extracted features for {data}: {features}")
        return features
    except Exception as e:
        logger.error(f"Feature extraction error for {data}: {str(e)}")
        return {}

def train_model():
    """Train and save a mock model."""
    try:
        X = pd.DataFrame([
            {'ip.len': 10, 'ip.proto': 6, 'ip.ttl': 64, 'tcp.window_size': 65535, 'port': 80},
            {'ip.len': 15, 'ip.proto': 6, 'ip.ttl': 32, 'tcp.window_size': 32768, 'port': 443},
            {'ip.len': 20, 'ip.proto': 6, 'ip.ttl': 128, 'tcp.window_size': 16384, 'port': 80}
        ])
        y = ['Safe', 'Malware', 'Safe']
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "ids_model.pkl"))
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(model, model_path)
        logger.info(f"Model trained and saved to {model_path}")
    except Exception as e:
        logger.error(f"Model training error: {str(e)}")

def predict_threat(data):
    """Predict threat for given data."""
    logger.debug(f"Predicting threat for data: {data}")
    try:
        model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "ids_model.pkl"))
        if not os.path.exists(model_path):
            logger.warning(f"Model file not found: {model_path}. Training new model.")
            train_model()
        model = joblib.load(model_path)
        features = extract_features(data)
        if not features:
            logger.error(f"No features extracted for {data}")
            return "Error"
        feature_df = pd.DataFrame([features])
        required_columns = ['ip.len', 'ip.proto', 'ip.ttl', 'tcp.window_size', 'port']
        for col in required_columns:
            if col not in feature_df.columns:
                feature_df[col] = 0
        feature_df = feature_df[required_columns]
        prediction = model.predict(feature_df)[0]
        logger.info(f"Prediction for {data}: {prediction}")
        return prediction
    except Exception as e:
        logger.error(f"Prediction error for {data}: {str(e)}", exc_info=True)
        return "Error"

if __name__ == "__main__":
    train_model()