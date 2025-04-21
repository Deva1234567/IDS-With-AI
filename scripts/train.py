import pandas as pd
import joblib
import logging
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Setup logging
log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(filename=os.path.join(log_dir, "train.log"), level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def train_model():
    """Train the IDS model."""
    try:
        # Load dataset
        data_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "raw", "domain_traffic.csv"))
        df = pd.read_csv(data_path)
        
        # Encode categorical features
        le = LabelEncoder()
        df['protocol'] = le.fit_transform(df['protocol'])
        
        # Features and target
        X = df[['ip.len', 'ip.proto', 'ip.ttl', 'tcp.window_size', 'port']]
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate
        score = model.score(X_test, y_test)
        logging.info(f"Model trained with accuracy: {score}")
        
        # Save model
        model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "ids_model.pkl"))
        joblib.dump(model, model_path)
        logging.info(f"Model saved to {model_path}")
        
        return score
    except Exception as e:
        logging.error(f"Training error: {str(e)}")
        return None

if __name__ == "__main__":
    train_model()