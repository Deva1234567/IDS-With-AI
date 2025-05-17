# scripts/preprocess.py
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os

def preprocess_data(input_file, output_file):
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file {input_file} does not exist.")
    
    try:
        df = pd.read_csv(input_file, on_bad_lines='skip')
    except Exception as e:
        raise Exception(f"Error reading {input_file}: {str(e)}")
    
    df.fillna(-1, inplace=True)
    
    # Encode categorical features
    categorical_cols = ['ip.proto']
    for col in categorical_cols:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
    
    # Normalize numerical features (exclude Label)
    numerical_cols = ['ip.len', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport']
    numerical_cols = [col for col in numerical_cols if col in df.columns]
    if numerical_cols:
        scaler = StandardScaler()
        df[numerical_cols] = scaler.fit_transform(df[numerical_cols].astype(float))
    
    # Drop non-numeric columns
    df = df.drop(columns=['ip.src', 'ip.dst'], errors='ignore')
    
    # Verify Label column
    if 'Label' not in df.columns:
        raise KeyError(f"Label column missing in {input_file}. Available columns: {df.columns.tolist()}")
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"Processed data saved to {output_file}")
    return df

if __name__ == "__main__":
    preprocess_data("data/raw/traffic_data.csv", "data/processed/processed_data.csv")