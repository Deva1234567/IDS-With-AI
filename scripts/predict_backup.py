import pandas as pd
import joblib
import time
import os
import socket
import logging
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    print("Warning: dnspython not installed. Domain resolution will use socket only.")
    DNS_AVAILABLE = False
from sklearn.preprocessing import LabelEncoder, StandardScaler
from functools import lru_cache
from scripts.config import THREAT_INTEL_IPS, ALERT_THRESHOLDS

# Setup logging
logging.basicConfig(filename="logs/predict.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

@lru_cache(maxsize=1000)
def resolve_ip(ip):
    try:
        ip = str(ip)
        if ip in ('127.0.0.1', '0.0.0.0', '-1'):
            return ip
        domain = socket.gethostbyaddr(ip)[0]
        logging.info(f"Resolved {ip} to {domain}")
        return domain if domain else ip
    except (socket.herror, socket.gaierror):
        if DNS_AVAILABLE:
            try:
                answers = dns.resolver.resolve_address(ip)
                domain = answers[0].to_text()
                logging.info(f"DNS resolved {ip} to {domain}")
                return domain if domain else ip
            except Exception as e:
                logging.error(f"DNS failed for {ip}: {str(e)}")
                return ip
        else:
            logging.warning(f"No DNS resolver for {ip}")
            return ip

def detect_threats(df):
    alerts = []
    try:
        # Signature-based
        if 'ip.len' in df and (df['ip.len'] > 1000).any():
            alerts.append("Large packet size detected (possible DDoS)")
        
        # Port scanning
        if 'tcp.dstport' in df and 'udp.dstport' in df:
            ports = pd.concat([df['tcp.dstport'], df['udp.dstport']]).dropna().unique()
            if len(ports) > ALERT_THRESHOLDS['port_scan']:
                alerts.append("Multiple ports detected (possible port scan)")
        
        # Threat intelligence
        if 'ip.dst' in df:
            for ip in df['ip.dst']:
                if ip in THREAT_INTEL_IPS:
                    alerts.append(f"Known malicious IP detected: {ip}")
        
        # TTL spoofing
        if 'ip.ttl' in df:
            ttl_counts = df['ip.ttl'].value_counts()
            if len(ttl_counts) > 1 or ttl_counts.index[0] not in [64, 128, 255]:
                alerts.append("Unusual TTL values (possible OS spoofing)")
        
        # TCP window anomalies
        if 'tcp.window_size' in df and (df['tcp.window_size'] == 0).any():
            alerts.append("Zero TCP window size detected")
        
        # DNS exfiltration
        if 'udp.dstport' in df and (df['udp.dstport'] == 53).sum() > ALERT_THRESHOLDS['dns']:
            alerts.append("High DNS query volume (possible exfiltration)")
        
        logging.info(f"Threat detection alerts: {alerts}")
    except Exception as e:
        logging.error(f"Threat detection error: {str(e)}")
    return alerts

def preprocess_live_data(input_file, output_file):
    try:
        df = pd.read_csv(input_file, sep=',', on_bad_lines='skip', dtype={'ip.src': str, 'ip.dst': str})
        if df.empty:
            logging.warning(f"{input_file} is empty")
            return df, df
        logging.info(f"Raw CSV shape: {df.shape}, columns: {df.columns.tolist()}")
    except Exception as e:
        logging.error(f"Error reading {input_file}: {str(e)}")
        raise Exception(f"Error reading {input_file}: {str(e)}")
    
    df_raw = df.copy()
    
    invalid_rows = df[df['ip.src'].isna() | df['ip.dst'].isna() | (df['ip.src'] == '-1') | (df['ip.dst'] == '-1')]
    if not invalid_rows.empty:
        logging.info(f"Dropped {len(invalid_rows)} invalid rows")
    
    df = df.dropna(subset=['ip.src', 'ip.dst'])
    df = df[df['ip.src'] != '-1']
    df = df[df['ip.dst'] != '-1']
    
    if df.empty:
        logging.warning("No valid rows after filtering")
        return df_raw, pd.DataFrame()  # Return empty processed DataFrame
    
    df.fillna(-1, inplace=True)
    
    expected_cols = ['ip.len', 'ip.proto', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'tcp.window_size', 'ip.ttl']
    for col in expected_cols:
        if col not in df.columns:
            df[col] = -1
            logging.info(f"Added missing column: {col}")
    
    categorical_cols = ['ip.proto']
    for col in categorical_cols:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            logging.info(f"Encoded column: {col}")
    
    numerical_cols = ['ip.len', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'tcp.window_size', 'ip.ttl']
    numerical_cols = [col for col in numerical_cols if col in df.columns]
    if numerical_cols:
        scaler = StandardScaler()
        df[numerical_cols] = scaler.fit_transform(df[numerical_cols].astype(float))
        logging.info(f"Scaled columns: {numerical_cols}")
    
    df_processed = df.drop(columns=['ip.src', 'ip.dst', 'Label', 'timestamp'], errors='ignore')
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df_processed.to_csv(output_file, index=False)
    logging.info(f"Saved processed CSV: {output_file}, shape: {df_processed.shape}")
    
    return df_raw, df_processed

def predict_attacks(model_file, input_file):
    logging.info(f"Starting prediction with model: {model_file}, input: {input_file}")
    processed_file = "data/processed/live_processed.csv"
    df_original, df_processed = preprocess_live_data(input_file, processed_file)
    
    # If no valid data, return original with default Safe prediction
    if df_processed.empty:
        logging.warning("No valid data to predict")
        if not df_original.empty:
            df_original['Prediction'] = 'Safe'
            df_original['Domain'] = df_original['ip.dst'].apply(resolve_ip)
            df_original['Port'] = df_original[['tcp.dstport', 'udp.dstport']].bfill(axis=1).iloc[:, 0].fillna(-1).astype(int)
            df_original['Port'] = df_original['Port'].apply(lambda x: x if x != -1 else '')
            df_original['Protocol'] = df_original.apply(
                lambda row: 'HTTP' if row['Port'] in [80, 443] else 'DNS' if row['Port'] == 53 else 'FTP' if row['Port'] == 21 else 'Other',
                axis=1
            )
            logging.info(f"Default Safe prediction added to original data")
            return df_original
        return pd.DataFrame(columns=['Domain', 'Prediction', 'ip.src', 'ip.dst', 'Port', 'Protocol', 'ip.len', 'ip.proto', 'ip.ttl', 'tcp.window_size'])
    
    try:
        model = joblib.load(model_file)
        logging.info("Model loaded successfully")
    except FileNotFoundError:
        logging.error(f"Model file {model_file} not found")
        raise FileNotFoundError(f"Model file {model_file} not found. Please run train.py.")
    
    try:
        predictions = model.predict(df_processed)
        logging.info(f"Predictions shape: {predictions.shape}")
    except Exception as e:
        logging.error(f"Prediction error: {str(e)}")
        # Fallback to Safe
        df_result = df_original.copy()
        df_result['Prediction'] = 'Safe'
        logging.warning("Fallback to Safe predictions due to model error")
        df_result['Domain'] = df_result['ip.dst'].apply(resolve_ip)
        df_result['Port'] = df_result[['tcp.dstport', 'udp.dstport']].bfill(axis=1).iloc[:, 0].fillna(-1).astype(int)
        df_result['Port'] = df_result['Port'].apply(lambda x: x if x != -1 else '')
        df_result['Protocol'] = df_result.apply(
            lambda row: 'HTTP' if row['Port'] in [80, 443] else 'DNS' if row['Port'] == 53 else 'FTP' if row['Port'] == 21 else 'Other',
            axis=1
        )
        return df_result
    
    valid_indices = df_processed.index
    df_result = df_original.loc[valid_indices].copy()
    
    df_result['Prediction'] = ['Attack' if p == 1 else 'Safe' for p in predictions]
    logging.info(f"Prediction counts: {df_result['Prediction'].value_counts().to_dict()}")
    
    df_result['Domain'] = df_result['ip.dst'].apply(resolve_ip)
    
    df_result['Port'] = df_result[['tcp.dstport', 'udp.dstport']].bfill(axis=1).iloc[:, 0].fillna(-1).astype(int)
    df_result['Port'] = df_result['Port'].apply(lambda x: x if x != -1 else '')
    
    # Protocol-specific
    df_result['Protocol'] = df_result.apply(
        lambda row: 'HTTP' if row['Port'] in [80, 443] else 'DNS' if row['Port'] == 53 else 'FTP' if row['Port'] == 21 else 'Other',
        axis=1
    )
    logging.info(f"Protocol distribution: {df_result['Protocol'].value_counts().to_dict()}")
    
    # Threat detection
    alerts = detect_threats(df_result)
    for alert in alerts:
        with open("logs/alerts.log", "a") as f:
            f.write(f"{time.ctime()}: {alert}\n")
        logging.info(f"Alert logged: {alert}")
    
    # SIEM logging
    siem_log = df_result.to_dict(orient='records')
    with open("logs/siem.json", "a") as f:
        for record in siem_log:
            record['timestamp'] = time.ctime()
            json.dump(record, f)
            f.write("\n")
    logging.info("SIEM log updated")
    
    display_cols = ['Domain', 'Prediction', 'ip.src', 'ip.dst', 'Port', 'Protocol', 'ip.len', 'ip.proto', 'ip.ttl', 'tcp.window_size']
    df_result = df_result[[col for col in display_cols if col in df_result.columns]]
    
    with open("logs/predictions.log", "a") as f:
        for pred in df_result['Prediction']:
            f.write(f"{time.ctime()}: {pred}\n")
    
    logging.info(f"Result shape: {df_result.shape}, columns: {df_result.columns.tolist()}")
    logging.info(f"Result head:\n{df_result.head().to_string()}")
    
    return df_result

if __name__ == "__main__":
    result = predict_attacks("models/ids_model.pkl", "data/raw/domain_traffic.csv")
    print("Final Result Shape:", result.shape)
    print("Final Result Columns:", result.columns.tolist())
    print("Final Result Head:\n", result.head())