# scripts/label_traffic.py
import pandas as pd
import os

def clean_traffic_file(file_path):
    try:
        # Read CSV, skip bad lines
        df = pd.read_csv(file_path, on_bad_lines='skip')
        
        # Expected columns from Tshark
        expected_cols = ['ip.src', 'ip.dst', 'ip.len', 'ip.proto', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport']
        
        # Keep only expected columns
        missing_cols = [col for col in expected_cols if col not in df.columns]
        if missing_cols:
            print(f"Warning: {file_path} missing columns: {missing_cols}")
            for col in missing_cols:
                df[col] = pd.NA
        
        df = df[expected_cols]
        
        # Drop rows with incorrect number of columns (if any remain)
        df.dropna(how='all', inplace=True)
        
        return df
    except Exception as e:
        print(f"Error cleaning {file_path}: {str(e)}")
        return pd.DataFrame()

def label_traffic(benign_file, attack_file, output_file):
    # Clean benign and attack data
    df_benign = clean_traffic_file(benign_file)
    df_attack = clean_traffic_file(attack_file)
    
    # Add Label column
    df_benign['Label'] = 0  # Benign
    df_attack['Label'] = 1  # Attack
    
    # Combine
    df = pd.concat([df_benign, df_attack], ignore_index=True)
    
    # Save
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"Labeled data saved to {output_file}")

if __name__ == "__main__":
    label_traffic("data/raw/benign_traffic.csv", "data/raw/attack_traffic.csv", "data/raw/traffic_data.csv")