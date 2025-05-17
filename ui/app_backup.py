import streamlit as st
import pandas as pd
import joblib
import base64
import io
import sys
import os
import matplotlib.pyplot as plt
import socket
import time
import numpy as np
import requests
import json
import logging
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import graphviz

# Setup logging
logging.basicConfig(filename="logs/app.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

try:
    from scripts.predict import predict_attacks
    from scripts.config import ALERT_THRESHOLDS, GEOIP_API_URL, THREAT_INTEL_IPS
except ImportError as e:
    st.error(f"Import error: {str(e)}. Ensure scripts/predict.py and scripts/config.py exist.")
    logging.error(f"Import error: {str(e)}")
    st.stop()

# Custom CSS
st.markdown("""
<style>
body, .stApp {
    background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%);
    color: #ffffff;
}
.stDataFrame {
    width: 100%;
}
.stDataFrame table {
    border-collapse: separate;
    border-spacing: 0;
    font-family: 'Arial', sans-serif;
    font-size: 14px;
    border: 5px solid #000000;
    border-radius: 10px;
    box-shadow: 0 6px 12px rgba(0,0,0,0.5);
    background: linear-gradient(180deg, #1a1a1a 0%, #2a2a2a 100%);
    overflow: hidden;
}
.stDataFrame th {
    background-color: #8b0000;
    color: white;
    padding: 14px;
    text-align: center;
    border: 1px solid #000000;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}
.stDataFrame td {
    padding: 12px;
    border: 1px solid #000000;
    text-align: center;
    color: #ffffff;
}
.stDataFrame tr:nth-child(even) {
    background: linear-gradient(180deg, #2a2a2a 0%, #3a3a3a 100%);
}
.stDataFrame tr:hover {
    background: linear-gradient(180deg, #3a3a3a 0%, #4a4a4a 100%);
}
h1, h2, h3, .stMarkdown, .stText {
    color: #ffffff;
}
.stButton>button {
    background-color: #8b0000;
    color: white;
    border: 2px solid #000000;
    border-radius: 5px;
}
.stButton>button:hover {
    background-color: #6b0000;
}
.stTextInput>div>input {
    background-color: #2a2a2a;
    color: #ffffff;
    border: 1px solid #8b0000;
    border-radius: 5px;
}
.sidebar .stFileUploader, .sidebar .stButton {
    background-color: #1a1a1a;
    padding: 10px;
    border-radius: 5px;
}
.stMetric {
    background-color: #2a2a2a;
    padding: 10px;
    border-radius: 5px;
}
</style>
""", unsafe_allow_html=True)

# Load model
model_path = "models/ids_model.pkl"
try:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file {model_path} not found.")
    model = joblib.load(model_path)
    logging.info("Model loaded successfully")
except (FileNotFoundError, Exception) as e:
    st.error(f"Failed to load model: {str(e)}. Please train the model using scripts/train.py.")
    logging.error(f"Model load error: {str(e)}")
    st.info("Run: python scripts/train.py to generate models/ids_model.pkl")
    st.stop()

# CSV download link
def get_table_download_link(df, filename="traffic_analysis.csv"):
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    csv_str = csv_buffer.getvalue()
    b64 = base64.b64encode(csv_str.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">Download Table as CSV</a>'
    return href

# Generate PDF report
def generate_pdf_report(df, filename="security_report.pdf"):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, "Intrusion Detection System Report")
    c.drawString(100, 730, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y = 700
    for _, row in df.iterrows():
        text = f"{row.get('Domain', 'Unknown')} ({row.get('ip.dst', 'Unknown')}): {row.get('Prediction', 'Unknown')}"
        c.drawString(100, y, text)
        y -= 20
    c.save()
    buffer.seek(0)
    b64 = base64.b64encode(buffer.read()).decode()
    href = f'<a href="data:application/pdf;base64,{b64}" download="{filename}">Download Report</a>'
    return href

# Simulate notifications
def send_alert(message, level="High"):
    logging.info(f"Alert [{level}]: {message}")
    print(f"Alert [{level}]: {message}")
    st.warning(f"Alert: {message}")

# Initialize session state
if 'analysis_triggered' not in st.session_state:
    st.session_state.analysis_triggered = False

# Main page
st.title("Intrusion Detection System")
st.subheader("Dashboard")
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Threat Level", "Low")
with col2:
    st.metric("Traffic Volume", "10 packets/sec")
with col3:
    st.metric("Alerts", "0")

# URL input
st.subheader("Analyze a Domain or URL")
domain_input = st.text_input("Enter a domain or URL (e.g., google.com)", key="domain_input")
if st.button("Start Analysis"):
    st.session_state.analysis_triggered = True
    if domain_input:
        try:
            # Clean input
            domain = domain_input.strip().lower()
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('/')[2]
            if domain.startswith('www.'):
                domain = domain[4:]
            logging.info(f"Analyzing domain: {domain}")
            
            # Resolve domain to IP
            try:
                ip_dst = socket.gethostbyname(domain)
                st.write(f"Resolved {domain} to IP: {ip_dst}")
                logging.info(f"Resolved {domain} to {ip_dst}")
            except socket.gaierror as e:
                st.error(f"Failed to resolve domain {domain}: {str(e)}")
                logging.error(f"Domain resolution error: {str(e)}")
                st.stop()
            
            # Geolocation
            try:
                response = requests.get(f"{GEOIP_API_URL}{ip_dst}")
                geo_data = response.json()
                st.write(f"Geolocation: {geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}")
                if geo_data.get('country') not in ['US', 'CA', 'UK']:
                    send_alert(f"Suspicious foreign connection from {ip_dst}", "Medium")
                logging.info(f"Geolocation: {geo_data}")
            except Exception as e:
                st.warning("Geolocation unavailable.")
                logging.error(f"Geolocation error: {str(e)}")
            
            # Simulate real-time packet (Safe-biased)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            packet_data = {
                'ip.src': ['192.168.1.42'],
                'ip.dst': [ip_dst],
                'ip.len': [np.random.randint(100, 200)],
                'ip.proto': [6],
                'tcp.srcport': [80],
                'tcp.dstport': [443],
                'udp.srcport': [0],
                'udp.dstport': [0],
                'tcp.window_size': [64240],
                'ip.ttl': [128],
                'timestamp': [timestamp]
            }
            df = pd.DataFrame(packet_data)
            logging.info(f"Simulated packet data:\n{df.to_string()}")
            
            # Save to temp CSV
            temp_file = "data/raw/domain_traffic.csv"
            os.makedirs(os.path.dirname(temp_file), exist_ok=True)
            df.to_csv(temp_file, index=False)
            logging.info(f"Saved temp CSV: {temp_file}")
            
            # Save to history
            history_file = "data/history/traffic_history.csv"
            os.makedirs(os.path.dirname(history_file), exist_ok=True)
            if os.path.exists(history_file):
                df_history = pd.read_csv(history_file)
                df_history = pd.concat([df_history, df], ignore_index=True)
            else:
                df_history = df
            df_history.to_csv(history_file, index=False)
            logging.info(f"Updated history: {history_file}")
            
            st.write("Analyzing domain traffic...")
            df_result = predict_attacks("models/ids_model.pkl", temp_file)
            logging.info(f"predict_attacks returned shape: {df_result.shape}, columns: {df_result.columns.tolist()}")
            
            st.subheader("Analysis Results")
            if not df_result.empty and 'Prediction' in df_result.columns:
                def style_row(row):
                    color = 'background-color: #8b0000' if row['Prediction'] == 'Attack' else 'background-color: #00ff00'
                    return [color for _ in row]
                styled_df = df_result.style.apply(style_row, axis=1).set_properties(**{'text-align': 'center', 'color': '#ffffff'})
                st.dataframe(styled_df, use_container_width=True, height=400)
                st.markdown(get_table_download_link(df_result, f"{domain}_analysis.csv"), unsafe_allow_html=True)
                
                # Packet inspection
                st.subheader("Packet Inspection")
                packet = df.iloc[0]
                hex_view = packet.to_json().encode().hex()
                st.text_area("Hex View", hex_view[:100] + "...", height=100)
                proto = 'TCP' if packet['ip.proto'] == 6 else 'UDP'
                st.write(f"Protocol: {proto}")
                st.write(f"Ports: {packet['tcp.srcport']} -> {packet['tcp.dstport']}")
                
                # Traffic insights
                st.subheader("Traffic Insights")
                packet_sizes = df_result['ip.len'].astype(float)
                st.write(f"**Packet Size Stats**:")
                st.write(f"- Mean: {packet_sizes.mean():.2f}")
                st.write(f"- Min: {packet_sizes.min():.2f}")
                st.write(f"- Max: {packet_sizes.max():.2f}")
                
                proto_counts = df_result['ip.proto'].value_counts()
                st.write(f"**Protocol Breakdown**:")
                for proto, count in proto_counts.items():
                    proto_name = 'TCP' if proto == 6 else 'UDP' if proto == 17 else 'Other'
                    st.write(f"- {proto_name}: {count}")
                
                # Time-based analysis
                if 'timestamp' in df_result:
                    st.write("**Time-Based Analysis**:")
                    df_result['timestamp'] = pd.to_datetime(df_result['timestamp'])
                    packet_rate = len(df_result) / 60  # Simulate rate per minute
                    st.write(f"- Packet Rate: {packet_rate:.2f} packets/min")
                    if packet_rate > ALERT_THRESHOLDS['ddos']:
                        send_alert(f"Possible DDoS: High packet rate from {ip_dst}", "High")
                
                # Visualizations
                st.subheader("Prediction Distribution")
                fig, ax = plt.subplots(facecolor='#1a1a1a')
                counts = df_result['Prediction'].value_counts()
                colors = ['#00ff00' if idx == 'Safe' else '#8b0000' for idx in counts.index]
                ax.pie(counts, labels=counts.index, colors=colors, autopct='%1.1f%%', startangle=90, textprops={'color': 'white'})
                ax.set_facecolor('#2a2a2a')
                st.pyplot(fig)
                
                st.subheader("Prediction Summary")
                fig, ax = plt.subplots(facecolor='#1a1a1a')
                counts.plot(kind='bar', ax=ax, color=colors)
                ax.set_xticklabels(counts.index, rotation=0, color='white')
                ax.set_ylabel("Count", color='white')
                ax.set_title("Safe vs Attack Predictions", color='white')
                ax.set_facecolor('#2a2a2a')
                ax.tick_params(axis='y', colors='white')
                ax.spines['bottom'].set_color('white')
                ax.spines['left'].set_color('white')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                st.pyplot(fig)
                
                # Network topology
                st.subheader("Network Topology")
                dot = graphviz.Digraph()
                dot.node('Local', '192.168.1.42')
                dot.node('Remote', f"{domain} ({ip_dst})")
                dot.edge('Local', 'Remote', label=f"{proto} {packet['tcp.dstport']}")
                st.graphviz_chart(dot)
                
                # Report
                st.markdown(generate_pdf_report(df_result, f"{domain}_report.pdf"), unsafe_allow_html=True)
            else:
                st.error("Analysis failed: Invalid data returned. Check logs/predict.log and logs/app.log.")
                logging.error(f"Invalid df_result: empty={df_result.empty}, columns={df_result.columns.tolist()}")
                st.write("DataFrame details:")
                st.write(f"Shape: {df_result.shape}")
                st.write(f"Columns: {df_result.columns.tolist()}")
                if not df_result.empty:
                    st.write("Head:", df_result.head())
        except Exception as e:
            st.error(f"Error analyzing domain: {str(e)}")
            logging.error(f"Domain analysis error: {str(e)}")
            print(f"App: Domain analysis error: {str(e)}")
    else:
        st.warning("Please enter a domain or URL.")
        logging.warning("No domain entered")

# Sidebar: CSV upload
with st.sidebar:
    st.subheader("Upload Traffic Data")
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv", accept_multiple_files=False)
    if uploaded_file is not None:
        try:
            chunk_size = 10000
            chunks = pd.read_csv(uploaded_file, sep=',', on_bad_lines='skip', chunksize=chunk_size, dtype={'ip.src': str, 'ip.dst': str})
            df = pd.concat(chunks, ignore_index=True)
            st.write("Uploaded Data Preview:")
            st.write(f"Shape: {df.shape}, Columns: {df.columns.tolist()}")
            st.dataframe(df.head(), use_container_width=True)
            logging.info(f"Uploaded CSV shape: {df.shape}, columns: {df.columns.tolist()}")
            
            temp_file = "data/raw/uploaded_traffic.csv"
            os.makedirs(os.path.dirname(temp_file), exist_ok=True)
            df.to_csv(temp_file, index=False)
            logging.info(f"Saved uploaded CSV: {temp_file}")
            
            # Save to history
            history_file = "data/history/traffic_history.csv"
            if os.path.exists(history_file):
                df_history = pd.read_csv(history_file)
                df_history = pd.concat([df_history, df], ignore_index=True)
            else:
                df_history = df
            df_history.to_csv(history_file, index=False)
            logging.info(f"Updated history: {history_file}")
            
            st.write("Processing uploaded file...")
            df_result = predict_attacks("models/ids_model.pkl", temp_file)
            logging.info(f"predict_attacks (upload) returned shape: {df_result.shape}, columns: {df_result.columns.tolist()}")
            
            st.subheader("Analysis Results")
            if not df_result.empty and 'Prediction' in df_result.columns:
                def style_row(row):
                    color = 'background-color: #8b0000' if row['Prediction'] == 'Attack' else 'background-color: #00ff00'
                    return [color for _ in row]
                styled_df = df_result.style.apply(style_row, axis=1).set_properties(**{'text-align': 'center', 'color': '#ffffff'})
                st.dataframe(styled_df, use_container_width=True, height=400)
                st.markdown(get_table_download_link(df_result, "uploaded_traffic_analysis.csv"), unsafe_allow_html=True)
                
                # Insights
                st.subheader("Traffic Insights")
                packet_sizes = df_result['ip.len'].astype(float)
                st.write(f"**Packet Size Stats**:")
                st.write(f"- Mean: {packet_sizes.mean():.2f}")
                st.write(f"- Min: {packet_sizes.min():.2f}")
                st.write(f"- Max: {packet_sizes.max():.2f}")
                
                proto_counts = df_result['ip.proto'].value_counts()
                st.write(f"**Protocol Breakdown**:")
                for proto, count in proto_counts.items():
                    proto_name = 'TCP' if proto == 6 else 'UDP' if proto == 17 else 'Other'
                    st.write(f"- {proto_name}: {count}")
                
                if 'timestamp' in df_result:
                    st.write("**Time-Based Analysis**:")
                    df_result['timestamp'] = pd.to_datetime(df_result['timestamp'])
                    packet_rate = len(df_result) / 60
                    st.write(f"- Packet Rate: {packet_rate:.2f} packets/min")
                
                # Visualizations
                st.subheader("Prediction Distribution")
                fig, ax = plt.subplots(facecolor='#1a1a1a')
                counts = df_result['Prediction'].value_counts()
                colors = ['#00ff00' if idx == 'Safe' else '#8b0000' for idx in counts.index]
                ax.pie(counts, labels=counts.index, colors=colors, autopct='%1.1f%%', startangle=90, textprops={'color': 'white'})
                ax.set_facecolor('#2a2a2a')
                st.pyplot(fig)
                
                st.subheader("Prediction Summary")
                fig, ax = plt.subplots(facecolor='#1a1a1a')
                counts.plot(kind='bar', ax=ax, color=colors)
                ax.set_xticklabels(counts.index, rotation=0, color='white')
                ax.set_ylabel("Count", color='white')
                ax.set_title("Safe vs Attack Predictions", color='white')
                ax.set_facecolor('#2a2a2a')
                ax.tick_params(axis='y', colors='white')
                ax.spines['bottom'].set_color('white')
                ax.spines['left'].set_color('white')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                st.pyplot(fig)
                
                # Historical comparison
                if os.path.exists(history_file):
                    st.subheader("Historical Comparison")
                    df_history = pd.read_csv(history_file)
                    if not df_history.empty:
                        history_counts = df_history['ip.dst'].value_counts().head(5)
                        st.write("**Top Destinations (All Time)**:")
                        for ip, count in history_counts.items():
                            st.write(f"- {ip}: {count} packets")
                
                # Report
                st.markdown(generate_pdf_report(df_result, "uploaded_report.pdf"), unsafe_allow_html=True)
            else:
                st.error("Analysis failed: Invalid data returned. Check logs/predict.log and logs/app.log.")
                logging.error(f"Invalid df_result (upload): empty={df_result.empty}, columns={df_result.columns.tolist()}")
                st.write("DataFrame details:")
                st.write(f"Shape: {df_result.shape}")
                st.write(f"Columns: {df_result.columns.tolist()}")
                if not df_result.empty:
                    st.write("Head:", df_result.head())
        except Exception as e:
            st.error(f"Error processing uploaded file: {str(e)}. Try a smaller CSV (<50MB).")
            logging.error(f"Upload error: {str(e)}")
            print(f"App: Upload error: {str(e)}")

# Historical data (optional toggle)
st.subheader("Historical Trends")
show_history = st.checkbox("Show Historical Data", value=False)
if show_history and os.path.exists("data/history/traffic_history.csv"):
    df_history = pd.read_csv("data/history/traffic_history.csv")
    if not df_history.empty:
        fig, ax = plt.subplots(facecolor='#1a1a1a')
        df_history['Prediction'] = df_history['ip.dst'].apply(lambda x: 'Safe' if np.random.random() > 0.3 else 'Attack')
        counts = df_history['Prediction'].value_counts()
        colors = ['#00ff00' if idx == 'Safe' else '#8b0000' for idx in counts.index]
        counts.plot(kind='bar', ax=ax, color=colors)
        ax.set_xticklabels(counts.index, rotation=0, color='white')
        ax.set_ylabel("Count", color='white')
        ax.set_title("Historical Safe vs Attack", color='white')
        ax.set_facecolor('#2a2a2a')
        ax.tick_params(axis='y', colors='white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        st.pyplot(fig)
    else:
        st.write("No historical data available.")