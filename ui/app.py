import importlib.util
import sys
import os

# Define project root (parent of 'ui' folder)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)


utils_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../scripts/utils.py"))
spec = importlib.util.spec_from_file_location("utils", utils_path)
utils = importlib.util.module_from_spec(spec)
spec.loader.exec_module(utils)

parallel_domain_analysis = utils.parallel_domain_analysis
if hasattr(utils, "parallel_domain_analysis"):
    parallel_domain_analysis = utils.parallel_domain_analysis
else:
    logger.error("utils module missing 'parallel_domain_analysis'")
    st.error("Missing 'parallel_domain_analysis' function in utils.py.")
    st.stop()




import logging
from logging.handlers import RotatingFileHandler
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import folium
from folium.plugins import HeatMap
from streamlit_folium import st_folium
import socket
import io
from datetime import datetime
import pytz
from dateutil.parser import parse
import ipaddress
import geoip2.database
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from scapy.all import sniff, wrpcap, rdpcap, get_working_ifaces, IP, Raw
import nmap
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup logging
logger = logging.getLogger("streamlit_app")
logger.setLevel(logging.DEBUG)

# Use a safe logging directory (relative or configurable)
log_dir = os.path.join(os.path.dirname(__file__), "logs")

os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "streamlit.log")
handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)
logger.info("App started")

# Streamlit setup
st.set_page_config(
    page_title="NetSec AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto"
)

# Safe import of custom modules
try:
    from scripts.config import VIRUSTOTAL_API_KEY, THREAT_INTEL_IPS, EMAIL_CONFIG
    from scripts.utils import (
        capture_and_analyze_packets,
        analyze_packets,
        check_flaws
    )
    from scripts.predict import predict_threat
except ImportError as e:
    logger.error(f"Failed to import scripts modules: {str(e)}")
    st.error(f"Failed to import scripts modules: {str(e)}. Ensure 'scripts' directory exists with config.py, predict.py, and utils.py.")
    st.stop()

# Example constant
GEOIP_DB_PATH = os.path.join(project_root, "data", "GeoLite2-Country.mmdb")

# The rest of your Streamlit UI code goes here...
# Example:
# [Add your sections for domain analysis, packet capture, predictions, charts, etc.]


MITRE_ATTACK_MAPPING = {
    "DDoS": {"technique": "T1498", "tactic": "Impact", "name": "Network Denial of Service"},
    "XSS": {"technique": "T1189", "tactic": "Initial Access", "name": "Drive-by Compromise"},
    "SQLi": {"technique": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
    "Ransomware": {"technique": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"},
    "Malware": {"technique": "T1204", "tactic": "Execution", "name": "User Execution"},
    "Suspicious": {"technique": "T1204", "tactic": "Execution", "name": "Potential Threat"},
    "Port Scan": {"technique": "T1046", "tactic": "Discovery", "name": "Network Service Scanning"},
    "VirusTotal": {"technique": "T1590", "tactic": "Reconnaissance", "name": "Gather Victim Network Information"}
}

FALLBACK_COORDINATES = {
    "Afghanistan": (33.9391, 67.7100),
    "Albania": (41.1533, 20.1683),
    "Algeria": (28.0339, 1.6596),
    "Argentina": (-38.4161, -63.6167),
    "Australia": (-25.2744, 133.7751),
    "Brazil": (-14.2350, -51.9253),
    "Canada": (56.1304, -106.3468),
    "China": (35.8617, 104.1954),
    "France": (46.6034, 1.8883),
    "Germany": (51.1657, 10.4515),
    "India": (20.5937, 78.9629),
    "Italy": (41.8719, 12.5674),
    "Japan": (36.2048, 138.2529),
    "Russia": (61.5240, 105.3188),
    "South Africa": (-30.5595, 22.9375),
    "United Kingdom": (55.3781, -3.4360),
    "United States": (37.0902, -95.7129),
    "Unknown": (0, 0)
}

import platform

def is_live_capture_supported():
    # Assume no support when deployed
    if platform.system() in ['Linux', 'Darwin', 'Windows']:
        return os.getenv("IS_DEPLOYED") != "true"
    return False

if is_live_capture_supported():
    st.sidebar.header("Live Traffic Capture")
    # ... your live capture code ...
else:
    st.sidebar.warning("Live capture is disabled on this deployment. Please upload a PCAP file.")




def get_mitre_mapping(threat):
    return MITRE_ATTACK_MAPPING.get(threat, {"technique": "N/A", "tactic": "N/A", "name": "Not Mapped"})

def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip == "0.0.0.0":
            logger.debug(f"IP {ip} is invalid (0.0.0.0), skipping")
            return False
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast)
    except ValueError:
        logger.warning(f"Invalid IP address: {ip}")
        return False

@lru_cache(maxsize=1000)
def get_country_from_ip(ip):
    logger.debug(f"Geolocation attempt for IP: {ip}")
    if not is_public_ip(ip):
        logger.debug(f"IP {ip} is private, invalid, or 0.0.0.0, returning 'Unknown'")
        return "Unknown"
    try:
        if not os.path.exists(GEOIP_DB_PATH):
            error_msg = f"GeoIP2 database not found at {GEOIP_DB_PATH}. Download GeoLite2-Country.mmdb from MaxMind and place it there."
            logger.error(error_msg)
            st.error(error_msg)
            return "Unknown"
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            try:
                response = reader.country(ip)
                country = response.country.name
                country = country if country else "Unknown"
                logger.info(f"Geolocation for {ip}: {country}")
                return country
            except geoip2.errors.AddressNotFoundError:
                logger.warning(f"IP {ip} not found in GeoIP2 database")
                return "Unknown"
    except Exception as e:
        logger.error(f"Unexpected geolocation error for {ip}: {str(e)}")
        st.error(f"Unexpected geolocation error: {str(e)}")
        return "Unknown"
def resolve_ip_to_domain(ip):
    try:
        result = socket.gethostbyaddr(ip)
        domain = result[0]  # The primary domain name
        logger.debug(f"Resolved IP {ip} to domain {domain}")
        return domain
    except socket.herror:
        logger.warning(f"Could not resolve IP {ip} to domain")
        return None
    except Exception as e:
        logger.error(f"Unexpected error resolving domain for IP {ip}: {str(e)}")
        return None


def nmap_scan(ip):
    try:
        nm = nmap.PortScanner()
        logger.debug(f"Starting Nmap scan for IP: {ip}")
        nm.scan(ip, arguments='-sS --open -p 1-1024')
        ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', 'unknown')
                    if state == 'open':
                        ports.append({"port": port, "state": state, "service": service})
        logger.info(f"Nmap scan completed for {ip}: {len(ports)} open ports found")
        return {"ports": ports}
    except Exception as e:
        logger.error(f"Nmap scan error for {ip}: {str(e)}")
        return {"error": f"Nmap scan failed: {str(e)}"}

def calculate_threat_score(prediction, vt_result, flaws, ssl_result, scan_result, packet_indicators, otx_result=None):
    score = 0
    if isinstance(prediction, str) and prediction != "Safe":
        score += 10 if prediction == "Low Risk" else 20
    if isinstance(vt_result, str) and "threats detected" in vt_result.lower():
        score += 10
    if isinstance(flaws, list) and flaws and "No major flaws detected" not in flaws:
        score += 8
    if isinstance(ssl_result, dict) and (ssl_result.get("expired", False) or not ssl_result.get("hostname_match", True)):
        score += 5
    if isinstance(scan_result, dict) and scan_result.get("ports"):
        suspicious_ports = [port["port"] for port in scan_result["ports"] if port["port"] in [4444, 6667]]
        if suspicious_ports:
            score += 5
    if isinstance(packet_indicators, dict) and packet_indicators.get("suspicious", False):
        score += 5
    if isinstance(otx_result, dict) and otx_result.get("pulse_count", 0) > 0:
        score += otx_result["pulse_count"] * 2
    score = max(0, min(score, 100))
    logger.debug(f"Calculated threat score: {score}")
    return score

def read_last_n_lines(file_path, n=50):
    try:
        with open(file_path, "r", encoding="latin-1") as f:
            lines = f.readlines()
            return lines[-n:] if lines else ["No logs available"]
    except Exception as e:
        logger.error(f"Error reading log file {file_path}: {str(e)}")
        return [f"Error reading log file: {str(e)}"]

def get_available_interfaces():
    try:
        interfaces = get_working_ifaces()
        return [iface.name for iface in interfaces] if interfaces else ["Wi-Fi"]
    except Exception as e:
        logger.error(f"Error fetching interfaces: {str(e)}")
        st.error(f"Error fetching network interfaces: {str(e)}. Defaulting to 'Wi-Fi'.")
        return ["Wi-Fi"]

def geocode_country(country):
    coords = FALLBACK_COORDINATES.get(country.strip(), FALLBACK_COORDINATES["Unknown"])
    return coords

def process_packet_data(packets=None, network_analysis=None, max_packets=1000):
    logger.debug("Starting packet data processing")
    if network_analysis:
        logger.debug("Processing network analysis data")
        packet_indicators = network_analysis
        protocol_distribution = network_analysis.get("protocol_distribution", {})
        traffic_direction = network_analysis.get("traffic_direction", {"inbound": 0, "outbound": 0})
        packet_sizes = network_analysis.get("packet_sizes", [])
        connection_states = network_analysis.get("connection_states", {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0})
        top_talkers = network_analysis.get("top_talkers", {"sources": {}, "destinations": {}})
        port_usage = network_analysis.get("port_usage", {"source_ports": {}, "dest_ports": {}})
        details = packet_indicators.get("details", [])
        if packet_indicators.get("suspicious", False):
            st.warning(f"Packet Analysis Warning: {'; '.join(details)}")
    elif packets:
        logger.debug("Processing packets from PCAP")
        packets_to_process = packets[:max_packets]
        logger.info(f"Processing {len(packets_to_process)} packets (limited to {max_packets})")
        packet_indicators = analyze_packets(packets_to_process)
        if "error" in packet_indicators:
            logger.error(f"Packet analysis failed: {packet_indicators['error']}")
            return packet_indicators, {}, {"inbound": 0, "outbound": 0}, [], {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0}, {"sources": {}, "destinations": {}}, {"source_ports": {}, "dest_ports": {}}
        protocol_distribution = packet_indicators.get("protocol_distribution", {})
        traffic_direction = packet_indicators.get("traffic_direction", {"inbound": 0, "outbound": 0})
        packet_sizes = packet_indicators.get("packet_sizes", [])
        packet_sizes = [int(size) for size in packet_sizes if isinstance(size, (int, float))]
        connection_states = packet_indicators.get("connection_states", {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0})
        top_talkers = packet_indicators.get("top_talkers", {"sources": {}, "destinations": {}})
        port_usage = packet_indicators.get("port_usage", {"source_ports": {}, "dest_ports": {}})
        details = packet_indicators.get("details", [])
        payload_suspicion = packet_indicators.get("payload_suspicion", [])
        if packet_indicators.get("suspicious", False):
            st.warning(f"Packet Analysis Warning: {'; '.join(details)}")
        if payload_suspicion:
            st.warning(f"Payload Concerns: {'; '.join(payload_suspicion)}")
    else:
        logger.warning("No packets or network analysis provided")
        return None, None, None, None, None, None, None

    if not packet_sizes:
        logger.warning("Packet sizes list is empty. Check PCAP content or analyze_packets implementation.")
    logger.debug(f"Protocol distribution: {protocol_distribution}")
    logger.debug(f"Traffic direction: {traffic_direction}")
    logger.debug(f"Packet sizes: {packet_sizes}")
    logger.debug(f"Connection states: {connection_states}")
    logger.debug(f"Top talkers: {top_talkers}")
    logger.debug(f"Port usage: {port_usage}")

    return packet_indicators, protocol_distribution, traffic_direction, packet_sizes, connection_states, top_talkers, port_usage

def display_packet_analysis(protocol_distribution, traffic_direction, packet_sizes, connection_states, top_talkers, port_usage):
    col1, col2 = st.columns(2)

    with col1:
        with st.expander("Protocol Distribution", expanded=True):
            if protocol_distribution:
                st.write("**Protocol Breakdown:**")
                proto_df = pd.DataFrame(list(protocol_distribution.items()), columns=["Protocol", "Count"])
                fig = px.pie(proto_df, names="Protocol", values="Count", title="Protocol Distribution",
                             color_discrete_sequence=["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"])
                st.plotly_chart(fig, use_container_width=True, key="protocol_distribution_chart")
            else:
                st.write("No protocol data available.")

        with st.expander("Packet Size Analysis", expanded=True):
            if packet_sizes:
                st.write("**Packet Size Distribution:**")
                size_df = pd.DataFrame(packet_sizes, columns=["Size"])
                fig = px.histogram(size_df, x="Size", nbins=20, title="Packet Size Distribution",
                                   color_discrete_sequence=["#4ECDC4"])
                st.plotly_chart(fig, use_container_width=True, key="packet_size_chart")
                avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
                largest_packet = str(max(packet_sizes)) if packet_sizes else "0"
                smallest_packet = str(min(packet_sizes)) if packet_sizes else "0"
                st.write(f"**Average Packet Size:** {avg_size:.2f} bytes")
                st.write(f"**Largest Packet:** {largest_packet} bytes")
                st.write(f"**Smallest Packet:** {smallest_packet} bytes")
            else:
                st.write("No packet size data available.")

        with st.expander("TCP Connection States", expanded=True):
            st.write("**Connection States (TCP):**")
            st.table(pd.DataFrame.from_dict(connection_states, orient="index", columns=["Count"]))

    with col2:
        with st.expander("Traffic Direction", expanded=True):
            st.write(f"**Inbound Traffic:** {traffic_direction['inbound']} packets")
            st.write(f"**Outbound Traffic:** {traffic_direction['outbound']} packets")

        with st.expander("Top Talkers", expanded=True):
            st.write("**Top Source IPs:**")
            if top_talkers["sources"]:
                sources_df = pd.DataFrame.from_dict(top_talkers["sources"], orient="index", columns=["Packet Count"])
                sources_df.reset_index(inplace=True)
                sources_df.rename(columns={"index": "Source IP"}, inplace=True)
                sources_df["Geolocation"] = sources_df["Source IP"].apply(
                    lambda ip: f"{get_country_from_ip(ip)}"
                )
                fig_sources = px.bar(sources_df, x="Packet Count", y="Source IP", title="Top Source IPs",
                                     hover_data=["Geolocation"], color_discrete_sequence=["#FF6B6B"])
                st.plotly_chart(fig_sources, use_container_width=True, key="top_sources_chart")
                st.table(sources_df[["Source IP", "Packet Count", "Geolocation"]])
            else:
                st.write("No data available.")
            st.write("**Top Destination IPs:**")
            if top_talkers["destinations"]:
                destinations_df = pd.DataFrame.from_dict(top_talkers["destinations"], orient="index", columns=["Packet Count"])
                destinations_df.reset_index(inplace=True)
                destinations_df.rename(columns={"index": "Destination IP"}, inplace=True)
                destinations_df["Geolocation"] = destinations_df["Destination IP"].apply(
                    lambda ip: f"{get_country_from_ip(ip)}"
                )
                fig_destinations = px.bar(destinations_df, x="Packet Count", y="Destination IP", title="Top Destination IPs",
                                          hover_data=["Geolocation"], color_discrete_sequence=["#45B7D1"])
                st.plotly_chart(fig_destinations, use_container_width=True, key="top_destinations_chart")
                st.table(destinations_df[["Destination IP", "Packet Count", "Geolocation"]])
            else:
                st.write("No data available.")

        with st.expander("Port Usage", expanded=True):
            st.write("**Top Source Ports:**")
            if port_usage["source_ports"]:
                src_ports_df = pd.DataFrame.from_dict(port_usage["source_ports"], orient="index", columns=["Count"])
                src_ports_df.reset_index(inplace=True)
                src_ports_df.rename(columns={"index": "Source Port"}, inplace=True)
                fig_src_ports = px.bar(src_ports_df, x="Count", y="Source Port", title="Top Source Ports",
                                       color_discrete_sequence=["#96CEB4"])
                st.plotly_chart(fig_src_ports, use_container_width=True, key="source_ports_chart")
                st.table(src_ports_df)
            else:
                st.write("No data available.")
            st.write("**Top Destination Ports:**")
            if port_usage["dest_ports"]:
                dst_ports_df = pd.DataFrame.from_dict(port_usage["dest_ports"], orient="index", columns=["Count"])
                dst_ports_df.reset_index(inplace=True)
                dst_ports_df.rename(columns={"index": "Destination Port"}, inplace=True)
                fig_dst_ports = px.bar(dst_ports_df, x="Count", y="Destination Port", title="Top Destination Ports",
                                       color_discrete_sequence=["#FFEEAD"])
                st.plotly_chart(fig_dst_ports, use_container_width=True, key="dest_ports_chart")
                st.table(dst_ports_df)
            else:
                st.write("No data available.")

def analyze_domain_or_ip(domain, ip, packet_indicators):
    analysis_result = {"domain": domain, "ip": ip}
    
    domain_results = parallel_domain_analysis(domain)
    ssl_result = domain_results.get("SSL", {"error": "SSL check failed"})
    otx_result = domain_results.get("OTX", {"error": "OTX lookup failed"})
    vt_result = domain_results.get("VirusTotal", "VirusTotal lookup failed")
    whois_result = domain_results.get("WHOIS", {"error": "WHOIS lookup failed"})
    
    scan_result = nmap_scan(ip)
    
    flaws_result = check_flaws(domain)
    if isinstance(flaws_result, list):
        flaws_result = [str(f) for f in flaws_result if f is not None]
    else:
        flaws_result = []
    
    prediction, probabilities = predict_threat(domain, packet_indicators=packet_indicators, ssl_result=ssl_result, scan_result=scan_result)
    
    threat_score = calculate_threat_score(prediction, vt_result, flaws_result, ssl_result, scan_result, packet_indicators, otx_result)
    
    analysis_result.update({
        "prediction": prediction,
        "probabilities": probabilities,
        "threat_score": threat_score,
        "virustotal": vt_result,
        "security_audit": flaws_result,
        "otx": otx_result,
        "whois": [[k, ', '.join(v) if isinstance(v, list) else str(v)] for k, v in whois_result.items()] if "error" not in whois_result else whois_result,
        "ssl": ssl_result,
        "scan": scan_result
    })
    
    return analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result

def display_analysis_result(domain, analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result, ssl_result, scan_result):
    with st.expander(f"Analysis for {domain}", expanded=True):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Threat Prediction")
            if isinstance(prediction, str) and "Error" not in prediction:
                if prediction == "Safe":
                    st.success(f"Prediction: {prediction} (Threat Score: {threat_score}/100)")
                elif prediction in ["Malware", "Suspicious"]:
                    st.error(f"Prediction: {prediction} (Threat Score: {threat_score}/100)")
                    if prediction == "Malware":
                        st.session_state.threat_counts["malware"] += 1
                    elif prediction == "Suspicious":
                        st.session_state.threat_counts["suspicious"] = st.session_state.threat_counts.get("suspicious", 0) + 1
                    st.session_state.recent_threats.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score])
                else:
                    st.warning(f"Prediction: {prediction} (Threat Score: {threat_score}/100)")
                    st.session_state.threat_counts[prediction.lower()] += 1
                    st.session_state.recent_threats.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score])
            else:
                st.warning(f"Prediction failed: {prediction}")

            if probabilities:
                prob_df = pd.DataFrame(list(probabilities.items()), columns=["Threat Level", "Probability"])
                fig = px.bar(prob_df, x="Probability", y="Threat Level", orientation="h",
                             title="Threat Level Probabilities",
                             color="Threat Level",
                             color_discrete_map={"Safe": "green", "Low Risk": "orange", "Malware": "red", "Suspicious": "purple"})
                fig.update_layout(xaxis_title="Probability", yaxis_title="", showlegend=False)
                st.plotly_chart(fig, use_container_width=True, key=f"threat_probabilities_{domain}")

            st.markdown("#### Basic Information")
            st.write(f"**IP Address:** {analysis_result['ip']}")
            st.write(f"**Country:** {get_country_from_ip(analysis_result['ip'])}")
            st.write(f"**VirusTotal Result:** {vt_result}")
            st.write(f"**Security Audit:** {', '.join(flaws_result) if flaws_result else 'No major flaws detected'}")

            st.markdown("#### WHOIS Lookup")
            whois_data = analysis_result.get("whois", {"error": "WHOIS lookup failed"})
            if isinstance(whois_data, dict) and 'error' in whois_data:
                st.error(whois_data['error'])
            else:
                st.table(pd.DataFrame(whois_data, columns=['Field', 'Value']))

        with col2:
            st.markdown("#### SSL Certificate Details")
            if 'error' not in ssl_result:
                st.write(f"- **Expired:** {'Yes' if ssl_result['expired'] else 'No'}")
                st.write(f"- **Expiration Date:** {ssl_result['not_after']}")
                st.write(f"- **Hostname Match:** {'Yes' if ssl_result['hostname_match'] else 'No'}")
                if ssl_result['expired'] or not ssl_result['hostname_match']:
                    st.warning("Potential security issues detected with the SSL/TLS certificate.")
            else:
                st.error(ssl_result['error'])

            st.markdown("#### Nmap Scan Results")
            if 'error' in scan_result:
                st.error(f"Nmap Scan Error: {scan_result['error']}")
            else:
                ports = scan_result.get('ports', [])
                if ports:
                    ports_df = pd.DataFrame(ports)
                    st.table(ports_df)
                else:
                    st.write("No open ports found.")

def process_uploaded_files(pcap_file):
    analysis_results = []
    threat_locations = st.session_state.get("threat_locations", [])

    if pcap_file is None:
        logger.warning("No PCAP file uploaded")
        return analysis_results

    with st.spinner("Analyzing uploaded file..."):
        try:
            pcap_path = os.path.join(log_dir, f"uploaded_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
            with open(pcap_path, "wb") as f:
                f.write(pcap_file.read())
            logger.info(f"Saved uploaded PCAP to {pcap_path}")

            packets = rdpcap(pcap_path)
            logger.info(f"Loaded {len(packets)} packets from PCAP file")
            packet_indicators = analyze_packets(packets)
            if "error" in packet_indicators:
                st.error(packet_indicators["error"])
                logger.warning(f"Packet analysis failed: {packet_indicators['error']}")
                return analysis_results

            st.subheader("PCAP File Analysis")
            if packet_indicators["suspicious"]:
                st.warning("Suspicious activity detected in the PCAP file:")
                for detail in packet_indicators["details"]:
                    st.write(f"- {detail}")
                if packet_indicators["payload_suspicion"]:
                    st.write("Suspicious payloads detected:")
                    for suspicion in packet_indicators["payload_suspicion"]:
                        st.write(f"- {suspicion}")
            else:
                st.success("No suspicious activity detected in the PCAP file.")

            packet_indicators, protocol_distribution, traffic_direction, packet_sizes, connection_states, top_talkers, port_usage = process_packet_data(packets=packets)
            display_packet_analysis(protocol_distribution, traffic_direction, packet_sizes, connection_states, top_talkers, port_usage)

            st.subheader("PCAP File Analysis")
            ips = [pkt[IP].src for pkt in packets if IP in pkt] + [pkt[IP].dst for pkt in packets if IP in pkt]
            unique_ips = list(dict.fromkeys(ips))[:5]
            st.write(f"Found {len(unique_ips)} unique IPs (analyzing first 5)")

            valid_ips = [ip for ip in unique_ips if is_public_ip(ip)]
            if not valid_ips:
                st.warning("No valid public IPs found in PCAP.")
                return analysis_results

            progress = st.progress(0)
            status_text = st.empty()
            total_ips = len(valid_ips)

            for idx, ip in enumerate(valid_ips):
                status_text.text(f"Analyzing IP {ip} ({idx + 1}/{total_ips})...")
                try:
                    domain = resolve_ip_to_domain(ip)
                    if not domain:
                        logger.warning(f"Could not resolve domain for IP {ip}")
                        continue

                    country = get_country_from_ip(ip)

                    analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result = analyze_domain_or_ip(domain, ip, packet_indicators)

                    threat_entry = {
                        "ip": ip,
                        "country": country,
                        "threat": prediction if isinstance(prediction, str) and "Error" not in prediction and prediction != "Safe" else "PCAP Entry",
                        "domain": domain,
                        "threat_score": f"{threat_score}/100",
                        "vt_result": vt_result,
                        "flaws": "; ".join(flaws_result) if flaws_result else "None"
                    }

                    if country != "Unknown" and threat_entry not in threat_locations:
                        threat_locations.append(threat_entry)

                    display_analysis_result(domain, analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result, analysis_result["ssl"], analysis_result["scan"])

                    for flaw in flaws_result:
                        flaw_key = flaw.lower()
                        if "xss" in flaw_key:
                            st.session_state.threat_counts["xss"] += 1
                            if country != "Unknown":
                                entry = threat_entry.copy()
                                entry["threat"] = "XSS"
                                if entry not in threat_locations:
                                    threat_locations.append(entry)
                        if "sqli" in flaw_key:
                            st.session_state.threat_counts["sqli"] += 1
                            if country != "Unknown":
                                entry = threat_entry.copy()
                                entry["threat"] = "SQLi"
                                if entry not in threat_locations:
                                    threat_locations.append(entry)

                    if packet_indicators.get("suspicious", False):
                        for suspicion in packet_indicators.get("payload_suspicion", []):
                            suspicion_lower = suspicion.lower()
                            if "malware" in suspicion_lower:
                                st.session_state.threat_counts["malware"] += 1
                                if country != "Unknown":
                                    entry = threat_entry.copy()
                                    entry["threat"] = "Malware"
                                    if entry not in threat_locations:
                                        threat_locations.append(entry)
                            elif "sqlmap" in suspicion_lower:
                                st.session_state.threat_counts["sqli"] += 1
                                if country != "Unknown":
                                    entry = threat_entry.copy()
                                    entry["threat"] = "SQLi"
                                    if entry not in threat_locations:
                                        threat_locations.append(entry)

                    if "threats detected" in vt_result.lower():
                        st.session_state.vt_alerts += 1
                        if country != "Unknown":
                            vt_entry = threat_entry.copy()
                            vt_entry["threat"] = "VirusTotal"
                            if vt_entry not in threat_locations:
                                threat_locations.append(vt_entry)

                    analysis_results.append(analysis_result)

                except Exception as e:
                    logger.error(f"Error processing IP {ip}: {str(e)}")
                    st.error(f"Error processing IP {ip}: {str(e)}")
                
                progress.progress((idx + 1) / total_ips)

            status_text.text("PCAP analysis complete!")

        except Exception as e:
            logger.error(f"Top-level PCAP processing error: {str(e)}")
            st.error(f"Failed to analyze PCAP: {str(e)}")

    st.session_state.threat_locations = threat_locations
    logger.debug(f"Threat locations after PCAP processing: {threat_locations}")
    return analysis_results

def capture_traffic(interface, duration, output_path):
    try:
        logger.info(f"Capturing traffic on {interface} for {duration} seconds, saving to {output_path}")
        packets = sniff(iface=interface, timeout=duration, filter="tcp or udp")
        wrpcap(output_path, packets)
        logger.info(f"Captured {len(packets)} packets, saved to {output_path}")
        return packets
    except PermissionError as e:
        logger.error(f"Permission error during capture: {str(e)}")
        st.error(f"Permission error: {str(e)}. Run Streamlit as administrator.")
        raise
    except Exception as e:
        logger.error(f"Traffic capture error: {str(e)}")
        st.error(f"Error capturing traffic: {str(e)}")
        raise

def process_live_capture(interface, duration):
    analysis_results = []
    threat_locations = st.session_state.get("threat_locations", [])
    
    with st.spinner("Capturing packets..."):
        try:
            pcap_path = os.path.join(log_dir, f"live_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
            packets = capture_traffic(interface, duration, pcap_path)
            network_analysis = capture_and_analyze_packets(duration=duration, interface=interface)
            if "error" in network_analysis:
                st.error(network_analysis["error"])
                logger.warning(f"Live capture failed: {network_analysis['error']}")
                return analysis_results

            st.subheader("Live Capture Analysis")
            if network_analysis["suspicious"]:
                st.warning("Suspicious activity detected during live capture:")
                for detail in network_analysis["details"]:
                    st.write(f"- {detail}")
            else:
                st.success("No suspicious activity detected during live capture.")

            packet_indicators, protocol_distribution, traffic_direction, packet_sizes, connection_states, top_talkers, port_usage = process_packet_data(network_analysis=network_analysis)
            display_packet_analysis(protocol_distribution, traffic_direction, packet_sizes, connection_states, top_talkers, port_usage)

            st.subheader("Live Capture Analysis")
            ips = [pkt[IP].src for pkt in packets if IP in pkt] + [pkt[IP].dst for pkt in packets if IP in pkt]
            unique_ips = list(dict.fromkeys(ips))[:5]
            st.write(f"Found {len(unique_ips)} unique IPs (analyzing first 5)")

            valid_ips = [ip for ip in unique_ips if is_public_ip(ip)]
            if not valid_ips:
                st.warning("No valid public IPs found in capture.")
                return analysis_results

            progress = st.progress(0)
            status_text = st.empty()
            total_ips = len(valid_ips)

            for idx, ip in enumerate(valid_ips):
                status_text.text(f"Analyzing IP {ip} ({idx + 1}/{total_ips})...")
                try:
                    domain = resolve_ip_to_domain(ip)
                    if not domain:
                        continue

                    country = get_country_from_ip(ip)

                    analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result = analyze_domain_or_ip(domain, ip, packet_indicators)

                    threat_entry = {
                        "ip": ip,
                        "country": country,
                        "threat": prediction if isinstance(prediction, str) and "Error" not in prediction and prediction != "Safe" else "Live Capture",
                        "domain": domain,
                        "threat_score": f"{threat_score}/100",
                        "vt_result": vt_result,
                        "flaws": "; ".join(flaws_result) if flaws_result else "None"
                    }

                    if country != "Unknown" and threat_entry not in threat_locations:
                        threat_locations.append(threat_entry)

                    display_analysis_result(domain, analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result, analysis_result["ssl"], analysis_result["scan"])

                    for flaw in flaws_result:
                        flaw_key = flaw.lower()
                        if "xss" in flaw_key:
                            st.session_state.threat_counts["xss"] += 1
                            if country != "Unknown":
                                entry = threat_entry.copy()
                                entry["threat"] = "XSS"
                                if entry not in threat_locations:
                                    threat_locations.append(entry)
                        if "sqli" in flaw_key:
                            st.session_state.threat_counts["sqli"] += 1
                            if country != "Unknown":
                                entry = threat_entry.copy()
                                entry["threat"] = "SQLi"
                                if entry not in threat_locations:
                                    threat_locations.append(entry)

                    if packet_indicators.get("suspicious", False):
                        for suspicion in packet_indicators.get("payload_suspicion", []):
                            suspicion_lower = suspicion.lower()
                            if "malware" in suspicion_lower:
                                st.session_state.threat_counts["malware"] += 1
                                if country != "Unknown":
                                    entry = threat_entry.copy()
                                    entry["threat"] = "Malware"
                                    if entry not in threat_locations:
                                        threat_locations.append(entry)
                            elif "sqlmap" in suspicion_lower:
                                st.session_state.threat_counts["sqli"] += 1
                                if country != "Unknown":
                                    entry = threat_entry.copy()
                                    entry["threat"] = "SQLi"
                                    if entry not in threat_locations:
                                        threat_locations.append(entry)

                    if "threats detected" in vt_result.lower():
                        st.session_state.vt_alerts += 1
                        if country != "Unknown":
                            vt_entry = threat_entry.copy()
                            vt_entry["threat"] = "VirusTotal"
                            if vt_entry not in threat_locations:
                                threat_locations.append(vt_entry)

                    analysis_results.append(analysis_result)

                except Exception as e:
                    logger.error(f"Analysis error for {ip}: {str(e)}")
                    st.error(f"Analysis error: {str(e)}")
                
                progress.progress((idx + 1) / total_ips)

            status_text.text("Live capture analysis complete!")

        except Exception as e:
            logger.error(f"Live capture processing error: {str(e)}")
            st.error(f"Error processing live capture: {str(e)}")

    st.session_state.threat_locations = threat_locations
    logger.debug(f"Threat locations after live capture: {threat_locations}")
    return analysis_results

def process_domain_analysis(domain):
    analysis_results = []
    threat_locations = st.session_state.get("threat_locations", [])

    if not domain:
        st.warning("Please enter a domain to analyze.")
        return analysis_results

    with st.spinner("Analyzing domain..."):
        try:
            ip = socket.gethostbyname(domain)
            if not is_public_ip(ip):
                st.warning(f"IP {ip} is not a valid public IP.")
                return analysis_results

            network_analysis = capture_and_analyze_packets(duration=10)
            if "error" in network_analysis:
                st.error(network_analysis["error"])
                logger.warning(f"Network analysis failed: {network_analysis['error']}")
                return analysis_results

            packet_indicators, protocol_distribution, traffic_direction, packet_sizes, connection_states, top_talkers, port_usage = process_packet_data(network_analysis=network_analysis)
            display_packet_analysis(protocol_distribution, traffic_direction, packet_sizes, connection_states, top_talkers, port_usage)

            country = get_country_from_ip(ip)

            analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result = analyze_domain_or_ip(domain, ip, packet_indicators)

            threat_entry = {
                "ip": ip,
                "country": country,
                "threat": prediction if isinstance(prediction, str) and "Error" not in prediction and prediction != "Safe" else "Analyzed",
                "domain": domain,
                "threat_score": f"{threat_score}/100",
                "vt_result": vt_result,
                "flaws": "; ".join(flaws_result) if flaws_result else "None"
            }
            if country != "Unknown" and threat_entry not in threat_locations:
                threat_locations.append(threat_entry)

            st.subheader(f"Domain Analysis for {domain}")
            display_analysis_result(domain, analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result, analysis_result["ssl"], analysis_result["scan"])

            for flaw in flaws_result:
                flaw_key = flaw.lower()
                if "xss" in flaw_key:
                    st.session_state.threat_counts["xss"] += 1
                    if country != "Unknown":
                        threat_locations.append({
                            "ip": ip,
                            "country": country,
                            "threat": "XSS",
                            "domain": domain,
                            "threat_score": f"{threat_score}/100",
                            "vt_result": vt_result,
                            "flaws": "; ".join(flaws_result)
                        })
                if "sqli" in flaw_key:
                    st.session_state.threat_counts["sqli"] += 1
                    if country != "Unknown":
                        threat_locations.append({
                            "ip": ip,
                            "country": country,
                            "threat": "SQLi",
                            "domain": domain,
                            "threat_score": f"{threat_score}/100",
                            "vt_result": vt_result,
                            "flaws": "; ".join(flaws_result)
                        })

            if prediction in ["Malware", "Suspicious"]:
                st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                if country != "Unknown":
                    threat_locations.append({
                        "ip": ip,
                        "country": country,
                        "threat": prediction,
                        "domain": domain,
                        "threat_score": f"{threat_score}/100",
                        "vt_result": vt_result,
                        "flaws": "; ".join(flaws_result)
                    })
            if packet_indicators.get("suspicious", False):
                for suspicion in packet_indicators.get("payload_suspicion", []):
                    suspicion_lower = suspicion.lower()
                    if "malware" in suspicion_lower:
                        st.session_state.threat_counts["malware"] += 1
                        if country != "Unknown":
                            threat_locations.append({
                                "ip": ip,
                                "country": country,
                                "threat": "Malware",
                                "domain": domain,
                                "threat_score": f"{threat_score}/100",
                                "vt_result": vt_result,
                                "flaws": "; ".join(flaws_result)
                            })
                    elif "sqlmap" in suspicion_lower:
                        st.session_state.threat_counts["sqli"] += 1
                        if country != "Unknown":
                            threat_locations.append({
                                "ip": ip,
                                "country": country,
                                "threat": "SQLi",
                                "domain": domain,
                                "threat_score": f"{threat_score}/100",
                                "vt_result": vt_result,
                                "flaws": "; ".join(flaws_result)
                            })

            if "threats detected" in vt_result.lower():
                st.session_state.vt_alerts += 1
                if country != "Unknown":
                    threat_locations.append({
                        "ip": ip,
                        "country": country,
                        "threat": "VirusTotal",
                        "domain": domain,
                        "threat_score": f"{threat_score}/100",
                        "vt_result": vt_result,
                        "flaws": "; ".join(flaws_result)
                    })

            analysis_results.append(analysis_result)

        except Exception as e:
            logger.error(f"Domain analysis error for {domain}: {str(e)}")
            st.error(f"Error analyzing {domain}: {str(e)}")

    st.session_state.threat_locations = threat_locations
    logger.debug(f"Threat locations after domain analysis: {threat_locations}")
    return analysis_results

def analyze_domain_for_map(domain):
    threat_locations = st.session_state.get("threat_locations", [])
    if not domain:
        logger.warning("No domain provided for map analysis")
        return threat_locations

    with st.spinner("Analyzing domain for map..."):
        try:
            ip = socket.gethostbyname(domain)
            if not is_public_ip(ip):
                st.warning(f"IP {ip} is not a valid public IP.")
                return threat_locations

            country = get_country_from_ip(ip)
            packet_indicators = {"suspicious": False, "details": []}

            analysis_result, prediction, probabilities, threat_score, vt_result, flaws_result, otx_result = analyze_domain_or_ip(domain, ip, packet_indicators)

            threat_entry = {
                "ip": ip,
                "country": country,
                "threat": prediction if isinstance(prediction, str) and "Error" not in prediction and prediction != "Safe" else "Analyzed",
                "domain": domain,
                "threat_score": f"{threat_score}/100",
                "vt_result": vt_result,
                "flaws": "; ".join(flaws_result) if flaws_result else "None"
            }
            if country != "Unknown" and threat_entry not in threat_locations:
                threat_locations.append(threat_entry)
                logger.info(f"Added threat entry for {domain}: {threat_entry}")

            if isinstance(prediction, str) and "Error" not in prediction and prediction != "Safe":
                st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                st.session_state.recent_threats.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score])

            for flaw in flaws_result:
                flaw_key = flaw.lower()
                if "xss" in flaw_key:
                    st.session_state.threat_counts["xss"] += 1
                    if country != "Unknown":
                        threat_locations.append({
                            "ip": ip,
                            "country": country,
                            "threat": "XSS",
                            "domain": domain,
                            "threat_score": f"{threat_score}/100",
                            "vt_result": vt_result,
                            "flaws": "; ".join(flaws_result)
                        })
                if "sqli" in flaw_key:
                    st.session_state.threat_counts["sqli"] += 1
                    if country != "Unknown":
                        threat_locations.append({
                            "ip": ip,
                            "country": country,
                            "threat": "SQLi",
                            "domain": domain,
                            "threat_score": f"{threat_score}/100",
                            "vt_result": vt_result,
                            "flaws": "; ".join(flaws_result)
                        })

            if "threats detected" in vt_result.lower():
                st.session_state.vt_alerts += 1
                if country != "Unknown":
                    threat_locations.append({
                        "ip": ip,
                        "country": country,
                        "threat": "VirusTotal",
                        "domain": domain,
                        "threat_score": f"{threat_score}/100",
                        "vt_result": vt_result,
                        "flaws": "; ".join(flaws_result)
                    })

        except Exception as e:
            logger.error(f"Domain analysis error for {domain} in map mode: {str(e)}")
            st.error(f"Error analyzing {domain} for map: {str(e)}")

    st.session_state.threat_locations = threat_locations
    logger.debug(f"Threat locations after map analysis: {threat_locations}")
    return threat_locations

def render_threat_map():
    m = folium.Map(location=[20, 0], zoom_start=1.5, tiles="CartoDB Dark_Matter", width=800, height=500)

    valid_markers = 0
    bounds = []
    heatmap_data = []
    country_summary = []
    threat_locations = st.session_state.get("threat_locations", [])
    logger.debug(f"Rendering threat map with {len(threat_locations)} threat locations")

    if not threat_locations:
        st.warning("No threat locations available. Analyze a domain to populate the map.")
        logger.warning("Threat locations list is empty")
    else:
        country_entries = {}
        for entry in threat_locations:
            country = entry.get("country")
            domain = entry.get("domain", "N/A")
            if domain == "N/A" or not country:
                logger.warning(f"Skipping entry due to missing domain or country: {entry}")
                continue
            if country != "Unknown":
                if country not in country_entries:
                    country_entries[country] = []
                country_entries[country].append(entry)
                lat, lon = geocode_country(country)
                bounds.append([lat, lon])
                try:
                    intensity = float(entry["threat_score"].split("/")[0]) / 100
                except (ValueError, AttributeError) as e:
                    logger.warning(f"Invalid threat score format for {domain}: {entry['threat_score']}, error: {str(e)}")
                    intensity = 0.1
                heatmap_data.append([lat, lon, intensity])
                valid_markers += 1
                logger.debug(f"Added marker for {domain} at ({lat}, {lon}) with intensity {intensity}")

        if heatmap_data:
            HeatMap(heatmap_data, radius=15, blur=10, max_zoom=1.5).add_to(m)
            logger.debug(f"Added {len(heatmap_data)} heatmap points")
        else:
            logger.warning("No heatmap data to display")

        for country, entries in country_entries.items():
            lat, lon = geocode_country(country)
            popup_content = f"Country: {country}<br>"
            total_score = 0
            for entry in entries:
                vt_summary = entry["vt_result"][:100] + "..." if len(entry["vt_result"]) > 100 else entry["vt_result"]
                flaws_summary = entry["flaws"][:100] + "..." if len(entry["flaws"]) > 100 else entry["flaws"]
                mitre = get_mitre_mapping(entry["threat"])
                try:
                    score = float(entry["threat_score"].split("/")[0])
                except (ValueError, AttributeError) as e:
                    logger.warning(f"Invalid threat score for {entry['domain']}: {entry['threat_score']}, error: {str(e)}")
                    score = 0
                total_score += score
                popup_content += (
                    f"Domain: {entry['domain']}<br>"
                    f"IP: {entry['ip']}<br>"
                    f"Threat: {entry['threat']}<br>"
                    f"MITRE ATT&CK: {mitre['technique']} - {mitre['name']} ({mitre['tactic']})<br>"
                    f"Score: {entry['threat_score']}/100<br>"
                    f"VirusTotal: {vt_summary}<br>"
                    f"Flaws: {flaws_summary}<br><br>"
                )

            folium.Marker(
                location=[lat, lon],
                popup=folium.Popup(popup_content, max_width=300, max_height=400),
                icon=folium.Icon(color="red" if any(e["threat"] != "Analyzed" for e in entries) else "green", icon="info-sign")
            ).add_to(m)
            logger.debug(f"Added marker for country {country} with {len(entries)} entries")

            if len(entries) >= 2:
                domains_summary = []
                for entry in entries:
                    mitre = get_mitre_mapping(entry["threat"])
                    domains_summary.append({
                        "Domain": entry["domain"],
                        "IP": entry["ip"],
                        "Threat": entry["threat"],
                        "MITRE ATT&CK": f"{mitre['technique']} - {mitre['name']} ({mitre['tactic']})",
                        "Threat Score": entry["threat_score"]
                    })
                country_summary.append({
                    "Country": country,
                    "Domain Count": len(entries),
                    "Total Threat Score": f"{total_score:.1f}",
                    "Details": domains_summary
                })

    if valid_markers > 1 and bounds:
        m.fit_bounds(bounds)
        logger.debug("Map bounds set successfully")
    else:
        m.location = [20, 0]
        m.zoom_start = 2
        logger.debug("Using default map location and zoom")

    with st.expander("Threat Statistics", expanded=True):
        threats = st.session_state.threat_counts
        if sum(threats.values()) == 0:
            st.write("No threat data available. Analyze domains to populate.")
        else:
            threats_df = pd.DataFrame(list(threats.items()), columns=["Threat Type", "Count"])
            fig = px.bar(threats_df, x="Count", y="Threat Type", orientation="h",
                         title="Threat Distribution",
                         color="Threat Type",
                         color_discrete_sequence=["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", "#FFEEAD"])
            fig.update_layout(xaxis_title="Count", yaxis_title="", showlegend=False)
            st.plotly_chart(fig, use_container_width=True, key="threat_distribution_chart")

        if country_summary:
            st.write("**Countries with Multiple Threats:**")
            for summary in country_summary:
                st.write(f"**{summary['Country']}** - {summary['Domain Count']} domains, Total Threat Score: {summary['Total Threat Score']}")
                details_df = pd.DataFrame(summary['Details'])
                st.table(details_df)

    try:
        st_folium(m, width=1800, height=600)
        st.write(f"Total markers plotted: {valid_markers}")
    except Exception as e:
        logger.error(f"Error rendering Folium map: {str(e)}")
        st.error(f"Failed to render threat map: {str(e)}")

def main():
    if "mode" not in st.session_state:
        st.session_state.mode = "Threat Map"
    if "threat_locations" not in st.session_state:
        st.session_state.threat_locations = []
    if "threat_counts" not in st.session_state:
        st.session_state.threat_counts = {"malware": 0, "xss": 0, "sqli": 0, "low risk": 0, "suspicious": 0}
    if "recent_threats" not in st.session_state:
        st.session_state.recent_threats = []
    if "vt_alerts" not in st.session_state:
        st.session_state.vt_alerts = 0
    if "analysis_results" not in st.session_state:
        st.session_state.analysis_results = []
    logger.debug("Session state initialized successfully.")

    st.title("NetSec AI:AI-Powered IDS with Cyber Attack Detection ")
    st.markdown("""
        <style>
/* Gradient Background */
.main {
  background: linear-gradient(135deg, #121417, #1f2a3a);
  color: #e0e8f0;
  padding: 16px;
  min-height: 100vh;
  font-family: 'Segoe UI', sans-serif;
}

/* Headings */
h1, h2, h3 {
  color: #00ffc8;
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-bottom: 10px;
}

/* Buttons */
.stButton>button {
  background: linear-gradient(90deg, #00ffc8, #3ddc97);
  color: #0e1117;
  border: none;
  padding: 10px 24px;
  border-radius: 10px;
  font-weight: bold;
  transition: all 0.3s ease-in-out;
  box-shadow: 0 0 10px #00ffc880;
}

.stButton>button:hover {
  background: linear-gradient(90deg, #3ddc97, #00ffc8);
  color: white;
  box-shadow: 0 0 20px #00ffc8aa;
}

/* Input Fields */
.stTextInput>div>div>input,
.stTextArea>div>div>textarea,
.stSelectbox>div>div>select {
  background-color: #1e2433;
  color: #e0e8f0;
  border: 1px solid #3ddc97;
  border-radius: 5px;
  padding: 10px;
}

/* Sliders */
.stSlider>div>div>div {
  background-color:black
  border:1px solid #3ddc97;
  border-radius: 5px;
  color: #e0e8f0;
}

/* Expanders and Containers */
.stExpander,
.chart-container {
  background: radial-gradient(circle, #2a3b4d 0%, #1e1e1e 100%);
  border: 1px solid #00ffc880;
  border-radius: 10px;
  padding: 14px;
  margin-top: 16px;
  box-shadow: 0 0 15px rgba(0,255,200,0.1);
}

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
  border-radius: 8px;
  overflow: hidden;
}

th {
  background-color: #1f2739;
  color: #00ffc8;
  padding: 12px;
  text-align: left;
}

td {
  background-color: #2a3b4d;
  color: #e0e8f0;
  padding: 12px;
  border-bottom: 1px solid #444;
}

/* Alert Sections */
.alert-success {
  background-color: #163d2d;
  color: #3ddc97;
  padding: 12px;
  border-radius: 6px;
  box-shadow: 0 0 10px #3ddc97aa;
}

.alert-warning {
  background-color: #3b2e1d;
  color: #ffd369;
  padding: 12px;
  border-radius: 6px;
  box-shadow: 0 0 10px #ffd369aa;
}

.alert-danger {
  background-color: #421c1c;
  color: #ff6b6b;
  padding: 12px;
  border-radius: 6px;
  box-shadow: 0 0 10px #ff6b6baa;
}

/* Transitions for smooth interactivity */
button, input, textarea, select {
  transition: all 0.3s ease;
}

</style>
    """, unsafe_allow_html=True)
    logger.debug("Title and CSS styles rendered successfully.")

    mode = st.sidebar.selectbox(
        "Select Mode",
        ["Threat Map", "Live Capture", "Upload PCAP", "Domain Analysis"],
        index=["Threat Map", "Live Capture", "Upload PCAP", "Domain Analysis"].index(st.session_state.mode)
    )
    st.session_state.mode = mode
    logger.debug(f"Mode set to: {mode}")

    st.sidebar.header("Threat Summary")
    st.sidebar.write(f"Total VirusTotal Alerts: {st.session_state.vt_alerts}")
    for threat, count in st.session_state.threat_counts.items():
        st.sidebar.write(f"{threat.capitalize()}: {count}")
    logger.debug("Sidebar rendered successfully.")

    if mode == "Upload PCAP":
        st.header("Upload PCAP")
        pcap_file = st.file_uploader("Upload PCAP file", type=["pcap", "pcapng"])
        if st.button("Analyze File"):
            if pcap_file is not None:
                st.session_state.analysis_results = process_uploaded_files(pcap_file)
                st.success("Analysis completed!")
            else:
                st.warning("Please upload a PCAP file to analyze.")

    elif mode == "Live Capture":
        st.header("Live Traffic Capture")
        interfaces = get_available_interfaces()
        interface = st.selectbox("Select Network Interface", interfaces)
        duration = st.slider("Capture Duration (seconds)", min_value=5, max_value=60, value=10)
        if st.button("Start Capture"):
            st.session_state.analysis_results = process_live_capture(interface, duration)
            st.success("Live capture analysis completed!")

    elif mode == "Domain Analysis":
        st.header("Domain Analysis")
        domain = st.text_input("Enter Domain (e.g., example.com)")
        if st.button("Analyze Domain"):
            st.session_state.analysis_results = process_domain_analysis(domain)
            if st.session_state.analysis_results:
                st.success("Domain analysis completed!")

    elif mode == "Threat Map":
        st.header("Threat Map")
        domain = st.text_input("Add Domain to Map (e.g., example.com)")
        if st.button("Add to Map"):
            st.session_state.threat_locations = analyze_domain_for_map(domain)
            st.success(f"Added {domain} to the threat map!")
        render_threat_map()

    with st.sidebar:
        st.header("Recent Threats")
        if st.session_state.recent_threats:
            threats_df = pd.DataFrame(st.session_state.recent_threats, columns=["Timestamp", "Domain", "Threat", "Score"])
            st.table(threats_df)
        else:
            st.write("No recent threats detected.")

        st.header("Logs")
        log_lines = read_last_n_lines(log_file, n=50)
        with st.expander("View Logs", expanded=False):
            st.text_area("Logs", "\n".join(log_lines), height=300)

if __name__ == "__main__":
    main()
