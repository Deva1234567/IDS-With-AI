import streamlit as st
import pandas as pd
import logging
import os
import sys
import time
from datetime import datetime
import folium
from folium.plugins import HeatMap
import json
import socket
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import ssl
import dns.resolver
import subprocess
from scapy.all import sniff, wrpcap, rdpcap, get_working_ifaces
from scapy.layers.inet import IP, TCP, UDP
from streamlit_folium import st_folium
from logging.handlers import RotatingFileHandler
import streamlit.components.v1 as components
import geoip2.database
import ipaddress
import matplotlib.pyplot as plt
import pytz
from dateutil.parser import parse

# Add project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)

# Setup logging
log_dir = os.path.join(r"C:\Users\devan\Desktop\Project\IDS project\logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "streamlit.log")
logger = logging.getLogger("app")
logger.setLevel(logging.DEBUG)
if not logger.handlers:  # Prevent duplicate handlers
    handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
logger.info("App started on VS Code in Windows with JDK 21")

# Import scripts with error handling
try:
    from scripts.utils import whois_lookup, nmap_scan, virustotal_lookup, check_flaws
    from scripts.predict import predict_threat
    from scripts.config import VIRUSTOTAL_API_KEY, GEOIP_API_URL, THREAT_INTEL_IPS, EMAIL_CONFIG
except ImportError as e:
    logger.error(f"Failed to import scripts module: {str(e)}")
    st.error(f"Failed to import scripts module: {str(e)}. Ensure 'scripts' directory exists with config.py, predict.py, and utils.py.")
    raise

# Set JAVA_HOME
os.environ["JAVA_HOME"] = r"C:\Program Files\Java\jdk-21"
JAVA_HOME = os.environ["JAVA_HOME"]

# Path to GeoLite2 database
GEOIP_DB_PATH = r"C:\Users\devan\Desktop\Project\IDS project\data\GeoLite2-Country.mmdb"

# MITRE ATT&CK Mapping
MITRE_ATTACK_MAPPING = {
    "DDoS": {"technique": "T1498", "tactic": "Impact", "name": "Network Denial of Service"},
    "XSS": {"technique": "T1189", "tactic": "Initial Access", "name": "Drive-by Compromise"},
    "SQLi": {"technique": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
    "Ransomware": {"technique": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"},
    "Malware": {"technique": "T1204", "tactic": "Execution", "name": "User Execution"},
    "Port Scan": {"technique": "T1046", "tactic": "Discovery", "name": "Network Service Scanning"},
    "VirusTotal": {"technique": "T1590", "tactic": "Reconnaissance", "name": "Gather Victim Network Information"}
}

# Fallback coordinates for countries
FALLBACK_COORDINATES = {
    "Afghanistan": (33.9391, 67.7100),
    "Albania": (41.1533, 20.1683),
    "Algeria": (28.0339, 1.6596),
    "Andorra": (42.5063, 1.5218),
    "Angola": (-11.2027, 17.8739),
    "Antigua and Barbuda": (17.0608, -61.7964),
    "Argentina": (-38.4161, -63.6167),
    "Armenia": (40.0691, 45.0382),
    "Australia": (-25.2744, 133.7751),
    "Austria": (47.5162, 14.5501),
    "Azerbaijan": (40.1431, 47.5769),
    "Bahamas": (25.0343, -77.3963),
    "Bahrain": (26.0667, 50.5577),
    "Bangladesh": (23.6850, 90.3563),
    "Barbados": (13.1939, -59.5432),
    "Belarus": (53.7098, 27.9534),
    "Belgium": (50.5039, 4.4699),
    "Belize": (17.1899, -88.4976),
    "Benin": (9.3077, 2.3158),
    "Bhutan": (27.5142, 90.4336),
    "Bolivia": (-16.2902, -63.5887),
    "Bosnia and Herzegovina": (43.9159, 17.6791),
    "Botswana": (-22.3285, 24.6849),
    "Brazil": (-14.2350, -51.9253),
    "Brunei": (4.5353, 114.7277),
    "Bulgaria": (42.7339, 25.4858),
    "Burkina Faso": (12.2383, -1.5616),
    "Burundi": (-3.3731, 29.9189),
    "Cabo Verde": (16.0021, -24.0132),
    "Cambodia": (12.5657, 104.9910),
    "Cameroon": (5.3690, 11.5137),
    "Canada": (56.1304, -106.3468),
    "Central African Republic": (6.6111, 20.9394),
    "Chad": (15.4542, 18.7322),
    "Chile": (-35.6751, -71.5430),
    "China": (35.8617, 104.1954),
    "Colombia": (4.5709, -74.2973),
    "Comoros": (-11.6455, 43.3333),
    "Congo (Congo-Brazzaville)": (-0.2280, 15.8277),
    "Costa Rica": (9.7489, -83.7534),
    "Croatia": (45.1000, 15.2000),
    "Cuba": (21.5218, -77.7812),
    "Cyprus": (35.1264, 33.4299),
    "Czechia": (49.8175, 15.4730),
    "Denmark": (56.2639, 9.5018),
    "Djibouti": (11.8251, 42.5903),
    "Dominica": (15.4150, -61.3710),
    "Dominican Republic": (18.7357, -70.1627),
    "Ecuador": (-1.8312, -78.1834),
    "Egypt": (26.8206, 30.8025),
    "El Salvador": (13.7942, -88.8965),
    "Equatorial Guinea": (1.6508, 10.2679),
    "Eritrea": (15.1794, 39.7823),
    "Estonia": (58.5953, 25.0136),
    "Eswatini": (-26.5225, 31.4659),
    "Ethiopia": (9.1450, 40.4897),
    "Fiji": (-17.7134, 178.0650),
    "Finland": (61.9241, 25.7482),
    "France": (46.2276, 2.2137),
    "Gabon": (-0.8037, 11.6094),
    "Gambia": (13.4432, -15.3101),
    "Georgia": (42.3154, 43.3569),
    "Germany": (51.1657, 10.4515),
    "Ghana": (7.9465, -1.0232),
    "Greece": (39.0742, 21.8243),
    "Grenada": (12.1165, -61.6790),
    "Guatemala": (15.7835, -90.2308),
    "Guinea": (9.9456, -9.6966),
    "Guinea-Bissau": (11.8037, -15.1804),
    "Guyana": (4.8604, -58.9302),
    "Haiti": (18.9712, -72.2852),
    "Honduras": (15.2000, -86.2419),
    "Hungary": (47.1625, 19.5033),
    "Iceland": (64.9631, -19.0208),
    "India": (20.5937, 78.9629),
    "Indonesia": (-0.7893, 113.9213),
    "Iran": (32.4279, 53.6880),
    "Iraq": (33.2232, 43.6793),
    "Ireland": (53.4129, -8.2439),
    "Israel": (31.0461, 34.8516),
    "Italy": (41.8719, 12.5674),
    "Ivory Coast": (7.5400, -5.5471),
    "Jamaica": (18.1096, -77.2975),
    "Japan": (36.2048, 138.2529),
    "Jordan": (30.5852, 36.2384),
    "Kazakhstan": (48.0196, 66.9237),
    "Kenya": (-0.0236, 37.9062),
    "Kiribati": (-3.3704, -168.7340),
    "Kuwait": (29.3117, 47.4818),
    "Kyrgyzstan": (41.2044, 74.7661),
    "Laos": (19.8563, 102.4955),
    "Latvia": (56.8796, 24.6032),
    "Lebanon": (33.8547, 35.8623),
    "Lesotho": (-29.6100, 28.2336),
    "Liberia": (6.4281, -9.4295),
    "Libya": (26.3351, 17.2283),
    "Liechtenstein": (47.1660, 9.5554),
    "Lithuania": (55.1694, 23.8813),
    "Luxembourg": (49.8153, 6.1296),
    "Madagascar": (-18.7669, 46.8691),
    "Malawi": (-13.2543, 34.3015),
    "Malaysia": (4.2105, 101.9758),
    "Maldives": (3.2028, 73.2207),
    "Mali": (17.5707, -3.9962),
    "Malta": (35.9375, 14.3754),
    "Marshall Islands": (7.1315, 171.1845),
    "Mauritania": (21.0079, -10.9408),
    "Mauritius": (-20.3484, 57.5522),
    "Mexico": (23.6345, -102.5528),
    "Micronesia": (7.4256, 150.5508),
    "Moldova": (47.4116, 28.3699),
    "Monaco": (43.7384, 7.4246),
    "Mongolia": (46.8625, 103.8467),
    "Montenegro": (42.7087, 19.3744),
    "Morocco": (31.7917, -7.0926),
    "Mozambique": (-18.6657, 35.5296),
    "Myanmar": (21.9162, 95.9560),
    "Namibia": (-22.9576, 18.4904),
    "Nauru": (-0.5228, 166.9315),
    "Nepal": (28.3949, 84.1240),
    "Netherlands": (52.3676, 4.9041),
    "New Zealand": (-40.9006, 174.8860),
    "Nicaragua": (12.8654, -85.2072),
    "Niger": (17.6078, 8.0817),
    "Nigeria": (9.0820, 8.6753),
    "North Korea": (40.3399, 127.5101),
    "North Macedonia": (41.6086, 21.7453),
    "Norway": (60.4720, 8.4689),
    "Oman": (21.4735, 55.9754),
    "Pakistan": (30.3753, 69.3451),
    "Palau": (7.5148, 134.5825),
    "Panama": (8.5379, -80.7821),
    "Papua New Guinea": (-6.3149, 143.9555),
    "Paraguay": (-23.4425, -58.4438),
    "Peru": (-9.1900, -75.0152),
    "Philippines": (12.8797, 121.7740),
    "Poland": (51.9194, 19.1451),
    "Portugal": (39.3999, -8.2245),
    "Qatar": (25.3548, 51.1839),
    "Romania": (45.9432, 24.9668),
    "Russia": (61.5240, 105.3188),
    "Rwanda": (-1.9403, 29.8739),
    "Saint Kitts and Nevis": (17.3578, -62.7830),
    "Saint Lucia": (13.9094, -60.9789),
    "Saint Vincent and the Grenadines": (13.2528, -61.1990),
    "Samoa": (-13.7590, -172.1046),
    "San Marino": (43.9424, 12.4578),
    "Sao Tome and Principe": (0.1864, 6.6131),
    "Saudi Arabia": (23.8859, 45.0792),
    "Senegal": (14.4974, -14.4524),
    "Serbia": (44.0165, 21.0059),
    "Seychelles": (-4.6796, 55.4920),
    "Sierra Leone": (8.4606, -11.7799),
    "Singapore": (1.3521, 103.8198),
    "Slovakia": (48.6690, 19.6990),
    "Slovenia": (46.1512, 14.9955),
    "Solomon Islands": (-9.6457, 160.1562),
    "Somalia": (5.1521, 46.1996),
    "South Africa": (-30.5595, 22.9375),
    "South Korea": (35.9078, 127.7669),
    "South Sudan": (6.8769, 31.3069),
    "Spain": (40.4637, -3.7492),
    "Sri Lanka": (7.8731, 80.7718),
    "Sudan": (12.8628, 30.2176),
    "Suriname": (3.9193, -56.0278),
    "Sweden": (60.1282, 18.6435),
    "Switzerland": (46.8182, 8.2275),
    "Syria": (34.8021, 38.9968),
    "Taiwan": (23.6978, 120.9605),
    "Tajikistan": (38.8610, 71.2761),
    "Tanzania": (-6.3690, 34.8888),
    "Thailand": (15.8700, 100.9925),
    "Timor-Leste": (-8.8742, 125.7275),
    "Togo": (8.6195, 0.8248),
    "Tonga": (-21.1780, -175.1982),
    "Trinidad and Tobago": (10.6918, -61.2225),
    "Tunisia": (33.8869, 9.5375),
    "Turkey": (38.9637, 35.2433),
    "Turkmenistan": (38.9697, 59.5563),
    "Tuvalu": (-7.1095, 177.6493),
    "Uganda": (1.3733, 32.2903),
    "Ukraine": (48.3794, 31.1656),
    "United Arab Emirates": (23.4241, 53.8478),
    "United Kingdom": (55.3781, -3.4360),
    "United States": (37.0902, -95.7129),
    "Uruguay": (-32.5228, -55.7658),
    "Uzbekistan": (41.3775, 64.5853),
    "Vanuatu": (-15.3767, 166.9592),
    "Vatican City": (41.9029, 12.4534),
    "Venezuela": (6.4238, -66.5897),
    "Vietnam": (14.0583, 108.2772),
    "Yemen": (15.5527, 48.5164),
    "Zambia": (-13.1339, 27.8493),
    "Zimbabwe": (-19.0154, 29.1549),
    "Unknown": (0, 0)
}

def get_mitre_mapping(threat):
    return MITRE_ATTACK_MAPPING.get(threat, {"technique": "N/A", "tactic": "N/A", "name": "Not Mapped"})

def check_java_version():
    try:
        result = subprocess.run(
            [f"{JAVA_HOME}\\bin\\java", "-version"],
            capture_output=True,
            text=True,
            check=True
        )
        if "21.0" in result.stderr:
            logger.info(f"Java JDK 21 detected at {JAVA_HOME}")
            return True
        else:
            logger.error("JDK 21 required, found different version")
            return False
    except Exception as e:
        logger.error(f"Java version check failed: {e}")
        return False

def check_dependencies():
    try:
        import streamlit_folium
        import folium
        import geoip2.database
        import matplotlib
        import pytz
        logger.info("streamlit_folium, folium, geoip2, matplotlib, and pytz imported successfully")
    except ImportError as e:
        logger.error(f"Dependency import error: {str(e)}")
        st.error(f"Missing dependencies: {str(e)}. Run 'pip install streamlit-folium folium geoip2 ipaddress matplotlib numpy pytz'.")
        st.stop()

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
                test_country = reader.country("8.8.8.8").country.name
                logger.debug(f"Database validation successful: Resolved 8.8.8.8 to {test_country}")
            except Exception as e:
                if "country method cannot be used" in str(e).lower():
                    error_msg = f"Invalid database at {GEOIP_DB_PATH}. Expected GeoLite2-Country.mmdb, but found GeoLite2-ASN.mmdb or another type. Replace with GeoLite2-Country.mmdb from MaxMind."
                    logger.error(error_msg)
                    st.error(error_msg)
                    return "Unknown"
                else:
                    error_msg = f"Database validation error at {GEOIP_DB_PATH}: {str(e)}"
                    logger.error(error_msg)
                    st.error(error_msg)
                    return "Unknown"
            try:
                response = reader.country(ip)
                country = response.country.name
                country = country if country else "Unknown"
                logger.info(f"Geolocation for {ip}: {country}")
                return country
            except geoip2.errors.AddressNotFoundError:
                logger.warning(f"IP {ip} not found in GeoIP2 database")
                return "Unknown"
    except geoip2.errors.GeoIP2Error as e:
        logger.error(f"GeoIP2 error for {ip}: {str(e)}")
        st.error(f"GeoIP2 error: {str(e)}. Verify {GEOIP_DB_PATH} is a valid GeoLite2-Country.mmdb file.")
        return "Unknown"
    except Exception as e:
        logger.error(f"Unexpected geolocation error for {ip}: {str(e)}")
        st.error(f"Unexpected geolocation error: {str(e)}. Check database file and permissions.")
        return "Unknown"

def resolve_ip_to_domain(ip):
    try:
        domain, _, _ = socket.gethostbyaddr(ip)
        logger.debug(f"Resolved IP {ip} to domain {domain}")
        return domain
    except socket.herror:
        logger.warning(f"Could not resolve IP {ip} to domain")
        return None

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert.get("notAfter")
                expiry_date = parse(expiry_str)
                if expiry_date.tzinfo is not None:
                    current_time = datetime.now(tz=pytz.UTC)
                else:
                    current_time = datetime.now()
                is_expired = expiry_date < current_time
                hostname_matches = False
                cert_hostnames = []
                for field in cert.get("subject", []):
                    if field[0][0] == "commonName":
                        cert_hostnames.append(field[0][1])
                for extension in cert.get("subjectAltName", []):
                    if extension[0] == "DNS":
                        cert_hostnames.append(extension[1])
                for cert_hostname in cert_hostnames:
                    if cert_hostname.startswith("*."):
                        cert_domain = cert_hostname[2:]
                        if domain == cert_domain or domain.endswith("." + cert_domain):
                            hostname_matches = True
                            break
                    elif cert_hostname == domain:
                        hostname_matches = True
                        break
                result = {
                    "issuer": cert.get("issuer"),
                    "subject": cert.get("subject"),
                    "expiry": expiry_str,
                    "valid": hostname_matches and not is_expired,
                    "expired": is_expired,
                    "hostname_match": hostname_matches,
                    "cert_hostnames": cert_hostnames
                }
                if not hostname_matches:
                    logger.warning(f"Hostname mismatch for {domain}: certificate valid for {cert_hostnames}")
                    result["error"] = f"Hostname mismatch: certificate valid for {cert_hostnames}"
                logger.debug(f"SSL check result for {domain}: {result}")
                return result
    except Exception as e:
        logger.error(f"SSL check error for {domain}: {str(e)}")
        return {"error": str(e), "valid": False, "expired": False, "hostname_match": False}

def dns_analysis(domain):
    results = {}
    try:
        for record_type in ['MX', 'TXT', 'SPF', 'DMARC']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(r) for r in answers]
            except:
                results[record_type] = []
        return results
    except Exception as e:
        logger.error(f"DNS analysis error for {domain}: {str(e)}")
        return {"error": str(e)}

def subdomain_enumeration(domain):
    try:
        common_subdomains = ['www', 'mail', 'ftp', 'api', 'dev', 'test']
        subdomains = []
        for sub in common_subdomains:
            try:
                socket.gethostbyname(f"{sub}.{domain}")
                subdomains.append(f"{sub}.{domain}")
            except:
                pass
        return subdomains
    except Exception as e:
        logger.error(f"Subdomain enumeration error for {domain}: {str(e)}")
        return []

def calculate_threat_score(prediction, vt_result, flaws, ssl_result, scan_result, packet_indicators):
    score = 0
    if isinstance(prediction, str) and prediction != "Safe" and "Error" not in prediction:
        score += 30
    elif "Error" in str(prediction):
        score += 5
    if isinstance(vt_result, str) and "threats detected" in vt_result.lower():
        score += 20
    if isinstance(flaws, list) and flaws and "No major flaws detected" not in flaws:
        score += 20
    if isinstance(ssl_result, dict) and (not ssl_result.get("valid", True) or ssl_result.get("expired", False)):
        score += 15
    if isinstance(scan_result, dict) and scan_result.get("ports"):
        suspicious_ports = [port["port"] for port in scan_result["ports"] if port["port"] in [4444, 6667, 31337]]
        if suspicious_ports:
            score += 15
    if isinstance(packet_indicators, dict) and packet_indicators.get("suspicious", False):
        score += 15
    return min(score, 100)

def read_last_n_lines(file_path, n=50):
    try:
        with open(file_path, "r", encoding="latin-1") as f:
            lines = f.readlines()
            return lines[-n:] if lines else ["No logs available"]
    except FileNotFoundError:
        logger.error(f"Log file not found: {file_path}")
        return ["Log file not found"]
    except Exception as e:
        logger.error(f"Error reading log file {file_path}: {str(e)}")
        return [f"Error reading log file: {str(e)}"]

def analyze_packets(packets):
    indicators = {"suspicious": False, "details": []}
    try:
        ip_counts = {}
        for pkt in packets:
            if IP in pkt:
                dst_ip = pkt[IP].dst
                if is_public_ip(dst_ip):
                    ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
        for ip, count in ip_counts.items():
            if count > 50:
                indicators["suspicious"] = True
                indicators["details"].append(f"High outbound traffic to {ip}: {count} packets")

        suspicious_ports = {4444, 6667, 31337}
        for pkt in packets:
            if TCP in pkt or UDP in pkt:
                port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                if port in suspicious_ports:
                    indicators["suspicious"] = True
                    indicators["details"].append(f"Connection to suspicious port {port}")

        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                if src_ip in THREAT_INTEL_IPS or dst_ip in THREAT_INTEL_IPS:
                    indicators["suspicious"] = True
                    indicators["details"].append(f"Connection to known malicious IP: {src_ip if src_ip in THREAT_INTEL_IPS else dst_ip}")

        return indicators
    except Exception as e:
        logger.error(f"Packet analysis error: {str(e)}")
        return {"suspicious": False, "details": [f"Error: {str(e)}"]}

def process_uploaded_files(pcap_file, csv_file):
    analysis_results = []
    threat_locations = st.session_state.get("threat_locations", [])

    if pcap_file is None:
        return analysis_results

    try:
        pcap_path = os.path.join(log_dir, f"uploaded_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
        with open(pcap_path, "wb") as f:
            f.write(pcap_file.read())
        logger.info(f"Saved uploaded PCAP to {pcap_path}")

        packets = rdpcap(pcap_path)
        packet_indicators = analyze_packets(packets)
        if packet_indicators["suspicious"]:
            st.warning(f"Packet Analysis Warning: {'; '.join(packet_indicators['details'])}")

        ips = [pkt[IP].src for pkt in packets if IP in pkt] + [pkt[IP].dst for pkt in packets if IP in pkt]
        unique_ips = list(dict.fromkeys(ips))[:5]

        st.subheader("PCAP File Analysis")
        st.write(f"Found {len(unique_ips)} unique IPs (analyzing first 5)")

        valid_ips = [ip for ip in unique_ips if is_public_ip(ip)]
        if not valid_ips:
            st.warning("No valid public IPs found in PCAP. Map will not update. Ensure PCAP contains traffic to public servers.")
            logger.warning("No valid public IPs found in PCAP")
            return analysis_results

        for ip in unique_ips:
            if not is_public_ip(ip):
                logger.debug(f"Skipping invalid or non-public IP: {ip}")
                continue

            try:
                logger.debug(f"Processing IP: {ip}")
                domain = resolve_ip_to_domain(ip)
                # Skip if domain cannot be resolved
                if not domain:
                    logger.debug(f"Skipping IP {ip}: Could not resolve to a domain")
                    continue

                country = get_country_from_ip(ip)
                analysis_result = {"domain": domain, "ip": ip}

                ssl_result = check_ssl_certificate(domain)
                scan_result = nmap_scan(ip)

                try:
                    prediction = predict_threat(domain, packet_indicators=packet_indicators, ssl_result=ssl_result, scan_result=scan_result)
                    logger.info(f"Prediction for {domain}: {prediction}")
                except Exception as e:
                    prediction = f"Prediction Error: {str(e)}"
                    logger.error(f"Prediction error for {domain}: {str(e)}")

                vt_result = virustotal_lookup(domain)
                flaws_result = check_flaws(domain)
                threat_score = calculate_threat_score(prediction, vt_result, flaws_result, ssl_result, scan_result, packet_indicators)

                analysis_result.update({
                    "prediction": prediction,
                    "threat_score": threat_score,
                    "virustotal": vt_result,
                    "security_audit": flaws_result,
                    "ssl": ssl_result,
                    "nmap": scan_result
                })

                base_entry = {
                    "ip": ip,
                    "country": country,
                    "threat": prediction if isinstance(prediction, str) and "Error" not in prediction and prediction != "Safe" else "PCAP Entry",
                    "domain": domain,
                    "threat_score": f"{threat_score}/100",
                    "vt_result": vt_result,
                    "flaws": "; ".join(flaws_result) if flaws_result else "None"
                }

                if country != "Unknown" and base_entry not in threat_locations:
                    threat_locations.append(base_entry)
                    logger.info(f"Added threat entry for {country}: {base_entry}")

                if isinstance(prediction, str) and "Error" not in prediction:
                    if prediction == "Safe":
                        st.success(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="✅")
                    elif prediction == "Malware":
                        st.error(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")
                        st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                        st.session_state.recent_threats.append([
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score
                        ])
                    else:
                        st.warning(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")
                        st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                        st.session_state.recent_threats.append([
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score
                        ])
                else:
                    st.warning(f"Prediction failed: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")

                for flaw in flaws_result:
                    flaw_key = flaw.lower()
                    if any(k in flaw_key for k in ["xss", "sqli"]):
                        flaw_type = "XSS" if "xss" in flaw_key else "SQLi"
                        st.session_state.threat_counts[flaw_type.lower()] += 1
                        if country != "Unknown":
                            entry = base_entry.copy()
                            entry["threat"] = flaw_type
                            if entry not in threat_locations:
                                threat_locations.append(entry)

                if "threats detected" in vt_result.lower():
                    st.session_state.vt_alerts += 1
                    if country != "Unknown":
                        vt_entry = base_entry.copy()
                        vt_entry["threat"] = "VirusTotal"
                        if vt_entry not in threat_locations:
                            threat_locations.append(vt_entry)

                with st.expander(f"WHOIS Lookup for {domain}"):
                    try:
                        whois_result = whois_lookup(domain)
                        if 'error' not in whois_result:
                            whois_data = [[k, ', '.join(v) if isinstance(v, list) else str(v)] for k, v in whois_result.items()]
                            st.table(pd.DataFrame(whois_data, columns=['Field', 'Value']))
                            analysis_result["whois"] = whois_data
                        else:
                            st.error(whois_result['error'])
                            analysis_result["whois"] = [("Error", whois_result['error'])]
                    except Exception as e:
                        st.error(f"WHOIS error: {str(e)}")
                        analysis_result["whois"] = [("Error", str(e))]

                with st.expander(f"Network Scan for {domain}"):
                    if 'error' not in scan_result:
                        ports = scan_result.get('ports', [])
                        if isinstance(ports, list) and all(isinstance(p, dict) for p in ports):
                            ports_df = pd.DataFrame(ports)
                            if not ports_df.empty:
                                st.table(ports_df[['port', 'state']])
                                analysis_result["nmap"] = ports_df[['port', 'state']].to_dict()
                            else:
                                st.warning("No open ports found")
                                analysis_result["nmap"] = [("Warning", "No open ports found")]
                        else:
                            st.warning("Invalid port data format")
                            analysis_result["nmap"] = [("Warning", "Invalid port data")]
                    else:
                        st.error(scan_result['error'])
                        analysis_result["nmap"] = [("Error", scan_result['error'])]

                with st.expander(f"SSL/TLS Certificate for {domain}"):
                    if ssl_result.get("valid"):
                        st.write(f"Issuer: {ssl_result['issuer']}\nSubject: {ssl_result['subject']}\nExpiry: {ssl_result['expiry']}")
                        if ssl_result.get("expired"):
                            st.warning("Certificate has expired!")
                        if not ssl_result.get("hostname_match"):
                            st.warning(f"Hostname mismatch: Certificate is valid for {ssl_result['cert_hostnames']}")
                    else:
                        st.error(f"SSL error: {ssl_result.get('error')}")
                        analysis_result["ssl"] = [("Error", ssl_result.get('error'))]

                with st.expander(f"DNS Analysis for {domain}"):
                    dns_result = dns_analysis(domain)
                    if "error" not in dns_result:
                        st.write(f"MX: {dns_result.get('MX', [])}\nTXT: {dns_result.get('TXT', [])}")
                        analysis_result["dns"] = dns_result
                    else:
                        st.error(f"DNS error: {dns_result['error']}")
                        analysis_result["dns"] = [("Error", dns_result['error'])]

                with st.expander(f"Subdomains for {domain}"):
                    subdomains = subdomain_enumeration(domain)
                    if subdomains:
                        st.write(", ".join(subdomains))
                        analysis_result["subdomains"] = subdomains
                    else:
                        st.write("No subdomains found")
                        analysis_result["subdomains"] = [("Warning", "No subdomains found")]

                analysis_results.append(analysis_result)

            except Exception as e:
                logger.error(f"Error processing IP {ip}: {str(e)}")
                st.error(f"Error processing IP {ip}: {str(e)}")

        st.success(f"Processed PCAP file with {len(valid_ips)} valid entries")

    except Exception as e:
        logger.error(f"Top-level PCAP processing error: {str(e)}")
        st.error(f"Failed to analyze PCAP: {str(e)}")

    st.session_state.threat_locations = threat_locations
    return analysis_results

def capture_traffic(interface, duration, output_path):
    try:
        logger.info(f"Capturing traffic on {interface} for {duration} seconds, saving to {output_path}")
        packets = sniff(iface=interface, timeout=duration)
        wrpcap(output_path, packets)
        logger.info(f"Captured {len(packets)} packets, saved to {output_path}")
        return True
    except PermissionError as e:
        logger.error(f"Permission error during capture: {str(e)}")
        st.error(f"Permission error: {str(e)}. Run as administrator.")
        raise
    except Exception as e:
        logger.error(f"Traffic capture error: {str(e)}")
        st.error(f"Error capturing traffic: {str(e)}")
        raise

def process_live_capture(pcap_path):
    analysis_results = []
    threat_locations = st.session_state.threat_locations

    try:
        packets = rdpcap(pcap_path)
        packet_indicators = analyze_packets(packets)
        if packet_indicators["suspicious"]:
            st.warning(f"Packet Analysis Warning: {'; '.join(packet_indicators['details'])}")

        ips = [pkt[IP].src for pkt in packets if IP in pkt] + [pkt[IP].dst for pkt in packets if IP in pkt]
        unique_ips = list(dict.fromkeys(ips))[:5]
        st.subheader("Live Capture Analysis")
        st.write(f"Found {len(unique_ips)} unique IPs (analyzing first 5)")

        valid_ips = [ip for ip in unique_ips if is_public_ip(ip)]
        if not valid_ips:
            st.warning("No valid public IPs found in capture. Ensure traffic includes public servers.")
            logger.warning("No valid public IPs found in capture")
            return analysis_results

        for ip in unique_ips:
            if not is_public_ip(ip):
                logger.debug(f"Skipping invalid or non-public IP: {ip}")
                continue

            try:
                logger.debug(f"Processing IP: {ip}")
                domain = resolve_ip_to_domain(ip)
                # Skip if domain cannot be resolved
                if not domain:
                    logger.debug(f"Skipping IP {ip}: Could not resolve to a domain")
                    continue

                country = get_country_from_ip(ip)
                analysis_result = {"domain": domain, "ip": ip}

                ssl_result = check_ssl_certificate(domain)
                scan_result = nmap_scan(ip)
                try:
                    prediction = predict_threat(domain, packet_indicators=packet_indicators, ssl_result=ssl_result, scan_result=scan_result)
                    logger.info(f"Prediction for {domain}: {prediction}")
                except Exception as e:
                    prediction = f"Prediction Error: {str(e)}"
                    logger.error(f"Prediction error for {domain}: {str(e)}")

                vt_result = virustotal_lookup(domain)
                flaws_result = check_flaws(domain)
                threat_score = calculate_threat_score(prediction, vt_result, flaws_result, ssl_result, scan_result, packet_indicators)

                analysis_result["prediction"] = prediction
                analysis_result["threat_score"] = threat_score
                analysis_result["virustotal"] = vt_result
                analysis_result["security_audit"] = flaws_result
                analysis_result["ssl"] = ssl_result
                analysis_result["nmap"] = scan_result

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
                    logger.info(f"Added threat entry for {country}: {threat_entry}")

                if isinstance(prediction, str) and "Error" not in prediction:
                    if prediction == "Safe":
                        st.success(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="✅")
                    elif prediction == "Malware":
                        st.error(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")
                        st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                        st.session_state.recent_threats.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score])
                    else:
                        st.warning(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")
                        st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                        st.session_state.recent_threats.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score])
                else:
                    st.warning(f"Prediction failed: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")

                for flaw in flaws_result:
                    if "XSS" in flaw:
                        st.session_state.threat_counts['xss'] += 1
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
                    if "SQLi" in flaw:
                        st.session_state.threat_counts['sqli'] += 1
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

                with st.expander(f"WHOIS Lookup for {domain}"):
                    try:
                        whois_result = whois_lookup(domain)
                        if 'error' not in whois_result:
                            whois_data = [[k, ', '.join(v) if isinstance(v, list) else str(v)] for k, v in whois_result.items()]
                            st.table(pd.DataFrame(whois_data, columns=['Field', 'Value']))
                            analysis_result["whois"] = whois_data
                        else:
                            st.error(whois_result['error'])
                            analysis_result["whois"] = [("Error", whois_result['error'])]
                    except Exception as e:
                        st.error(f"WHOIS error: {str(e)}")
                        analysis_result["whois"] = [("Error", str(e))]

                with st.expander(f"Network Scan for {domain}"):
                    if 'error' not in scan_result:
                        ports = scan_result.get('ports', [])
                        if isinstance(ports, list) and all(isinstance(p, dict) and 'port' in p and 'state' in p for p in ports):
                            ports_df = pd.DataFrame(ports)
                            if not ports_df.empty:
                                st.table(ports_df[['port', 'state']])
                                analysis_result["nmap"] = ports_df[['port', 'state']].to_dict()
                            else:
                                st.warning("No open ports found")
                                analysis_result["nmap"] = [("Warning", "No open ports found")]
                        else:
                            st.warning("Invalid port data format from nmap_scan")
                            analysis_result["nmap"] = [("Warning", "Invalid port data")]
                    else:
                        st.error(scan_result['error'])
                        analysis_result["nmap"] = [("Error", scan_result['error'])]

                with st.expander(f"SSL/TLS Certificate for {domain}"):
                    if ssl_result.get("valid"):
                        st.write(f"Issuer: {ssl_result['issuer']}\nSubject: {ssl_result['subject']}\nExpiry: {ssl_result['expiry']}")
                        if ssl_result.get("expired"):
                            st.warning("Certificate has expired!")
                        if not ssl_result.get("hostname_match"):
                            st.warning(f"Hostname mismatch: Certificate is valid for {ssl_result['cert_hostnames']}")
                    else:
                        st.error(f"SSL error: {ssl_result.get('error')}")
                        analysis_result["ssl"] = [("Error", ssl_result.get('error'))]

                with st.expander(f"DNS Analysis for {domain}"):
                    dns_result = dns_analysis(domain)
                    if "error" not in dns_result:
                        st.write(f"MX: {dns_result.get('MX', [])}\nTXT: {dns_result.get('TXT', [])}")
                        analysis_result["dns"] = dns_result
                    else:
                        st.error(f"DNS error: {dns_result['error']}")
                        analysis_result["dns"] = [("Error", dns_result['error'])]

                with st.expander(f"Subdomains for {domain}"):
                    subdomains = subdomain_enumeration(domain)
                    if subdomains:
                        st.write(", ".join(subdomains))
                        analysis_result["subdomains"] = subdomains
                    else:
                        st.write("No subdomains found")
                        analysis_result["subdomains"] = [("Warning", "No subdomains found")]

                analysis_results.append(analysis_result)

            except Exception as e:
                logger.error(f"Analysis error for {ip}: {str(e)}")
                st.error(f"Analysis error: {str(e)}")
                analysis_result["prediction"] = f"Error: {str(e)}"

    except Exception as e:
        logger.error(f"Live capture processing error: {str(e)}")
        st.error(f"Error processing live capture: {str(e)}")

    st.session_state.threat_locations = threat_locations
    return analysis_results

def analyze_domain_for_map(domain):
    threat_locations = st.session_state.threat_locations
    if domain:
        try:
            ip = socket.gethostbyname(domain)
            logger.debug(f"Resolved domain {domain} to IP: {ip}")
            if not is_public_ip(ip):
                logger.debug(f"Skipping invalid or non-public IP: {ip}")
                st.warning(f"IP {ip} is not a valid public IP. Skipping analysis.")
                return threat_locations

            country = get_country_from_ip(ip)
            ssl_result = check_ssl_certificate(domain)
            scan_result = nmap_scan(ip)
            packet_indicators = {"suspicious": False, "details": []}
            try:
                prediction = predict_threat(domain, packet_indicators=packet_indicators, ssl_result=ssl_result, scan_result=scan_result)
                logger.info(f"Prediction for {domain}: {prediction}")
            except Exception as e:
                prediction = f"Prediction Error: {str(e)}"
                logger.error(f"Prediction error for {domain}: {str(e)}")

            vt_result = virustotal_lookup(domain)
            flaws_result = check_flaws(domain)
            threat_score = calculate_threat_score(prediction, vt_result, flaws_result, ssl_result, scan_result, packet_indicators)
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
                logger.info(f"Added threat entry for {country}: {threat_entry}")

            if isinstance(prediction, str) and "Error" not in prediction and prediction != "Safe":
                st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                st.session_state.recent_threats.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score])
            elif "Error" in str(prediction):
                st.warning(f"Prediction failed for {domain}: {prediction} (Threat Score: {threat_score}/100)")

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
            for flaw in flaws_result:
                if "XSS" in flaw:
                    st.session_state.threat_counts['xss'] += 1
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
                if "SQLi" in flaw:
                    st.session_state.threat_counts['sqli'] += 1
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

        except Exception as e:
            logger.error(f"Domain analysis error for {domain}: {str(e)}")
            st.error(f"Error analyzing {domain}: {str(e)}")
    st.session_state.threat_locations = threat_locations
    return threat_locations

def geocode_country(country):
    country = country.strip()
    coords = FALLBACK_COORDINATES.get(country, FALLBACK_COORDINATES["Unknown"])
    logger.debug(f"Geocoded {country} to {coords}")
    return coords

def get_available_interfaces():
    try:
        interfaces = get_working_ifaces()
        return [iface.name for iface in interfaces] if interfaces else ["Wi-Fi"]
    except Exception as e:
        logger.error(f"Error fetching interfaces: {str(e)}")
        return ["Wi-Fi"]

def render_threat_map():
    m = folium.Map(location=[0, 0], zoom_start=1, tiles="CartoDB Dark_Matter", width=700, height=600)

    valid_markers = 0
    bounds = []
    heatmap_data = []
    country_summary = []
    if st.session_state.threat_locations:
        country_entries = {}
        for entry in st.session_state.threat_locations:
            country = entry["country"]
            domain = entry.get("domain", "N/A")
            # Skip entries where domain is "N/A"
            if domain == "N/A":
                logger.debug(f"Skipping entry for {country}: Domain is 'N/A'")
                continue
            if country != "Unknown":
                if country not in country_entries:
                    country_entries[country] = []
                country_entries[country].append(entry)
                lat, lon = geocode_country(country)
                bounds.append([lat, lon])
                try:
                    intensity = float(entry["threat_score"].split("/")[0]) / 100
                except (ValueError, AttributeError):
                    intensity = 0.1
                heatmap_data.append([lat, lon, intensity])
                valid_markers += 1
                logger.debug(f"Processing entry for {country} at ({lat}, {lon})")

        if heatmap_data:
            HeatMap(heatmap_data, radius=15, blur=10, max_zoom=1).add_to(m)
            logger.debug("Added heatmap layer to map")

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
                except (ValueError, AttributeError):
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
            logger.debug(f"Added marker for {country} with {len(entries)} entries")

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
    else:
        m.location = [20, 0]
        m.zoom_start = 1
        logger.info("Using default zoom level 1 due to single or no markers")

    with st.expander("Threat Statistics", expanded=True):
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        fig, ax = plt.subplots(figsize=(10, 5))
        threats = st.session_state.threat_counts
        if sum(threats.values()) == 0:
            st.write("No threat data available. Analyze domains to populate. Check `predict_threat()` in scripts/predict.py to ensure it returns non-'Safe' predictions.")
            logger.warning("Threat counts are zero. Verify predict_threat() logic.")
        else:
            colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEEAD', '#D4A5A5']
            bars = ax.bar(threats.keys(), threats.values(), color=colors[:len(threats)], edgecolor='#e0e8f0', linewidth=1.5)
            for bar in bars:
                yval = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, yval + 0.1, int(yval), ha='center', va='bottom', fontsize=10, color='#e0e8f0')
            ax.set_title("Threat Distribution", fontsize=14, pad=15, color='#e0e8f0')
            ax.set_ylabel("Count", fontsize=12, color='#e0e8f0')
            ax.set_xlabel("Threat Types", fontsize=12, color='#e0e8f0')
            ax.grid(True, linestyle='--', alpha=0.7, color='#444')
            plt.xticks(rotation=45, ha='right', fontsize=10, color='#e0e8f0')
            plt.yticks(fontsize=10, color='#e0e8f0')
            ax.set_facecolor('#2a3b4d')
            fig.patch.set_facecolor('#2a3b4d')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.spines['left'].set_color('#e0e8f0')
            ax.spines['bottom'].set_color('#e0e8f0')
            st.pyplot(fig)
        st.markdown('</div>', unsafe_allow_html=True)

    if country_summary:
        with st.expander("Countries with Multiple Domains", expanded=True):
            for summary in country_summary:
                st.subheader(f"{summary['Country']} ({summary['Domain Count']} Domains)")
                st.write(f"**Total Threat Score:** {summary['Total Threat Score']}")
                df = pd.DataFrame(summary["Details"])
                st.table(df)

    with st.expander("Debug: Threat Locations"):
        if st.session_state.threat_locations:
            st.write(pd.DataFrame(st.session_state.threat_locations))
        else:
            st.write("No threat locations recorded. Analyze a domain to populate.")

    st_folium(m, width=700, height=600, returned_objects=[])
    st.caption(f"Displaying {valid_markers} markers with heatmap")

# Custom CSS
st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #1a2a3b 0%, #2a3b4d 100%);
        color: #e0e8f0;
        font-family: 'Courier New', monospace;
    }
    .stButton>button {
        background-color: #4da8da;
        color: #e0e8f0;
        border: 2px solid #4da8da;
        border-radius: 8px;
        padding: 10px 20px;
        width: 100%;
    }
    .stButton>button:hover {
        background-color: #b85450;
        border-color: #b85450;
    }
    .active-tab>button {
        background-color: #b85450;
        border-color: #b85450;
    }
    .folium-map {
        width: 100%;
        height: 600px;
        background-color: #1a1a1a;
        z-index: 1000 !important;
        margin-top: 0 !important;
        padding-top: 0 !important;
    }
    .chart-container {
        background-color: #2a3b4d;
        padding: 10px;
        border-radius: 8px;
        margin-top: 10px;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'threat_counts' not in st.session_state:
    st.session_state.threat_counts = {'ddos': 0, 'port_scan': 0, 'xss': 0, 'sqli': 0, 'ransomware': 0, 'malware': 0}
if 'vt_alerts' not in st.session_state:
    st.session_state.vt_alerts = 0
if 'threat_locations' not in st.session_state:
    st.session_state.threat_locations = []
if 'mode' not in st.session_state:
    st.session_state.mode = "Domain Analysis"
if 'recent_threats' not in st.session_state:
    st.session_state.recent_threats = []
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = []

# Check dependencies
check_dependencies()

# Sidebar for file uploads
with st.sidebar:
    st.subheader("File Uploads")
    pcap_file = st.file_uploader("Upload PCAP file", type="pcap")
    if st.button("Analyze Files"):
        if pcap_file:
            with st.spinner("Processing uploaded files..."):
                if not check_java_version():
                    st.error(f"Java JDK 21 required at {JAVA_HOME}. Please install or configure correctly.")
                    st.stop()
                process_uploaded_files(pcap_file, None)

# Header
st.markdown('<h1 style="color: #4da8da;">CYBERSECURITY DASHBOARD</h1>', unsafe_allow_html=True)

# Navigation
col1, col2, col3 = st.columns(3)
with col1:
    if st.session_state.mode == "Domain Analysis":
        st.markdown('<div class="active-tab">', unsafe_allow_html=True)
    if st.button("Domain Analysis"):
        st.session_state.mode = "Domain Analysis"
        st.session_state.analysis_results = []
        st.rerun()
    if st.session_state.mode == "Domain Analysis":
        st.markdown('</div>', unsafe_allow_html=True)
with col2:
    if st.session_state.mode == "Live Capture":
        st.markdown('<div class="active-tab">', unsafe_allow_html=True)
    if st.button("Live Capture"):
        st.session_state.mode = "Live Capture"
        st.rerun()
    if st.session_state.mode == "Live Capture":
        st.markdown('</div>', unsafe_allow_html=True)
with col3:
    if st.session_state.mode == "Threat Map":
        st.markdown('<div class="active-tab">', unsafe_allow_html=True)
    if st.button("Threat Map"):
        st.session_state.mode = "Threat Map"
        st.rerun()
    if st.session_state.mode == "Threat Map":
        st.markdown('</div>', unsafe_allow_html=True)

if st.session_state.mode == "Domain Analysis":
    st.header("Domain Analysis")
    domain = st.text_input("Enter domain (e.g., google.com)", "")
    if st.button("Analyze"):
        if domain:
            logger.info(f"Analyzing domain: {domain}")
            with st.spinner("Analyzing..."):
                if not check_java_version():
                    st.error(f"Java JDK 21 required at {JAVA_HOME}. Please install or configure correctly.")
                    st.stop()
                st.session_state.analysis_results = []
                try:
                    st.subheader(f"Analysis for {domain}")
                    ip = socket.gethostbyname(domain)
                    analysis_result = {"domain": domain, "ip": ip}
                    ssl_result = check_ssl_certificate(domain)
                    scan_result = nmap_scan(ip)
                    packet_indicators = {"suspicious": False, "details": []}
                    try:
                        prediction = predict_threat(domain, packet_indicators=packet_indicators, ssl_result=ssl_result, scan_result=scan_result)
                        logger.info(f"Prediction for {domain}: {prediction}")
                    except Exception as e:
                        prediction = f"Prediction Error: {str(e)}"
                        logger.error(f"Prediction error for {domain}: {str(e)}")

                    vt_result = virustotal_lookup(domain)
                    flaws_result = check_flaws(domain)
                    threat_score = calculate_threat_score(prediction, vt_result, flaws_result, ssl_result, scan_result, packet_indicators)
                    analysis_result["prediction"] = prediction
                    analysis_result["threat_score"] = threat_score
                    analysis_result["virustotal"] = vt_result
                    analysis_result["security_audit"] = flaws_result
                    analysis_result["ssl"] = ssl_result
                    analysis_result["nmap"] = scan_result

                    if isinstance(prediction, str) and "Error" not in prediction:
                        if prediction == "Safe":
                            st.success(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="✅")
                        elif prediction == "Malware":
                            st.error(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")
                            st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                            st.session_state.recent_threats.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score])
                        else:
                            st.warning(f"Prediction: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")
                            st.session_state.threat_counts[prediction.lower()] = st.session_state.threat_counts.get(prediction.lower(), 0) + 1
                            st.session_state.recent_threats.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, prediction, threat_score])
                    else:
                        st.warning(f"Prediction failed: {prediction} (Threat Score: {threat_score}/100)", icon="⚠️")

                    with st.expander("WHOIS Lookup"):
                        whois_result = whois_lookup(domain)
                        if 'error' not in whois_result:
                            whois_data = [[k, ', '.join(v) if isinstance(v, list) else str(v)] for k, v in whois_result.items()]
                            st.table(pd.DataFrame(whois_data, columns=['Field', 'Value']))
                            analysis_result["whois"] = whois_data
                        else:
                            st.error(whois_result['error'])
                            analysis_result["whois"] = [("Error", whois_result['error'])]

                    with st.expander("Network Scan"):
                        if 'error' not in scan_result:
                            ports = scan_result.get('ports', [])
                            if isinstance(ports, list) and all(isinstance(p, dict) and 'port' in p and 'state' in p for p in ports):
                                ports_df = pd.DataFrame(ports)
                                if not ports_df.empty:
                                    st.table(ports_df[['port', 'state']])
                                    analysis_result["nmap"] = ports_df[['port', 'state']].to_dict()
                                else:
                                    st.warning("No open ports found")
                                    analysis_result["nmap"] = [("Warning", "No open ports found")]
                            else:
                                st.warning("Invalid port data format from nmap_scan")
                                analysis_result["nmap"] = [("Warning", "Invalid port data")]
                        else:
                            st.error(scan_result['error'])
                            analysis_result["nmap"] = [("Error", scan_result['error'])]

                    with st.expander("SSL/TLS Certificate"):
                        if ssl_result.get("valid"):
                            st.write(f"Issuer: {ssl_result['issuer']}\nSubject: {ssl_result['subject']}\nExpiry: {ssl_result['expiry']}")
                            if ssl_result.get("expired"):
                                st.warning("Certificate has expired!")
                            if not ssl_result.get("hostname_match"):
                                st.warning(f"Hostname mismatch: Certificate is valid for {ssl_result['cert_hostnames']}")
                        else:
                            st.error(f"SSL error: {ssl_result.get('error')}")
                            analysis_result["ssl"] = [("Error", ssl_result.get('error'))]

                    with st.expander("DNS Analysis"):
                        dns_result = dns_analysis(domain)
                        if "error" not in dns_result:
                            st.write(f"MX: {dns_result.get('MX', [])}\nTXT: {dns_result.get('TXT', [])}")
                            analysis_result["dns"] = dns_result
                        else:
                            st.error(f"DNS error: {dns_result['error']}")
                            analysis_result["dns"] = [("Error", dns_result['error'])]

                    with st.expander("Subdomains"):
                        subdomains = subdomain_enumeration(domain)
                        if subdomains:
                            st.write(", ".join(subdomains))
                            analysis_result["subdomains"] = subdomains
                        else:
                            st.write("No subdomains found")
                            analysis_result["subdomains"] = [("Warning", "No subdomains found")]

                    st.session_state.analysis_results.append(analysis_result)

                except Exception as e:
                    logger.error(f"Domain analysis error for {domain}: {str(e)}")
                    st.error(f"Error analyzing {domain}: {str(e)}")
                    analysis_result["prediction"] = f"Error: {str(e)}"
                    st.session_state.analysis_results.append(analysis_result)

elif st.session_state.mode == "Live Capture":
    st.header("Live Traffic Capture")
    interfaces = get_available_interfaces()
    interface = st.selectbox("Select Network Interface", interfaces)
    duration = st.slider("Capture Duration (seconds)", 5, 60, 10)
    if st.button("Start Capture"):
        with st.spinner(f"Capturing traffic on {interface} for {duration} seconds..."):
            if not check_java_version():
                st.error(f"Java JDK 21 required at {JAVA_HOME}. Please install or configure correctly.")
                st.stop()
            pcap_path = os.path.join(log_dir, f"live_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
            try:
                capture_traffic(interface, duration, pcap_path)
                process_live_capture(pcap_path)
            except Exception as e:
                logger.error(f"Capture error: {str(e)}")
                st.error(f"Capture error: {str(e)}")

elif st.session_state.mode == "Threat Map":
    st.header("Threat Map")
    domain_input = st.text_input("Enter domain to add to map (e.g., google.com)", "")
    if st.button("Add Domain to Map"):
        if domain_input:
            with st.spinner("Adding to map..."):
                analyze_domain_for_map(domain_input)
    render_threat_map()

# Display Recent Threats
st.header("Recent Threats")
if st.session_state.recent_threats:
    threats_df = pd.DataFrame(
        st.session_state.recent_threats,
        columns=["Timestamp", "Domain/IP", "Threat", "Score"]
    )
    st.table(threats_df)
else:
    st.write("No recent threats detected.")

# Display Logs
st.header("Application Logs")
logs = read_last_n_lines(log_file)
st.text_area("Logs", "\n".join(logs), height=200)