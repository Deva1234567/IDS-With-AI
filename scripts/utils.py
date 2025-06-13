# scripts/utils.py
import logging
import socket
import ssl
import OpenSSL
import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, UDP, Raw
import requests
import importlib


logger = logging.getLogger(__name__)

# Import API keys from config
try:
    from .config import VIRUSTOTAL_API_KEY
except ImportError as e:
    logger.error(f"Failed to import API keys from config: {str(e)}")
    VIRUSTOTAL_API_KEY = "f8f5f1819ee8339d9b33cf5832990357cd9832ceea1a68f8ee048eff6a640a0e"  # Fallback

def ssl_check(domain):
    """
    Check the SSL certificate of a domain for expiration and hostname match.
    Returns a dictionary with SSL details or an error.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False  # Temporarily disable hostname verification
        context.verify_mode = ssl.CERT_REQUIRED
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Force TLS 1.2 or higher
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
        cert_x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        not_after = datetime.datetime.strptime(cert_x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
        expired = not_after < datetime.datetime.utcnow()
        # Extract subjectAltName
        san = []
        for i in range(cert_x509.get_extension_count()):
            ext = cert_x509.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                san.extend([s.strip() for s in str(ext).split(',') if s.strip().startswith('DNS:')])
        hostname_match = domain.lower() in [s.replace('DNS:', '').lower() for s in san]
        return {
            "expired": expired,
            "not_after": not_after.strftime('%Y-%m-%d %H:%M:%S'),
            "hostname_match": hostname_match,
            "subject_alt_names": [s.replace('DNS:', '') for s in san]
        }
    except ssl.SSLError as e:
        logger.error(f"SSL check failed for {domain}: {str(e)}")
        return {"error": f"SSL check failed: {str(e)}"}
    except Exception as e:
        logger.error(f"SSL check failed for {domain}: {str(e)}")
        return {"error": f"SSL check failed: {str(e)}"}

def virustotal_lookup(domain, api_key=None):
    """Check domain reputation on VirusTotal."""
    if not api_key:
        try:
            from .config import VIRUSTOTAL_API_KEY
            api_key = VIRUSTOTAL_API_KEY
        except ImportError:
            return "VirusTotal error: API key missing or config import failed"

    try:
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data.get("response_code") == 1:
            positives = data.get("detected_urls", [])
            if positives:
                return f"Threats detected: {len(positives)} malicious URLs"
            else:
                return "No threats detected"
        return "VirusTotal lookup failed: Invalid response"
    except requests.exceptions.RequestException as e:
        return f"VirusTotal error: {str(e)}"


def whois_lookup(domain):
    try:
        whois = importlib.import_module("whois")
        w = whois.whois(domain)
        if w:
            return {
                "domain_name": w.get("domain_name", "N/A"),
                "registrar": w.get("registrar", "N/A"),
                "creation_date": str(w.get("creation_date", "N/A")),
                "expiration_date": str(w.get("expiration_date", "N/A")),
                "name_servers": w.get("name_servers", "N/A")
            }
        else:
            return {"error": "No WHOIS data available"}
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
        return {"error": f"WHOIS lookup failed: {str(e)}"}
    
    
    
def parallel_domain_analysis(domain):
    """
    Perform parallel analysis on a domain (SSL, VirusTotal, WHOIS).
    Returns a dictionary with results from all analyses.
    """
    with ThreadPoolExecutor() as executor:
        futures = {
            "SSL": executor.submit(ssl_check, domain),
            "VirusTotal": executor.submit(virustotal_lookup, domain, VIRUSTOTAL_API_KEY),
            "WHOIS": executor.submit(whois_lookup, domain)
        }
        results = {key: future.result() for key, future in futures.items()}
    return results

def analyze_packets(packets):
    """
    Analyze captured packets for suspicious activity.
    Returns a dictionary with analysis results or an error.
    """
    try:
        protocol_distribution = {"TCP": 0, "UDP": 0, "Other": 0}
        traffic_direction = {"inbound": 0, "outbound": 0}
        packet_sizes = []
        connection_states = {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0}
        top_talkers = {"sources": {}, "destinations": {}}
        port_usage = {"source_ports": {}, "dest_ports": {}}
        suspicious = False
        details = []
        payload_suspicion = []

        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                packet_sizes.append(len(pkt))

                top_talkers["sources"][src_ip] = top_talkers["sources"].get(src_ip, 0) + 1
                top_talkers["destinations"][dst_ip] = top_talkers["destinations"].get(dst_ip, 0) + 1

                if TCP in pkt:
                    protocol_distribution["TCP"] += 1
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    port_usage["source_ports"][src_port] = port_usage["source_ports"].get(src_port, 0) + 1
                    port_usage["dest_ports"][dst_port] = port_usage["dest_ports"].get(dst_port, 0) + 1
                    flags = pkt[TCP].flags
                    if flags & 0x02: connection_states["SYN"] += 1
                    if flags & 0x10: connection_states["ACK"] += 1
                    if flags & 0x01: connection_states["FIN"] += 1
                    if flags & 0x04: connection_states["RST"] += 1
                elif UDP in pkt:
                    protocol_distribution["UDP"] += 1
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    port_usage["source_ports"][src_port] = port_usage["source_ports"].get(src_port, 0) + 1
                    port_usage["dest_ports"][dst_port] = port_usage["dest_ports"].get(dst_port, 0) + 1
                else:
                    protocol_distribution["Other"] += 1

                if Raw in pkt:
                    payload = str(pkt[Raw].load)
                    if "sqlmap" in payload.lower():
                        suspicious = True
                        payload_suspicion.append("SQLmap signature detected")
                    if "malware" in payload.lower():
                        suspicious = True
                        payload_suspicion.append("Malware signature detected")

        return {
            "suspicious": suspicious,
            "details": details,
            "payload_suspicion": payload_suspicion,
            "protocol_distribution": protocol_distribution,
            "traffic_direction": traffic_direction,
            "packet_sizes": packet_sizes,
            "connection_states": connection_states,
            "top_talkers": top_talkers,
            "port_usage": port_usage
        }
    except Exception as e:
        logger.error(f"Packet analysis failed: {str(e)}")
        return {"error": f"Packet analysis failed: {str(e)}"}

def capture_and_analyze_packets(duration=10, interface=None):
    """
    Capture packets for a specified duration and analyze them.
    Returns the analysis results or an error.
    """
    from scapy.all import sniff
    try:
        packets = sniff(timeout=duration, iface=interface)
        return analyze_packets(packets)
    except Exception as e:
        logger.error(f"Packet capture failed: {str(e)}")
        return {"error": f"Packet capture failed: {str(e)}"}

def check_flaws(domain):
    """
    Check for potential security flaws in the domain's HTTP response.
    Returns a list of flaws or an error message.
    """
    try:
        flaws = []
        response = requests.get(f"http://{domain}", timeout=5)
        if "xss" in response.text.lower():
            flaws.append("Potential XSS vulnerability")
        if "sql" in response.text.lower():
            flaws.append("Potential SQL injection vulnerability")
        return flaws if flaws else ["No major flaws detected"]
    except Exception as e:
        logger.error(f"Flaw check failed for {domain}: {str(e)}")
        return ["Flaw check failed"]
