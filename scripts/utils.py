import logging
import os
import pandas as pd
import whois
import nmap
import scapy.all as scapy
import requests
import socket
from scripts.config import VIRUSTOTAL_API_KEY, THREAT_INTEL_IPS

# Setup logging
log_dir = r"C:\Users\devan\Desktop\Project\IDS project\logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "utils.log")
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("utils")
logger.info("utils.py logging initialized")

def whois_lookup(domain):
    """Perform WHOIS lookup for a domain."""
    try:
        logger.debug(f"Attempting WHOIS lookup for {domain}")
        w = whois.whois(domain)
        result = {
            "domain_name": w.get("domain_name", "N/A"),
            "registrar": w.get("registrar", "N/A"),
            "creation_date": str(w.get("creation_date", "N/A")),
            "expiration_date": str(w.get("expiration_date", "N/A")),
            "name_servers": ", ".join(w.get("name_servers", ["N/A"]))
        }
        logger.debug(f"WHOIS lookup successful for {domain}: {result}")
        return result
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
        return {"error": str(e)}

def nmap_scan(ip):
    """Perform Nmap scan on an IP."""
    try:
        logger.debug(f"Starting Nmap scan on {ip}")
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sS -p 1-1000")
        ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    ports.append({"port": port, "state": nm[host][proto][port]["state"]})
        result = {"ports": ports}
        logger.debug(f"Nmap scan completed for {ip}: {result}")
        return result
    except Exception as e:
        logger.error(f"Nmap scan failed for {ip}: {str(e)}")
        return {"error": str(e)}

def capture_traffic(interface, count):
    """Capture network traffic on specified interface."""
    try:
        logger.debug(f"Capturing {count} packets on interface {interface}")
        packets = scapy.sniff(iface=interface, count=count, timeout=10)
        data = []
        for pkt in packets:
            if scapy.IP in pkt:
                data.append({
                    "src_ip": pkt[scapy.IP].src,
                    "dst_ip": pkt[scapy.IP].dst,
                    "protocol": pkt[scapy.IP].proto
                })
        df = pd.DataFrame(data)
        logger.debug(f"Captured {len(df)} packets on {interface}")
        return df
    except Exception as e:
        logger.error(f"Traffic capture failed on {interface}: {str(e)}")
        return pd.DataFrame()

def virustotal_lookup(domain):
    """Check domain reputation on VirusTotal."""
    try:
        logger.debug(f"Performing VirusTotal lookup for {domain}")
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={VIRUSTOTAL_API_KEY}&domain={domain}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        if response.status_code == 200:
            data = response.json()
            if data.get("response_code") == 1:
                positives = data.get("detected_urls", [])
                if positives:
                    result = f"Threats detected: {len(positives)} malicious URLs"
                else:
                    result = "No threats detected"
                logger.debug(f"VirusTotal lookup successful for {domain}: {result}")
                return result
        logger.warning(f"VirusTotal lookup failed for {domain}: Invalid response code")
        return "VirusTotal lookup failed"
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal request failed for {domain}: {str(e)}")
        return f"VirusTotal error: {str(e)}"
    except Exception as e:
        logger.error(f"VirusTotal unexpected error for {domain}: {str(e)}")
        return f"VirusTotal error: {str(e)}"

def check_flaws(domain):
    """Check for common security flaws."""
    try:
        logger.debug(f"Checking security flaws for {domain}")
        flaws = []
        target_ip = socket.gethostbyname(domain)
        logger.debug(f"Resolved {domain} to IP: {target_ip}")
        for threat_ip in THREAT_INTEL_IPS:
            try:
                resolved_ip = socket.gethostbyname(threat_ip)
                if resolved_ip == target_ip:
                    flaws.append(f"Match with known threat IP: {threat_ip}")
                    logger.debug(f"Found match with threat IP {threat_ip} for {domain}")
            except socket.gaierror:
                logger.debug(f"Could not resolve threat IP {threat_ip}, skipping")
                continue
        if not flaws:
            flaws.append("No major flaws detected")
            logger.debug(f"No security flaws detected for {domain}")
        return flaws
    except socket.gaierror as e:
        logger.error(f"Failed to resolve domain {domain}: {str(e)}")
        return [f"Domain resolution error: {str(e)}"]
    except Exception as e:
        logger.error(f"Security audit failed for {domain}: {str(e)}")
        return [f"Security audit error: {str(e)}"]