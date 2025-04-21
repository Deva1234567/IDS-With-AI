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
logging.basicConfig(
    filename=os.path.join(os.path.expanduser("~"), "Desktop", "logs", "utils.log"),
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("utils")

def whois_lookup(domain):
    """Perform WHOIS lookup for a domain."""
    try:
        w = whois.whois(domain)
        result = {
            "domain_name": w.get("domain_name", "N/A"),
            "registrar": w.get("registrar", "N/A"),
            "creation_date": str(w.get("creation_date", "N/A")),
            "expiration_date": str(w.get("expiration_date", "N/A")),
            "name_servers": ", ".join(w.get("name_servers", ["N/A"]))
        }
        logger.debug(f"WHOIS lookup for {domain}: {result}")
        return result
    except Exception as e:
        logger.error(f"WHOIS error for {domain}: {str(e)}")
        return {"error": str(e)}

def nmap_scan(ip):
    """Perform Nmap scan on an IP."""
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sS -p 1-1000")
        ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    ports.append({"port": port, "state": nm[host][proto][port]["state"]})
        result = {"ports": ports}
        logger.debug(f"Nmap scan result for {ip}: {result}")
        return result
    except Exception as e:
        logger.error(f"Nmap scan error for {ip}: {str(e)}")
        return {"error": str(e)}

def capture_traffic(interface, count):
    """Capture network traffic on specified interface."""
    try:
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
        logger.error(f"Capture error on {interface}: {str(e)}")
        return pd.DataFrame()

def virustotal_lookup(domain):
    """Check domain reputation on VirusTotal."""
    try:
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={VIRUSTOTAL_API_KEY}&domain={domain}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if data.get("response_code") == 1:
                positives = data.get("detected_urls", [])
                if positives:
                    return f"Threats detected: {len(positives)} malicious URLs"
                return "No threats detected"
        return "VirusTotal lookup failed"
    except Exception as e:
        logger.error(f"VirusTotal error for {domain}: {str(e)}")
        return f"VirusTotal error: {str(e)}"

def check_flaws(domain):
    """Check for common security flaws."""
    try:
        flaws = []
        for threat_ip in THREAT_INTEL_IPS:
            try:
                resolved_ip = socket.gethostbyname(threat_ip)
                target_ip = socket.gethostbyname(domain)
                if resolved_ip == target_ip:
                    flaws.append(f"Match with known threat IP: {threat_ip}")
            except:
                continue
        if not flaws:
            flaws.append("No major flaws detected")
        logger.debug(f"Security flaws for {domain}: {flaws}")
        return flaws
    except Exception as e:
        logger.error(f"Security audit error for {domain}: {str(e)}")
        return [f"Security audit error: {str(e)}"]