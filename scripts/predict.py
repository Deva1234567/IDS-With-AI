import logging
import re
from logging.handlers import RotatingFileHandler
import os

# Setup logging
log_dir = os.path.join(r"C:\Users\devan\Desktop\Project\IDS project\logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "predict.log")
logger = logging.getLogger("predict")
logger.setLevel(logging.DEBUG)
if not logger.handlers:  # Prevent duplicate handlers
    handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

def predict_threat(domain, packet_indicators=None, ssl_result=None, scan_result=None):
    """
    Predicts if a domain poses a cybersecurity threat.
    Returns: 'Safe', 'Malware', 'DDoS', 'Port Scan', 'Ransomware', or 'Potential Risk'
    """
    try:
        logger.info(f"Starting threat prediction for domain: {domain}")
        threat_score = 0
        max_individual_score = 15  # Cap for each indicator
        safe_threshold = 25  # Threshold for "Safe" classification

        # Initialize indicators
        if packet_indicators is None:
            packet_indicators = {"suspicious": False, "details": []}
        if ssl_result is None:
            ssl_result = {"valid": True, "expired": False, "hostname_match": True}
        if scan_result is None:
            scan_result = {"ports": []}

        # Check domain patterns for common malicious indicators
        suspicious_patterns = [
            r"malware", r"phish", r"exploit", r"hack", r"trojan", r"ransom",
            r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}",  # IP-like patterns
            r"^[a-f0-9]{32}$",  # MD5 hash-like pattern
            r"^[a-f0-9]{40}$",  # SHA1 hash-like pattern
        ]
        domain_lower = domain.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, domain_lower):
                threat_score += max_individual_score
                logger.debug(f"Domain pattern match: {pattern}, score += {max_individual_score}")
                break

        # Packet indicators scoring
        if packet_indicators.get("suspicious", False):
            details = packet_indicators.get("details", [])
            if len(details) > 2:  # Require multiple indicators
                threat_score += max_individual_score
                logger.debug(f"Suspicious packet indicators: {details}, score += {max_individual_score}")
            elif len(details) == 1:
                threat_score += 5
                logger.debug(f"Single packet indicator: {details}, score += 5")
        else:
            logger.debug("No suspicious packet indicators, score unchanged")

        # SSL/TLS certificate scoring
        if not ssl_result.get("valid", True):
            threat_score += 10
            logger.debug("Invalid SSL certificate, score += 10")
        if ssl_result.get("expired", False):
            threat_score += 8
            logger.debug("Expired SSL certificate, score += 8")
        if not ssl_result.get("hostname_match", True):
            threat_score += 5
            logger.debug("Hostname mismatch in SSL, score += 5")

        # Nmap scan result scoring
        suspicious_ports = [4444, 6667, 31337]  # Known malicious ports
        ports = scan_result.get("ports", [])
        for port in ports:
            if port.get("port") in suspicious_ports:
                threat_score += max_individual_score
                logger.debug(f"Suspicious port {port.get('port')} detected, score += {max_individual_score}")
                break

        # Normalize the score
        threat_score = max(0, min(threat_score, 100))
        logger.info(f"Final threat score for {domain}: {threat_score}")

        # Determine threat type based on indicators
        if threat_score < safe_threshold:
            logger.info(f"Prediction for {domain}: Safe (score {threat_score} < {safe_threshold})")
            return "Safe"
        elif "packet" in str(packet_indicators).lower() and "traffic" in str(packet_indicators).lower():
            logger.info(f"Prediction for {domain}: DDoS (based on packet indicators)")
            return "DDoS"
        elif any(port.get("port") in suspicious_ports for port in ports):
            logger.info(f"Prediction for {domain}: Port Scan (suspicious ports detected)")
            return "Port Scan"
        elif any("ransom" in detail.lower() for detail in packet_indicators.get("details", [])):
            logger.info(f"Prediction for {domain}: Ransomware (ransom keyword in packet indicators)")
            return "Ransomware"
        elif threat_score >= 50:
            logger.info(f"Prediction for {domain}: Malware (score {threat_score} >= 50)")
            return "Malware"
        else:
            logger.info(f"Prediction for {domain}: Potential Risk (score {threat_score} >= {safe_threshold})")
            return "Potential Risk"

    except Exception as e:
        logger.error(f"Error in predict_threat for {domain}: {str(e)}")
        return f"Prediction Error: {str(e)}"
