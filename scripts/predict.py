import logging
import re

# Setup logging
logger = logging.getLogger("predict")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

def predict_threat(domain, packet_indicators=None, ssl_result=None, scan_result=None):
    """
    Predict the threat level of a domain or traffic.
    
    Args:
        domain (str): The domain or identifier to analyze.
        packet_indicators (dict, optional): Indicators from packet analysis.
        ssl_result (dict, optional): SSL certificate analysis result.
        scan_result (dict, optional): Network scan result.
    
    Returns:
        str: Prediction ("Safe", "Unsafe", "Malware", or "Error").
    """
    try:
        logger.info(f"Predicting threat for domain: {domain}")
        
        # Initialize a scoring system
        threat_score = 0
        reasons = []

        # Domain-based heuristics
        known_safe_domains = {"google.com", "microsoft.com", "apple.com", "github.com", "wikipedia.org"}
        known_malicious_patterns = [r"malware", r"phish", r"hack", r"exploit", r"trojan"]

        # Check domain reputation
        if domain in known_safe_domains:
            threat_score -= 20  # Reduce threat score for known safe domains
            reasons.append(f"Domain {domain} is in known safe list")
        else:
            # Check for suspicious keywords in domain
            for pattern in known_malicious_patterns:
                if re.search(pattern, domain.lower()):
                    threat_score += 30
                    reasons.append(f"Domain {domain} contains suspicious pattern: {pattern}")
                    break

        # Packet indicators
        if packet_indicators and packet_indicators.get("suspicious", False):
            threat_score += 30
            details = packet_indicators.get("details", [])
            reasons.append(f"Suspicious packet indicators: {details}")
            # Check for explicit malware indicators
            if any("malicious" in detail.lower() for detail in details):
                threat_score += 20
                reasons.append("Explicit malicious indicator in packet details")

        # SSL certificate issues
        if ssl_result:
            if not ssl_result.get("valid", True):
                threat_score += 15
                reasons.append("SSL certificate is invalid")
            if ssl_result.get("expired", False):
                threat_score += 10
                reasons.append("SSL certificate is expired")
            if not ssl_result.get("hostname_match", True):
                threat_score += 10
                reasons.append("SSL hostname mismatch")

        # Network scan results
        if scan_result and scan_result.get("ports"):
            suspicious_ports = [port["port"] for port in scan_result["ports"] if port["port"] in [4444, 6667, 31337]]
            if suspicious_ports:
                threat_score += 20
                reasons.append(f"Suspicious ports found: {suspicious_ports}")

        # Clamp score between 0 and 100
        threat_score = max(0, min(threat_score, 100))
        logger.debug(f"Threat score for {domain}: {threat_score}, Reasons: {reasons}")

        # Determine prediction based on score
        if threat_score < 20:
            prediction = "Safe"
        elif threat_score < 50:
            prediction = "Unsafe"
        else:
            prediction = "Malware"

        logger.info(f"Final prediction for {domain}: {prediction} (Score: {threat_score})")
        return prediction

    except Exception as e:
        logger.error(f"Error predicting threat for {domain}: {str(e)}")
        return f"Error: {str(e)}"