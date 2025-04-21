ALERT_THRESHOLDS = {
    'ddos': 100,  # packets per minute
    'port_scan': 50,  # unique ports per minute
}

GEOIP_API_URL = "https://api.ipgeolocation.io/ipgeo?apiKey=aef47f0cd39049589aef8e95c797c4e1&ip="

THREAT_INTEL_IPS = [
    "198.51.100.1",
    "203.0.113.2",
]

VIRUSTOTAL_API_KEY = "5b23009cac33f0c67b776774b860c992c7284a67fd548045fe3668e82e6265d2"

EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'devanshjain209@gmail.com',
    'sender_password': 'okdd posa ucfm fchp',
    'receiver_email': 'djain7359@gmail.com'
}