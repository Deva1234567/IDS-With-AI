ALERT_THRESHOLDS = {
    'ddos': 100,  # packets per minute
    'port_scan': 50,  # unique ports per minute
}

GEOIP_API_URL = "https://api.ipgeolocation.io/ipgeo?apiKey=aef47f0cd39049589aef8e95c797c4e1&ip="

THREAT_INTEL_IPS = [
    "198.51.100.1",
    "203.0.113.2",
]

VIRUSTOTAL_API_KEY = "f8f5f1819ee8339d9b33cf5832990357cd9832ceea1a68f8ee048eff6a640a0e"


EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'devanshjain209@gmail.com',
    'sender_password': 'okdd posa ucfm fchp',
    'receiver_email': 'djain7359@gmail.com'
}
