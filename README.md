Cybersecurity Dashboard
Overview
The Cybersecurity Dashboard is a Streamlit-based web application designed to analyze network traffic, domains, and potential cybersecurity threats. It provides tools for domain analysis, live traffic capture, and visualization of threats on a global map. Key features include:

Domain Analysis: Analyze domains for potential threats using WHOIS lookup, Nmap scans, SSL/TLS certificate checks, DNS analysis, and VirusTotal integration.
Live Traffic Capture: Capture and analyze network traffic using Scapy, identifying suspicious activity.
Threat Map: Visualize threats geographically with a Folium-based heatmap, including MITRE ATT&CK mappings.
Threat Statistics: Display charts of detected threats using Matplotlib.
Logging: Comprehensive logging for debugging and monitoring.

This project is intended for cybersecurity professionals and enthusiasts to monitor and analyze network activity in a controlled environment.
Project Structure

cybersecurity_dashboard.py: Main application script.
scripts/: Directory containing utility scripts.
utils.py: Functions for WHOIS lookup, Nmap scans, VirusTotal checks, and security audits.
predict.py: Threat prediction logic.
config.py: Configuration settings (API keys, threat intel IPs, etc.).


logs/: Directory for application logs.
data/: Directory for the GeoLite2-Country database.

Prerequisites

Operating System: Windows (tested on Windows with VS Code).
Java: JDK 21 (set JAVA_HOME to C:\Program Files\Java\jdk-21).
Python: Version 3.8+.
GeoLite2 Database: Download GeoLite2-Country.mmdb from MaxMind and place it in C:\Users\your_username\Desktop\Project\IDS project\data\.

Installation

Clone the Repository:
git clone <repository-url>
cd <repository-directory>


Set Up a Virtual Environment (optional but recommended):
python -m venv venv
.\venv\Scripts\activate  # On Windows


Install Dependencies:Install the required Python packages using:
pip install -r requirements.txt

If requirements.txt is not available, install the following manually:
pip install streamlit streamlit-folium folium geoip2 ipaddress matplotlib numpy pytz pandas reportlab scapy python-dateutil dnspython


Set Up Java:

Ensure JDK 21 is installed.
Set the JAVA_HOME environment variable:set JAVA_HOME=C:\Program Files\Java\jdk-21


Verify Java version:java -version




Download GeoLite2 Database:

Sign up for a free MaxMind account and download the GeoLite2-Country.mmdb file.
Place it in C:\Users\your_username\Desktop\Project\IDS project\data\.


Configure API Keys:

Edit scripts/config.py to add your VirusTotal API key and other configurations:VIRUSTOTAL_API_KEY = "your_virustotal_api_key"





Usage

Run the Application:
streamlit run cybersecurity_dashboard.py

The app will open in your default browser.

Modes of Operation:

Domain Analysis:
Enter a domain (e.g., google.com) to analyze it for potential threats.
View results including WHOIS data, Nmap scans, SSL/TLS certificate details, DNS records, and subdomains.


Live Capture:
Select a network interface and capture duration to monitor live traffic.
Analyze captured packets for suspicious activity.


Threat Map:
Add domains to visualize their geolocation and associated threats on a map.
View a heatmap and threat statistics.




Logs:

Logs are stored in C:\Users\your_username\Desktop\Project\IDS project\logs\streamlit.log.
View the last 50 lines of logs in the app under "Application Logs".



Features

Threat Prediction: Uses a custom prediction model (in scripts/predict.py) to classify threats like DDoS, XSS, SQLi, and Malware.
Geolocation: Maps IP addresses to countries using the GeoLite2 database.
MITRE ATT&CK Mapping: Maps detected threats to MITRE ATT&CK techniques and tactics.
Visualization: Includes a Folium-based threat map and Matplotlib charts for threat distribution.
Packet Analysis: Analyzes PCAP files and live captures for suspicious traffic patterns.

Troubleshooting

Java Errors: Ensure JDK 21 is installed and JAVA_HOME is set correctly.
GeoIP2 Errors: Verify that GeoLite2-Country.mmdb is in the correct directory and is not an ASN database.
Permission Issues: Run the app as an administrator if capturing live traffic fails.
No Threat Data: If the threat map or charts are empty, ensure predict_threat() in scripts/predict.py is returning non-"Safe" predictions for detected threats.

Dependencies

streamlit: For the web interface.
streamlit-folium: For rendering Folium maps.
folium: For creating interactive maps.
geoip2: For geolocation.
ipaddress: For IP validation.
matplotlib: For plotting charts.
numpy: For numerical operations.
pytz: For timezone handling.
pandas: For data manipulation.
reportlab: For generating PDF reports.
scapy: For packet capture and analysis.
python-dateutil: For parsing dates.
dnspython: For DNS analysis.

Notes

Ensure you have the necessary permissions to capture network traffic (e.g., run as administrator on Windows).
The app requires an internet connection for VirusTotal lookups and WHOIS queries.
Use this tool responsibly and only analyze domains or networks you have permission to test.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgments

Built with Streamlit.
Geolocation data provided by MaxMind GeoLite2.
Threat intelligence and mappings based on MITRE ATT&CK.

