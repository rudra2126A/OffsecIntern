# Offensive-Security-Internship-inlighn-tech
This repo contains the projects made by me during my Remote Internship in offsec at INLIGHN-TECH 

## Flask Web Application

A modern web-based GUI for all the security tools in this repository.

### Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the Flask application:
```bash
python app.py
```

3. Open your browser and navigate to:
```
http://localhost:5000
```

### Available Tools

- **Network Scanner**: Scan network ranges for active hosts, MAC addresses, and hostnames
- **Port Scanner**: Scan target hosts for open ports and services
- **Hash Cracker**: Crack password hashes using wordlists or brute force
- **Subdomain Enumeration**: Discover subdomains for target domains
- **DNS Enumeration**: Enumerate DNS records (A, AAAA, MX, NS, TXT, SOA)
- **FTP Cracker**: Brute force FTP server credentials
- **SSH Brute Force**: Brute force SSH server credentials
- **PDF Tools**: Information about PDF protection and cracking tools

### Notes

- Some tools require specific permissions (e.g., network scanning may require root/admin privileges)
- Network scanner interface name may need to be adjusted in `app.py` (currently set to "Ethernet0")
- Wordlist paths should be absolute or relative to the application directory
- Use these tools responsibly and only on systems you own or have permission to test

### Requirements

- Python 3.7+
- Flask
- scapy (for network scanning)
- dnspython (for DNS enumeration)
- requests (for subdomain enumeration)
- paramiko (for SSH brute force)
- tqdm (for hash cracking progress)
- colorama (for colored output in CLI tools)
