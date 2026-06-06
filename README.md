# MiniSOC

MiniSOC is a personal project built to better understand how network monitoring and intrusion detection systems work.

The application captures network traffic in real time, analyzes packets using a custom rule engine, and generates alerts when suspicious activity is detected.

All collected data is stored in a MySQL database and exposed through REST APIs built with FastAPI. A web dashboard is used to visualize packets, alerts, rules and statistics.

---

## Project Goals

The main purpose of this project was to gain hands-on experience with:

* Network traffic analysis
* TCP/IP protocols
* Intrusion Detection Systems (IDS)
* Alert generation and correlation
* REST API development
* Backend and frontend integration
* Cybersecurity concepts and workflows

---


## Technologies Used

* Python
* Scapy
* MySQL
* FastAPI
* React
* JavaScript
* HTML/CSS

---

## Architecture

Collector → Detector → MySQL → FastAPI → Frontend


### Collector

Captures network traffic and stores packet information in the database.

### Detector

Loads detection rules from the database, analyzes packets and generates alerts when a rule matches.

### API

Provides access to packets, alerts, rules and statistics through REST endpoints.

### Frontend

Displays data through a simple dashboard interface.

---
## Detection Rules

The detection engine currently includes the following rules:

### TCP to SSH (22)

Detects TCP connections targeting port 22, commonly used for SSH remote access.

### TCP to RDP (3389)

Detects TCP traffic targeting port 3389, the default port used by Microsoft Remote Desktop Protocol.

### TCP to SMB (445)

Detects TCP connections targeting port 445, commonly used for Windows file sharing and SMB services.

### HTTP Request in Payload Preview

Detects common HTTP methods (GET, POST, PUT, DELETE, etc.) found in captured payload previews.

### Suspicious: Bash Reverse Shell String

Detects common reverse shell patterns such as `bash -i`, often associated with command execution attempts.

### Large Packet Size (>= 1400 Bytes)

Identifies unusually large packets that may be relevant during network investigations or anomaly detection.

### TCP to MySQL (3306)

Detects TCP traffic directed to port 3306, the default MySQL database service port.

### TCP to Telnet (23)

Detects connections to port 23, commonly associated with insecure Telnet services.

### UDP to DNS (53)

Detects DNS queries and responses over UDP port 53.

### ICMP Traffic

Detects ICMP packets such as ping and traceroute traffic.

### TCP to FTP (21)

Detects connections to FTP control port 21.

### TCP to Redis (6379)

Detects traffic targeting Redis services running on the default port 6379.

### Suspicious: PowerShell in Payload

Detects PowerShell-related strings within packet payloads that may indicate script execution activity.

### Suspicious: SQL Injection Pattern

Detects common SQL injection patterns and keywords within captured payload data.

### TCP SYN Without ACK (Possible Port Scan)

Detects TCP SYN packets without the ACK flag, which may indicate reconnaissance or port scanning activity.

### TCP to Reverse Shell Port (4444)

Detects traffic targeting port 4444, frequently used by penetration testing frameworks and reverse shells.


---

## Project Structure

```text
miniSoc/
├── api/
├── collector/
├── detector/
├── frontend/
├── scripts/
├── shared/
├── screenshots/
├── README.md
├── requirements.txt
└── schema.sql
```

---

## Installation

### Clone the repository

```bash
git clone <repository-url>
cd miniSoc
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Database setup

Import the database schema:

```sql
schemaMySql.sql
```

Configure your database credentials inside the `.env` file.

---

## Running the Project

Start the required components according to your local configuration:

1. Collector
2. Detector
3. FastAPI backend
4. Frontend dashboard

---

## Testing

Example commands that can generate traffic for testing:

```bash
ping -c 5 8.8.8.8
curl http://example.com
nmap -sS localhost
```

Generated traffic should appear in the packet database and trigger alerts when matching configured rules.

---

## Screenshots

Application screenshots can be found inside the `screenshots/` directory.

---


## Features

* Real-time packet capture using Scapy
* Packet storage in MySQL
* Rule-based detection engine
* Automatic alert generation
* Alert correlation and deduplication
* REST APIs built with FastAPI
* Web dashboard for monitoring and analysis
* Configurable detection rules stored in the database

---

## Notes

This project was developed as a learning experience to explore cybersecurity concepts, network monitoring, intrusion detection and full-stack application development.
