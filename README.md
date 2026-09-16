# Network Security Analyzer

A Python-based defensive network security monitoring system that analyzes network logs, detects suspicious connection patterns, stores security events in SQLite, and provides a Flask-based web dashboard.

## Features

- Network log parsing
- Failed connection detection
- Possible port scan detection
- Source IP risk analysis
- SQLite security event database
- Flask web dashboard
- Login authentication
- Security alert visualization
- Source IP filtering
- CSV security event export
- Automated security report generation

## Architecture

Network Logs
     |
     v
Python Log Analyzer
     |
     +----------------+
     |                |
     v                v
Security Rules     Security Report
     |
     v
SQLite Database
     |
     v
Flask Dashboard
     |
     +--------+
     |        |
     v        v
Charts     CSV Export

## Detection Logic

### Multiple Failed Connections

If an IP address generates 3 or more failed connections, the system creates a MEDIUM severity alert.

### Possible Port Scan

If an IP address connects to 4 or more unique ports, the system creates a HIGH severity alert.

These are heuristic indicators and do not by themselves prove malicious activity.

## Technologies

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- Chart.js

## Project Structure

network-security-analyzer/
|
├── logs/
│   └── network.log
|
├── reports/
│   ├── security_report.txt
│   └── security_events.db
|
├── src/
│   ├── log_analyzer.py
│   └── dashboard.py
|
├── templates/
│   ├── dashboard.html
│   └── login.html
|
└── README.md

## How to Run

Install Flask:

    python -m pip install flask

Run the analyzer:

    python src/log_analyzer.py

Start the dashboard:

    python src/dashboard.py

Open:

    http://127.0.0.1:5000

Demo credentials:

    Username: admin
    Password: admin123

## Disclaimer

This project is designed for defensive security analysis and uses synthetic network log data for demonstration purposes.