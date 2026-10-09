# Mini SOC

A lightweight Python-based Security Operations Center project for Linux.

Mini SOC is developed in three versions, progressing from log monitoring to security detection, alerting, and HTML reporting.

## Features

### V1 — Log Monitoring
- Linux log collection
- Basic event parsing

### V2 — Detection & Alerting
- Failed login detection
- Successful SSH login detection
- Sudo activity detection
- User creation event detection
- Possible brute-force detection
- Configurable JSON detection rules
- Alert severity levels
- Alert logging

### V3 — HTML Reporting
- Security event statistics
- Alert severity summary
- Detailed alert tables
- Event details including username and source IP
- Responsive dark-themed HTML report
- Local report generation without external Python dependencies

## Architecture

Linux Logs
    ↓
Collector
    ↓
Parser
    ↓
Detection Engine
    ↓
Security Rules
    ↓
Alerting
    ↓
HTML Report

## Project Structure

```text
mini-soc/
├── alerts.py
├── collector.py
├── config.py
├── detector.py
├── main.py
├── parser.py
├── report.py
├── rules.json
├── requirements.txt
├── .gitignore
├── README.md
└── __init__.py
```

## Requirements

- Python 3
- Linux or Kali Linux
- Access to relevant system logs

No third-party Python packages are required.

## Usage

Run the application:

```bash
python3 main.py
```

If log access requires elevated privileges:

```bash
sudo python3 main.py
```

The HTML report is generated as:

```text
report.html
```

Open it in a browser:

```bash
xdg-open report.html
```

Alerts are saved locally in:

```text
alerts.log
```

Both local output files are excluded from Git tracking.

## Limitations

- Detection depends on the log formats and events available on the host.
- Brute-force detection counts failed login events within the collected log batch; it does not implement a time-windowed detector.
- A detected event is not automatically proof of malicious activity.
- This project is an educational monitoring tool, not a replacement for an enterprise SIEM.

## Responsible Use

Use Mini SOC only on systems and logs you are authorized to monitor.

## Author

Saif Alamarat

GitHub: https://github.com/saifamarat
