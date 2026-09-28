#  Mini SOC

A lightweight Python-based Security Operations Center (SOC) project built on Linux.

The project is developed in three versions, with each version adding new security monitoring and detection capabilities.

---

##  Current Version

### V2 — Detection & Alerting ✅

V2 introduces a basic security detection engine capable of analyzing Linux authentication activity and generating security alerts.

### V2 Features

- Linux log collection
- Authentication event parsing
- Failed login detection
- Successful login detection
- Sudo activity detection
- User creation detection
- Brute-force detection
- Configurable detection rules
- Severity levels
- Alert logging

---

##  Architecture

```text
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
Alerts
    ↓
Alert Log
