import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",
]

ALERT_LOG_FILE = os.path.join(BASE_DIR, "alerts.log")
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
REPORT_FILE = os.path.join(BASE_DIR, "report.html")

FAILED_LOGIN_THRESHOLD = 5
