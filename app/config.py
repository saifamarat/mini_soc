from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILES = [
    Path("/var/log/auth.log"),
    Path("/var/log/syslog"),
    Path("/var/log/secure"),
]

MAX_LINES = 5000

BRUTE_FORCE_THRESHOLD = 5
