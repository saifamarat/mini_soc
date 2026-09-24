import subprocess
from pathlib import Path

from .config import LOG_FILES, MAX_LINES


def collect_from_files():
    records = []

    for log_file in LOG_FILES:

        if not log_file.exists():
            continue

        try:
            with log_file.open(
                "r",
                errors="replace"
            ) as file:

                lines = file.readlines()[-MAX_LINES:]

            for line in lines:
                line = line.strip()

                if line:
                    records.append({
                        "source": str(log_file),
                        "raw": line
                    })

        except PermissionError:
            print(f"[!] Permission denied: {log_file}")

    return records


def collect_from_journal():
    records = []

    try:
        result = subprocess.run(
            [
                "journalctl",
                "-n",
                str(MAX_LINES),
                "--no-pager"
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        if result.returncode != 0:
            return records

        for line in result.stdout.splitlines():

            line = line.strip()

            if line:
                records.append({
                    "source": "journalctl",
                    "raw": line
                })

    except FileNotFoundError:
        print("[!] journalctl not found")

    except subprocess.TimeoutExpired:
        print("[!] journalctl timeout")

    return records


def collect_logs():

    records = collect_from_files()

    if records:
        return records

    print("[*] Log files not found.")
    print("[*] Trying journalctl...")

    return collect_from_journal()
