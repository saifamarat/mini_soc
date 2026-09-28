import os
import subprocess

from config import LOG_FILES


def find_log_file():
    """
    Find an available authentication log file.
    """

    for log_file in LOG_FILES:

        if os.path.exists(log_file):
            return log_file

    return None


def collect_logs():
    """
    Collect authentication logs from the system.
    """

    log_file = find_log_file()

    if log_file:

        try:

            with open(
                log_file,
                "r",
                errors="ignore"
            ) as file:

                return file.readlines()

        except PermissionError:

            print("[!] Permission denied while reading log file.")
            return []

    # Fallback to systemd journal
    try:

        result = subprocess.run(
            [
                "journalctl",
                "-n",
                "500",
                "--no-pager"
            ],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            return result.stdout.splitlines()

    except FileNotFoundError:

        print("[!] journalctl not found.")

    return []
