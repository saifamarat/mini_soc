import os
import subprocess

from config import LOG_FILES


def find_log_file():
    for log_file in LOG_FILES:
        if os.path.isfile(log_file):
            return log_file

    return None


def collect_logs():
    log_file = find_log_file()

    if log_file:
        try:
            with open(
                log_file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:
                return file.readlines()

        except PermissionError:
            print("[!] Permission denied reading authentication log.")
        except OSError as error:
            print(f"[!] Could not read authentication log: {error}")

    print("[*] Trying systemd journal...")

    try:
        result = subprocess.run(
            [
                "journalctl",
                "-n",
                "1000",
                "--no-pager",
                "-o",
                "short-iso"
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )

        if result.returncode == 0:
            return result.stdout.splitlines()

        print("[!] journalctl could not read the journal.")

        if result.stderr.strip():
            print(result.stderr.strip()[-500:])

    except FileNotFoundError:
        print("[!] journalctl is not installed.")
    except subprocess.TimeoutExpired:
        print("[!] journalctl timed out.")
    except OSError as error:
        print(f"[!] Log collection failed: {error}")

    return []
