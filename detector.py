from collections import defaultdict
import json

from config import RULES_FILE


def load_rules():
    try:
        with open(
            RULES_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError) as error:
        print(f"[!] Could not load detection rules: {error}")
        return {}


def detect_events(events):
    rules = load_rules()
    alerts = []
    failed_attempts = defaultdict(list)

    for event in events:
        event_type = event.get("event_type", "unknown")
        rule = rules.get(event_type, {})

        if not rule.get("enabled", False):
            continue

        severity = rule.get("severity", "LOW")
        source_ip = event.get("source_ip")
        username = event.get("username")

        if event_type == "failed_login":
            if source_ip:
                failed_attempts[source_ip].append(event)

            alerts.append({
                "type": "FAILED_LOGIN",
                "severity": severity,
                "message": (
                    f"Failed login for '{username or 'unknown'}' "
                    f"from {source_ip or 'unknown IP'}"
                ),
                "source_ip": source_ip,
                "username": username
            })

        elif event_type == "successful_login":
            alerts.append({
                "type": "SUCCESSFUL_LOGIN",
                "severity": severity,
                "message": (
                    f"Successful login for '{username or 'unknown'}' "
                    f"from {source_ip or 'unknown IP'}"
                ),
                "source_ip": source_ip,
                "username": username
            })

        elif event_type == "sudo_usage":
            alerts.append({
                "type": "SUDO_USAGE",
                "severity": severity,
                "message": (
                    f"Sudo activity detected for "
                    f"'{username or 'unknown'}'"
                ),
                "username": username
            })

        elif event_type == "user_creation":
            alerts.append({
                "type": "USER_CREATION",
                "severity": severity,
                "message": (
                    f"Possible user creation event: "
                    f"{username or 'username not identified'}"
                ),
                "username": username
            })

    brute_force_rule = rules.get("brute_force", {})

    if brute_force_rule.get("enabled", False):
        threshold = int(brute_force_rule.get("threshold", 5))
        severity = brute_force_rule.get("severity", "HIGH")

        for ip, attempts in failed_attempts.items():
            if len(attempts) >= threshold:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "severity": severity,
                    "message": (
                        f"Possible brute-force activity from {ip}. "
                        f"Failed attempts in collected logs: "
                        f"{len(attempts)}"
                    ),
                    "source_ip": ip,
                    "attempts": len(attempts)
                })

    return alerts
