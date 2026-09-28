from collections import defaultdict
import json

from config import RULES_FILE


def load_rules():

    try:

        with open(RULES_FILE, "r") as file:
            return json.load(file)

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):

        print("[!] Could not load rules.json.")
        return {}


def detect_events(events):

    rules = load_rules()

    alerts = []

    failed_attempts = defaultdict(list)

    for event in events:

        event_type = event["event_type"]

        rule = rules.get(event_type, {})

        if not rule.get("enabled", False):
            continue

        severity = rule.get(
            "severity",
            "LOW"
        )

        if event_type == "failed_login":

            ip = event.get("source_ip")

            if ip:
                failed_attempts[ip].append(event)

            alerts.append({
                "type": "FAILED_LOGIN",
                "severity": severity,
                "message": (
                    f"Failed login detected for "
                    f"user '{event.get('username')}' "
                    f"from {ip}"
                ),
                "source_ip": ip,
                "username": event.get("username")
            })

        elif event_type == "successful_login":

            alerts.append({
                "type": "SUCCESSFUL_LOGIN",
                "severity": severity,
                "message": (
                    f"Successful login detected for "
                    f"user '{event.get('username')}' "
                    f"from {event.get('source_ip')}"
                ),
                "source_ip": event.get("source_ip"),
                "username": event.get("username")
            })

        elif event_type == "sudo_usage":

            alerts.append({
                "type": "SUDO_USAGE",
                "severity": severity,
                "message": (
                    f"Sudo activity detected "
                    f"for user '{event.get('username')}'"
                ),
                "username": event.get("username")
            })

        elif event_type == "user_creation":

            alerts.append({
                "type": "USER_CREATION",
                "severity": severity,
                "message": "New user creation detected"
            })

    # Brute force detection
    brute_force_rule = rules.get(
        "brute_force",
        {}
    )

    if brute_force_rule.get(
        "enabled",
        False
    ):

        threshold = brute_force_rule.get(
            "threshold",
            5
        )

        severity = brute_force_rule.get(
            "severity",
            "HIGH"
        )

        for ip, attempts in failed_attempts.items():

            if len(attempts) >= threshold:

                alerts.append({
                    "type": "BRUTE_FORCE",
                    "severity": severity,
                    "message": (
                        f"Possible brute-force attack detected "
                        f"from {ip}. "
                        f"Failed attempts: {len(attempts)}"
                    ),
                    "source_ip": ip,
                    "attempts": len(attempts)
                })

    return alerts
