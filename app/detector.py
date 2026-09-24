from collections import defaultdict

from .config import BRUTE_FORCE_THRESHOLD


def detect_ssh_bruteforce(events):

    failed_attempts = defaultdict(list)

    for event in events:

        if event["event_type"] != "SSH_FAILED_LOGIN":
            continue

        source_ip = event["source_ip"]

        failed_attempts[source_ip].append(event)

    alerts = []

    for source_ip, attempts in failed_attempts.items():

        count = len(attempts)

        if count >= BRUTE_FORCE_THRESHOLD:

            usernames = set(
                event["username"]
                for event in attempts
                if event["username"]
            )

            alerts.append({
                "type": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": source_ip,
                "attempts": count,
                "usernames": list(usernames),
                "mitre": "T1110",
                "description": (
                    f"Detected {count} failed SSH "
                    f"authentication attempts from "
                    f"{source_ip}"
                )
            })

    return alerts


def detect_suspicious_sudo(events):

    alerts = []

    for event in events:

        if event["event_type"] != "SUDO_COMMAND":
            continue

        alerts.append({
            "type": "SUDO_ACTIVITY",
            "severity": "MEDIUM",
            "source_ip": None,
            "attempts": 1,
            "usernames": [],
            "mitre": "T1548.003",
            "description": event["message"]
        })

    return alerts


def detect(events):

    alerts = []

    alerts.extend(
        detect_ssh_bruteforce(events)
    )

    alerts.extend(
        detect_suspicious_sudo(events)
    )

    return alerts
