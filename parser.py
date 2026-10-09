import re


IP_PATTERN = r"(\d{1,3}(?:\.\d{1,3}){3})"


def parse_log_line(line):
    event = {
        "event_type": "unknown",
        "username": None,
        "source_ip": None,
        "raw": line.strip()
    }

    # Failed SSH login
    failed = re.search(
        r"Failed password for (?:invalid user )?"
        r"(\S+) from " + IP_PATTERN,
        line,
        re.IGNORECASE
    )

    if failed:
        event["event_type"] = "failed_login"
        event["username"] = failed.group(1)
        event["source_ip"] = failed.group(2)
        return event

    # Invalid SSH user
    invalid_user = re.search(
        r"Invalid user (\S+) from " + IP_PATTERN,
        line,
        re.IGNORECASE
    )

    if invalid_user:
        event["event_type"] = "failed_login"
        event["username"] = invalid_user.group(1)
        event["source_ip"] = invalid_user.group(2)
        return event

    # Successful SSH login
    accepted = re.search(
        r"Accepted \S+ for (\S+) from " + IP_PATTERN,
        line,
        re.IGNORECASE
    )

    if accepted:
        event["event_type"] = "successful_login"
        event["username"] = accepted.group(1)
        event["source_ip"] = accepted.group(2)
        return event

    # Sudo command execution
    sudo_command = re.search(
        r"sudo.*COMMAND=",
        line,
        re.IGNORECASE
    )

    if sudo_command:
        event["event_type"] = "sudo_usage"

        user_match = re.search(
            r"\bUSER=(\S+)",
            line
        )

        event["username"] = (
            user_match.group(1) if user_match else None
        )

        return event

    # Sudo session opened
    sudo_session = re.search(
        r"sudo.*session opened for user (\S+)",
        line,
        re.IGNORECASE
    )

    if sudo_session:
        event["event_type"] = "sudo_usage"
        event["username"] = sudo_session.group(1)
        return event

    # User creation
    user_created = re.search(
        r"useradd.*(?:name=|user )(\S+)",
        line,
        re.IGNORECASE
    )

    if user_created:
        event["event_type"] = "user_creation"
        event["username"] = user_created.group(1).rstrip(",")
        return event

    if re.search(
        r"new user:",
        line,
        re.IGNORECASE
    ):
        event["event_type"] = "user_creation"
        return event

    return event


def parse_logs(lines):
    events = []

    for line in lines:
        event = parse_log_line(line)

        if event["event_type"] != "unknown":
            events.append(event)

    return events
