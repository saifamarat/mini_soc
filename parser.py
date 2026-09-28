import re


def parse_log_line(line):

    event = {
        "event_type": "unknown",
        "username": None,
        "source_ip": None,
        "raw": line.strip()
    }

    # Failed SSH login
    failed = re.search(
        r"Failed password for (?:invalid user )?(\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)",
        line,
        re.IGNORECASE
    )

    if failed:
        event["event_type"] = "failed_login"
        event["username"] = failed.group(1)
        event["source_ip"] = failed.group(2)

        return event

    # Successful SSH login
    accepted = re.search(
        r"Accepted \S+ for (\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)",
        line,
        re.IGNORECASE
    )

    if accepted:
        event["event_type"] = "successful_login"
        event["username"] = accepted.group(1)
        event["source_ip"] = accepted.group(2)

        return event

    # Sudo session opened
    sudo_open = re.search(
        r"sudo.*session opened for user (\S+)",
        line,
        re.IGNORECASE
    )

    if sudo_open:
        event["event_type"] = "sudo_usage"
        event["username"] = sudo_open.group(1)

        return event

    # Sudo command execution
    sudo_command = re.search(
        r"sudo.*COMMAND=(.*)",
        line,
        re.IGNORECASE
    )

    if sudo_command:
        event["event_type"] = "sudo_usage"
        event["username"] = "root"

        return event

    # User creation
    if re.search(
        r"useradd|new user|new user:",
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
