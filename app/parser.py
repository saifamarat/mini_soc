import re


SSH_FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<ip>\S+)"
)

SSH_SUCCESS_PATTERN = re.compile(
    r"Accepted \S+ for "
    r"(?P<username>\S+) from "
    r"(?P<ip>\S+)"
)

INVALID_USER_PATTERN = re.compile(
    r"Invalid user "
    r"(?P<username>\S+) from "
    r"(?P<ip>\S+)"
)

SUDO_PATTERN = re.compile(
    r"sudo.*?:\s+(?P<message>.*)"
)


def parse_log(record):

    raw = record["raw"]

    event = {
        "source": record["source"],
        "raw": raw,
        "event_type": "UNKNOWN",
        "username": None,
        "source_ip": None,
        "message": raw
    }

    # Failed SSH login
    match = SSH_FAILED_PATTERN.search(raw)

    if match:

        event["event_type"] = "SSH_FAILED_LOGIN"
        event["username"] = match.group("username")
        event["source_ip"] = match.group("ip")

        return event

    # Successful SSH login
    match = SSH_SUCCESS_PATTERN.search(raw)

    if match:

        event["event_type"] = "SSH_SUCCESS_LOGIN"
        event["username"] = match.group("username")
        event["source_ip"] = match.group("ip")

        return event

    # Invalid SSH user
    match = INVALID_USER_PATTERN.search(raw)

    if match:

        event["event_type"] = "SSH_INVALID_USER"
        event["username"] = match.group("username")
        event["source_ip"] = match.group("ip")

        return event

    # Sudo
    match = SUDO_PATTERN.search(raw)

    if match:

        event["event_type"] = "SUDO_COMMAND"
        event["message"] = match.group("message")

        return event

    return event


def parse_logs(records):

    events = []

    for record in records:

        event = parse_log(record)

        if event["event_type"] != "UNKNOWN":
            events.append(event)

    return events
