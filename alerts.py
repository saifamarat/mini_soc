from datetime import datetime

from config import ALERT_LOG_FILE


def display_alert(alert):

    print("\n" + "=" * 60)

    print(
        f"[ALERT] {alert['severity']} | "
        f"{alert['type']}"
    )

    print(
        f"Message: {alert['message']}"
    )

    if alert.get("source_ip"):

        print(
            f"Source IP: {alert['source_ip']}"
        )

    if alert.get("username"):

        print(
            f"Username: {alert['username']}"
        )

    print("=" * 60)


def save_alert(alert):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    line = (
        f"[{timestamp}] "
        f"[{alert['severity']}] "
        f"{alert['type']} - "
        f"{alert['message']}\n"
    )

    with open(
        ALERT_LOG_FILE,
        "a"
    ) as file:

        file.write(line)


def process_alerts(alerts):

    for alert in alerts:

        display_alert(alert)

        save_alert(alert)
