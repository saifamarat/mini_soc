from datetime import datetime

from config import ALERT_LOG_FILE


def display_alert(alert):
    print("\n" + "=" * 60)
    print(
        f"[ALERT] {alert.get('severity', 'UNKNOWN')} | "
        f"{alert.get('type', 'UNKNOWN')}"
    )
    print(f"Message: {alert.get('message', '')}")

    if alert.get("source_ip"):
        print(f"Source IP: {alert['source_ip']}")

    if alert.get("username"):
        print(f"Username: {alert['username']}")

    if alert.get("attempts") is not None:
        print(f"Failed attempts: {alert['attempts']}")

    print("=" * 60)


def save_alert(alert):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = (
        f"[{timestamp}] "
        f"[{alert.get('severity', 'UNKNOWN')}] "
        f"{alert.get('type', 'UNKNOWN')} - "
        f"{alert.get('message', '')}\n"
    )

    with open(
        ALERT_LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:
        file.write(line)


def process_alerts(alerts):
    for alert in alerts:
        display_alert(alert)

        try:
            save_alert(alert)
        except OSError as error:
            print(f"[!] Could not save alert: {error}")
