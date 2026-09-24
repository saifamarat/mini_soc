from .collector import collect_logs
from .parser import parse_logs
from .detector import detect


def print_event(event):

    print("\n[EVENT]")

    print(f"Type:     {event['event_type']}")
    print(f"Username: {event['username']}")
    print(f"Source:   {event['source_ip']}")


def print_alert(alert):

    print("\n" + "=" * 60)

    print("[ALERT]")

    print(f"Type:       {alert['type']}")
    print(f"Severity:   {alert['severity']}")
    print(f"Source IP:  {alert['source_ip']}")
    print(f"Attempts:   {alert['attempts']}")
    print(f"MITRE:      {alert['mitre']}")

    print(
        f"Description: "
        f"{alert['description']}"
    )

    print("=" * 60)


def main():

    print("=" * 60)
    print("        MINI SOC ")
    print("=" * 60)

    print("\n[*] Collecting logs...")

    records = collect_logs()

    print(
        f"[*] Collected records: "
        f"{len(records)}"
    )

    print("\n[*] Parsing logs...")

    events = parse_logs(records)

    print(
        f"[*] Security events: "
        f"{len(events)}"
    )

    print("\n[*] Running detection engine...")

    alerts = detect(events)

    print(
        f"[*] Alerts generated: "
        f"{len(alerts)}"
    )

    for event in events[:10]:
        print_event(event)

    for alert in alerts:
        print_alert(alert)

    print("\n[*] SOC analysis completed.")


if __name__ == "__main__":
    main()
