from collector import collect_logs
from parser import parse_logs
from detector import detect_events
from alerts import process_alerts


def main():

    print("\n" + "=" * 60)
    print("                 MINI SOC V2")
    print("=" * 60)

    print("\n[*] Collecting system logs...")

    raw_logs = collect_logs()

    if not raw_logs:

        print(
            "[!] No logs were collected."
        )

        return

    print(
        f"[+] Collected {len(raw_logs)} log lines."
    )

    print(
        "\n[*] Parsing security events..."
    )

    events = parse_logs(raw_logs)

    print(
        f"[+] Security events detected: "
        f"{len(events)}"
    )

    print(
        "\n[*] Running detection engine..."
    )

    alerts = detect_events(events)

    print(
        f"[+] Alerts generated: "
        f"{len(alerts)}"
    )

    if alerts:

        process_alerts(alerts)

    else:

        print(
            "\n[+] No security alerts detected."
        )

    print(
        "\n[+] Mini SOC V2 scan completed."
    )


if __name__ == "__main__":
    main()
