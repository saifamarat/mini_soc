from collector import collect_logs
from parser import parse_logs
from detector import detect_events
from alerts import process_alerts
from report import create_html_report


def main():
    print("\n" + "=" * 60)
    print("                 MINI SOC V3")
    print("=" * 60)

    print("\n[*] Collecting system logs...")
    raw_logs = collect_logs()
    print(f"[+] Collected {len(raw_logs)} log lines.")

    print("\n[*] Parsing security events...")
    events = parse_logs(raw_logs)
    print(f"[+] Security events detected: {len(events)}")

    print("\n[*] Running detection engine...")
    alerts = detect_events(events)
    print(f"[+] Alerts generated: {len(alerts)}")

    if alerts:
        process_alerts(alerts)
    else:
        print("[+] No security alerts detected.")

    print("\n[*] Generating HTML report...")

    try:
        create_html_report(events, alerts)
    except OSError as error:
        print(f"[!] Could not generate HTML report: {error}")
        return

    print("\n[+] Mini SOC V3 scan completed.")


if __name__ == "__main__":
    main()
