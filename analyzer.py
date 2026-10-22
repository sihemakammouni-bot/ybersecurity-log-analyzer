
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
import re

LOG_FILE = Path("sample_logs.txt")
REPORT_FILE = Path("report.txt")

SUSPICIOUS_THRESHOLD = 3
TIME_WINDOW_MINUTES = 1

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"LOGIN (?P<status>SUCCESS|FAILED) "
    r"IP=(?P<ip>\S+)$"
)


def parse_log_line(line):
    """Parse one log line. Return None if its format is invalid."""
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"),
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "status": match.group("status"),
        "ip": match.group("ip"),
    }


def analyze_logs(lines):
    """Analyze log lines and return summary information."""
    events = []
    invalid_lines = 0

    for line in lines:
        if not line.strip():
            continue

        event = parse_log_line(line)

        if event is None:
            invalid_lines += 1
        else:
            events.append(event)

    failed_events = [
        event for event in events
        if event["status"] == "FAILED"
    ]

    failed_counts = Counter(
        event["ip"] for event in failed_events
    )

    suspicious_ips = {
        ip: count
        for ip, count in failed_counts.items()
        if count >= SUSPICIOUS_THRESHOLD
    }

    # Detect repeated failures within a time window.
    window_alerts = []
    events_by_ip = {}

    for event in failed_events:
        events_by_ip.setdefault(event["ip"], []).append(
            event["timestamp"]
        )

    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for ip, timestamps in events_by_ip.items():
        timestamps.sort()

        for start in range(len(timestamps)):
            end = start

            while (
                end < len(timestamps)
                and timestamps[end] - timestamps[start] <= window
            ):
                end += 1

            count = end - start

            if count >= SUSPICIOUS_THRESHOLD:
                window_alerts.append({
                    "ip": ip,
                    "count": count,
                    "start": timestamps[start],
                    "end": timestamps[end - 1],
                })
                break

    return {
        "total_events": len(events),
        "successful_logins": sum(
            event["status"] == "SUCCESS" for event in events
        ),
        "failed_logins": len(failed_events),
        "failed_counts": failed_counts,
        "suspicious_ips": suspicious_ips,
        "window_alerts": window_alerts,
        "invalid_lines": invalid_lines,
    }


def create_report(results):
    """Create a readable text report."""
    report = [
        "=== Cybersecurity Log Analyzer ===",
        "",
        f"Total valid events: {results['total_events']}",
        f"Successful logins: {results['successful_logins']}",
        f"Failed logins: {results['failed_logins']}",
        f"Invalid log lines: {results['invalid_lines']}",
        "",
        "=== Failed Attempts by IP ===",
    ]

    if results["failed_counts"]:
        for ip, count in sorted(results["failed_counts"].items()):
            report.append(f"{ip}: {count} failed attempts")
    else:
        report.append("No failed login attempts found.")

    report.extend([
        "",
        "=== Repeated Failure Alerts ===",
    ])

    if results["suspicious_ips"]:
        for ip, count in sorted(results["suspicious_ips"].items()):
            report.append(
                f"WARNING: {ip} has {count} failed attempts."
            )
    else:
        report.append("No IP reached the configured threshold.")

    report.extend([
        "",
        f"=== Failures Within {TIME_WINDOW_MINUTES} Minute(s) ===",
    ])

    if results["window_alerts"]:
        for alert in results["window_alerts"]:
            report.append(
                f"WARNING: {alert['ip']} had at least "
                f"{SUSPICIOUS_THRESHOLD} failures between "
                f"{alert['start']} and {alert['end']}."
            )
    else:
        report.append("No time-window alert detected.")

    report.extend([
        "",
        "Note: Alerts are indicators for review, not proof of an attack.",
    ])

    return "\n".join(report) + "\n"


def main():
    try:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            lines = file.readlines()
    except OSError as error:
        print(f"Error reading {LOG_FILE}: {error}")
        return

    results = analyze_logs(lines)
    report = create_report(results)

    try:
        REPORT_FILE.write_text(report, encoding="utf-8")
    except OSError as error:
        print(f"Error saving report: {error}")
        return

    print(report)
    print(f"Report saved to {REPORT_FILE.resolve()}")


if __name__ == "__main__":
    main()

