import sqlite3
from datetime import datetime

LOG_FILE = "logs/network.log"
DATABASE = "reports/security_events.db"
REPORT_FILE = "reports/security_report.txt"

total_connections = 0
successful_connections = 0
failed_connections = 0

failed_by_ip = {}
ports_by_ip = {}
connections_by_ip = {}

with open(LOG_FILE, "r") as file:
    for line in file:
        line = line.strip()

        if not line:
            continue

        parts = [part.strip() for part in line.split("|")]

        if len(parts) != 6:
            continue

        timestamp, source_ip, destination_ip, protocol, port, status = parts

        total_connections += 1
        connections_by_ip[source_ip] = connections_by_ip.get(source_ip, 0) + 1

        if status == "SUCCESS":
            successful_connections += 1

        elif status == "FAILED":
            failed_connections += 1
            failed_by_ip[source_ip] = failed_by_ip.get(source_ip, 0) + 1

        if source_ip not in ports_by_ip:
            ports_by_ip[source_ip] = set()

        ports_by_ip[source_ip].add(port)


# Detect security alerts
alerts = []

for source_ip, count in failed_by_ip.items():
    if count >= 3:
        alerts.append({
            "severity": "MEDIUM",
            "event_type": "Multiple Failed Connections",
            "source_ip": source_ip,
            "details": f"{count} failed attempts"
        })


for source_ip, ports in ports_by_ip.items():
    if len(ports) >= 4:
        sorted_ports = sorted(ports, key=int)

        alerts.append({
            "severity": "HIGH",
            "event_type": "Possible Port Scan",
            "source_ip": source_ip,
            "details": f"{len(ports)} unique ports: {', '.join(sorted_ports)}"
        })


# Connect to SQLite database
connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at TEXT,
    severity TEXT,
    event_type TEXT,
    source_ip TEXT,
    details TEXT
)
""")


# Insert only new alerts
inserted_alerts = 0

for alert in alerts:
    cursor.execute("""
    SELECT id
    FROM security_events
    WHERE severity = ?
    AND event_type = ?
    AND source_ip = ?
    AND details = ?
    """, (
        alert["severity"],
        alert["event_type"],
        alert["source_ip"],
        alert["details"]
    ))

    existing_event = cursor.fetchone()

    if existing_event is None:
        cursor.execute("""
        INSERT INTO security_events (
            detected_at,
            severity,
            event_type,
            source_ip,
            details
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            alert["severity"],
            alert["event_type"],
            alert["source_ip"],
            alert["details"]
        ))

        inserted_alerts += 1


connection.commit()


# Generate security report
with open(REPORT_FILE, "w") as report:

    report.write("NETWORK SECURITY ANALYSIS REPORT\n")
    report.write("=" * 50 + "\n\n")

    report.write(
        "Report Generated: "
        + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        + "\n\n"
    )

    # Traffic summary
    report.write("TRAFFIC SUMMARY\n")
    report.write("-" * 30 + "\n")

    report.write(f"Total Connections: {total_connections}\n")
    report.write(f"Successful Connections: {successful_connections}\n")
    report.write(f"Failed Connections: {failed_connections}\n\n")

    # Source IP summary
    report.write("SOURCE IP SUMMARY\n")
    report.write("-" * 30 + "\n")

    for source_ip in sorted(connections_by_ip):

        failed = failed_by_ip.get(source_ip, 0)
        unique_ports = len(ports_by_ip.get(source_ip, set()))

        if unique_ports >= 4:
            risk = "HIGH"
        elif failed >= 3:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        report.write(
            f"{source_ip} | "
            f"Connections: {connections_by_ip[source_ip]} | "
            f"Failed: {failed} | "
            f"Unique Ports: {unique_ports} | "
            f"Risk: {risk}\n"
        )

    report.write("\n")

    # Security alerts
    report.write("SECURITY ALERTS\n")
    report.write("-" * 30 + "\n")

    if alerts:
        for alert in alerts:
            report.write(
                f"[{alert['severity']}] "
                f"{alert['event_type']} | "
                f"{alert['source_ip']} | "
                f"{alert['details']}\n"
            )
    else:
        report.write("No security alerts detected.\n")


connection.close()


# Console output
print()
print("Network Security Analysis Complete")
print("----------------------------------")
print(f"Total connections: {total_connections}")
print(f"Successful connections: {successful_connections}")
print(f"Failed connections: {failed_connections}")
print(f"Detected alerts: {len(alerts)}")
print(f"New alerts inserted: {inserted_alerts}")
print()
print("Report saved to:")
print(REPORT_FILE)
print()
print("Database saved to:")
print(DATABASE)