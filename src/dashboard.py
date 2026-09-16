import os
import sqlite3
import csv
from flask import Flask, render_template, request, redirect, url_for, session, Response

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
DATABASE = os.path.join(BASE_DIR, "reports", "security_events.db")
LOG_FILE = os.path.join(BASE_DIR, "logs", "network.log")

app = Flask(__name__, template_folder=TEMPLATES_DIR)
app.secret_key = "network-security-demo-key"


def get_events():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()
    connection.close()

    return events


def get_ip_summary():

    connections_by_ip = {}
    failed_by_ip = {}
    ports_by_ip = {}

    with open(LOG_FILE, "r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            parts = [part.strip() for part in line.split("|")]

            if len(parts) != 6:
                continue

            timestamp, source_ip, destination_ip, protocol, port, status = parts

            connections_by_ip[source_ip] = (
                connections_by_ip.get(source_ip, 0) + 1
            )

            if status == "FAILED":

                failed_by_ip[source_ip] = (
                    failed_by_ip.get(source_ip, 0) + 1
                )

            if source_ip not in ports_by_ip:
                ports_by_ip[source_ip] = set()

            ports_by_ip[source_ip].add(port)

    ip_summary = []

    for source_ip in sorted(connections_by_ip):

        connections = connections_by_ip[source_ip]

        failed = failed_by_ip.get(source_ip, 0)

        unique_ports = len(
            ports_by_ip.get(source_ip, set())
        )

        if unique_ports >= 4:
            risk = "HIGH"

        elif failed >= 3:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        ip_summary.append({
            "source_ip": source_ip,
            "connections": connections,
            "failed": failed,
            "unique_ports": unique_ports,
            "risk": risk
        })

    return ip_summary


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "admin123":

            session["logged_in"] = True

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


@app.route("/export")
def export_events():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    events = get_events()

    output = []

    header = [
        "ID",
        "Detected At",
        "Severity",
        "Event Type",
        "Source IP",
        "Details"
    ]

    output.append(header)

    for event in events:

        output.append([
            event["id"],
            event["detected_at"],
            event["severity"],
            event["event_type"],
            event["source_ip"],
            event["details"]
        ])

    response = Response(
        "\n".join(
            ",".join(
                '"' + str(value).replace('"', '""') + '"'
                for value in row
            )
            for row in output
        ),
        mimetype="text/csv"
    )

    response.headers["Content-Disposition"] = (
        "attachment; filename=security_events.csv"
    )

    return response

@app.route("/run-analysis")
def run_analysis():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    os.system("python src/log_analyzer.py")

    return redirect(url_for("dashboard"))
@app.route("/")
def dashboard():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    events = get_events()

    ip_summary = get_ip_summary()

    total_events = len(events)

    high_alerts = sum(
        1
        for event in events
        if event["severity"] == "HIGH"
    )

    medium_alerts = sum(
        1
        for event in events
        if event["severity"] == "MEDIUM"
    )

    return render_template(
        "dashboard.html",
        events=events,
        ip_summary=ip_summary,
        total_events=total_events,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts
    )


if __name__ == "__main__":
    app.run(debug=True)