
import os
import sqlite3
import csv
import subprocess
import sys
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, Response
)

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
DATABASE = os.path.join(
    BASE_DIR, "reports", "security_events.db"
)
LOG_FILE = os.path.join(BASE_DIR, "logs", "network.log")

app = Flask(__name__, template_folder=TEMPLATES_DIR)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "local-development-only-change-this"
)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_events():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT *
            FROM security_events
            ORDER BY id DESC
        """)
        return cursor.fetchall()
    finally:
        connection.close()


def get_ip_summary():
    connections_by_ip = {}
    failed_by_ip = {}
    ports_by_ip = {}

    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
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

            ports_by_ip.setdefault(source_ip, set()).add(port)

    ip_summary = []

    for source_ip in sorted(connections_by_ip):
        connections = connections_by_ip[source_ip]
        failed = failed_by_ip.get(source_ip, 0)
        unique_ports = len(ports_by_ip.get(source_ip, set()))

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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Temporary local demo login; not production authentication.
        expected_username = os.environ.get(
            "DEMO_USERNAME", "labuser"
        )
        expected_password = os.environ.get(
            "DEMO_PASSWORD", "LabTest123!"
        )

        if (
            username == expected_username
            and password == expected_password
        ):
            session.clear()
            session["logged_in"] = True
            session["username"] = username
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


@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    events = get_events()
    ip_summary = get_ip_summary()

    total_events = len(events)
    high_alerts = sum(
        1 for event in events
        if event["severity"] == "HIGH"
    )
    medium_alerts = sum(
        1 for event in events
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


@app.route("/export")
@login_required
def export_events():
    events = get_events()

    response = Response(
        "",
        mimetype="text/csv"
    )
    response.headers["Content-Disposition"] = (
        "attachment; filename=security_events.csv"
    )

    # Use Python's CSV writer to safely quote CSV fields.
    from io import StringIO
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID", "Detected At", "Severity",
        "Event Type", "Source IP", "Details"
    ])

    for event in events:
        writer.writerow([
            event["id"],
            event["detected_at"],
            event["severity"],
            event["event_type"],
            event["source_ip"],
            event["details"]
        ])

    response.set_data(output.getvalue())
    return response


@app.route("/run-analysis")
@login_required
def run_analysis():
    script_path = os.path.join(BASE_DIR, "src", "log_analyzer.py")

    if not os.path.isfile(script_path):
        return "Analysis script not found.", 404

    result = subprocess.run(
        [sys.executable, script_path],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        timeout=60
    )

    if result.returncode != 0:
        app.logger.error("Analysis failed: %s", result.stderr)
        return "Analysis failed. Check the application terminal logs.", 500

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
