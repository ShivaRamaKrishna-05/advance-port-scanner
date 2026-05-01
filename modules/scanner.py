import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
from utils.database import get_db

scanner_bp = Blueprint("scanner", __name__)


COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9000: "PHP-FPM",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def login_required():
    return session.get("user_id") is not None


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def get_risk(port):
    high = [21, 22, 23, 25, 135, 139, 445, 3389, 5432, 3306, 6379, 27017]
    low = [53, 80, 110, 123, 143, 443, 587, 993, 995]
    if port in high:
        return "High"
    if port in low:
        return "Low"
    return "Medium"


def scan_single_port(target, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = COMMON_PORTS.get(port, "unknown")

            return {
                "port": port,
                "status": "open",
                "service": service,
                "version": "Unknown",
                "protocol": "TCP",
                "response_time": "-",
                "risk": get_risk(port)
            }
        return None
    except Exception:
        return None
    finally:
        sock.close()


def perform_scan(target, start_port, end_port, max_workers=200):
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_single_port, target, port): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


@scanner_bp.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()

    recent_scans = db.execute(
        """
        SELECT id, scan_name, target, resolved_ip, port_range, total_open_ports, is_favorite, created_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        (session["user_id"],)
    ).fetchall()

    total_scans = db.execute(
        "SELECT COUNT(*) AS count FROM scans WHERE user_id = ?",
        (session["user_id"],)
    ).fetchone()["count"]

    favorite_scans = db.execute(
        "SELECT COUNT(*) AS count FROM scans WHERE user_id = ? AND is_favorite = 1",
        (session["user_id"],)
    ).fetchone()["count"]

    total_open_ports = db.execute(
        "SELECT COALESCE(SUM(total_open_ports), 0) AS total FROM scans WHERE user_id = ?",
        (session["user_id"],)
    ).fetchone()["total"]

    return render_template(
        "dashboard/home.html",
        recent_scans=recent_scans,
        total_scans=total_scans,
        favorite_scans=favorite_scans,
        total_open_ports=total_open_ports
    )


@scanner_bp.route("/newscan")
def newscan():
    if not login_required():
        return redirect(url_for("auth.login"))
    return render_template("dashboard/newscan.html")


@scanner_bp.route("/history")
def history():
    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()
    scans = db.execute(
        """
        SELECT id, scan_name, target, resolved_ip, port_range, total_open_ports, is_favorite, notes, created_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    return render_template("dashboard/history.html", scans=scans)


@scanner_bp.route("/saved")
def saved_scans():
    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()
    scans = db.execute(
        """
        SELECT id, scan_name, target, resolved_ip, port_range, total_open_ports, is_favorite, notes, created_at
        FROM scans
        WHERE user_id = ? AND is_favorite = 1
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    return render_template("dashboard/saved.html", scans=scans)


@scanner_bp.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()

    scan = db.execute(
        """
        SELECT *
        FROM scans
        WHERE id = ? AND user_id = ?
        """,
        (scan_id, session["user_id"])
    ).fetchone()

    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("scanner.history"))

    results = db.execute(
        """
        SELECT *
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY port ASC
        """,
        (scan_id,)
    ).fetchall()

    return render_template("dashboard/scan_detail.html", scan=scan, results=results)


@scanner_bp.route("/start-scan", methods=["POST"])
def start_scan():
    if not login_required():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    target = request.form.get("target", "").strip()
    start_port = request.form.get("start_port", "").strip()
    end_port = request.form.get("end_port", "").strip()
    scan_name = request.form.get("scan_name", "").strip()
    notes = request.form.get("notes", "").strip()

    if not target or not start_port or not end_port:
        return jsonify({"success": False, "message": "All required fields must be filled."}), 400

    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except ValueError:
        return jsonify({"success": False, "message": "Ports must be numbers."}), 400

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        return jsonify({"success": False, "message": "Invalid port range."}), 400

    resolved_ip = resolve_target(target)
    if not resolved_ip:
        return jsonify({"success": False, "message": "Could not resolve target host."}), 400

    results = perform_scan(resolved_ip, start_port, end_port)
    total_open_ports = len(results)

    if not scan_name:
        scan_name = f"Scan {target} [{start_port}-{end_port}]"

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO scans (user_id, scan_name, target, resolved_ip, port_range, total_open_ports, is_favorite, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            scan_name,
            target,
            resolved_ip,
            f"{start_port}-{end_port}",
            total_open_ports,
            0,
            notes,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
    )

    scan_id = cursor.lastrowid

    for row in results:
        db.execute(
            """
            INSERT INTO scan_results (scan_id, port, status, service, version, protocol, response_time, risk)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                row["port"],
                row["status"],
                row["service"],
                row["version"],
                row["protocol"],
                row["response_time"],
                row["risk"]
            )
        )

    db.commit()

    return jsonify({
        "success": True,
        "message": "Scan completed successfully.",
        "scan_id": scan_id,
        "scan_name": scan_name,
        "target": target,
        "resolved_ip": resolved_ip,
        "total_open_ports": total_open_ports,
        "results": results,
    })


@scanner_bp.route("/scan/<int:scan_id>/favorite", methods=["POST"])
def toggle_favorite(scan_id):
    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()
    scan = db.execute(
        "SELECT is_favorite FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, session["user_id"])
    ).fetchone()

    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("scanner.history"))

    new_value = 0 if scan["is_favorite"] == 1 else 1

    db.execute(
        "UPDATE scans SET is_favorite = ? WHERE id = ? AND user_id = ?",
        (new_value, scan_id, session["user_id"])
    )
    db.commit()

    flash("Scan updated successfully.", "success")
    return redirect(request.referrer or url_for("scanner.history"))


@scanner_bp.route("/scan/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()

    db.execute(
        "DELETE FROM scan_results WHERE scan_id = ?",
        (scan_id,)
    )
    db.execute(
        "DELETE FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, session["user_id"])
    )
    db.commit()

    flash("Scan deleted successfully.", "success")
    return redirect(request.referrer or url_for("scanner.history"))


@scanner_bp.route("/scan/<int:scan_id>/notes", methods=["POST"])
def update_notes(scan_id):
    if not login_required():
        return redirect(url_for("auth.login"))

    notes = request.form.get("notes", "").strip()
    db = get_db()

    db.execute(
        "UPDATE scans SET notes = ? WHERE id = ? AND user_id = ?",
        (notes, scan_id, session["user_id"])
    )
    db.commit()

    flash("Notes updated successfully.", "success")
    return redirect(url_for("scanner.scan_detail", scan_id=scan_id))