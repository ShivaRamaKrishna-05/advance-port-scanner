import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    flash,
)

from utils.database import get_db
from utils.geolocation import get_ip_info
from utils.os_detection import detect_os

scanner_bp = Blueprint("scanner", __name__)


COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
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

    high = [21,22,23,135,139,445,3306,3389,6379,27017]
    low = [53,80,110,143,443]

    if port in high:
        return "High"

    if port in low:
        return "Low"

    return "Medium"


def get_vulnerability(port):

    vulns = {
        21: "FTP insecure",
        23: "Telnet insecure",
        445: "SMB vulnerable",
        3306: "MySQL exposed",
        3389: "RDP exposed",
    }

    return vulns.get(port, "No major issue")


def scan_single_port(target, port, timeout=0.5):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:

        result = sock.connect_ex((target, port))

        if result == 0:

            try:
                service = socket.getservbyport(port)

            except OSError:
                service = COMMON_PORTS.get(port, "Unknown")

            return {
                "port": port,
                "status": "Open",
                "service": service,
                "version": "Unknown",
                "protocol": "TCP",
                "response_time": "-",
                "risk": get_risk(port),
                "os": detect_os(64),
                "vulnerability": get_vulnerability(port),
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
            executor.submit(
                scan_single_port,
                target,
                port
            ): port

            for port in range(
                start_port,
                end_port + 1
            )
        }

        for future in as_completed(futures):

            result = future.result()

            if result:
                open_ports.append(result)

    open_ports.sort(
        key=lambda x: x["port"]
    )

    return open_ports


@scanner_bp.route("/dashboard")
def dashboard():

    if not login_required():
        return redirect(
            url_for("auth.login")
        )

    db = get_db()

    recent_scans = db.execute(
        """
        SELECT *
        FROM scans
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 5
        """,
        (session["user_id"],)
    ).fetchall()

    total_scans = db.execute(
        """
        SELECT COUNT(*) count
        FROM scans
        WHERE user_id=?
        """,
        (session["user_id"],)
    ).fetchone()["count"]

    return render_template(
        "dashboard/home.html",
        recent_scans=recent_scans,
        total_scans=total_scans
    )


@scanner_bp.route("/newscan")
def newscan():

    if not login_required():
        return redirect(url_for("auth.login"))

    return render_template(
        "dashboard/newscan.html"
    )


@scanner_bp.route("/history")
def history():

    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()

    scans = db.execute(
        """
        SELECT *
        FROM scans
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    return render_template(
        "dashboard/history.html",
        scans=scans
    )


@scanner_bp.route("/saved_scans")
def saved_scans():

    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()

    scans = db.execute(
        """
        SELECT *
        FROM scans
        WHERE user_id=?
        AND is_favorite=1
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    return render_template(
        "dashboard/saved_scans.html",
        scans=scans
    )


@scanner_bp.route("/scan/<int:scan_id>")
def scan_detail(scan_id):

    if not login_required():
        return redirect(url_for("auth.login"))

    db = get_db()

    scan = db.execute(
        """
        SELECT *
        FROM scans
        WHERE id=?
        AND user_id=?
        """,
        (scan_id, session["user_id"])
    ).fetchone()

    results = db.execute(
        """
        SELECT *
        FROM scan_results
        WHERE scan_id=?
        ORDER BY port ASC
        """,
        (scan_id,)
    ).fetchall()

    return render_template(
        "dashboard/scan_detail.html",
        scan=scan,
        results=results
    )


@scanner_bp.route("/start-scan", methods=["POST"])
def start_scan():

    if not login_required():

        return jsonify(
            success=False
        ), 401

    target = request.form.get(
        "target"
    ).strip()

    start_port = int(
        request.form.get("start_port")
    )

    end_port = int(
        request.form.get("end_port")
    )

    scan_name = request.form.get(
        "scan_name"
    ).strip()

    notes = request.form.get(
        "notes"
    ).strip()

    resolved_ip = resolve_target(target)

    if not resolved_ip:

        return jsonify(
            success=False,
            message="Invalid target"
        )

    geo = get_ip_info(resolved_ip)
    if geo is None:
        geo = {}
    country = geo.get("country", "Unknown")
    city = geo.get("city", "Unknown")
    isp = geo.get("org", "Unknown")
    latitude = geo.get("lat", "Unknown")
    longitude = geo.get("lon", "Unknown")
    
    results = perform_scan(
        resolved_ip,
        start_port,
        end_port
    )

    db = get_db()

    cursor = db.execute(
        """
         INSERT INTO scans(
             user_id,
             scan_name,
             target,
             resolved_ip,
             port_range,
             total_open_ports,
             is_favorite,
             notes,
             country,
             city,
             isp,
             latitude,
             longitude,
             created_at
         )
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                session["user_id"],
                scan_name or target,
                target,
                resolved_ip,
                f"{start_port}-{end_port}",
                len(results),
                0,
                notes,
                country,
                city,
                isp,
                latitude,
                longitude,
                datetime.now()
                )
                )

    scan_id = cursor.lastrowid

    for row in results:

        db.execute(
            """
            INSERT INTO scan_results(
            scan_id,
            port,
            status,
            service,
            version,
            protocol,
            response_time,
            risk,
            os,
            vulnerability
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                scan_id,
                row["port"],
                row["status"],
                row["service"],
                row["version"],
                row["protocol"],
                row["response_time"],
                row["risk"],
                row["os"],
                row["vulnerability"],
            )
        )

    db.commit()

    return jsonify(
    success=True,

    message="Scan completed successfully",

    scan_id=scan_id,

    scan_name=scan_name or target,

    resolved_ip=resolved_ip,

    hostname=target,

    total_open_ports=len(results),

    threads=request.form.get("threads"),

    os=detect_os(64),

    geo=geo,

    results=results
)


@scanner_bp.route(
"/scan/<int:scan_id>/favorite",
methods=["POST"]
)
def toggle_favorite(scan_id):

    db = get_db()

    scan = db.execute(
        """
        SELECT is_favorite
        FROM scans
        WHERE id=?
        AND user_id=?
        """,
        (
            scan_id,
            session["user_id"]
        )
    ).fetchone()

    if not scan:

        flash("Not found")
        return redirect(
            url_for("scanner.history")
        )

    value = 0 if scan["is_favorite"] else 1

    db.execute(
        """
        UPDATE scans
        SET is_favorite=?
        WHERE id=?
        """,
        (value, scan_id)
    )

    db.commit()

    return redirect(
        url_for("scanner.saved_scans")
    )


@scanner_bp.route(
"/scan/<int:scan_id>/delete",
methods=["POST"]
)
def delete_scan(scan_id):

    db = get_db()

    db.execute(
        "DELETE FROM scan_results WHERE scan_id=?",
        (scan_id,)
    )

    db.execute(
        "DELETE FROM scans WHERE id=?",
        (scan_id,)
    )

    db.commit()

    flash(
        "Deleted",
        "success"
    )

    return redirect(
        request.referrer
    )


@scanner_bp.route(
"/scan/<int:scan_id>/update-notes",
methods=["POST"]
)
def update_notes(scan_id):

    notes = request.form.get(
        "notes"
    )

    db = get_db()

    db.execute(
        """
        UPDATE scans
        SET notes=?
        WHERE id=?
        """,
        (notes, scan_id)
    )

    db.commit()

    return redirect(
        url_for(
            "scanner.scan_detail",
            scan_id=scan_id
        )
    )