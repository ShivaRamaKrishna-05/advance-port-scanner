import socket
import time

TOP_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MONGODB"
}

HIGH_RISK_PORTS = {21, 23, 69, 111, 135, 137, 138, 139, 445, 1433, 1521, 3306, 3389}
MEDIUM_RISK_PORTS = {25, 53, 80, 110, 143, 389, 587, 8080}


def parse_ports_input(text):
    ports = set()
    parts = [p.strip() for p in text.split(",") if p.strip()]

    for part in parts:
        if "-" in part:
            start, end = part.split("-", 1)
            start_port = int(start)
            end_port = int(end)
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Invalid port range.")
            for p in range(start_port, end_port + 1):
                ports.add(p)
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535.")
            ports.add(port)

    return sorted(ports)


def resolve_scan_ports(scan_type, custom_ports):
    if custom_ports:
        return custom_ports

    if scan_type == "quick":
        return [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]

    if scan_type == "top":
        return sorted(TOP_PORTS.keys())

    if scan_type == "full":
        return list(range(1, 1025))

    return [21, 22, 80, 443]


def detect_service_name(port):
    return TOP_PORTS.get(port, "Unknown")


def classify_risk(port, status):
    if status != "OPEN":
        return "LOW"
    if port in HIGH_RISK_PORTS:
        return "HIGH"
    if port in MEDIUM_RISK_PORTS:
        return "MEDIUM"
    return "LOW"


def probe_port(target, port):
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.35)

    try:
        result = sock.connect_ex((target, port))
        elapsed_ms = int((time.perf_counter() - start) * 1000)

        status = "OPEN" if result == 0 else "CLOSED"
        service = detect_service_name(port)

        version = "-"
        if status == "OPEN" and port in (80, 8080, 443, 21, 22, 25):
            version = "Detected"

        return {
            "port": port,
            "status": status,
            "service": service,
            "version": version,
            "protocol": "TCP",
            "response_time": f"{elapsed_ms}ms",
            "risk": classify_risk(port, status)
        }
    except socket.gaierror:
        raise ValueError("Target could not be resolved.")
    except Exception:
        return {
            "port": port,
            "status": "CLOSED",
            "service": detect_service_name(port),
            "version": "-",
            "protocol": "TCP",
            "response_time": "-",
            "risk": "LOW"
        }
    finally:
        sock.close()


def run_scan(target, scan_type, custom_ports=None):
    ports_to_scan = resolve_scan_ports(scan_type, custom_ports)
    results = [probe_port(target, port) for port in ports_to_scan]

    open_count = sum(1 for row in results if row["status"] == "OPEN")
    high_risk_count = sum(1 for row in results if row["risk"] == "HIGH" and row["status"] == "OPEN")

    summary = {
        "total_ports": len(results),
        "open_ports": open_count,
        "high_risk": high_risk_count,
        "scanned_range": (
            ",".join(map(str, custom_ports)) if custom_ports else
            "Top Ports" if scan_type == "top" else
            "1-1024" if scan_type == "full" else
            "Quick Common Ports"
        )
    }

    return results, summary