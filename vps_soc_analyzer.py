import hashlib
import ipaddress
import re
import socket


def extract_ip(log_line: str) -> str | None:
    """Return the IPv4 address from a failed SSH password log, if present."""
    if "Failed password" not in log_line:
        return None

    match = re.search(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})(?=\s|$)", log_line)
    if match is None:
        return None

    ip_address = match.group(1)
    try:
        ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        return None
    return ip_address


def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """Count failed SSH attempts by source IP address."""
    ip_counts: dict[str, int] = {}
    for log_line in log_lines:
        ip_address = extract_ip(log_line)
        if ip_address is not None:
            ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1
    return ip_counts


def detect_brute_force(ip_counts: dict[str, int], threshold: int = 5) -> list[str]:
    """Return IPs with at least threshold failed SSH attempts."""
    return [
        ip_address
        for ip_address, count in ip_counts.items()
        if count >= threshold
    ]


def detect_suspicious_paths(log_line: str) -> bool:
    """Detect the web attack signatures specified in the lab instructions."""
    signatures = (
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
        "union+select",
        "shell.php",
    )
    normalized_line = log_line.lower()
    return any(signature in normalized_line for signature in signatures)


def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    """Map weighted SSH and web alert counts to a risk category."""
    risk_score = brute_force_alerts * 3 + web_alerts
    if risk_score == 0:
        return "LOW"
    if risk_score < 5:
        return "MEDIUM"
    return "HIGH"


def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check whether a TCP port accepts a connection, closing the socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            return connection.connect_ex((ip, port)) == 0
    except (OSError, ValueError):
        return False


def get_file_hash(filepath: str) -> str:
    """Return a file's SHA-256 digest, reading in chunks."""
    file_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as file:
            for block in iter(lambda: file.read(65536), b""):
                file_hash.update(block)
    except FileNotFoundError:
        return "FILE_NOT_FOUND"
    return file_hash.hexdigest()
