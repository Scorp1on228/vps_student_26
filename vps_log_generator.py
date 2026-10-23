import random


def generate_mock_ssh_logs(num_lines: int = 100) -> list[str]:
    """Generate sample SSH authentication log lines."""
    if num_lines < 0:
        raise ValueError("num_lines must be non-negative")

    random_source = random.Random()
    source_ips = ("203.0.113.15", "198.51.100.27", "192.0.2.42", "10.0.0.8")
    users = ("root", "admin", "guest", "student")
    lines: list[str] = []
    for index in range(num_lines):
        ip_address = random_source.choice(source_ips)
        username = random_source.choice(users)
        outcome = "Accepted" if index % 7 == 0 else "Failed"
        lines.append(
            f"Oct 23 18:00:00 vps sshd[1234]: {outcome} password for "
            f"{username} from {ip_address} port 43210 ssh2"
        )
    return lines


def generate_mock_nginx_logs(num_lines: int = 50) -> list[str]:
    """Generate sample normal and suspicious Nginx access log lines."""
    if num_lines < 0:
        raise ValueError("num_lines must be non-negative")

    random_source = random.Random()
    source_ips = ("203.0.113.15", "198.51.100.27", "192.0.2.42")
    requests = (
        ("GET", "/index.html", 200),
        ("GET", "/assets/site.css", 200),
        ("GET", "/.env", 404),
        ("GET", "/etc/passwd", 404),
        ("GET", "/wp-admin/", 404),
        ("GET", "/search?q=select+union", 400),
        ("GET", "/shell.php", 404),
    )
    lines: list[str] = []
    for index in range(num_lines):
        ip_address = random_source.choice(source_ips)
        method, path, status = requests[index % len(requests)]
        lines.append(
            f'{ip_address} - - [23/Oct/2026:18:00:{index % 60:02d} +0000] '
            f'"{method} {path} HTTP/1.1" {status} 150'
        )
    return lines
