import hashlib
import socket
import tempfile
import unittest
from pathlib import Path

import vps_soc_analyzer as analyzer


class TestVPSSOCAnalyzer(unittest.TestCase):
    def test_extract_ip_from_failed_login(self) -> None:
        line = (
            "Sep 02 12:00:00 server sshd[1234]: Failed password for invalid "
            "user admin from 192.168.1.55 port 43210 ssh2"
        )
        self.assertEqual(analyzer.extract_ip(line), "192.168.1.55")

    def test_extract_ip_ignores_successful_login(self) -> None:
        line = "Accepted password for admin from 192.168.1.55 port 22 ssh2"
        self.assertIsNone(analyzer.extract_ip(line))

    def test_extract_ip_rejects_invalid_and_empty_lines(self) -> None:
        self.assertIsNone(
            analyzer.extract_ip("Failed password for root from 999.1.1.1 port 22")
        )
        self.assertIsNone(analyzer.extract_ip(""))

    def test_group_by_ip_counts_only_failed_logins(self) -> None:
        logs = [
            "Failed password for root from 1.1.1.1 port 22",
            "Failed password for admin from 1.1.1.1 port 22",
            "Failed password for guest from 2.2.2.2 port 22",
            "Accepted password for root from 1.1.1.1 port 22",
        ]
        self.assertEqual(analyzer.group_by_ip(logs), {"1.1.1.1": 2, "2.2.2.2": 1})

    def test_detect_brute_force_includes_exact_threshold(self) -> None:
        self.assertEqual(
            analyzer.detect_brute_force({"1.1.1.1": 5, "2.2.2.2": 4}),
            ["1.1.1.1"],
        )

    def test_detect_suspicious_paths_is_case_insensitive(self) -> None:
        self.assertTrue(analyzer.detect_suspicious_paths("GET /.ENV HTTP/1.1"))
        self.assertTrue(
            analyzer.detect_suspicious_paths("GET /search?q=select+union HTTP/1.1")
        )
        self.assertFalse(analyzer.detect_suspicious_paths("GET /index.html HTTP/1.1"))

    def test_calculate_risk_score_categories(self) -> None:
        self.assertEqual(analyzer.calculate_risk_score(0, 0), "LOW")
        self.assertEqual(analyzer.calculate_risk_score(1, 1), "MEDIUM")
        self.assertEqual(analyzer.calculate_risk_score(2, 0), "HIGH")

    def test_is_port_open_detects_local_listener(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            host, port = listener.getsockname()
            self.assertTrue(analyzer.is_port_open(host, port))

    def test_get_file_hash_reads_file_and_handles_missing_path(self) -> None:
        contents = b"configuration data" * 10000
        with tempfile.TemporaryDirectory() as temporary_directory:
            file_path = Path(temporary_directory) / "config.txt"
            file_path.write_bytes(contents)
            self.assertEqual(
                analyzer.get_file_hash(str(file_path)),
                hashlib.sha256(contents).hexdigest(),
            )
            self.assertEqual(
                analyzer.get_file_hash(str(file_path / "missing")),
                "FILE_NOT_FOUND",
            )


if __name__ == "__main__":
    unittest.main()
