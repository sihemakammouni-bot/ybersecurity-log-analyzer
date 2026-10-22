
import unittest
from datetime import datetime

from analyzer import analyze_logs, parse_log_line


class TestLogAnalyzer(unittest.TestCase):

    def test_parse_valid_log(self):
        line = (
            "2026-10-22 09:00:00 "
            "LOGIN FAILED IP=203.0.113.5"
        )

        result = parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["ip"], "203.0.113.5")

    def test_rejects_invalid_log(self):
        result = parse_log_line("This is not a valid log")
        self.assertIsNone(result)

    def test_counts_failed_attempts(self):
        logs = [
            "2026-10-22 09:00:00 LOGIN FAILED IP=203.0.113.5",
            "2026-10-22 09:00:10 LOGIN FAILED IP=203.0.113.5",
            "2026-10-22 09:00:20 LOGIN FAILED IP=203.0.113.5",
            "2026-10-22 09:01:00 LOGIN SUCCESS IP=192.168.1.10",
        ]

        result = analyze_logs(logs)

        self.assertEqual(result["failed_logins"], 3)
        self.assertEqual(result["failed_counts"]["203.0.113.5"], 3)
        self.assertIn("203.0.113.5", result["suspicious_ips"])

    def test_detects_failures_within_time_window(self):
        logs = [
            "2026-10-22 09:00:00 LOGIN FAILED IP=203.0.113.5",
            "2026-10-22 09:00:20 LOGIN FAILED IP=203.0.113.5",
            "2026-10-22 09:00:40 LOGIN FAILED IP=203.0.113.5",
        ]

        result = analyze_logs(logs)

        self.assertEqual(len(result["window_alerts"]), 1)
        self.assertEqual(
            result["window_alerts"][0]["ip"],
            "203.0.113.5"
        )

    def test_empty_logs(self):
        result = analyze_logs([])

        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["failed_logins"], 0)
        self.assertEqual(result["suspicious_ips"], {})

    def test_counts_invalid_lines(self):
        logs = [
            "This line is invalid",
            "2026-10-22 09:00:00 LOGIN FAILED IP=203.0.113.5",
        ]

        result = analyze_logs(logs)

        self.assertEqual(result["invalid_lines"], 1)
        self.assertEqual(result["total_events"], 1)


if __name__ == "__main__":
    unittest.main()
