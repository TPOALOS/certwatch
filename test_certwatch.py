import os
import socket
import ssl
import tempfile
import unittest

import certwatch

NOW = ssl.cert_time_to_seconds("Jun  1 00:00:00 2030 GMT")


def fake_fetch(not_after):
    return lambda host, port: not_after


class ParseTests(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(certwatch.parse_target("example.com"), ("example.com", 443))
        self.assertEqual(certwatch.parse_target("example.com:8443"), ("example.com", 8443))
        self.assertEqual(certwatch.parse_target("[::1]:9000"), ("::1", 9000))
        self.assertEqual(certwatch.parse_target("[::1]"), ("::1", 443))

    def test_days_left(self):
        d = certwatch.days_left("Jun 11 00:00:00 2030 GMT", now=NOW)
        self.assertAlmostEqual(d, 10.0)

    def test_classify(self):
        self.assertEqual(certwatch.classify(-1), "EXPIRED")
        self.assertEqual(certwatch.classify(3), "CRITICAL")
        self.assertEqual(certwatch.classify(20), "WARNING")
        self.assertEqual(certwatch.classify(90), "OK")
        self.assertEqual(certwatch.classify(20, warn=10), "OK")


class CheckTests(unittest.TestCase):
    def test_ok(self):
        s, d = certwatch.check("h", fetch=fake_fetch("Jan  1 00:00:00 2031 GMT"), now=NOW)
        self.assertEqual(s, "OK")

    def test_warning(self):
        s, _ = certwatch.check("h", fetch=fake_fetch("Jun 21 00:00:00 2030 GMT"), now=NOW)
        self.assertEqual(s, "WARNING")

    def test_expired(self):
        s, _ = certwatch.check("h", fetch=fake_fetch("May  1 00:00:00 2030 GMT"), now=NOW)
        self.assertEqual(s, "EXPIRED")

    def test_network_error(self):
        def boom(host, port):
            raise socket.timeout("timed out")
        s, d = certwatch.check("h", fetch=boom)
        self.assertEqual(s, "ERROR")
        self.assertIn("timed out", d)

    def test_verification_failure(self):
        def bad(host, port):
            e = ssl.SSLCertVerificationError(1, "verify failed")
            e.verify_message = "certificate has expired"
            raise e
        s, d = certwatch.check("h", fetch=bad)
        self.assertEqual(s, "INVALID")
        self.assertIn("expired", d)

    def test_bad_port(self):
        s, _ = certwatch.check("h:notaport", fetch=fake_fetch("Jan  1 00:00:00 2031 GMT"))
        self.assertEqual(s, "ERROR")


class CliTests(unittest.TestCase):
    def test_no_targets(self):
        self.assertEqual(certwatch.main([]), 2)

    def test_missing_file(self):
        self.assertEqual(certwatch.main(["-f", "/nonexistent/targets.txt"]), 2)

    def test_unreachable_local_port(self):
        # Port 1 on localhost: connection refused -> ERROR -> exit 1 (no external network).
        self.assertEqual(certwatch.main(["localhost:1"]), 1)


if __name__ == "__main__":
    unittest.main()
