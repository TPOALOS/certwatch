import contextlib
import io
import json
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


def cert(not_after, cn="example.com", issuer="Test CA", san=("example.com", "www.example.com")):
    return {"notAfter": not_after, "subject": ((("commonName", cn),),), "issuer": ((("organizationName", issuer),),),
            "subjectAltName": tuple(("DNS", n) for n in san) + (("IP Address", "10.0.0.1"),)}


def run_main(*argv, fetch):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = certwatch.main(list(argv), _fetch=fetch)
    return code, out.getvalue(), err.getvalue()


class InspectTests(unittest.TestCase):
    def test_details_extracted(self):
        r = certwatch.inspect("example.com", fetch=lambda h, p, t: cert("Jan  1 00:00:00 2031 GMT"), now=NOW)
        self.assertEqual((r["status"], r["subject"], r["issuer"]), ("OK", "example.com", "Test CA"))
        self.assertEqual(r["san"], ["example.com", "www.example.com"])  # IP SANs are not DNS names
        self.assertGreater(r["days_left"], 90)

    def test_legacy_two_argument_fetcher_still_works(self):
        r = certwatch.inspect("h", fetch=lambda h, p: cert("Jan  1 00:00:00 2031 GMT"), now=NOW)
        self.assertEqual(r["status"], "OK")

    def test_errors_become_results(self):
        def boom(h, p, t):
            raise socket.timeout("timed out")
        r = certwatch.inspect("h", fetch=boom)
        self.assertEqual((r["status"], r["days_left"]), ("ERROR", None))
        self.assertIn("timed out", r["detail"])

    def test_verification_failure_is_invalid(self):
        def bad(h, p, t):
            e = ssl.SSLCertVerificationError()
            e.verify_message = "self signed certificate"
            raise e
        r = certwatch.inspect("h", fetch=bad)
        self.assertEqual(r["status"], "INVALID")
        self.assertIn("self signed", r["detail"])

    def test_bad_port_is_error_not_crash(self):
        self.assertEqual(certwatch.inspect("host:notaport", fetch=lambda *a: {})["status"], "ERROR")

    def test_missing_not_after_is_error(self):
        self.assertEqual(certwatch.inspect("h", fetch=lambda h, p, t: {})["status"], "ERROR")

    def test_unexpected_type_error_in_fetcher_is_still_a_result(self):
        def broken(h, p, t=None):
            raise TypeError("boom")
        self.assertEqual(certwatch.inspect("h", fetch=broken)["status"], "ERROR")

    def test_name_helper(self):
        self.assertEqual(certwatch._name(None), "")
        self.assertEqual(certwatch._name(((("organizationName", "Org"),),)), "Org")


class NewCliTests(unittest.TestCase):
    FUTURE = "Jan  1 00:00:00 2099 GMT"
    PAST = "Jan  1 00:00:00 2001 GMT"

    def fetch(self, host, port, timeout):
        return cert(self.PAST if host.startswith("old") else self.FUTURE, cn=host)

    def test_json_output_and_order_preserved(self):
        targets = ["ok%d.example.com" % i for i in range(5)] + ["old.example.com"]
        code, out, _ = run_main(*targets, "--json", fetch=self.fetch)
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual([d["target"] for d in data], targets)
        self.assertEqual(data[-1]["status"], "EXPIRED")

    def test_all_ok_exit_zero(self):
        self.assertEqual(run_main("a.example.com", "b.example.com", fetch=self.fetch)[0], 0)

    def test_text_output_unchanged(self):
        _, out, _ = run_main("a.example.com", fetch=self.fetch)
        self.assertTrue(out.startswith("OK        a.example.com"))

    def test_timeout_is_passed_through(self):
        seen = []
        run_main("a.example.com", "--timeout", "3.5", fetch=lambda h, p, t: seen.append(t) or cert(self.FUTURE))
        self.assertEqual(seen, [3.5])

    def test_workers_flag_runs_in_parallel_without_losing_results(self):
        targets = ["h%d.example.com" % i for i in range(20)]
        code, out, _ = run_main(*targets, "--workers", "5", "--json", fetch=self.fetch)
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), 20)

    def test_workers_zero_or_negative_still_works(self):
        self.assertEqual(run_main("a.example.com", "--workers", "0", fetch=self.fetch)[0], 0)

    def test_crit_must_be_below_warn(self):
        code, _, err = run_main("a.example.com", "--warn", "5", "--crit", "10", fetch=self.fetch)
        self.assertEqual(code, 2)
        self.assertIn("--crit", err)

    def test_file_targets_and_comments(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "hosts.txt")
            with open(p, "w") as fh:
                fh.write("# production\na.example.com  # web\n\nold.example.com:8443\n")
            code, out, _ = run_main("-f", p, "--json", fetch=self.fetch)
        self.assertEqual([d["target"] for d in json.loads(out)], ["a.example.com", "old.example.com:8443"])

    def test_no_targets_is_usage_error(self):
        self.assertEqual(run_main(fetch=self.fetch)[0], 2)


if __name__ == "__main__":
    unittest.main()
