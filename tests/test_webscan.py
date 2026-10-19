"""
Small automated tests for webscan.py.

They start a tiny fake website on your own computer (it is NOT Juice Shop) and
check that Webscan reacts correctly. Run them with either:

    python -m unittest discover -s tests -v
    python -m pytest tests -v
"""

import http.server
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import webscan  # noqa: E402

HOME_PAGE = b"<!doctype html><html><head><title>Fake shop</title></head><body>app</body></html>"
GOOD_LOGIN = {"email": "test@example.com", "password": "pass12345"}


class FakeShop(http.server.BaseHTTPRequestHandler):
    """A single-page app that logs in with a token and has no cookies."""

    def log_message(self, *args):
        pass

    def send(self, status, body, ctype="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/rest/user/login":
            if data.get("email") == GOOD_LOGIN["email"] and data.get("password") == GOOD_LOGIN["password"]:
                body = {"authentication": {"token": "tok123", "bid": 6}}
                self.send(200, json.dumps(body).encode(), "application/json")
            else:
                self.send(401, b"Invalid email or password.", "text/plain")
        else:
            self.send(404, b"no", "text/plain")

    def do_GET(self):
        authed = self.headers.get("Authorization") == "Bearer tok123"
        if self.path.startswith("/api/orders"):
            self.send(500, b"<html><body>Error: Unexpected path</body></html>")
        elif self.path.startswith("/rest/basket/"):
            if authed:
                self.send(200, b'{"status":"success","data":{"id":1}}', "application/json")
            else:
                self.send(401, b"Unauthorized", "text/plain")
        else:
            self.send(200, HOME_PAGE)  # every other address shows the home page


def start_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), FakeShop)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def by_name(results):
    return {r.name: r for r in results}


class PermissionTests(unittest.TestCase):
    def test_local_addresses_are_local(self):
        self.assertTrue(webscan.is_local("http://127.0.0.1:3000"))
        self.assertTrue(webscan.is_local("http://localhost:3000"))

    def test_other_addresses_are_not_local(self):
        self.assertFalse(webscan.is_local("http://example.com"))
        self.assertFalse(webscan.is_local("http://192.168.1.10"))

    def test_remote_target_is_refused_without_permission(self):
        old_argv = sys.argv
        sys.argv = ["webscan.py", "http://example.com"]
        try:
            self.assertEqual(webscan.main(), 2)
        finally:
            sys.argv = old_argv


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start_server()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def scan(self, user, **kw):
        s = webscan.Scanner(self.base, user, kw.get("order1", "1"), kw.get("order2", "2"),
                            "/rest/user/login", kw.get("orders_path", "/api/orders"),
                            "/admin", login_field="email", auth="bearer")
        return s, by_name(s.run())

    def test_token_login_works(self):
        s, _ = self.scan(("test@example.com", "pass12345"))
        self.assertTrue(s.logged_in)

    def test_bad_login_is_skipped_not_crashed(self):
        s, res = self.scan(("test@example.com", "wrong"))
        self.assertFalse(s.logged_in)
        self.assertEqual(res["Normal users cannot open the admin page"].status, webscan.SKIP)

    def test_single_page_app_admin_is_inconclusive_not_fail(self):
        _, res = self.scan(("test@example.com", "pass12345"))
        self.assertEqual(res["The admin page needs a login"].status, webscan.INCONCLUSIVE)
        self.assertEqual(res["Normal users cannot open the admin page"].status, webscan.INCONCLUSIVE)

    def test_server_error_orders_is_inconclusive_not_fail(self):
        _, res = self.scan(("test@example.com", "pass12345"))
        self.assertEqual(res["Orders need a login"].status, webscan.INCONCLUSIVE)

    def test_reading_another_users_basket_is_a_fail(self):
        _, res = self.scan(("test@example.com", "pass12345"),
                           orders_path="/rest/basket", order1="6", order2="1")
        self.assertEqual(res["Orders need a login"].status, webscan.PASS)
        self.assertEqual(res["Users cannot read other users' orders"].status, webscan.FAIL)

    def test_missing_headers_fail_and_nosniff_passes(self):
        _, res = self.scan(("test@example.com", "pass12345"))
        self.assertEqual(res["Content-Security-Policy is set"].status, webscan.FAIL)
        self.assertEqual(res["X-Content-Type-Options is nosniff"].status, webscan.PASS)

    def test_reports_include_new_status_and_name(self):
        s, _ = self.scan(("test@example.com", "pass12345"))
        text, _ = webscan.build_report(self.base, s.results, name="Fake shop")
        self.assertIn("inconclusive", text)
        self.assertIn("- Name: Fake shop", text)
        data = json.loads(webscan.build_json(self.base, s.results, name="Fake shop"))
        self.assertEqual(len(data["checks"]), 16)


if __name__ == "__main__":
    unittest.main()
