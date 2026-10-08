"""
webscan.py - a small tool that checks a website and its API for common weaknesses.

It runs 16 checks in four groups (settings and headers, cookies, access,
responses) and writes a report that explains each failed check and how to fix it.

Only scan websites you own or have written permission to test.
Webscan refuses any website that is not on your own computer unless you
add --i-have-permission.
"""

import argparse
import datetime
import ipaddress
import re
import sys
from urllib.parse import urlparse

import requests

TIMEOUT = 10  # seconds to wait for each request

GROUP_HEADERS = "Settings and headers"
GROUP_COOKIES = "Cookies"
GROUP_ACCESS = "Access"
GROUP_RESPONSES = "Responses"
GROUP_ORDER = [GROUP_HEADERS, GROUP_COOKIES, GROUP_ACCESS, GROUP_RESPONSES]

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIPPED"

# A reply with these "key: value" words may be leaking private data.
SECRET_PATTERN = re.compile(
    r"""["']?\w*(?:password|passwd|pwd|secret|api[_-]?key|private[_-]?key)\w*["']?\s*[:=]""",
    re.IGNORECASE,
)
# Words that show the inside of a program in an error page.
INTERNALS_PATTERN = re.compile(
    r"""Traceback|File\s+["'].+\.py|\.py["'],?\s+line\s+\d+|werkzeug|stack\s?trace|
        Exception\b|SQLSTATE|ORA-\d+|at\s+\S+\(\S+:\d+\)""",
    re.IGNORECASE | re.VERBOSE,
)
VERSION_PATTERN = re.compile(r"\d+\.\d+")

REDIRECT_OR_DENIED = (301, 302, 303, 307, 308, 401, 403, 404)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

class Result(object):
    def __init__(self, group, name, status, seen, fix):
        self.group = group
        self.name = name
        self.status = status
        self.seen = seen
        self.fix = fix


def short(text, limit=200):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "..."


def is_local(url):
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def get(url, cookie=None, **kwargs):
    headers = {"Cookie": cookie} if cookie else {}
    return requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False, **kwargs)


def set_cookie_headers(resp):
    """All Set-Cookie lines from a reply (there can be more than one)."""
    try:
        return resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        value = resp.headers.get("Set-Cookie")
        return [value] if value else []


def cookie_header_from(set_cookies):
    """Build a Cookie header (name=value) from Set-Cookie lines."""
    pairs = [line.split(";")[0].strip() for line in set_cookies if "=" in line]
    return "; ".join(pairs) if pairs else None


class Scanner(object):
    def __init__(self, base_url, user1, order1, order2,
                 login_path, orders_path, admin_path):
        self.base = base_url.rstrip("/")
        self.user1 = user1  # (username, password)
        self.order1 = order1
        self.order2 = order2
        self.login_path = login_path
        self.orders_path = orders_path
        self.admin_path = admin_path
        self.results = []
        self.bodies = []          # every reply body we saw (for the secrets check)
        self.login_set_cookies = []
        self.cookie1 = None       # logged-in cookie for user 1

    def url(self, path):
        return self.base + path

    def add(self, group, name, status, seen, fix):
        self.results.append(Result(group, name, status, seen, fix))

    def note_body(self, resp):
        self.bodies.append(resp.text)

    # ---- login -----------------------------------------------------------

    def login(self, username, password):
        return requests.post(
            self.url(self.login_path),
            json={"username": username, "password": password},
            timeout=TIMEOUT, allow_redirects=False,
        )

    def do_login_user1(self):
        try:
            resp = self.login(*self.user1)
            self.note_body(resp)
            self.login_set_cookies = set_cookie_headers(resp)
            if resp.status_code == 200 and self.login_set_cookies:
                self.cookie1 = cookie_header_from(self.login_set_cookies)
        except requests.RequestException:
            pass

    # ---- group 1: settings and headers -----------------------------------

    def check_headers(self):
        try:
            resp = get(self.url("/"))
        except requests.RequestException as err:
            for name in ["Content-Security-Policy", "Strict-Transport-Security",
                         "X-Content-Type-Options", "Clickjacking protection",
                         "Referrer-Policy", "Server version hidden"]:
                self.add(GROUP_HEADERS, name, SKIP, "Could not load the home page: %s" % err, "")
            return
        h = resp.headers

        def header_check(name, header, fix, ok=lambda v: bool(v)):
            value = h.get(header)
            if value and ok(value):
                self.add(GROUP_HEADERS, name, PASS, "%s: %s" % (header, short(value)), "")
            else:
                seen = "Header '%s' is missing." % header if not value else "%s: %s" % (header, value)
                self.add(GROUP_HEADERS, name, FAIL, seen, fix)

        header_check(
            "Content-Security-Policy is set", "Content-Security-Policy",
            "Add a Content-Security-Policy header. It tells the browser which sources of "
            "scripts and images are allowed, which helps stop injected code. "
            "A simple start is: default-src 'self'.")
        header_check(
            "Strict-Transport-Security is set", "Strict-Transport-Security",
            "Add a Strict-Transport-Security header (for example max-age=31536000) so browsers "
            "always use the secure https version of the website.",
            ok=lambda v: "max-age" in v.lower())
        header_check(
            "X-Content-Type-Options is nosniff", "X-Content-Type-Options",
            "Add the header X-Content-Type-Options: nosniff so browsers do not guess file types.",
            ok=lambda v: v.strip().lower() == "nosniff")

        csp = h.get("Content-Security-Policy", "")
        if h.get("X-Frame-Options") or "frame-ancestors" in csp.lower():
            self.add(GROUP_HEADERS, "Clickjacking protection is set", PASS,
                     "X-Frame-Options: %s" % h.get("X-Frame-Options", "(frame-ancestors in CSP)"), "")
        else:
            self.add(GROUP_HEADERS, "Clickjacking protection is set", FAIL,
                     "Neither X-Frame-Options nor a frame-ancestors rule was found.",
                     "Add X-Frame-Options: DENY (or a frame-ancestors rule) so other websites "
                     "cannot show your pages inside a hidden frame to trick users.")

        header_check(
            "Referrer-Policy is set", "Referrer-Policy",
            "Add a Referrer-Policy header (for example no-referrer) so your web addresses "
            "are not leaked to other websites.")

        leaks = []
        for name in ("Server", "X-Powered-By"):
            value = h.get(name)
            if value and VERSION_PATTERN.search(value):
                leaks.append("%s: %s" % (name, value))
        if leaks:
            self.add(GROUP_HEADERS, "Server version is hidden", FAIL, "; ".join(leaks),
                     "Remove the version numbers from the Server and X-Powered-By headers. "
                     "Attackers use them to look up known problems for that exact version.")
        else:
            self.add(GROUP_HEADERS, "Server version is hidden", PASS,
                     "No version number found in Server or X-Powered-By.", "")

    # ---- group 2: cookies ------------------------------------------------

    def check_cookies(self):
        names = ["Cookies are HttpOnly", "Cookies are Secure", "Cookies have SameSite"]
        if not self.login_set_cookies:
            for n in names:
                self.add(GROUP_COOKIES, n, SKIP,
                         "No cookie was seen. The login did not work or the website sets no cookie.", "")
            return

        def flag_check(name, test, fix):
            bad = []
            for line in self.login_set_cookies:
                parts = [p.strip().lower() for p in line.split(";")]
                if not test(parts):
                    bad.append(line.split("=")[0])
            if bad:
                self.add(GROUP_COOKIES, name, FAIL, "Cookie(s) missing it: %s" % ", ".join(bad), fix)
            else:
                self.add(GROUP_COOKIES, name, PASS, "All %d cookie(s) have it." % len(self.login_set_cookies), "")

        flag_check(names[0], lambda p: "httponly" in p,
                   "Add the HttpOnly flag to every cookie so scripts on the page cannot read it.")
        flag_check(names[1], lambda p: "secure" in p,
                   "Add the Secure flag to every cookie so it is only sent over https.")
        flag_check(names[2], lambda p: any(x.startswith("samesite=") for x in p),
                   "Add SameSite=Strict (or Lax) to every cookie so other websites cannot "
                   "make the browser send it.")

    # ---- group 3: access -------------------------------------------------

    def check_access(self):
        order1_url = self.url("%s/%s" % (self.orders_path, self.order1))
        order2_url = self.url("%s/%s" % (self.orders_path, self.order2))
        admin_url = self.url(self.admin_path)

        # A1: an order cannot be read without logging in
        try:
            r = get(order1_url)
            self.note_body(r)
            if r.status_code in REDIRECT_OR_DENIED:
                self.add(GROUP_ACCESS, "Orders need a login", PASS, "Without logging in, got status %d." % r.status_code, "")
            else:
                self.add(GROUP_ACCESS, "Orders need a login", FAIL,
                         "Without logging in, got status %d and: %s" % (r.status_code, short(r.text)),
                         "Check on the server that the person is logged in before returning any order.")
        except requests.RequestException as err:
            self.add(GROUP_ACCESS, "Orders need a login", SKIP, "Request failed: %s" % err, "")

        # A2: one user cannot read another user's order
        if self.cookie1:
            try:
                r = get(order2_url, cookie=self.cookie1)
                self.note_body(r)
                if r.status_code == 200:
                    self.add(GROUP_ACCESS, "Users cannot read other users' orders", FAIL,
                             "%s asked for order %s (not theirs) and got status 200: %s"
                             % (self.user1[0], self.order2, short(r.text)),
                             "On every request, check that the order belongs to the logged-in user "
                             "(not just that the user is logged in). Return 403 or 404 otherwise.")
                else:
                    self.add(GROUP_ACCESS, "Users cannot read other users' orders", PASS,
                             "Asking for someone else's order got status %d." % r.status_code, "")
            except requests.RequestException as err:
                self.add(GROUP_ACCESS, "Users cannot read other users' orders", SKIP, "Request failed: %s" % err, "")
        else:
            self.add(GROUP_ACCESS, "Users cannot read other users' orders", SKIP,
                     "Could not log in as %s." % self.user1[0], "")

        # A3: a normal user cannot open the admin page
        if self.cookie1:
            try:
                r = get(admin_url, cookie=self.cookie1)
                self.note_body(r)
                if r.status_code in REDIRECT_OR_DENIED:
                    self.add(GROUP_ACCESS, "Normal users cannot open the admin page", PASS,
                             "A normal user got status %d." % r.status_code, "")
                else:
                    self.add(GROUP_ACCESS, "Normal users cannot open the admin page", FAIL,
                             "%s (a normal user) opened the admin page: status %d, %s"
                             % (self.user1[0], r.status_code, short(r.text)),
                             "Check the user's role on the server before showing any admin page. "
                             "Hiding the link is not enough.")
            except requests.RequestException as err:
                self.add(GROUP_ACCESS, "Normal users cannot open the admin page", SKIP, "Request failed: %s" % err, "")
        else:
            self.add(GROUP_ACCESS, "Normal users cannot open the admin page", SKIP,
                     "Could not log in as %s." % self.user1[0], "")

        # A4: the admin page needs a login
        try:
            r = get(admin_url)
            self.note_body(r)
            if r.status_code in REDIRECT_OR_DENIED:
                self.add(GROUP_ACCESS, "The admin page needs a login", PASS,
                         "Without logging in, got status %d." % r.status_code, "")
            else:
                self.add(GROUP_ACCESS, "The admin page needs a login", FAIL,
                         "Without logging in, got status %d: %s" % (r.status_code, short(r.text)),
                         "Require a login before showing the admin page.")
        except requests.RequestException as err:
            self.add(GROUP_ACCESS, "The admin page needs a login", SKIP, "Request failed: %s" % err, "")

    # ---- group 4: responses ----------------------------------------------

    def check_responses(self):
        # R1: login errors do not reveal which users exist
        name = "Login errors do not reveal which users exist"
        try:
            unknown = self.login("no_such_user_xyz", "wrong-password-123")
            wrong = self.login(self.user1[0], "wrong-password-123")
            self.note_body(unknown)
            self.note_body(wrong)
            same = (unknown.status_code == wrong.status_code
                    and " ".join(unknown.text.split()) == " ".join(wrong.text.split()))
            if same:
                self.add(GROUP_RESPONSES, name, PASS, "Both bad logins got the same reply: %s" % short(unknown.text), "")
            else:
                self.add(GROUP_RESPONSES, name, FAIL,
                         "Unknown user: %d %s | Real user, wrong password: %d %s"
                         % (unknown.status_code, short(unknown.text), wrong.status_code, short(wrong.text)),
                         "Give the same error for an unknown user and a wrong password, for example "
                         "'Invalid username or password'.")
        except requests.RequestException as err:
            self.add(GROUP_RESPONSES, name, SKIP, "Request failed: %s" % err, "")

        # R2: error pages do not show internal details
        name = "Error pages do not show internal details"
        if self.cookie1:
            try:
                r = get(self.url("%s/not-a-number" % self.orders_path), cookie=self.cookie1)
                self.note_body(r)
                hit = INTERNALS_PATTERN.search(r.text)
                if hit:
                    self.add(GROUP_RESPONSES, name, FAIL,
                             "A bad request (status %d) showed internal details: %s" % (r.status_code, short(r.text)),
                             "Turn off debug output. Show users a short, generic error and write the "
                             "details to a private log instead.")
                else:
                    self.add(GROUP_RESPONSES, name, PASS,
                             "A bad request got status %d with no internal details." % r.status_code, "")
            except requests.RequestException as err:
                self.add(GROUP_RESPONSES, name, SKIP, "Request failed: %s" % err, "")
        else:
            self.add(GROUP_RESPONSES, name, SKIP, "Could not log in as %s." % self.user1[0], "")

        # R3: replies do not contain passwords or secrets
        name = "Replies do not contain passwords or secrets"
        found = []
        for body in self.bodies:
            m = SECRET_PATTERN.search(body)
            if m:
                found.append(m.group(0).strip())
        if found:
            self.add(GROUP_RESPONSES, name, FAIL,
                     "Found private-looking fields in replies: %s" % ", ".join(sorted(set(found))),
                     "Never send passwords, keys or secrets to the browser. Remove those fields "
                     "from the reply.")
        else:
            self.add(GROUP_RESPONSES, name, PASS,
                     "Checked %d replies. No password or secret fields found." % len(self.bodies), "")

    # ---- run everything --------------------------------------------------

    def run(self):
        self.do_login_user1()
        self.check_headers()
        self.check_cookies()
        self.check_access()
        self.check_responses()
        self.results.sort(key=lambda r: GROUP_ORDER.index(r.group))  # stable: keeps order inside a group
        return self.results


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def build_report(target, results):
    passed = sum(1 for r in results if r.status == PASS)
    failed = sum(1 for r in results if r.status == FAIL)
    skipped = sum(1 for r in results if r.status == SKIP)
    lines = []
    lines.append("# Webscan report")
    lines.append("")
    lines.append("- Target: %s" % target)
    lines.append("- Date: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    lines.append("- Result: %d passed, %d failed, %d skipped (out of %d checks)"
                 % (passed, failed, skipped, len(results)))
    lines.append("")
    lines.append("A passing report does not mean a website is fully secure. "
                 "Webscan only checks a short list of well-known weaknesses.")
    lines.append("")
    for group in GROUP_ORDER:
        lines.append("## %s" % group)
        lines.append("")
        for r in [x for x in results if x.group == group]:
            lines.append("- [%s] %s" % (r.status, r.name))
            if r.status == FAIL:
                lines.append("    - What was seen: %s" % r.seen)
                lines.append("    - How to fix it: %s" % r.fix)
            elif r.status == SKIP:
                lines.append("    - Why skipped: %s" % r.seen)
        lines.append("")
    return "\n".join(lines), failed


def parse_user(text):
    if ":" not in text:
        raise argparse.ArgumentTypeError("use the form username:password")
    username, password = text.split(":", 1)
    return username, password


def main():
    p = argparse.ArgumentParser(description="Webscan: check a website and its API for common weaknesses.")
    p.add_argument("target", help="website address, for example http://127.0.0.1:5000")
    p.add_argument("--i-have-permission", action="store_true",
                   help="confirm you own the website or have written permission to test it "
                        "(needed for any website that is not on your own computer)")
    p.add_argument("--user1", type=parse_user, default=("alice", "alice-pass"),
                   help="a normal (non-admin) user, as username:password (default alice:alice-pass)")
    p.add_argument("--order1", default="1", help="id of an order that belongs to the user (default 1)")
    p.add_argument("--order2", default="2", help="id of an order that belongs to a different user (default 2)")
    p.add_argument("--login-path", default="/api/login")
    p.add_argument("--orders-path", default="/api/orders")
    p.add_argument("--admin-path", default="/admin")
    p.add_argument("--report", default="webscan_report.md", help="file to write the report to")
    args = p.parse_args()

    parsed = urlparse(args.target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print("Error: the target must start with http:// or https://")
        return 2

    if not is_local(args.target) and not args.i_have_permission:
        print("Refused: %s is not on your own computer." % parsed.hostname)
        print("Only scan websites you own or have written permission to test.")
        print("If you do, run again with --i-have-permission")
        return 2

    print("Scanning %s ..." % args.target)
    scanner = Scanner(args.target, args.user1, args.order1, args.order2,
                      args.login_path, args.orders_path, args.admin_path)
    try:
        results = scanner.run()
    except requests.RequestException as err:
        print("Error: could not reach the website: %s" % err)
        return 2

    report, failed = build_report(args.target, results)
    print(report)
    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print("\nReport saved to %s" % args.report)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
