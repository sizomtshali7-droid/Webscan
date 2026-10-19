# Webscan: Test Results

## Test setup

| Item | Value |
|---|---|
| Computer | Windows 10 version 1709 (build 16299.1087) |
| Python | 3.14.8 (64-bit) in a virtual environment |
| Packages | Flask 3.1.3, Requests 2.34.2, Werkzeug 3.1.9 |
| Target | The included practice website at `http://127.0.0.1:5000` |
| Weak scan | 9 October 2026, 15:04 |
| Fixed scan | 9 October 2026, 16:45 |

During development the same checks were also run on Linux with Python 3.12 and gave the same results.

## Result at a glance

| Practice website | Passed | Failed | Skipped | Expected |
|---|---|---|---|---|
| Weak version | 1 | 15 | 0 | 15 of 16 fail |
| Fixed version | 16 | 0 | 0 | 16 of 16 pass |

Webscan can tell the weak site from the fixed site, which is what the Week 1 plan set out to show.

## Result for each check

| ID | Check | Weak | Fixed | What Webscan saw on the weak site |
|---|---|---|---|---|
| H1 | Content-Security-Policy is set | FAIL | PASS | Header missing |
| H2 | Strict-Transport-Security is set | FAIL | PASS | Header missing |
| H3 | X-Content-Type-Options is nosniff | FAIL | PASS | Header missing |
| H4 | Clickjacking protection is set | FAIL | PASS | No X-Frame-Options and no frame-ancestors rule |
| H5 | Referrer-Policy is set | FAIL | PASS | Header missing |
| H6 | Server version is hidden | FAIL | PASS | `Server: Werkzeug/3.1.9 Python/3.14.8` and `X-Powered-By: Flask 3.0.0` |
| C1 | Cookies are HttpOnly | FAIL | PASS | `session` cookie missing the flag |
| C2 | Cookies are Secure | FAIL | PASS | `session` cookie missing the flag |
| C3 | Cookies have SameSite | FAIL | PASS | `session` cookie missing the flag |
| A1 | Orders need a login | FAIL | PASS | Status 200 with order data, including `owner_password` and `internal_api_key`, without logging in |
| A2 | Users cannot read other users' orders | FAIL | PASS | alice asked for order 2 (not hers) and got status 200 |
| A3 | Normal users cannot open the admin page | FAIL | PASS | alice (a normal user) opened the admin page: status 200 |
| A4 | The admin page needs a login | **PASS** | PASS | Without logging in, got a denied status (the one check the weak site passes) |
| R1 | Login errors do not reveal which users exist | FAIL | PASS | Unknown user: 401 "No such user: ..." versus real user: 401 "Wrong password for alice" |
| R2 | Error pages do not show internal details | FAIL | PASS | A bad request returned status 500 with a Python traceback and the file path of `practice_app.py` |
| R3 | Replies do not contain passwords or secrets | FAIL | PASS | Private-looking fields in replies (see note below) |

**Note on R3.** The screenshots of the weak scan list only `internal_api_key`. The check was improved after those screenshots were taken and now lists every field, so a new weak report shows `internal_api_key, owner_password`. The pass or fail result did not change.

## Evidence

### Weak version (1 passed, 15 failed)

![Weak scan part 1](../screenshots/08-weak-scan-part1-summary-and-headers.png)
![Weak scan part 2](../screenshots/09-weak-scan-part2-cookies-and-access.png)
![Weak scan part 3](../screenshots/10-weak-scan-part3-access-and-responses.png)
![Weak scan part 4](../screenshots/11-weak-scan-part4-secrets-and-report-saved.png)

### Fixed version (16 passed, 0 failed)

![Fixed scan part 1](../screenshots/16-fixed-scan-part1-summary-headers-cookies.png)
![Fixed scan part 2](../screenshots/17-fixed-scan-part2-access-responses.png)

## Other tests

| Test | Result |
|---|---|
| Scan `https://example.com` without `--i-have-permission` | Refused, exit code 2, no request sent |
| `python webscan.py --help` | Help screen shown (see `screenshots/07-webscan-help-working.png`) |
| Exit codes | 0 when all checks pass, 1 when any fail, 2 when the tool cannot run |

## How to repeat the test

One command (starts the practice website, scans both versions, saves the reports):

```
python run_demo.py
```

The reports are saved as `reports/webscan_report_weak.md` and `reports/webscan_report_fixed.md`.

Or step by step:

```
python practice_app.py --mode weak --port 5000
python webscan.py http://127.0.0.1:5000 --report reports/webscan_report_weak.md
```

Stop the site (Ctrl+C), then repeat with `--mode fixed` and `reports/webscan_report_fixed.md`.

## Limits of these tests

- Only the included practice website was tested. Webscan has not been run against OWASP Juice Shop, crAPI or any other site.
- The practice website was written to match the checks, so the results show that the checks work as designed, not how common these problems are in real websites.


## Week 3: further testing (19 October 2026)

### 1. What was tested

| Target | What it is | How it was run |
|---|---|---|
| Practice website, weak and fixed versions | The small practice site that comes with Webscan | `python run_demo.py` |
| OWASP Juice Shop 20.3.0 | A second, independent web application made on purpose to be insecure for learning | Run on my own computer at `http://127.0.0.1:3000` (Windows build, Node 22) |

Only my own computer was scanned. The Juice Shop test account (`test@example.com`) was created by me for this test.

### 2. Automated tests

Command: `python -m unittest discover -s tests -v`

Result: **Ran 10 tests, OK.**

The tests start a tiny fake website on my own computer (it is not Juice Shop). They check that:

| Test | What it proves |
|---|---|
| Local addresses are local / other addresses are not | The "own computer only" rule works |
| A remote website is refused without `--i-have-permission` | Webscan stops and exits with code 2 |
| Token login works | Webscan can log in with `--auth bearer` |
| A bad login is skipped, not crashed | Wrong password gives SKIPPED checks, not an error |
| A single-page app admin address is INCONCLUSIVE, not FAIL | The false FAIL from the first Juice Shop scan is fixed |
| A server error on the orders address is INCONCLUSIVE, not FAIL | The second false FAIL is fixed |
| Reading another user's basket is a FAIL | Real access problems are still caught |
| Missing headers fail and `nosniff` passes | Header checks still work |
| Reports include the new status and the name | Text and JSON reports have 16 checks and the new fields |

### 3. Check that Week 2 still works

Command: `python run_demo.py`

| Practice website | Result | Same as Week 2? |
|---|---|---|
| Weak version | 1 passed, 15 failed, 0 skipped, 0 inconclusive | Yes |
| Fixed version | 16 passed, 0 failed, 0 skipped, 0 inconclusive | Yes |

### 4. Juice Shop scans

| Scan | Time | Passed | Failed | Skipped | Inconclusive | Report |
|---|---|---|---|---|---|---|
| 1. First scan (Week 2 version of Webscan) | 12:18 | 5 | 5 | 6 | 0 | `reports/juiceshop/juiceshop_report_before.md` |
| 2. After code changes (token login) | 13:09 | 5 | 4 | 3 | 4 | `reports/juiceshop/juiceshop_report_after.md` |
| 3. Real API addresses | 13:20 | 7 | 6 | 3 | 0 | `reports/juiceshop/juiceshop_report_paths.md` |

Commands for scans 2 and 3 are in the README (replace the password placeholder with your own test password).

### 5. What changed between the scans

| Check | Scan 1 | Scan 2 | Scan 3 |
|---|---|---|---|
| Orders need a login | FAIL (false: address does not exist, server error 500) | INCONCLUSIVE | PASS (status 401 without login) |
| Users cannot read other users' orders | SKIPPED (login failed) | INCONCLUSIVE | **FAIL** (status 200 for basket 1) |
| Normal users cannot open the admin page | SKIPPED (login failed) | INCONCLUSIVE | **FAIL** (status 200 with configuration data) |
| The admin page needs a login | FAIL (false: home page returned) | INCONCLUSIVE | **FAIL** (status 200 with configuration data, no login) |
| Error pages do not show internal details | SKIPPED (login failed) | **FAIL** (server path and error shown) | PASS (this address gave no error page) |
| 3 header checks (CSP, HSTS, Referrer-Policy) | FAIL | FAIL | FAIL |
| 3 cookie checks | SKIPPED | SKIPPED | SKIPPED (Juice Shop sets no cookie at login) |

### 6. Checked by hand

- Opening `http://127.0.0.1:3000/api/orders/not-a-number` in Chrome shows a 500 error page with the message "Unexpected path" and a list of file paths from the server. This confirms the "Error pages" FAIL in scan 2 is a true result.

### 7. Limits seen in testing

- The error-page check tests one address only. It failed on `/api/orders/...` but passed on `/rest/basket/...`.
- The "admin page" address used in scan 3 (`/rest/admin/application-configuration`) is a configuration data address, not an admin screen.
- Cookie checks cannot run on apps that do not use cookies for login.
- Two applications have been tested so far.
