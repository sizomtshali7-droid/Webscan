# Webscan report

- Target: http://127.0.0.1:3000
- Date: 2026-10-19 12:18
- Result: 5 passed, 5 failed, 6 skipped (out of 16 checks)

A passing report does not mean a website is fully secure. Webscan only checks a short list of well-known weaknesses.

## Settings and headers

- [FAIL] Content-Security-Policy is set
    - What was seen: Header 'Content-Security-Policy' is missing.
    - How to fix it: Add a Content-Security-Policy header. It tells the browser which sources of scripts and images are allowed, which helps stop injected code. A simple start is: default-src 'self'.
- [FAIL] Strict-Transport-Security is set
    - What was seen: Header 'Strict-Transport-Security' is missing.
    - How to fix it: Add a Strict-Transport-Security header (for example max-age=31536000) so browsers always use the secure https version of the website.
- [PASS] X-Content-Type-Options is nosniff
- [PASS] Clickjacking protection is set
- [FAIL] Referrer-Policy is set
    - What was seen: Header 'Referrer-Policy' is missing.
    - How to fix it: Add a Referrer-Policy header (for example no-referrer) so your web addresses are not leaked to other websites.
- [PASS] Server version is hidden

## Cookies

- [SKIPPED] Cookies are HttpOnly
    - Why skipped: No cookie was seen. The login did not work or the website sets no cookie.
- [SKIPPED] Cookies are Secure
    - Why skipped: No cookie was seen. The login did not work or the website sets no cookie.
- [SKIPPED] Cookies have SameSite
    - Why skipped: No cookie was seen. The login did not work or the website sets no cookie.

## Access

- [FAIL] Orders need a login
    - What was seen: Without logging in, got status 500 and: <html> <head> <meta charset='utf-8'> <title>Error: Unexpected path: /api/orders/1</title> <style>* { margin: 0; padding: 0; outline: 0; } body { padding: 80px 100px; font: 13px "Helvetica Neue", "Luci...
    - How to fix it: Check on the server that the person is logged in before returning any order.
- [SKIPPED] Users cannot read other users' orders
    - Why skipped: Could not log in as alice.
- [SKIPPED] Normal users cannot open the admin page
    - Why skipped: Could not log in as alice.
- [FAIL] The admin page needs a login
    - What was seen: Without logging in, got status 200: <!-- ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors. ~ SPDX-License-Identifier: MIT --> <!doctype html> <html lang="en" data-beasties-container> <head> <meta charset="u...
    - How to fix it: Require a login before showing the admin page.

## Responses

- [PASS] Login errors do not reveal which users exist
- [SKIPPED] Error pages do not show internal details
    - Why skipped: Could not log in as alice.
- [PASS] Replies do not contain passwords or secrets

