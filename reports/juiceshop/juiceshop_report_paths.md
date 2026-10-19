# Webscan report

- Name: OWASP Juice Shop (real API paths)
- Target: http://127.0.0.1:3000
- Date: 2026-10-19 13:20
- Result: 7 passed, 6 failed, 3 skipped, 0 inconclusive (out of 16 checks)

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

- [PASS] Orders need a login
- [FAIL] Users cannot read other users' orders
    - What was seen: test@example.com asked for order 1 (not theirs) and got status 200: {"status":"success","data":{"id":1,"coupon":null,"UserId":1,"createdAt":"2026-10-19T10:15:48.492Z","updatedAt":"2026-10-19T10:15:48.492Z","Products":[{"id":1,"name":"Apple Juice (1000ml)","description...
    - How to fix it: On every request, check that the order belongs to the logged-in user (not just that the user is logged in). Return 403 or 404 otherwise.
- [FAIL] Normal users cannot open the admin page
    - What was seen: test@example.com (a normal user) opened the admin page: status 200, {"config":{"server":{"port":3000,"basePath":"","baseUrl":"http://localhost:3000"},"application":{"domain":"juice-sh.op","name":"OWASP Juice Shop","logo":"JuiceShop_Logo.png","favicon":"favicon_js.ico"...
    - How to fix it: Check the user's role on the server before showing any admin page. Hiding the link is not enough.
- [FAIL] The admin page needs a login
    - What was seen: Without logging in, got status 200: {"config":{"server":{"port":3000,"basePath":"","baseUrl":"http://localhost:3000"},"application":{"domain":"juice-sh.op","name":"OWASP Juice Shop","logo":"JuiceShop_Logo.png","favicon":"favicon_js.ico"...
    - How to fix it: Require a login before showing the admin page.

## Responses

- [PASS] Login errors do not reveal which users exist
- [PASS] Error pages do not show internal details
- [PASS] Replies do not contain passwords or secrets

