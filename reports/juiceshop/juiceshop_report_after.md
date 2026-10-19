# Webscan report

- Name: OWASP Juice Shop
- Target: http://127.0.0.1:3000
- Date: 2026-10-19 13:09
- Result: 5 passed, 4 failed, 3 skipped, 4 inconclusive (out of 16 checks)

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

- [INCONCLUSIVE] Orders need a login
    - Why inconclusive: The website answered with a server error (status 500), so the address may not exist or the server failed. This does not show if a login is needed.
- [INCONCLUSIVE] Users cannot read other users' orders
    - Why inconclusive: The website answered with a server error (status 500), so the address may not exist or the server failed. This does not show if a login is needed.
- [INCONCLUSIVE] Normal users cannot open the admin page
    - Why inconclusive: The website answered with its normal home page, so this address is not a real page or API address (typical for single-page apps). Try a real address with the matching --*-path option.
- [INCONCLUSIVE] The admin page needs a login
    - Why inconclusive: The website answered with its normal home page, so this address is not a real page or API address (typical for single-page apps). Try a real address with the matching --*-path option.

## Responses

- [PASS] Login errors do not reveal which users exist
- [FAIL] Error pages do not show internal details
    - What was seen: A bad request (status 500) showed internal details: <html> <head> <meta charset='utf-8'> <title>Error: Unexpected path: /api/orders/not-a-number</title> <style>* { margin: 0; padding: 0; outline: 0; } body { padding: 80px 100px; font: 13px "Helvetica N...
    - How to fix it: Turn off debug output. Show users a short, generic error and write the details to a private log instead.
- [PASS] Replies do not contain passwords or secrets

