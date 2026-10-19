# Webscan report

- Target: http://127.0.0.1:5050
- Date: 2026-10-19 13:31
- Result: 16 passed, 0 failed, 0 skipped, 0 inconclusive (out of 16 checks)

A passing report does not mean a website is fully secure. Webscan only checks a short list of well-known weaknesses.

## Settings and headers

- [PASS] Content-Security-Policy is set
- [PASS] Strict-Transport-Security is set
- [PASS] X-Content-Type-Options is nosniff
- [PASS] Clickjacking protection is set
- [PASS] Referrer-Policy is set
- [PASS] Server version is hidden

## Cookies

- [PASS] Cookies are HttpOnly
- [PASS] Cookies are Secure
- [PASS] Cookies have SameSite

## Access

- [PASS] Orders need a login
- [PASS] Users cannot read other users' orders
- [PASS] Normal users cannot open the admin page
- [PASS] The admin page needs a login

## Responses

- [PASS] Login errors do not reveal which users exist
- [PASS] Error pages do not show internal details
- [PASS] Replies do not contain passwords or secrets

