# Webscan report

- Target: http://127.0.0.1:5050
- Date: 2026-10-19 13:31
- Result: 1 passed, 15 failed, 0 skipped, 0 inconclusive (out of 16 checks)

A passing report does not mean a website is fully secure. Webscan only checks a short list of well-known weaknesses.

## Settings and headers

- [FAIL] Content-Security-Policy is set
    - What was seen: Header 'Content-Security-Policy' is missing.
    - How to fix it: Add a Content-Security-Policy header. It tells the browser which sources of scripts and images are allowed, which helps stop injected code. A simple start is: default-src 'self'.
- [FAIL] Strict-Transport-Security is set
    - What was seen: Header 'Strict-Transport-Security' is missing.
    - How to fix it: Add a Strict-Transport-Security header (for example max-age=31536000) so browsers always use the secure https version of the website.
- [FAIL] X-Content-Type-Options is nosniff
    - What was seen: Header 'X-Content-Type-Options' is missing.
    - How to fix it: Add the header X-Content-Type-Options: nosniff so browsers do not guess file types.
- [FAIL] Clickjacking protection is set
    - What was seen: Neither X-Frame-Options nor a frame-ancestors rule was found.
    - How to fix it: Add X-Frame-Options: DENY (or a frame-ancestors rule) so other websites cannot show your pages inside a hidden frame to trick users.
- [FAIL] Referrer-Policy is set
    - What was seen: Header 'Referrer-Policy' is missing.
    - How to fix it: Add a Referrer-Policy header (for example no-referrer) so your web addresses are not leaked to other websites.
- [FAIL] Server version is hidden
    - What was seen: Server: Werkzeug/3.1.9 Python/3.14.8; X-Powered-By: Flask 3.0.0
    - How to fix it: Remove the version numbers from the Server and X-Powered-By headers. Attackers use them to look up known problems for that exact version.

## Cookies

- [FAIL] Cookies are HttpOnly
    - What was seen: Cookie(s) missing it: session
    - How to fix it: Add the HttpOnly flag to every cookie so scripts on the page cannot read it.
- [FAIL] Cookies are Secure
    - What was seen: Cookie(s) missing it: session
    - How to fix it: Add the Secure flag to every cookie so it is only sent over https.
- [FAIL] Cookies have SameSite
    - What was seen: Cookie(s) missing it: session
    - How to fix it: Add SameSite=Strict (or Lax) to every cookie so other websites cannot make the browser send it.

## Access

- [FAIL] Orders need a login
    - What was seen: Without logging in, got status 200 and: {"id":1,"internal_api_key":"sk-test-1234","item":"Blue notebook","owner":"alice","owner_password":"alice-pass","total":120}
    - How to fix it: Check on the server that the person is logged in before returning any order.
- [FAIL] Users cannot read other users' orders
    - What was seen: alice asked for order 2 (not theirs) and got status 200: {"id":2,"internal_api_key":"sk-test-1234","item":"Red pen set","owner":"bob","owner_password":"bob-pass","total":45}
    - How to fix it: On every request, check that the order belongs to the logged-in user (not just that the user is logged in). Return 403 or 404 otherwise.
- [FAIL] Normal users cannot open the admin page
    - What was seen: alice (a normal user) opened the admin page: status 200, {"page":"admin panel","users":["alice","bob","admin"]}
    - How to fix it: Check the user's role on the server before showing any admin page. Hiding the link is not enough.
- [PASS] The admin page needs a login

## Responses

- [FAIL] Login errors do not reveal which users exist
    - What was seen: Unknown user: 401 {"error":"No such user: no_such_user_xyz"} | Real user, wrong password: 401 {"error":"Wrong password for alice"}
    - How to fix it: Give the same error for an unknown user and a wrong password, for example 'Invalid username or password'.
- [FAIL] Error pages do not show internal details
    - What was seen: A bad request (status 500) showed internal details: <pre>Traceback (most recent call last): File "C:\Users\king7\Desktop\Sizo\CyberFox\Further Development and Testing\Webscan\practice_app.py", line 106, in get_order order = ORDERS.get(int(order_id)) ~~...
    - How to fix it: Turn off debug output. Show users a short, generic error and write the details to a private log instead.
- [FAIL] Replies do not contain passwords or secrets
    - What was seen: Found private-looking fields in replies: internal_api_key, owner_password
    - How to fix it: Never send passwords, keys or secrets to the browser. Remove those fields from the reply.

