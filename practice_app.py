"""
practice_app.py - the practice website for Webscan.

It has two versions:
  --mode weak   a website that is weak on purpose (for testing Webscan)
  --mode fixed  the same website with the weaknesses repaired

WARNING: the weak version is unsafe on purpose. Only run it on your own
computer. It listens on 127.0.0.1 only, so other computers cannot reach it.
"""

import argparse
import secrets
import traceback

from flask import Flask, jsonify, make_response, request
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
MODE = "weak"  # set from the command line in main()

# Fake data. Nothing here is real.
USERS = {
    "alice": {"password": "alice-pass", "role": "user", "id": 1},
    "bob": {"password": "bob-pass", "role": "user", "id": 2},
    "admin": {"password": "admin-pass", "role": "admin", "id": 3},
}
ORDERS = {
    1: {"id": 1, "item": "Blue notebook", "total": 120, "owner": "alice"},
    2: {"id": 2, "item": "Red pen set", "total": 45, "owner": "bob"},
}
SESSIONS = {}  # session token -> username


class HiddenVersionHandler(WSGIRequestHandler):
    """Used in fixed mode: the built-in server no longer announces its version."""

    def version_string(self):
        return "webscan-practice"


def is_weak():
    return MODE == "weak"


def current_user():
    token = request.cookies.get("session")
    return SESSIONS.get(token)


@app.after_request
def add_headers(resp):
    if is_weak():
        # Weak: no safety headers, and the server tells everyone its version.
        resp.headers["X-Powered-By"] = "Flask 3.0.0"
    else:
        # Fixed: safety headers on every reply, and no version shown.
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.route("/")
def home():
    return jsonify({"message": "Webscan practice website", "mode": MODE})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    user = USERS.get(username)

    if user is None or user["password"] != password:
        if is_weak():
            # Weak: the error tells an attacker which usernames exist.
            if user is None:
                return jsonify({"error": "No such user: " + username}), 401
            return jsonify({"error": "Wrong password for " + username}), 401
        # Fixed: one answer for both cases.
        return jsonify({"error": "Invalid username or password"}), 401

    token = secrets.token_hex(16)
    SESSIONS[token] = username
    resp = make_response(jsonify({"message": "Logged in"}))
    if is_weak():
        resp.set_cookie("session", token)  # no protections
    else:
        resp.set_cookie("session", token, httponly=True, secure=True, samesite="Strict")
    return resp


@app.route("/api/orders/<order_id>")
def get_order(order_id):
    user = current_user()

    # Weak: no login needed. Fixed: login required.
    if user is None and not is_weak():
        return jsonify({"error": "Login required"}), 401

    try:
        order = ORDERS.get(int(order_id))
    except Exception:
        if is_weak():
            # Weak: shows the inside of the program in the error page.
            return "<pre>" + traceback.format_exc() + "</pre>", 500
        return jsonify({"error": "Bad request"}), 400

    if order is None:
        return jsonify({"error": "Not found"}), 404

    if is_weak():
        # Weak: any order for anyone, plus private data in the reply.
        reply = dict(order)
        reply["owner_password"] = USERS[order["owner"]]["password"]
        reply["internal_api_key"] = "sk-test-1234"
        return jsonify(reply)

    # Fixed: only the owner may read it, and the reply has no private data.
    if order["owner"] != user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(order)


@app.route("/admin")
def admin():
    user = current_user()
    if user is None:
        return jsonify({"error": "Login required"}), 401  # both versions
    if not is_weak() and USERS[user]["role"] != "admin":
        return jsonify({"error": "Admins only"}), 403
    # Weak: any logged-in user gets in.
    return jsonify({"page": "admin panel", "users": list(USERS)})


def main():
    global MODE
    parser = argparse.ArgumentParser(description="Webscan practice website")
    parser.add_argument("--mode", choices=["weak", "fixed"], default="weak")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    MODE = args.mode
    print("Practice website running in %s mode on http://127.0.0.1:%d" % (MODE, args.port))
    handler = WSGIRequestHandler if is_weak() else HiddenVersionHandler
    app.run(host="127.0.0.1", port=args.port, debug=False, request_handler=handler)


if __name__ == "__main__":
    main()
