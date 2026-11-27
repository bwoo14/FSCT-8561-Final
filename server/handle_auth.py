import json
import secrets
import time
import datetime
from pathlib import Path
from framing import send_json
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

from handle_logging import logging

LOGIN_ATTEMPT_MAX = 3      # failures allowed per connection, and per account before lockout
LOCKOUT_SECONDS = 60       # how long an account stays locked
USERS_FILE = Path(__file__).with_name("users.json")

# One message for every auth failure, so the client can't tell WHICH check failed.
# The specific reason goes in the server log instead.
GENERIC_FAIL = {"status": "ERROR", "message": "Authentication failed"}

_ph = PasswordHasher()
_failures = {}   # username -> {"count": int, "locked_until": float}
_last_otp_step = {}   # username -> last accepted TOTP time step (replay protection, in memory)


class Session:
    """State for ONE client connection. Created on connect, discarded on disconnect."""
    def __init__(self, address):
        self.address = address
        self.username = None
        self.password_verified = False
        self.authenticated = False
        self.session_id = None
        self.failed_attempts = 0
        self.key = None
        self.key_exchanged = False


def load_users(path=USERS_FILE):
    """Persistent credentials only: {username: {"password_hash", "totp_secret"}}."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)["users"]


def verify_password(password, stored_hash):
    try:
        return _ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def verify_otp(secret, otp):
    """Return the time step the code is valid for, or None. Only the CURRENT 30 s code is accepted."""
    totp = pyotp.TOTP(secret)
    step = totp.timecode(datetime.datetime.now())
    if totp.verify(otp, for_time=step * totp.interval, valid_window=0):
        return step
    return None


# ---- account lockout (time-limited, so it clears itself) ----
def is_locked(username):
    rec = _failures.get(username)
    if not rec:
        return False
    if rec["locked_until"] > time.monotonic():
        return True
    if rec["locked_until"]:          # lock has expired, start fresh
        del _failures[username]
    return False


def record_failure(username):
    rec = _failures.setdefault(username, {"count": 0, "locked_until": 0})
    rec["count"] += 1
    if rec["count"] >= LOGIN_ATTEMPT_MAX:
        rec["locked_until"] = time.monotonic() + LOCKOUT_SECONDS
        logging("ERROR", f"Account '{username}' locked for {LOCKOUT_SECONDS}s")


def clear_failures(username):
    _failures.pop(username, None)


# ---- step 1: username + password ----
def auth_loop(client_socket, session, msg, users):
    username = msg.get("username")
    password = msg.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        send_json(client_socket, GENERIC_FAIL)
        session.failed_attempts += 1
        return

    # A new AUTH attempt always starts from zero: wipe any earlier login, token and key
    session.username = None
    session.password_verified = False
    session.authenticated = False
    session.session_id = None
    session.key = None
    session.key_exchanged = False

    user = users.get(username)
    if user is None or is_locked(username):
        logging("ERROR", f"Login rejected for unknown/locked user from {session.address}")
        session.failed_attempts += 1
        send_json(client_socket, GENERIC_FAIL)
        return

    if not verify_password(password, user["password_hash"]):
        logging("INFO", f"Incorrect password for '{username}' from {session.address}")
        record_failure(username)
        session.failed_attempts += 1
        send_json(client_socket, GENERIC_FAIL)
        return

    session.username = username
    session.password_verified = True
    send_json(client_socket, {"status": "OK", "message": "OTP_REQUIRED"})

# ---- step 2: TOTP ----
def otp_loop(client_socket, session, msg, users):
    otp = msg.get("otp")
    if not session.password_verified or session.username is None or not isinstance(otp, str):
        session.failed_attempts += 1
        send_json(client_socket, GENERIC_FAIL)
        return

    username = session.username
    step = None if is_locked(username) else verify_otp(users[username]["totp_secret"], otp.strip())
    if step is None:
        logging("INFO", f"OTP failure for '{username}' from {session.address}")
        record_failure(username)
        session.failed_attempts += 1
        send_json(client_socket, GENERIC_FAIL)
        return

    # Replay protection: each code (time step) can be used ONCE per user, even while still valid
    if _last_otp_step.get(username, -1) >= step:
        logging("INFO", f"OTP replay rejected for '{username}' from {session.address}")
        record_failure(username)
        session.failed_attempts += 1
        send_json(client_socket, GENERIC_FAIL)
        return
    _last_otp_step[username] = step

    session.authenticated = True
    session.failed_attempts = 0
    session.session_id = secrets.token_urlsafe(32)
    clear_failures(username)
    logging("INFO", f"Successful login for '{username}' from {session.address}")
    send_json(client_socket, {"status": "OK", "message": "ACCESS_GRANTED",
                              "session": session.session_id})