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
# Failures are counted for ANY username, real or not. A locked message therefore can't be
# used to find out which accounts exist: every username locks the same way.
MAX_USERNAME_LEN = 64      # stops junk usernames from bloating the in-memory failure table


def is_locked(username):
    rec = _failures.get(username)
    if not rec:
        return False
    if rec["locked_until"] > time.monotonic():
        return True
    if rec["locked_until"]:          # lock has expired, start fresh
        del _failures[username]
    return False


def lock_remaining(username):
    """Whole seconds until the lock on this username expires."""
    return max(1, int(_failures[username]["locked_until"] - time.monotonic() + 0.999))


def record_failure(username):
    rec = _failures.setdefault(username, {"count": 0, "locked_until": 0})
    rec["count"] += 1
    if rec["count"] >= LOGIN_ATTEMPT_MAX:
        rec["locked_until"] = time.monotonic() + LOCKOUT_SECONDS
        logging("ERROR", f"Account '{username}' locked for {LOCKOUT_SECONDS}s")


def clear_failures(username):
    _failures.pop(username, None)


def auth_fail(client_socket, session, username, reason, count=True):
    """Single exit point for every auth failure.
    The client only learns: generic failure, account locked, or that it is being disconnected.
    The real reason goes to the server log."""
    logging("INFO", f"{reason} from {session.address}")
    session.failed_attempts += 1
    if username is not None and count:
        record_failure(username)

    reply = dict(GENERIC_FAIL)
    if username is not None and is_locked(username):
        reply["message"] = (f"Account locked after {LOGIN_ATTEMPT_MAX} failed attempts. "
                            f"Try again in {lock_remaining(username)} seconds")
        reply["locked"] = True
    if session.failed_attempts >= LOGIN_ATTEMPT_MAX:
        if not reply.get("locked"):
            reply["message"] = "Authentication failed - too many failed attempts"
        reply["disconnect"] = True               # main.py closes the connection after this reply
    send_json(client_socket, reply)


# ---- step 1: username + password ----
def auth_loop(client_socket, session, msg, users):
    username = msg.get("username")
    password = msg.get("password")

    # A new AUTH attempt always starts from zero: wipe any earlier login, token and key
    session.username = None
    session.password_verified = False
    session.authenticated = False
    session.session_id = None
    session.key = None
    session.key_exchanged = False

    if (not isinstance(username, str) or not isinstance(password, str)
            or not username or len(username) > MAX_USERNAME_LEN):
        auth_fail(client_socket, session, None, "Malformed AUTH message")
        return

    if is_locked(username):
        # Don't count it again: that would keep pushing the unlock time back
        auth_fail(client_socket, session, username, f"Login attempt on locked account '{username}'", count=False)
        return

    user = users.get(username)
    if user is None:
        auth_fail(client_socket, session, username, f"Login attempt for unknown user '{username}'")
        return

    if not verify_password(password, user["password_hash"]):
        auth_fail(client_socket, session, username, f"Incorrect password for '{username}'")
        return

    session.username = username
    session.password_verified = True
    send_json(client_socket, {"status": "OK", "message": "OTP_REQUIRED"})

# ---- step 2: TOTP ----
def otp_loop(client_socket, session, msg, users):
    otp = msg.get("otp")
    if not session.password_verified or session.username is None or not isinstance(otp, str):
        auth_fail(client_socket, session, None, "OTP sent before a valid password")
        return

    username = session.username
    if is_locked(username):
        auth_fail(client_socket, session, username, f"OTP attempt on locked account '{username}'", count=False)
        return

    step = verify_otp(users[username]["totp_secret"], otp.strip())
    if step is None:
        auth_fail(client_socket, session, username, f"OTP failure for '{username}'")
        return

    # Replay protection: each code (time step) can be used ONCE per user, even while still valid
    if _last_otp_step.get(username, -1) >= step:
        auth_fail(client_socket, session, username, f"OTP replay rejected for '{username}'")
        return
    _last_otp_step[username] = step

    session.authenticated = True
    session.failed_attempts = 0
    session.session_id = secrets.token_urlsafe(32)
    clear_failures(username)
    logging("INFO", f"Successful login for '{username}' from {session.address}")
    send_json(client_socket, {"status": "OK", "message": "ACCESS_GRANTED",
                              "session": session.session_id})
