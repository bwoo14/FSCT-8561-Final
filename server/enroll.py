import getpass
import json
import os
import sys
from pathlib import Path

import pyotp
from argon2 import PasswordHasher

USERS_FILE = Path(__file__).with_name("users.json")
ISSUER = "FSCT8561"

# Argon2id with library defaults; a random salt is generated for every hash
ph = PasswordHasher()


def load_file():
    if USERS_FILE.exists():
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"users": {}}


def save_file(data):
    # Write to a temp file, then swap it in, so a crash can't leave a half-written file
    tmp = USERS_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(tmp, 0o600) 
    except OSError:
        pass
    os.replace(tmp, USERS_FILE)


def main():
    data = load_file()

    username = input("Username to enroll: ").strip()
    if not username:
        sys.exit("Username cannot be empty.")

    if username in data["users"]:
        answer = input(f"'{username}' already exists. Overwrite? (y/N): ")
        if answer.lower() != "y":
            sys.exit("Cancelled.")

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        sys.exit("Passwords do not match.")
    if not password:
        sys.exit("Password cannot be empty.")

    secret = pyotp.random_base32()

    data["users"][username] = {
        "password_hash": ph.hash(password),
        "totp_secret": secret,
    }
    save_file(data)

    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)
    print(f"\nSaved '{username}' to {USERS_FILE.name}")
    print("Add this to your authenticator app NOW (it is not shown again):")
    print(f"  Secret: {secret}")
    print(f"  URI:    {uri}")


if __name__ == "__main__":
    main()