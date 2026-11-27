from getpass import getpass
from framing import send_json, recv_json


class LoginBlocked(Exception):
    """Server locked the account or is closing the connection after too many failures."""


def check_disconnect(response):
    # The server says it is closing the connection (too many failures / account locked):
    # stop here instead of prompting again and writing to a dead socket
    if response.get("disconnect") or response.get("locked"):
        raise LoginBlocked(response.get("message", "Login blocked by server"))


def auth_password(client_socket):
    while True:
        username = input("Enter your username: ")
        if username.upper() == "EXIT":
            send_json(client_socket, {"type": "EXIT"})
            raise SystemExit
        password = getpass("Password: ")

        send_json(client_socket, {"type": "AUTH", "username": username, "password": password})
        response = recv_json(client_socket)
        print("Server:", response.get("message"))

        if response.get("status") == "OK" and response.get("message") == "OTP_REQUIRED":
            return True
        check_disconnect(response)


def auth_mfa(client_socket, session):
    while True:
        otp = input("Enter your TOTP Code: ")
        send_json(client_socket, {"type": "OTP", "otp": otp})

        response = recv_json(client_socket)
        if response.get("status") == "OK" and response.get("message") == "ACCESS_GRANTED":
            session["session_id"] = response["session"]
            print("Server: ACCESS GRANTED")
            return True
        print("Server:", response.get("message"))
        check_disconnect(response)