from getpass import getpass
from framing import send_json, recv_json


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