# t08_no_auth.py  (put it in client/ and run: py t08_no_auth.py)
import socket, ssl
from framing import send_json, recv_json

ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="certs/server.crt")
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 12345), timeout=10), server_hostname="127.0.0.1")

# No AUTH, no OTP: go straight to EVIDENCE with a made-up session token
send_json(s, {"type": "EVIDENCE", "session": "fake-token", "size": 321})
print("Server replied:", recv_json(s))
s.close()