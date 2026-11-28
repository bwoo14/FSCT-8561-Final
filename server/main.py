import socket

from handle_auth import load_users, auth_loop, otp_loop, Session, LOGIN_ATTEMPT_MAX
from handle_logging import logging
from handle_command import authenticate_commands, DropConnection
from framing import recv_json, send_json, FramingError, ConnectionClosed, IncompleteMessage, OversizedMessage, MalformedMessage


import os
import ssl
import threading

USE_TLS = os.environ.get("FSCT_USE_TLS", "1") != "0"   # set to 0 only for the T09 comparison test

HOST = "127.0.0.1"
PORT = 12345
CLIENT_TIMEOUT = 60      # seconds of silence before a client is dropped

try:
    USERS = load_users()
except FileNotFoundError:
    print("users.json not found. Run enroll.py first.")
    raise SystemExit(1)

def build_tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2        # no SSLv3/TLS1.0/1.1
    ctx.load_cert_chain("certs/server.crt", "certs/server.key")
    return ctx


def handle_client(client_socket, client_address):
    session = Session(client_address)
    client_socket.settimeout(CLIENT_TIMEOUT)

    try:
        while True:
            msg = recv_json(client_socket)          # one complete, parsed message
            command = msg.get("type")
            if not isinstance(command, str):
                send_json(client_socket, {"status": "ERROR", "message": "Missing type"})
                continue

            logging("INFO", f"Received {command[:20]} from {client_address}")

            if command == "AUTH":
                auth_loop(client_socket, session, msg, USERS)
            elif command == "OTP":
                otp_loop(client_socket, session, msg, USERS)
            elif command == "EXIT":
                send_json(client_socket, {"status": "OK", "message": "Goodbye"})
                break
            elif session.authenticated:
                authenticate_commands(client_socket, session, msg)
            else:
                logging("ERROR", f"Unauthenticated command from {client_address}")
                send_json(client_socket, {"status": "ERROR", "message": "Unauthenticated command"})

            if not session.authenticated and session.failed_attempts >= LOGIN_ATTEMPT_MAX:
                logging("ERROR", f"Too many failed attempts, dropping {client_address}")
                break

    except ConnectionClosed:
        logging("INFO", f"Client {client_address} disconnected")
    except IncompleteMessage as e:
        logging("ERROR", f"Incomplete message from {client_address}: {e}. Nothing stored.")
    except OversizedMessage as e:
        logging("ERROR", f"Oversized message from {client_address}: {e}. Dropping.")
    except MalformedMessage as e:
        logging("ERROR", f"Malformed message from {client_address}: {e}. Dropping.")
    except socket.timeout:
        logging("INFO", f"{client_address} timed out")
    except (ConnectionResetError, BrokenPipeError):
        logging("INFO", f"Connection reset by {client_address}")
    except DropConnection as e:
        logging("ERROR", f"Dropping {client_address} after security failure: {e}")
    except ssl.SSLError as e:       # must come before Exception, or it is never reached
        logging("ERROR", f"TLS error with {client_address}: {e}. Nothing stored.")
    except Exception as e:
        logging("ERROR", f"Unexpected error with {client_address}: {e!r}")
    finally:
        client_socket.close()


def main():
    tls_context = None
    if USE_TLS:
        try:
            tls_context = build_tls_context()
        except (FileNotFoundError, ssl.SSLError) as e:
            print(f"TLS setup failed ({e}). Run gen_cert.py first.")
            raise SystemExit(1)
    else:
        logging("ERROR", "TLS DISABLED - credentials will cross the network in plaintext")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    logging("INFO", f"Server listening on {HOST}:{PORT} (TLS {'on' if tls_context else 'OFF'})")

    server_thread = threading.Thread(target=serve, args=(server_socket, tls_context), daemon=True)
    server_thread.start()
    try:
        while server_thread.is_alive():
            server_thread.join(0.5)
    except KeyboardInterrupt:
        logging("INFO", "Shutting down")
    finally:
        server_socket.close()


def serve(server_socket, tls_context):
    """Accept loop: one client at a time."""
    while True:
        try:
            client_socket, client_address = server_socket.accept()
        except OSError:
            return                                      # listening socket was closed: shutting down
        logging("INFO", f"Connected by: {client_address}")

        if tls_context:
            try:
                client_socket.settimeout(CLIENT_TIMEOUT)   # a stalled handshake can't hang the server
                client_socket = tls_context.wrap_socket(client_socket, server_side=True)
                logging("INFO", f"TLS established with {client_address}: {client_socket.version()}")
            except (ssl.SSLError, OSError) as e:
                logging("ERROR", f"TLS handshake failed with {client_address}: {e}")
                client_socket.close()
                continue

        handle_client(client_socket, client_address)


if __name__ == "__main__":
    main()