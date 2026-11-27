from handle_logging import logging
import secrets
import datetime
from pathlib import Path

from framing import send_json, recv_msg, MAX_EVIDENCE
from crypto_utils import (new_ephemeral, derive_key, decrypt_evidence, sha256_hex, IntegrityError,
                          NONCE_LEN, TAG_LEN, DIGEST_LEN)
# from anomaly_detector import anomaly_detector

MIN_BLOB = NONCE_LEN + TAG_LEN + DIGEST_LEN     # smallest valid blob: nonce + tag + embedded hash
RECEIVED_DIR = Path("received")


class DropConnection(Exception):
    """Raised after a security failure: the connection is closed and nothing is kept."""

def authenticate_commands(client_socket, session, msg):
    token = msg.get("session")
    if (not session.session_id or not isinstance(token, str)
            or not secrets.compare_digest(token.encode(), session.session_id.encode())):
        logging("ERROR", f"Command authentication failed from {session.address}")
        send_json(client_socket, {"status": "ERROR", "message": "Unauthenticated command"})
        return
    else:
        command = msg["type"]
        if command == "MSG":
            text = msg.get("text", "")
            if not isinstance(text, str) or text == "" or len(text) > 200:
                send_json(client_socket, {"status": "ERROR", "message": "Invalid message"})
            else:
                logging("INFO", f"{session.username} says: {text}")
                send_json(client_socket, {"status": "OK", "message": f"Message received from {session.username}"})
        elif command == "KEY_EXCHANGE":
            handle_key_exchange(client_socket, session, msg)
        elif command == "EVIDENCE":
            handle_evidence(client_socket, session, msg)
        else:
            send_json(client_socket, {"status": "ERROR", "message": "Unknown command"})
    return

def handle_key_exchange(client_socket, session, msg):
    if session.key_exchanged:                       # one exchange per session
        send_json(client_socket, {"status": "ERROR", "message": "Key already established"})
        return

    try:
        client_pub = bytes.fromhex(msg.get("pub", ""))
        if len(client_pub) != 32:
            raise ValueError
    except (ValueError, TypeError):
        logging("ERROR", f"Invalid key exchange from {session.address}")
        send_json(client_socket, {"status": "ERROR", "message": "Invalid key exchange"})
        return

    priv, server_pub = new_ephemeral()
    try:
        session.key = derive_key(priv, client_pub, session.session_id, client_pub, server_pub)
    except IntegrityError:
        logging("ERROR", f"Invalid public key from {session.address}")
        send_json(client_socket, {"status": "ERROR", "message": "Invalid key exchange"})
        return

    session.key_exchanged = True
    logging("INFO", f"Session key established for {session.address}")   # never log the key itself
    send_json(client_socket, {"status": "OK", "pub": server_pub.hex()})

def store_evidence(manifesto: bytes) -> Path:
    RECEIVED_DIR.mkdir(exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = RECEIVED_DIR / f"architect_manifesto_{stamp}.txt"
    with open(path, "xb") as f:                     # "x" = fail rather than overwrite an existing file
        f.write(manifesto)
    return path


def handle_evidence(client_socket, session, msg):
    # 1. A key must exist for THIS session (it only exists after password + OTP + key exchange)
    if not session.key_exchanged or session.key is None:
        logging("ERROR", f"Evidence refused from {session.address}: no key exchange")
        send_json(client_socket, {"status": "ERROR", "message": "Key exchange required"})
        return

    # 2. Validate the declared size BEFORE accepting any payload bytes
    size = msg.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or not (MIN_BLOB <= size <= MAX_EVIDENCE):
        logging("ERROR", f"Evidence refused from {session.address}: invalid declared size")
        send_json(client_socket, {"status": "ERROR", "message": "Invalid size"})
        raise DropConnection("invalid declared size")
    send_json(client_socket, {"status": "READY"})

    # 3. Receive the framed blob; a header larger than the declared size raises OversizedMessage
    blob = recv_msg(client_socket, max_len=size)
    if len(blob) != size:
        logging("ERROR", f"Evidence from {session.address} rejected: size mismatch. Nothing stored.")
        send_json(client_socket, {"status": "ERROR", "message": "Evidence rejected"})
        raise DropConnection("size mismatch")

    # 4. Authenticate + decrypt. Tampered, wrong-key or wrong-session data never gets past here
    try:
        manifesto = decrypt_evidence(session.key, blob, session.session_id)
    except IntegrityError as e:
        logging("ERROR", f"Evidence from {session.address} REJECTED ({e}). Nothing stored.")
        send_json(client_socket, {"status": "ERROR", "message": "Evidence rejected"})
        raise DropConnection("integrity check failed")

    # 5. Only verified plaintext touches the disk; reply with its hash so the client can compare
    path = store_evidence(manifesto)
    digest = sha256_hex(manifesto)
    logging("INFO", f"Evidence from '{session.username}' verified and stored as {path.name} "
                    f"({len(manifesto)} bytes, sha256={digest})")      # never log the manifesto itself
    send_json(client_socket, {"status": "OK", "message": "DELIVERED", "sha256": digest, "bytes": len(manifesto)})
