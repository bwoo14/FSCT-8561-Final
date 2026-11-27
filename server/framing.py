import json
import struct

HEADER = struct.Struct("!I")          # 4-byte big-endian unsigned length
MAX_CONTROL = 4096                    # cap for small JSON messages
MAX_EVIDENCE = 1024 * 1024            # cap for the encrypted evidence payload


class FramingError(Exception):
    """Base class for all framing problems."""

class ConnectionClosed(FramingError):
    """Peer closed cleanly between messages."""

class IncompleteMessage(FramingError):
    """Connection ended in the middle of a message."""

class OversizedMessage(FramingError):
    """Length header exceeds the allowed maximum."""

class MalformedMessage(FramingError):
    """Body was not valid JSON / not a JSON object."""


def _recv_exact(sock, n, at_boundary=False):
    """Loop on recv until exactly n bytes have arrived."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            if at_boundary and not buf:
                raise ConnectionClosed("peer closed the connection")
            raise IncompleteMessage(f"connection closed after {len(buf)} of {n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock, data: bytes):
    sock.sendall(HEADER.pack(len(data)) + data)


def recv_msg(sock, max_len=MAX_CONTROL) -> bytes:
    (length,) = HEADER.unpack(_recv_exact(sock, HEADER.size, at_boundary=True))
    if length > max_len:
        # Reject BEFORE reading or allocating anything
        raise OversizedMessage(f"declared length {length} exceeds limit {max_len}")
    return _recv_exact(sock, length)


def send_json(sock, obj: dict):
    send_msg(sock, json.dumps(obj).encode("utf-8"))


def recv_json(sock, max_len=MAX_CONTROL) -> dict:
    raw = recv_msg(sock, max_len)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise MalformedMessage("body is not valid UTF-8 JSON")
    if not isinstance(obj, dict):
        raise MalformedMessage("JSON body must be an object")
    return obj