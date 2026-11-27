import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_LEN = 12          # 96-bit nonce, the size GCM is designed for
TAG_LEN = 16            # GCM authentication tag appended to the ciphertext
DIGEST_LEN = 32         # SHA-256
AAD_PREFIX = b"FSCT8561-v1|"


class IntegrityError(Exception):
    """Payload failed authentication or is structurally invalid."""


def new_ephemeral():
    """Return (private_key_object, public_key_bytes). Discard the private key after use."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


def derive_key(priv, peer_pub: bytes, session_token: str, client_pub: bytes, server_pub: bytes) -> bytes:
    """Both sides call this with the same token and the same (client_pub, server_pub) order."""
    try:
        shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    except ValueError:
        raise IntegrityError("invalid peer public key")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=AAD_PREFIX + b"key|" + session_token.encode() + client_pub + server_pub,).derive(shared)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _aad(session_token: str) -> bytes:
    # Binds the ciphertext to THIS authenticated session and protocol version
    return AAD_PREFIX + session_token.encode()


def encrypt_evidence(key: bytes, manifesto: bytes, session_token: str) -> bytes:
    """Return nonce || ciphertext || tag. The plaintext is SHA-256(manifesto) || manifesto."""
    plaintext = hashlib.sha256(manifesto).digest() + manifesto
    nonce = os.urandom(NONCE_LEN)                       # fresh random nonce for every message
    return nonce + AESGCM(key).encrypt(nonce, plaintext, _aad(session_token))


def decrypt_evidence(key: bytes, blob: bytes, session_token: str) -> bytes:
    """Verify and decrypt. Raises IntegrityError on ANY problem; never returns unverified data."""
    if len(blob) < NONCE_LEN + TAG_LEN + DIGEST_LEN:
        raise IntegrityError("payload too short")
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _aad(session_token))
    except InvalidTag:
        raise IntegrityError("authentication tag mismatch (tampered, wrong key, or wrong session)")
    digest, manifesto = plaintext[:DIGEST_LEN], plaintext[DIGEST_LEN:]
    if hashlib.sha256(manifesto).digest() != digest:
        raise IntegrityError("embedded SHA-256 does not match decrypted content")
    return manifesto