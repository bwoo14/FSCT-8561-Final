from photo_scan import extract_manifesto, PhotoScanError, NoEvidenceError
from pathlib import Path
# from framing import send_json, recv_json, send_msg
from framing import send_json, recv_json, send_msg, HEADER     # HEADER only needed for the T11 test
from crypto_utils import new_ephemeral, derive_key, encrypt_evidence, sha256_hex


IMAGE_PATH = "evidence/evidence.png"
MANIFESTO_PATH = "evidence/architect_manifesto.txt"

def recover_evidence():
	print("=========== STARTING EVIDENCE RECOVERY ===========")
	try:
		result = extract_manifesto(IMAGE_PATH, MANIFESTO_PATH)
	except NoEvidenceError as e:
		print(f"No evidence recovered: {e}")
		return None
	except PhotoScanError as e:
		print(f"Extraction failed: {e}")
		return None

	print(f"Manifesto recovered ({len(result['manifesto'])} bytes) -> {result['output_path']}")
	print(f"  Image SHA-256:      {result['image_sha256']}")
	print(f"  Manifesto SHA-256:  {result['manifesto_sha256']}")
	print(f"  Manifesto Text:     {result['text']}")
	print()
	print(f"  Decoded {result['decoded_bytes']} bytes up to the stop flag; "
		f"{len(result['trailing_bytes'])} byte(s) after the signature discarded: {result['trailing_bytes']!r}")
	print("  Original image unchanged: yes")
	print("=========== COMPLETED EVIDENCE RECOVERY ===========")
	return result

def handle_command(command, client_socket, SESSION):
	# Dispatch the menu selection; every server command carries the session token
	if command == "MSG":
		message = input("Enter your message: ")
		send_json(client_socket, {"type": "MSG", "session": SESSION["session_id"], "text": message})
		response = recv_json(client_socket)
		print("Message from Server:", response.get("message"))
	elif command == "EXTRACT":
		recover_evidence()
	elif command == "SEND":
		send_evidence(client_socket, SESSION)

def key_exchange(client_socket, session_token):
	priv, client_pub = new_ephemeral()
	send_json(client_socket, {"type": "KEY_EXCHANGE", "session": session_token, "pub": client_pub.hex()})

	resp = recv_json(client_socket)
	if resp.get("status") != "OK":
		raise RuntimeError("Server rejected the key exchange")
	try:
		server_pub = bytes.fromhex(resp["pub"])
		if len(server_pub) != 32:
			raise ValueError
	except (KeyError, ValueError, TypeError):
		raise RuntimeError("Server sent an invalid public key")

	return derive_key(priv, server_pub, session_token, client_pub, server_pub)



def send_evidence(client_socket, SESSION):
	"""Encrypt the manifesto and send it. Returns True only if delivery is VERIFIED."""
	try:
		manifesto = Path(MANIFESTO_PATH).read_bytes()
	except FileNotFoundError:
		print("No recovered manifesto found. Run 'Recover Evidence' first.")
		return False
	if not SESSION.get("key") or not SESSION.get("session_id"):
		print("No session key. Log in and complete the key exchange first.")
		return False

	# Hash the ORIGINAL now so we can compare against what the server says it stored
	local_hash = sha256_hex(manifesto)

	
	
	blob = encrypt_evidence(SESSION["key"], manifesto, SESSION["session_id"])

	# Testing a modification to the manifesto to see how the server reacts
	# blob = blob[:-1] + bytes([blob[-1] ^ 1])
	

	# Announce the size first so the server can validate it before reading the payload
	send_json(client_socket, {"type": "EVIDENCE", "session": SESSION["session_id"], "size": len(blob)})
	response = recv_json(client_socket)
	if response.get("status") != "READY":
		print("Server refused the transfer:", response.get("message"))
		return False

	send_msg(client_socket, blob)                       # framed: 4-byte length + nonce|ciphertext|tag

	# T11 TEST: announce the full blob in the header, send only half, then cut the connection
	# client_socket.sendall(HEADER.pack(len(blob)) + blob[:len(blob) // 2])
	# client_socket.close()
	# print("Connection interrupted during transfer - delivery NOT confirmed")
	# return False

	response = recv_json(client_socket)                # a lost connection raises here: NOT delivered
	if response.get("status") != "OK":
		print("Server rejected the evidence:", response.get("message"))
		return False
	if response.get("sha256") != local_hash:
		print("WARNING: server's hash does not match the original - delivery NOT verified")
		return False

	print(f"DELIVERED and verified ({len(manifesto)} bytes, SHA-256 {local_hash})")
	return True

