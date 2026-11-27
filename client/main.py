import socket
from getpass import getpass
from handle_auth import auth_mfa, auth_password
from handle_command import handle_command, key_exchange
from framing import FramingError, send_json, recv_json, RequiredServiceUnavailableError
import os
import ssl
from tcp_scan import tcp_scan

USE_TLS = os.environ.get("FSCT_USE_TLS", "1") != "0"

def make_tls_context():
    # cafile=... means ONLY our own cert is trusted. Verification and hostname checking stay ON.
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="certs/server.crt")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

def port_scan():
	scan = tcp_scan()
	if isinstance(scan, dict):
		for port, info in scan.items():
			if port == PORT and info.get("state") == "open":
				return True
	return False
				

# Set host and port
HOST = "127.0.0.1"
PORT = 12345

# Session object to store session ID
SESSION = {"session_id": ""}

# Menu dict corresponding number inputs to commands
menu_dict = {
	"1": "EXTRACT",
	"2": "SEND",
	"3": "MSG",
	"4": "EXIT"
}

# Template for menu to be displayed for user
MENU_TEMPLATE = """
Enter one of the following:

[1] Recover Evidence
[2] Send Evidence
[3] Message Server
[4] Exit

Enter Selection (1-4):
"""
client_socket = None
STAGE = "connect"
try:

	port_open = port_scan()

	if not port_open:
		raise RequiredServiceUnavailableError(
        	host=HOST,
        	port=PORT,
        	message="Target port is not open or reachable",)
	else:
		print(f"INFO -- {HOST} and port: {PORT} are open, attempting connection")
	
	client_socket = socket.create_connection((HOST, PORT), timeout=15)

	if USE_TLS:
		client_socket = make_tls_context().wrap_socket(client_socket, server_hostname=HOST)
		print(f"INFO: TLS established ({client_socket.version()})")
	else:
		print("WARNING: TLS disabled, credentials will be sent in plaintext")

	# Track which phase we are in so a dropped connection gets the right error message
	STAGE = "auth"

	# Begin password authentication requests using helper function
	password_authenticated = False
	password_authenticated = auth_password(client_socket)

	# Begin OTP authentication using Helpder function 
	otp_authenticated = False
	otp_authenticated = auth_mfa(client_socket, SESSION)

	SESSION["key"] = key_exchange(client_socket, SESSION["session_id"])
	print("INFO: Encryption key established for this session")
	STAGE = "session"

	# Maintain connection using While loop
	while True:
		# Prompt user for message to send
		command_selection = input(
			MENU_TEMPLATE
		)
		try: # Ensure valid command selection
			command = menu_dict[command_selection]
		except: # If not, continue loop from start
			print("Invalid Option")
			continue
		

		# Check if message is "EXIT"; if yes, terminate connection
		if command.upper() == "EXIT":
			# Sending "EXIT" command to server
			send_json(client_socket, {"type": "EXIT"})
			print("Server:", recv_json(client_socket).get("message"))
			# Get server response, decode, and print
			break
		else:
			#  send command to helper function to be sent to server
			message = handle_command(command, client_socket, SESSION)

# Discovery said the service is not there (T02) - must come BEFORE FramingError (it is a subclass)
except RequiredServiceUnavailableError as e:
	print(f"\nERROR: Required service unavailable - {e}. Not connecting.")

# Handle case for offline server
except ConnectionRefusedError:
	print("\nERROR: Couldn't establish a connection to the target machine - closing")

# Certificate check failed - must come BEFORE ssl.SSLError (it is a subclass)
except ssl.SSLCertVerificationError:
	print("\nERROR: Server certificate could not be verified - refusing to send credentials")

# Server went quiet for longer than the socket timeout
except (socket.timeout, TimeoutError):
	print("\nERROR: Server did not respond in time - closing")
	if STAGE == "session":
		print("ERROR: Any evidence transfer in progress was NOT confirmed")

# Connection dropped (under TLS a cut connection shows up as ssl.SSLError)
except (ConnectionResetError, BrokenPipeError, FramingError, ssl.SSLError) as e:
	if STAGE == "connect":
		print(f"\nERROR: Could not establish a secure connection: {e}")
	elif STAGE == "auth":
		print("\nERROR: Server closed the connection during login (too many failed attempts?)")
	else:
		print("\nERROR: Connection lost - any evidence transfer in progress was NOT confirmed")

# Handle case if user terminates program
except KeyboardInterrupt:
	print("\nINFO: Program terminated by user")

except RuntimeError as e:
	print(f"\nERROR: {e}")

# Any other network error (e.g. host unreachable)
except OSError as e:
	print(f"\nERROR: Network error: {e}")
# Close connection
finally:
	try:
		client_socket.close()
	except:
		print("Exiting")