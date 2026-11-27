import socket
import csv
import nmap

SCAN_RESULTS = "scan_results.csv"
CSV_FIELDS = ["host", "port", "state", "service", "product", "version", "extrainfo"]

def get_host_input(prompt):
	# Check if hostname is valid
	invalid = True
	while invalid:
		target = input(prompt)
		try:
			target_ip = socket.gethostbyname(target)
			print ("INFO - IP Resolved - Target IP is ", target_ip)
		except socket.gaierror:
			print("ERROR: Invalid hostname or IP address")
			continue
		break
	return target_ip

# Get port input
def get_port_input(prompt, starting_port=0):
	invalid = True
	while invalid:
		# Make sure user entered an integer
		try:
			port = int(input(prompt))
		except:
			print("ERROR: Enter a valid integer between 1 and 65535")
			continue

		# Ensure that the end port is bigger than the starting port
		if port < starting_port:
			print("ERROR: End Port must be larger than Starting Port")
			continue

		# make sure port within correct range
		if not (1 <= port <= 65535):
			print("ERROR: Invalid Port Number - Port must be between 1 and 65535")
			continue
		
		if (starting_port != 0) and (port - starting_port > 1000):
			print("ERROR: Port Range too large. Try something smaller")
		else:
			return port

def tcp_scan():
	# Get inputs from user
	target = get_host_input("Target host: ")
	start_port = get_port_input("Start port: ")
	end_port = get_port_input("End port: ", starting_port=start_port)

	# Return an empty result if range is too large (caller treats it as "service unavailable")
	if end_port - start_port >= 1000:
		print("ERROR: Range too large")
		return {}

	# Create scanner. -sV = probe open ports for service/version info
	try:
		scanner = nmap.PortScanner()
		scanner.scan(target, f"{start_port}-{end_port}", arguments="-sV")
	except nmap.PortScannerError as e:
		print(f"ERROR: Scan failed (is nmap installed and on PATH?): {e}")
		return {}

	# Host down / unreachable: nmap returns no entry for it, so don't index scanner[target]
	if target not in scanner.all_hosts():
		print(f"ERROR: Target {target} is down or unreachable")
		return {}

	results = scanner[target].get("tcp", {})

	# Save findings as a real comma-separated CSV (nmap's own csv() uses ';')
	with open(SCAN_RESULTS, "w", newline="") as f:
		writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
		writer.writeheader()
		for port, info in results.items():
			writer.writerow({"host": target, "port": port, "state": info["state"],
				"service": info["name"] or "unknown", "product": info["product"],
				"version": info["version"], "extrainfo": info["extrainfo"]})

	print()
	# If open_ports less than 1, print no open ports. Else, print open ports
	if len(results) < 1:
		print("No open ports found in the selected range")
	else:
		print(f"{'Port':<10} {'State':<10} {'Service':<15} {'Version'}")
		print("-" * 60)
		for port, info in results.items():
			service = info["name"] or "unknown"
			version = f"{info['product']} {info['version']}".strip() or "-"
			print(f"{port:<10} {info['state']:<10} {service:<15} {version}")
	print()
	print(f"Scan Complete. Results saved to {SCAN_RESULTS}")

	return results


	