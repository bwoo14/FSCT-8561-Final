import csv
import datetime
from pathlib import Path

LOG_FILE = Path(__file__).with_name("server_log.csv")   # always next to the server code, whatever the cwd
LOG_FIELDS = ["timestamp", "type", "message"]


def _safe(text):
	# Stop CSV/formula injection: attacker-controlled text (e.g. a username) starting with
	# = + - @ would run as a formula if the log is opened in Excel
	text = str(text)
	if text[:1] in ("=", "+", "-", "@"):
		text = "'" + text
	return text


def logging(type, message): # Simple logging function: prints AND appends to server_log.csv
	timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
	print(f"{timestamp} {type} - {message}")

	new_file = not LOG_FILE.exists()
	with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
		writer = csv.writer(f)          # csv module quotes commas/newlines, so one event = one row
		if new_file:
			writer.writerow(LOG_FIELDS)
		writer.writerow([timestamp, type, _safe(message)])
