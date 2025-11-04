# server/app.py
import os, sys, datetime, sqlite3
from flask import (
    Flask,
    g,
    render_template,
    request,
    jsonify,
    send_from_directory,
    abort,
)

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "ctf.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
ROOM_LOG_DIR = os.path.join(BASE_DIR, "static", "rooms", "web-logs-1")

app = Flask(__name__)


# --- Database and Initialization ---
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


# server/app.py faylının içindəki init_db() funksiyası


def init_db():
    db = get_db()

    # Sıfırdan başlamaq üçün cədvəlləri sil
    db.executescript(
        """
        DROP TABLE IF EXISTS rooms;
        DROP TABLE IF EXISTS questions;
        DROP TABLE IF EXISTS solves;
    """
    )

    db.executescript(
        """
        CREATE TABLE rooms (id TEXT PRIMARY KEY, title TEXT, description TEXT, log_file TEXT);
        CREATE TABLE questions (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT, key TEXT, prompt TEXT, expected TEXT, hint TEXT);
        CREATE TABLE solves (id INTEGER PRIMARY KEY AUTOINCREMENT, question_key TEXT, nickname TEXT, timestamp TEXT);
        """
    )

    # --- ROOM 1 (Log4Shell Attack) ---
    db.execute(
        "INSERT INTO rooms (id, title, description, log_file) VALUES (?, ?, ?, ?)",
        (
            "log4shell-attack",
            "SOC Challenge 1: Log4Shell Exploitation",
            "A multi-stage Log4Shell attack was detected. Download the log and use the SOC Analyzer Tool to find the initial reconnaissance, exploit payload, and final exfiltration.",
            "ctf_attack_log4shell.log",
        ),
    )
    questions_1 = [
        (
            "log4shell-attack",
            "q1",
            "What is the IP address of the initial reconnaissance scanner that used 'Nmap'?",
            "45.55.199.155",
            "Use the 'Log Explorer' tab in the SOC Analyzer. Filter the 'user_agent' column for 'nmap'.",
        ),
        (
            "log4shell-attack",
            "q2",
            "From which **Country (2-letter code)** did the Log4Shell attack (`jndi:ldap`) originate?",
            "GB",  # <-- DÜZƏLİŞ BURADADIR (DE -> GB)
            "Find the jndi IP (167.99.196.188), check its CTI data in the 'Deep-Dive' tab. The tool fetches the LIVE country code.",
        ),
        (
            "log4shell-attack",
            "q3",
            "What is the full filename of the backup file the attacker exfiltrated (stole)?",
            "classified_backup.zip",
            "Look for suspicious 'GET' requests for large files (e.g., .zip) at /backups/.",
        ),
        (
            "log4shell-attack",
            "q4",
            "The Log4Shell exploit payload contained a hidden Base64 string. Decode it and submit the flag.",
            "flag{th1s_is_th3_h1dd3n_l0g4sh3ll_fl4g}",
            "Find the 'jndi' path in the Log Explorer and decode the Base64 string.",
        ),
        (
            "log4shell-attack",
            "q5",
            "Which IP address has the highest AbuseIPDB score (100%) and is associated with 'Contabo'?",
            "104.248.140.21",
            "Check the 'Suspicious IPs Deep-Dive' tab for highest score and owner.",
        ),
        (
            "log4shell-attack",
            "q6",
            "According to the Dashboard Summary, what was the most frequent 404 Not Found error (the most scanned path)?",
            "/admin",
            "Check the 'Top 10 404 Not Found Paths' chart on the 'Dashboard Summary' tab.",
        ),
    ]
    db.executemany(
        "INSERT INTO questions (room_id, key, prompt, expected, hint) VALUES (?, ?, ?, ?, ?)",
        questions_1,
    )

    # --- ROOM 2 (Forensics & Hijack) ---
    db.execute(
        "INSERT INTO rooms (id, title, description, log_file) VALUES (?, ?, ?, ?)",
        (
            "forensics-hijack",
            "SOC Challenge 2: Brute-Force and Session Hijack",
            "Analyze the log to find the successful login and the subsequent data exfiltration by a Tor Exit Node.",
            "ctf_forensics_hijack.log",
        ),
    )
    questions_2 = [
        (
            "forensics-hijack",
            "q7",
            "Which IP address made the most brute-force attempts (highest number of POST /login requests)?",
            "20.12.33.4",
            "Check 'Log Explorer' for the source of '401' responses on /login.",
        ),
        (
            "forensics-hijack",
            "q8",
            "What is the IP address of the Tor Exit Node that stole the session cookie?",
            "185.220.101.40",
            "Filter 'user_agent' for 'Tor Browser'.",
        ),
        (
            "forensics-hijack",
            "q9",
            "The exfiltrated session cookie was Base64 encoded in the request. What is the decoded session value?",
            "StreamableSandstorm",
            "Find the request by the Tor IP (q8) and decode the Base64 value in the URI/COOKIE field.",
        ),
        (
            "forensics-hijack",
            "q10",
            "What is the full path of the API page the attacker successfully exfiltrated data from?",
            "/api/v1/user/settings",
            "Check the request made by the Tor IP (q8).",
        ),
    ]
    db.executemany(
        "INSERT INTO questions (room_id, key, prompt, expected, hint) VALUES (?, ?, ?, ?, ?)",
        questions_2,
    )
    db.commit()


# --- Flask Routes (Same as before) ---
@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db:
        db.close()


@app.route("/")
def index():
    db = get_db()
    rooms = db.execute("SELECT * FROM rooms").fetchall()
    return render_template("index.html", rooms=rooms)


@app.route("/room/<room_id>")
def room(room_id):
    db = get_db()
    room = db.execute("SELECT * FROM rooms WHERE id=?", (room_id,)).fetchone()
    if not room:
        return "Room not found", 404
    questions = db.execute(
        "SELECT key, prompt, COALESCE(hint,'') AS hint FROM questions WHERE room_id=? ORDER BY id ASC",
        (room_id,),
    ).fetchall()
    # Log dosyasının adını template'e gönderiyoruz
    return render_template("room.html", room=room, questions=questions)


# --- CORRECTED DOWNLOAD ROUTE (Downloads the specific log file) ---
@app.route("/room/<room_id>/log")
def download_log(room_id):
    db = get_db()
    room = db.execute("SELECT log_file FROM rooms WHERE id=?", (room_id,)).fetchone()
    if not room:
        abort(404)

    log_filename = room["log_file"]
    log_file_path = os.path.join(ROOM_LOG_DIR, log_filename)

    if not os.path.exists(log_file_path):
        return (
            f"Log file '{log_filename}' not found. Run `python create_new_log.py` in the root folder first.",
            404,
        )

    return send_from_directory(ROOM_LOG_DIR, log_filename, as_attachment=True)


# -----------------------------------------------------------------


@app.route("/leaderboard")
def leaderboard_page():
    return render_template("leaderboard.html")


# Serves the app.js file
@app.route("/static/js/<filename>")
def static_js(filename):
    return send_from_directory(os.path.join(STATIC_DIR, "js"), filename)


# API routes (submit, leaderboard) are unchanged


@app.route("/api/submit", methods=["POST"])
def api_submit():
    data = request.json or {}
    qkey = (data.get("question_key") or "").strip()
    nickname = (data.get("nickname") or "").strip()
    answer = (data.get("answer") or "").strip()

    if not qkey or not nickname or not answer:
        return jsonify({"ok": False, "error": "missing"}), 400

    db = get_db()
    row = db.execute("SELECT expected FROM questions WHERE key=?", (qkey,)).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "no_such_question"}), 404

    exp = (row["expected"] or "").strip()
    correct = answer.strip() == exp

    if correct:
        done = db.execute(
            "SELECT 1 FROM solves WHERE question_key=? AND nickname=?", (qkey, nickname)
        ).fetchone()
        if not done:
            db.execute(
                "INSERT INTO solves (question_key, nickname, timestamp) VALUES (?,?,?)",
                (qkey, nickname, datetime.datetime.utcnow().isoformat() + "Z"),
            )
            db.commit()
        return jsonify({"ok": True, "result": "correct"})
    else:
        return jsonify({"ok": True, "result": "wrong"})


@app.route("/api/leaderboard")
def api_leaderboard():
    db = get_db()
    rows = db.execute(
        "SELECT nickname, COUNT(*) AS solves FROM solves GROUP BY nickname ORDER BY solves DESC, nickname ASC"
    ).fetchall()
    return jsonify([{"nickname": r["nickname"], "solves": r["solves"]} for r in rows])


if __name__ == "__main__":
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print("Previous database cleared.")

    with app.app_context():
        init_db()
        print("Database initialized with new questions.")

    print("--- SOC CTF Platform (Server 1) ---")
    print("Running on: http://127.0.0.1:5001")
    print("-----------------------------------")
    app.run(host="0.0.0.0", port=5001, debug=True)
