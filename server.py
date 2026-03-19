import json
import os
import secrets
import sqlite3
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import hashlib


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"

AUTH_HASH_ITERATIONS = 120000
MAX_LOGIN_ATTEMPTS = 3
LOGIN_LOCK_MS = 30000
CURRENT_SCHEMA_VERSION = 2

DEFAULT_USERNAME = "besir"
DEFAULT_PASSWORD = "Mys7806720?"

SESSIONS = {}


def now_ms() -> int:
    return int(time.time() * 1000)


def default_user_data():
    return {
        "schemaVersion": CURRENT_SCHEMA_VERSION,
        "history": [],
        "draft": [],
        "hiddenColumns": [],
        "imageDirName": "",
        "isimListesi": [{"id": i, "isim": f"{i}. Komite Uyesi Adayi"} for i in range(1, 13)],
    }


def hash_password(password: str, salt_hex: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        AUTH_HASH_ITERATIONS,
    )
    return digest.hex()


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lock_until INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                data_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(username) REFERENCES users(username)
            )
            """
        )

        existing = conn.execute(
            "SELECT username FROM users WHERE username = ?",
            (DEFAULT_USERNAME,),
        ).fetchone()

        if not existing:
            salt_hex = secrets.token_hex(16)
            ts = now_ms()
            conn.execute(
                """
                INSERT INTO users (username, password_salt, password_hash, failed_attempts, lock_until, created_at, updated_at)
                VALUES (?, ?, ?, 0, 0, ?, ?)
                """,
                (DEFAULT_USERNAME, salt_hex, hash_password(DEFAULT_PASSWORD, salt_hex), ts, ts),
            )

        existing_profile = conn.execute(
            "SELECT username FROM profiles WHERE username = ?",
            (DEFAULT_USERNAME,),
        ).fetchone()
        if not existing_profile:
            ts = now_ms()
            conn.execute(
                """
                INSERT INTO profiles (username, schema_version, data_json, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (DEFAULT_USERNAME, CURRENT_SCHEMA_VERSION, json.dumps(default_user_data(), ensure_ascii=False), ts),
            )


class AppHandler(SimpleHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _get_auth_username(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:].strip()
        return SESSIONS.get(token)

    def _handle_default_user(self):
        self._send_json({"username": DEFAULT_USERNAME})

    def _handle_login_status(self, query):
        username = (query.get("username", [""])[0] or "").strip()
        if not username:
            self._send_json({"locked": False, "lockUntil": 0})
            return
        with get_conn() as conn:
            row = conn.execute(
                "SELECT lock_until FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        lock_until = int(row["lock_until"]) if row else 0
        self._send_json({"locked": lock_until > now_ms(), "lockUntil": lock_until})

    def _handle_login(self):
        body = self._read_json()
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))

        if not username or not password:
            self._send_json({"error": "Kullanıcı adı ve şifre zorunlu."}, status=400)
            return

        with get_conn() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user:
                self._send_json({"error": "Kullanıcı adı veya şifre hatalı."}, status=401)
                return

            lock_until = int(user["lock_until"] or 0)
            if lock_until > now_ms():
                self._send_json({"error": "Hesap kilitli.", "lockUntil": lock_until}, status=423)
                return

            expected = user["password_hash"]
            incoming = hash_password(password, user["password_salt"])
            if incoming != expected:
                failed_attempts = int(user["failed_attempts"] or 0) + 1
                if failed_attempts >= MAX_LOGIN_ATTEMPTS:
                    next_lock = now_ms() + LOGIN_LOCK_MS
                    conn.execute(
                        "UPDATE users SET failed_attempts = 0, lock_until = ?, updated_at = ? WHERE username = ?",
                        (next_lock, now_ms(), username),
                    )
                    self._send_json(
                        {"error": "Hesap kilitli.", "lockUntil": next_lock},
                        status=423,
                    )
                    return
                conn.execute(
                    "UPDATE users SET failed_attempts = ?, lock_until = 0, updated_at = ? WHERE username = ?",
                    (failed_attempts, now_ms(), username),
                )
                self._send_json(
                    {
                        "error": "Kullanıcı adı veya şifre hatalı.",
                        "remainingAttempts": max(0, MAX_LOGIN_ATTEMPTS - failed_attempts),
                    },
                    status=401,
                )
                return

            conn.execute(
                "UPDATE users SET failed_attempts = 0, lock_until = 0, updated_at = ? WHERE username = ?",
                (now_ms(), username),
            )

            profile = conn.execute(
                "SELECT data_json, updated_at FROM profiles WHERE username = ?",
                (username,),
            ).fetchone()
            if profile:
                user_data = json.loads(profile["data_json"])
                profile_updated_at = int(profile["updated_at"] or 0)
            else:
                user_data = default_user_data()
                profile_updated_at = now_ms()
                conn.execute(
                    "INSERT INTO profiles (username, schema_version, data_json, updated_at) VALUES (?, ?, ?, ?)",
                    (username, CURRENT_SCHEMA_VERSION, json.dumps(user_data, ensure_ascii=False), profile_updated_at),
                )

        token = secrets.token_urlsafe(32)
        SESSIONS[token] = username
        self._send_json(
            {
                "token": token,
                "username": username,
                "userData": user_data,
                "updatedAt": profile_updated_at,
            }
        )

    def _handle_get_profile(self):
        username = self._get_auth_username()
        if not username:
            self._send_json({"error": "Yetkisiz."}, status=401)
            return
        with get_conn() as conn:
            profile = conn.execute(
                "SELECT data_json, updated_at FROM profiles WHERE username = ?",
                (username,),
            ).fetchone()
            if not profile:
                user_data = default_user_data()
                profile_updated_at = now_ms()
                conn.execute(
                    "INSERT INTO profiles (username, schema_version, data_json, updated_at) VALUES (?, ?, ?, ?)",
                    (username, CURRENT_SCHEMA_VERSION, json.dumps(user_data, ensure_ascii=False), profile_updated_at),
                )
            else:
                user_data = json.loads(profile["data_json"])
                profile_updated_at = int(profile["updated_at"] or 0)
        self._send_json({"userData": user_data, "updatedAt": profile_updated_at})

    def _handle_put_profile(self):
        username = self._get_auth_username()
        if not username:
            self._send_json({"error": "Yetkisiz."}, status=401)
            return
        body = self._read_json()
        user_data = body.get("userData")
        if not isinstance(user_data, dict):
            self._send_json({"error": "Geçersiz veri."}, status=400)
            return
        ts = now_ms()
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO profiles (username, schema_version, data_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                  schema_version=excluded.schema_version,
                  data_json=excluded.data_json,
                  updated_at=excluded.updated_at
                """,
                (username, CURRENT_SCHEMA_VERSION, json.dumps(user_data, ensure_ascii=False), ts),
            )
        self._send_json({"ok": True, "updatedAt": ts})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/default-user":
            self._handle_default_user()
            return
        if parsed.path == "/api/login-status":
            self._handle_login_status(parse_qs(parsed.query))
            return
        if parsed.path == "/api/profile":
            self._handle_get_profile()
            return
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            self._handle_login()
            return
        self._send_json({"error": "Not found"}, status=404)

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/profile":
            self._handle_put_profile()
            return
        self._send_json({"error": "Not found"}, status=404)

    def log_message(self, format, *args):
        return


def main():
    init_db()
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"Server running: http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
