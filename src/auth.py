import sqlite3
import bcrypt

class AuthManager:
    def __init__(self, db_path="/home/kali/SecureFileTransfer/db/access_control.db"):
        self.db_path = db_path
        self._setup_db()

    def _setup_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS permissions (
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    PRIMARY KEY (role, action)
                )
            """)
            # Check if default users exist, add if not
            cursor = conn.execute("SELECT username FROM users WHERE username = 'admin'")
            if not cursor.fetchone():
                conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                            ("admin", self.hash_password("adminpass".encode()), "admin"))
            cursor = conn.execute("SELECT username FROM users WHERE username = 'user'")
            if not cursor.fetchone():
                conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                            ("user", self.hash_password("userpass".encode()), "user"))
            # Add default permissions
            conn.execute("INSERT OR IGNORE INTO permissions (role, action) VALUES (?, ?)", ("admin", "scan"))
            conn.execute("INSERT OR IGNORE INTO permissions (role, action) VALUES (?, ?)", ("admin", "transfer"))
            conn.execute("INSERT OR IGNORE INTO permissions (role, action) VALUES (?, ?)", ("admin", "encrypt"))
            conn.execute("INSERT OR IGNORE INTO permissions (role, action) VALUES (?, ?)", ("user", "scan"))
            conn.commit()

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password, salt)

    def verify_password(self, password, hashed):
        return bcrypt.checkpw(password, hashed)  # Removed extra encode

    def register_user(self, username, password, role):
        hashed = self.hash_password(password.encode())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                        (username, hashed, role))
            conn.commit()

    def authenticate(self, username, password):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            if result and self.verify_password(password.encode(), result[0]):  # Encode password once
                return {"authenticated": True, "role": result[1]}
            return {"authenticated": False, "role": None}

    def has_permission(self, role, action):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT 1 FROM permissions WHERE role = ? AND action = ?", (role, action))
            return cursor.fetchone() is not None

if __name__ == "__main__":
    auth = AuthManager()
    print(auth.authenticate("admin", "adminpass"))
    print(auth.has_permission("admin", "encrypt"))