import sqlite3
import bcrypt

db_path = "db/access_control.db"
with sqlite3.connect(db_path) as conn:
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")  # Clear old placeholder data
    conn.commit()
    # Add users with hashed passwords
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("admin", bcrypt.hashpw("admin".encode(), bcrypt.gensalt()), "admin"))
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("user", bcrypt.hashpw("user".encode(), bcrypt.gensalt()), "user"))
    conn.commit()