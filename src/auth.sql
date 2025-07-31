CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
);
CREATE TABLE permissions (
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    PRIMARY KEY (role, action)
);
INSERT INTO users (username, password_hash, role) VALUES ('admin', 'hashed_admin_pass', 'admin');
INSERT INTO users (username, password_hash, role) VALUES ('user', 'hashed_user_pass', 'user');
INSERT INTO permissions (role, action) VALUES ('admin', 'upload');
INSERT INTO permissions (role, action) VALUES ('admin', 'delete');
INSERT INTO permissions (role, action) VALUES ('user', 'upload');
