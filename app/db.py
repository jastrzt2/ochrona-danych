import datetime
import sqlite3
import os
from Crypto.PublicKey import RSA
from AES_encrypter_decrypted import rsa_aes_decrypt, rsa_aes_encrypt
from authorization import hash_password
from signer import create_sign

DB_PATH = 'database.db'

def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                password TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                content TEXT,
                sign TEXT,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                ip_address TEXT NOT NULL,
                login_time TEXT NOT NULL,
                country TEXT,
                country_code TEXT,
                isp TEXT,
                city TEXT,
                user_agent TEXT NULL,
                success INTEGER NOT NULL NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                attempt_time TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS send_reset_email_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                attempt_time TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS registration_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                attempt_time TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, private_key, public_key, password, email FROM users WHERE id=?', (user_id,))
    row = c.fetchone()
    conn.close()
    return row

def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, private_key, public_key, password, email, totp_secret FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    return row

def get_user_basic_data_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, public_key FROM users WHERE id=?', (user_id,))
    row = c.fetchone()
    conn.close()
    return row

def is_email_in_database(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
    result = c.fetchone()
    return result[0] > 0

def get_user_id_by_email(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def update_user_password(user_id, new_password, current_password):
    private_key = get_user_private_key(user_id) 
    decrypted_private_key = rsa_aes_decrypt(private_key, current_password)
    encrypted_private_key = rsa_aes_encrypt(decrypted_private_key, new_password)
    totp = get_user_totp_secret(user_id, current_password)
    encrypted_totp = rsa_aes_encrypt(totp, new_password)
    new_password_hash = hash_password(new_password)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET password = ?, private_key = ?, totp_secret = ? WHERE id = ?', (new_password_hash, encrypted_private_key, encrypted_totp, user_id))
    conn.commit()  
    conn.close() 

def reset_password_update_user_data(user_id, new_password, new_totp_secrect):
    private_key = RSA.generate(2048) 
    public_key = private_key.public_key()
    encrypted_private_key = rsa_aes_encrypt(private_key.export_key(), new_password)
    public_key_exported = public_key.export_key()
    
    resign_all_notes(user_id, private_key)
    
    encrypted_totp = rsa_aes_encrypt(new_totp_secrect, new_password)
    new_password_hash = hash_password(new_password)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET password = ?, private_key = ?, public_key = ?, totp_secret = ? WHERE id = ?', (new_password_hash, encrypted_private_key, public_key_exported, encrypted_totp, user_id))
    conn.commit()  
    conn.close() 

def resign_all_notes(user_id, private_key):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, content FROM notes WHERE user_id=?', (user_id,))
    rows = c.fetchall()
    conn.close()
    for row in rows:
        note_id = row[0]
        content = row[1]
        sign = create_sign(content, private_key)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE notes SET sign = ? WHERE id=? AND user_id=?', (sign, note_id, user_id))
        conn.commit()
        conn.close()

def get_user_totp_secret(user_id, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT totp_secret FROM users WHERE id=?', (user_id,))
    row = c.fetchone()
    conn.close()
    encrypted_totp_secret = row[0]
    decrypted_totp_secret = rsa_aes_decrypt(encrypted_totp_secret, password)

    return decrypted_totp_secret

def create_user(username, password, email, totp_secret):
    hashed_password = hash_password(password)
    private_key = RSA.generate(2048) 
    public_key = private_key.public_key()
    encrypted_private_key = rsa_aes_encrypt(private_key.export_key(), password)
    public_key_exported = public_key.export_key()
    
    totp_secret_encrypted = rsa_aes_encrypt(totp_secret.encode('utf-8'), password)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password, private_key, public_key, email, totp_secret) VALUES (?, ?, ?, ?, ?, ?)', (username, hashed_password, encrypted_private_key, public_key_exported, email, totp_secret_encrypted))
    conn.commit()
    conn.close()

def get_user_private_key(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT private_key FROM users WHERE id=?', (user_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise ValueError(f"User with ID {user_id} not found.")

    private_key = row[0]

    return private_key


def create_note(title, content, user_id, password):
    encrypted_private_key = get_user_private_key(user_id)
    private_key = RSA.import_key(rsa_aes_decrypt(encrypted_private_key, password))
    sign = create_sign(content, private_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO notes (title, content, sign, user_id) VALUES (?, ?, ?, ?)', (title, content, sign, user_id))
    conn.commit()
    conn.close()

def get_notes_by_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, title, content FROM notes WHERE user_id=?', (user_id,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_note_by_id(note_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, title, content, sign, user_id FROM notes WHERE id=?', (note_id,))
    row = c.fetchone()
    conn.close()
    return row

def get_user_note_by_id(note_id, user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, title, content, sign, user_id FROM notes WHERE id=? AND user_id=?', (note_id, user_id))
    row = c.fetchone()
    conn.close()
    return row

def update_note(note_id, title, content, user_id, password):
    encrypted_private_key = get_user_private_key(user_id)
    private_key = RSA.import_key(rsa_aes_decrypt(encrypted_private_key, password))
    sign = create_sign(content, private_key)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE notes SET title=?, content=?, sign = ? WHERE id=? AND user_id=?', (title, content, sign, note_id, user_id))
    conn.commit()
    conn.close()


def delete_note(note_id, user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM notes WHERE id=? AND user_id=?', (note_id, user_id))
    conn.commit()
    conn.close()

def get_latest_notes(limit=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if limit is not None:
        c.execute('SELECT notes.id, notes.title, users.username FROM notes JOIN users ON notes.user_id = users.id ORDER BY notes.id DESC LIMIT ?', (limit,))
    else:
        c.execute('SELECT notes.id, notes.title, users.username FROM notes JOIN users ON notes.user_id = users.id ORDER BY notes.id DESC')
    rows = c.fetchall()
    conn.close()
    return rows


def get_latest_users(limit=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if limit is not None:
        c.execute('SELECT id, username FROM users ORDER BY id DESC LIMIT ?', (limit,))
    else:
        c.execute('SELECT id, username FROM users ORDER BY id DESC')  # Bez limitu
    rows = c.fetchall()
    conn.close()
    return rows

def save_reset_token(user_id, token):
    expiration_time = (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO password_reset_tokens (user_id, token, expires_at)
        VALUES (?, ?, ?)
    ''', (user_id, token, expiration_time))
    conn.commit()
    conn.close()
    
def get_user_id_by_reset_token(token):
    now = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT user_id FROM password_reset_tokens
        WHERE token = ? AND expires_at > ?
    ''', (token, now))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def delete_reset_token(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM password_reset_tokens WHERE token = ?', (token,))
    conn.commit()
    conn.close()
    
def record_login_attempt(user_id, ip_address, country, country_code, isp, city, login_time, user_agent, success):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO login_attempts (user_id, ip_address, country, country_code, isp, city, login_time, user_agent, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 
              (user_id, ip_address, country, country_code, isp, city, login_time, user_agent, success ))
    conn.commit()
    conn.close()
    
def get_unique_ips(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT ip_address, COUNT(*) AS attempts
        FROM login_attempts
        WHERE user_id = ?
        GROUP BY ip_address
        ORDER BY attempts DESC
    ''', (user_id,))
    rows = c.fetchall()
    conn.close()
    return rows 

def get_login_attempts(user_id, limit=100):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT id, ip_address, login_time, country, country_code, isp, city, user_agent, success
        FROM login_attempts
        WHERE user_id = ?
        ORDER BY login_time DESC
        LIMIT ?
    ''', (user_id, limit))
    rows = c.fetchall()
    conn.close()
    return rows

def has_exceeded_login_attempts(ip_address, time_limit=30, attempt_limit=5):
    thirty_minutes_ago = datetime.datetime.now() - datetime.timedelta(minutes=time_limit)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        SELECT COUNT(*) FROM login_attempts
        WHERE ip_address = ? AND login_time >= ? 
    ''', (ip_address, thirty_minutes_ago))

    count = c.fetchone()[0]
    conn.close()
    return count > attempt_limit

def record_password_reset_attempt(ip, attempt_time):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO password_reset_attempts (ip, attempt_time) VALUES (?, ?)', (ip, attempt_time))
    conn.commit()
    conn.close()

def count_password_reset_attempts(ip, time_limit=30, attempt_limit = 5):
    time_limit_ago = (datetime.datetime.now() - datetime.timedelta(minutes=time_limit))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT COUNT(*) FROM password_reset_attempts
        WHERE ip = ? AND attempt_time >= ?
    ''', (ip, time_limit_ago))
    count = c.fetchone()[0]
    conn.close()
    return count > attempt_limit


def record_send_reset_email_attempt(ip, attempt_time):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO send_reset_email_attempts (ip, attempt_time) VALUES (?, ?)', (ip, attempt_time))
    conn.commit()
    conn.close()

def count_send_reset_email_attempts(ip, time_limit=30, attempt_limit = 5):
    time_limit_ago = (datetime.datetime.now() - datetime.timedelta(minutes=time_limit))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT COUNT(*) FROM send_reset_email_attempts
        WHERE ip = ? AND attempt_time >= ?
    ''', (ip, time_limit_ago))
    count = c.fetchone()[0]
    conn.close()
    return count > attempt_limit

def record_registration_attempt(ip, attempt_time):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO registration_attempts (ip, attempt_time) VALUES (?, ?)', (ip, attempt_time))
    conn.commit()
    conn.close()

def count_registration_attempts(ip, time_limit=30, attempt_limit = 5):
    time_limit_ago = (datetime.datetime.now() - datetime.timedelta(minutes=time_limit))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT COUNT(*) FROM registration_attempts
        WHERE ip = ? AND attempt_time >= ?
    ''', (ip, time_limit_ago))
    count = c.fetchone()[0]
    conn.close()
    return count > attempt_limit