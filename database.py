"""
=============================================================================
SecureSync – Production Database & Security Layer
File: database.py
Description: Production-ready persistent database manager supporting both
             PostgreSQL (via DATABASE_URL) and SQLite (local fallback).
             Enforces salted PBKDF2:SHA-256 password hashing, strict multi-tenant
             user isolation, secure password recovery tokens, and full account lifecycle.
=============================================================================
"""

import os
import re
import json
import uuid
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

# Try importing PostgreSQL driver if available
try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_DB_PATH = os.path.join(BASE_DIR, 'database.db')


def get_database_url() -> Optional[str]:
    """Returns the normalized DATABASE_URL if configured for PostgreSQL."""
    url = os.environ.get('DATABASE_URL')
    if url and url.startswith('postgres://'):
        # Fix Render / Heroku legacy postgres:// scheme to postgresql://
        url = url.replace('postgres://', 'postgresql://', 1)
    return url


def is_postgres() -> bool:
    """Checks whether the application is configured to connect to PostgreSQL."""
    db_url = get_database_url()
    return bool(db_url and db_url.startswith('postgresql://') and HAS_PSYCOPG2)


class DBConnection:
    """Context manager for unified PostgreSQL and SQLite transactions."""
    def __init__(self):
        self.is_pg = is_postgres()
        self.conn = None

    def __enter__(self):
        if self.is_pg:
            db_url = get_database_url()
            self.conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            self.conn = sqlite3.connect(SQLITE_DB_PATH)
            self.conn.row_factory = sqlite3.Row
            # Enable SQLite foreign key constraints
            self.conn.execute("PRAGMA foreign_keys = ON")
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()


def placeholder(param_name_or_num: int = 1) -> str:
    """Returns '%s' for PostgreSQL or '?' for SQLite."""
    return '%s' if is_postgres() else '?'


def init_db():
    """
    Initializes database tables if they do not exist:
      - users
      - scans
      - password_resets
    Data is permanently persisted and NEVER wiped on startup.
    """
    with DBConnection() as conn:
        cursor = conn.cursor()

        if is_postgres():
            # PostgreSQL Schema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    full_name VARCHAR(150),
                    role VARCHAR(50) DEFAULT 'Security Analyst',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id SERIAL PRIMARY KEY,
                    scan_id VARCHAR(64) UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    submitted_message TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level VARCHAR(20) NOT NULL,
                    threat_classification VARCHAR(50) NOT NULL,
                    detection_reasons TEXT NOT NULL,
                    suspicious_indicators TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_resets (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(64) UNIQUE NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    used INTEGER DEFAULT 0,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            ''')
        else:
            # SQLite Schema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    role TEXT DEFAULT 'Security Analyst',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    submitted_message TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    threat_classification TEXT NOT NULL,
                    detection_reasons TEXT NOT NULL,
                    suspicious_indicators TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_resets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );
            ''')


def validate_email(email: str) -> bool:
    """Validates email format using standard regex."""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(pattern, email.strip()))


# -----------------------------------------------------------------------------
# User Authentication & Management
# -----------------------------------------------------------------------------
def register_user(username: str, email: str, password: str, full_name: Optional[str] = None, role: str = 'Security Analyst') -> Dict[str, Any]:
    """
    Registers a new user with salted PBKDF2:SHA-256 password hashing.
    Enforces unique username and email.
    """
    username = username.strip() if username else ""
    email = email.strip().lower() if email else ""

    if not username or len(username) < 3:
        return {"success": False, "message": "Username must be at least 3 characters long."}

    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return {"success": False, "message": "Username can only contain letters, numbers, dots, hyphens, and underscores."}

    if not validate_email(email):
        return {"success": False, "message": "Please enter a valid email address."}

    if not password or len(password) < 6:
        return {"success": False, "message": "Password must be at least 6 characters long."}

    display_name = full_name.strip() if (full_name and full_name.strip()) else username
    p = placeholder()

    with DBConnection() as conn:
        cursor = conn.cursor()

        # Check duplicate username
        cursor.execute(f"SELECT id FROM users WHERE LOWER(username) = LOWER({p})", (username,))
        if cursor.fetchone():
            return {"success": False, "message": f"Username '{username}' is already taken. Please choose another."}

        # Check duplicate email
        cursor.execute(f"SELECT id FROM users WHERE LOWER(email) = LOWER({p})", (email,))
        if cursor.fetchone():
            return {"success": False, "message": f"Email '{email}' is already registered. Please sign in or use another email."}

        # Cryptographically hash password with salt
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        if is_postgres():
            cursor.execute(f"""
                INSERT INTO users (username, email, password_hash, full_name, role)
                VALUES ({p}, {p}, {p}, {p}, {p}) RETURNING id
            """, (username, email, password_hash, display_name, role))
            user_id = cursor.fetchone()['id']
        else:
            cursor.execute(f"""
                INSERT INTO users (username, email, password_hash, full_name, role)
                VALUES ({p}, {p}, {p}, {p}, {p})
            """, (username, email, password_hash, display_name, role))
            user_id = cursor.lastrowid

        return {"success": True, "user_id": user_id, "message": "Account created successfully! Please sign in."}


def authenticate_user(identifier: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticates a user via Username OR Email with PBKDF2 hash verification.
    """
    if not identifier or not password:
        return None

    clean_identifier = identifier.strip().lower()
    p = placeholder()

    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT * FROM users
            WHERE LOWER(username) = LOWER({p}) OR LOWER(email) = LOWER({p})
        """, (clean_identifier, clean_identifier))
        user_row = cursor.fetchone()

        if not user_row:
            return None

        # Convert row to standard dict
        user_dict = dict(user_row)
        stored_hash = user_dict['password_hash']

        if check_password_hash(stored_hash, password):
            return {
                "id": user_dict['id'],
                "username": user_dict['username'],
                "email": user_dict['email'],
                "full_name": user_dict.get('full_name') or user_dict['username'],
                "role": user_dict.get('role', 'Security Analyst'),
                "created_at": str(user_dict.get('created_at', ''))
            }
        return None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves user profile by ID."""
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email, full_name, role, created_at FROM users WHERE id = {p}", (user_id,))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            d['created_at'] = str(d.get('created_at', ''))
            return d
        return None


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieves user profile by Email."""
    if not email:
        return None
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email, full_name, role FROM users WHERE LOWER(email) = LOWER({p})", (email.strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def change_user_password(user_id: int, current_password: str, new_password: str) -> Dict[str, Any]:
    """
    Validates current password and updates to a new salted PBKDF2 hash.
    """
    if not new_password or len(new_password) < 6:
        return {"success": False, "message": "New password must be at least 6 characters long."}

    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT password_hash FROM users WHERE id = {p}", (user_id,))
        row = cursor.fetchone()
        if not row:
            return {"success": False, "message": "User not found."}

        stored_hash = dict(row)['password_hash']
        if not check_password_hash(stored_hash, current_password):
            return {"success": False, "message": "Current password is incorrect."}

        new_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute(f"UPDATE users SET password_hash = {p} WHERE id = {p}", (new_hash, user_id))
        return {"success": True, "message": "Password changed successfully."}


def delete_user_account(user_id: int) -> Dict[str, Any]:
    """
    Permanently and securely deletes a user account and all associated scans and tokens.
    """
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        # Delete associated scans
        cursor.execute(f"DELETE FROM scans WHERE user_id = {p}", (user_id,))
        # Delete password reset tokens
        cursor.execute(f"DELETE FROM password_resets WHERE user_id = {p}", (user_id,))
        # Delete user
        cursor.execute(f"DELETE FROM users WHERE id = {p}", (user_id,))
        return {"success": True, "message": "Account and all associated data permanently erased."}


# -----------------------------------------------------------------------------
# Password Reset Tokens
# -----------------------------------------------------------------------------
def hash_token(raw_token: str) -> str:
    """Hashes token with SHA-256 for safe database storage."""
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()


def create_password_reset_token(email: str) -> Optional[Tuple[str, str]]:
    """
    Generates a secure single-use password reset token with 1-hour expiration.
    Returns (raw_token, username) or None if user does not exist.
    """
    user = get_user_by_email(email)
    if not user:
        return None

    raw_token = secrets.token_urlsafe(32)
    token_hashed = hash_token(raw_token)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    p = placeholder()

    with DBConnection() as conn:
        cursor = conn.cursor()
        # Invalidate previous unused tokens for this user
        cursor.execute(f"UPDATE password_resets SET used = 1 WHERE user_id = {p}", (user['id'],))
        # Insert new token
        cursor.execute(f"""
            INSERT INTO password_resets (user_id, token_hash, expires_at, used)
            VALUES ({p}, {p}, {p}, 0)
        """, (user['id'], token_hashed, expires_at))

    return raw_token, user['username']


def verify_and_use_reset_token(raw_token: str, new_password: str) -> Dict[str, Any]:
    """
    Validates token expiration, applies new password, and marks token as used.
    """
    if not raw_token or not new_password or len(new_password) < 6:
        return {"success": False, "message": "Password must be at least 6 characters long."}

    token_hashed = hash_token(raw_token)
    p = placeholder()

    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT pr.id, pr.user_id, pr.expires_at, pr.used
            FROM password_resets pr
            WHERE pr.token_hash = {p}
        """, (token_hashed,))
        record = cursor.fetchone()

        if not record:
            return {"success": False, "message": "Invalid or expired password reset link."}

        rec_dict = dict(record)
        if rec_dict['used']:
            return {"success": False, "message": "This password reset link has already been used."}

        # Check expiration
        expires_at = rec_dict['expires_at']
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            except Exception:
                pass

        # Handle UTC naive vs aware
        now = datetime.utcnow()
        if hasattr(expires_at, 'tzinfo') and expires_at.tzinfo is not None:
            from datetime import timezone
            now = datetime.now(timezone.utc)

        if now > expires_at:
            return {"success": False, "message": "This reset link has expired. Please request a new one."}

        # Token is valid; apply new password
        new_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        user_id = rec_dict['user_id']

        cursor.execute(f"UPDATE users SET password_hash = {p} WHERE id = {p}", (new_hash, user_id))
        cursor.execute(f"UPDATE password_resets SET used = 1 WHERE id = {p}", (rec_dict['id'],))

        return {"success": True, "message": "Password reset successfully! You can now log in with your new password."}


# -----------------------------------------------------------------------------
# Scans & User Threat History
# -----------------------------------------------------------------------------
def save_scan(user_id: int, submitted_message: str, risk_score: int, risk_level: str,
              threat_classification: str, detection_reasons: List[str],
              suspicious_indicators: List[Dict[str, Any]], recommended_action: str) -> str:
    """
    Saves a complete scan report linked to a user. Returns the generated unique scan_id.
    """
    scan_id = f"SCN-{uuid.uuid4().hex[:12].upper()}"
    reasons_json = json.dumps(detection_reasons)
    indicators_json = json.dumps(suspicious_indicators)
    p = placeholder()

    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            INSERT INTO scans (
                scan_id, user_id, submitted_message, risk_score, risk_level,
                threat_classification, detection_reasons, suspicious_indicators,
                recommended_action
            ) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
        """, (
            scan_id, user_id, submitted_message, int(risk_score), risk_level,
            threat_classification, reasons_json, indicators_json, recommended_action
        ))
    return scan_id


def get_user_scans(user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves all past scans strictly belonging to user_id.
    Guarantees cross-tenant data isolation.
    """
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT scan_id, submitted_message, risk_score, risk_level,
                   threat_classification, detection_reasons, suspicious_indicators,
                   recommended_action, created_at
            FROM scans
            WHERE user_id = {p}
            ORDER BY created_at DESC
            LIMIT {p}
        """, (user_id, limit))
        rows = cursor.fetchall()

    results = []
    for r in rows:
        d = dict(r)
        # Parse JSON fields safely
        try:
            d['detection_reasons'] = json.loads(d['detection_reasons'])
        except Exception:
            d['detection_reasons'] = []
        try:
            d['suspicious_indicators'] = json.loads(d['suspicious_indicators'])
        except Exception:
            d['suspicious_indicators'] = []
        
        # Message preview
        raw_msg = d['submitted_message']
        d['message_preview'] = raw_msg[:90] + ('...' if len(raw_msg) > 90 else '')
        d['created_at'] = str(d.get('created_at', ''))
        d['date'] = d['created_at'][:19]
        d['scanned_at'] = d['date']
        d['classification'] = d.get('threat_classification', 'Unknown')
        d['confidence'] = d.get('risk_score', 0)
        results.append(d)

    return results


def get_scan_by_id(scan_id: str, user_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieves a single scan by scan_id ONLY if it belongs to user_id.
    Strictly prevents User B from accessing User A's scans.
    """
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT scan_id, user_id, submitted_message, risk_score, risk_level,
                   threat_classification, detection_reasons, suspicious_indicators,
                   recommended_action, created_at
            FROM scans
            WHERE scan_id = {p} AND user_id = {p}
        """, (scan_id, user_id))
        row = cursor.fetchone()
        if not row:
            return None

        d = dict(row)
        try:
            d['detection_reasons'] = json.loads(d['detection_reasons'])
        except Exception:
            d['detection_reasons'] = []
        try:
            d['suspicious_indicators'] = json.loads(d['suspicious_indicators'])
        except Exception:
            d['suspicious_indicators'] = []
        d['created_at'] = str(d.get('created_at', ''))
        d['date'] = d['created_at'][:19]
        d['scanned_at'] = d['date']
        d['classification'] = d.get('threat_classification', 'Unknown')
        d['confidence'] = d.get('risk_score', 0)
        return d


def get_user_stats(user_id: int) -> Dict[str, Any]:
    """Computes summary statistics specifically for a single user."""
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN threat_classification = 'Suspicious/Scam' THEN 1 ELSE 0 END) as scams,
                SUM(CASE WHEN threat_classification = 'Legitimate' THEN 1 ELSE 0 END) as safe,
                AVG(risk_score) as avg_score
            FROM scans
            WHERE user_id = {p}
        """, (user_id,))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            return {
                "total_scanned": int(d.get('total') or 0),
                "threats_detected": int(d.get('scams') or 0),
                "suspicious_count": int(d.get('scams') or 0),
                "safe_verified": int(d.get('safe') or 0),
                "legitimate_count": int(d.get('safe') or 0),
                "average_risk": round(float(d.get('avg_score') or 0), 1)
            }
        return {
            "total_scanned": 0,
            "threats_detected": 0,
            "suspicious_count": 0,
            "safe_verified": 0,
            "legitimate_count": 0,
            "average_risk": 0
        }


if __name__ == '__main__':
    print("[*] Initializing SecureSync Database...")
    init_db()
    print("[+] Database ready. Target:", "PostgreSQL" if is_postgres() else "SQLite")
