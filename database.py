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
import time
from datetime import datetime, timedelta, timezone
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
    if not url:
        return None
    url = url.strip().strip("'\"")
    if url.startswith('postgres://'):
        # Fix Render / Heroku legacy postgres:// scheme to postgresql://
        url = url.replace('postgres://', 'postgresql://', 1)
    # Ensure Neon and remote cloud PostgreSQL uses sslmode=require
    if 'sslmode=' not in url and 'localhost' not in url and '127.0.0.1' not in url:
        sep = '&' if '?' in url else '?'
        url = f"{url}{sep}sslmode=require"
    return url



def is_postgres() -> bool:
    """Checks whether the application is configured to connect to PostgreSQL."""
    db_url = get_database_url()
    return bool(db_url and db_url.startswith('postgresql://') and HAS_PSYCOPG2)


class DBConnection:
    """Context manager for unified PostgreSQL and SQLite transactions with automatic reconnect retry."""
    def __init__(self):
        self.is_pg = is_postgres()
        self.conn = None

    def __enter__(self):
        if self.is_pg:
            db_url = get_database_url()
            max_retries = 3
            last_err = None
            for attempt in range(max_retries):
                try:
                    self.conn = psycopg2.connect(
                        db_url,
                        cursor_factory=psycopg2.extras.RealDictCursor,
                        connect_timeout=10
                    )
                    break
                except Exception as e:
                    last_err = e
                    if attempt < max_retries - 1:
                        time.sleep(0.8)
                    else:
                        raise last_err
        else:
            self.conn = sqlite3.connect(SQLITE_DB_PATH)
            self.conn.row_factory = sqlite3.Row
            # Enable SQLite foreign key constraints
            self.conn.execute("PRAGMA foreign_keys = ON")
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            try:
                if exc_type is None:
                    self.conn.commit()
                else:
                    self.conn.rollback()
            finally:
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
    Idempotent and safe to run on deployment without destroying data.
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

            # Performance & Data Integrity Indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets(token_hash);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);')

            # Safe column additions if needed (non-destructive migrations)
            cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(150);')
            cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT \'Security Analyst\';')
            cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS privacy_settings TEXT DEFAULT \'{"auto_quarantine_links": true, "sanitize_metadata": true, "retention_days": 90}\';')
            cursor.execute('ALTER TABLE scans ADD COLUMN IF NOT EXISTS modality VARCHAR(20) DEFAULT \'text\';')
            cursor.execute('ALTER TABLE scans ADD COLUMN IF NOT EXISTS file_name VARCHAR(255) DEFAULT \'\';')
            cursor.execute('ALTER TABLE scans ADD COLUMN IF NOT EXISTS file_hash VARCHAR(64) DEFAULT \'\';')
            cursor.execute('ALTER TABLE scans ADD COLUMN IF NOT EXISTS technical_details TEXT DEFAULT \'{}\';')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_modality ON scans(modality);')
            # Clean up obsolete legacy tables if present
            cursor.execute('DROP TABLE IF EXISTS scan_history;')
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
                    privacy_settings TEXT DEFAULT '{"auto_quarantine_links": true, "sanitize_metadata": true, "retention_days": 90}',
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
                    modality TEXT DEFAULT 'text',
                    file_name TEXT DEFAULT '',
                    file_hash TEXT DEFAULT '',
                    technical_details TEXT DEFAULT '{}',
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

            # Non-destructive SQLite column additions for existing databases
            cursor.execute("PRAGMA table_info(scans)")
            scan_cols = [row[1] for row in cursor.fetchall()]
            if 'modality' not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN modality TEXT DEFAULT 'text';")
            if 'file_name' not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN file_name TEXT DEFAULT '';")
            if 'file_hash' not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN file_hash TEXT DEFAULT '';")
            if 'technical_details' not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN technical_details TEXT DEFAULT '{}';")

            cursor.execute("PRAGMA table_info(users)")
            user_cols = [row[1] for row in cursor.fetchall()]
            if 'privacy_settings' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN privacy_settings TEXT DEFAULT '{\"auto_quarantine_links\": true, \"sanitize_metadata\": true, \"retention_days\": 90}';")

            # SQLite Performance & Data Integrity Indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_modality ON scans(modality);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets(token_hash);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);')

            # Clean up obsolete legacy tables if present
            cursor.execute('DROP TABLE IF EXISTS scan_history;')


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
    username = username.strip().replace('\x00', '') if username else ""
    email = email.strip().lower().replace('\x00', '') if email else ""
    if full_name:
        full_name = full_name.replace('\x00', '')
    if password:
        password = password.replace('\x00', '')

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
    if not user_id:
        return None
    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        return None

    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email, full_name, role, created_at FROM users WHERE id = {p}", (user_id,))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            d['id'] = int(d['id'])
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

    from datetime import timezone
    raw_token = secrets.token_urlsafe(32)
    token_hashed = hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    p = placeholder()

    with DBConnection() as conn:
        cursor = conn.cursor()
        # Invalidate previous unused tokens for this user
        cursor.execute(f"UPDATE password_resets SET used = 1 WHERE user_id = {p}", (user['id'],))
        # Insert new token
        cursor.execute(f"""
            INSERT INTO password_resets (user_id, token_hash, expires_at, used)
            VALUES ({p}, {p}, {p}, 0)
        """, (user['id'], token_hashed, expires_at if is_postgres() else expires_at.isoformat()))

    return raw_token, user['username']


def verify_and_use_reset_token(raw_token: str, new_password: str) -> Dict[str, Any]:
    """
    Validates token expiration, applies new password, and marks token as used.
    """
    if not raw_token or not new_password or len(new_password) < 6:
        return {"success": False, "message": "Password must be at least 6 characters long."}

    new_password = new_password.replace('\x00', '')
    raw_token = raw_token.replace('\x00', '')
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

        # Check expiration safely using timezone-aware UTC datetime
        from datetime import timezone
        now = datetime.now(timezone.utc)
        expires_at = rec_dict['expires_at']
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            except Exception:
                pass

        if hasattr(expires_at, 'tzinfo') and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

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
              suspicious_indicators: List[Dict[str, Any]], recommended_action: str,
              modality: str = 'text', file_name: str = '', file_hash: str = '',
              technical_details: Optional[Dict[str, Any]] = None) -> str:
    """
    Saves a complete scan report linked to a user. Returns the generated unique scan_id.
    Supports multi-modal threats (text, image, audio, video).
    Validates that user_id exists in the users table before insertion to enforce referential integrity.
    """
    if not user_id:
        raise ValueError("Cannot save scan without an authenticated user ID.")

    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid user ID: {user_id}")

    p = placeholder()

    with DBConnection() as conn:
        cursor = conn.cursor()

        # Strict validation: verify user exists in DB before attempting insert
        cursor.execute(f"SELECT id FROM users WHERE id = {p}", (user_id,))
        if not cursor.fetchone():
            raise ValueError(f"User with ID {user_id} does not exist in the database.")

        clean_modality = (modality or 'text').lower()
        if clean_modality.startswith('image'):
            prefix = "SCN-IMG"
        elif clean_modality.startswith('audio'):
            prefix = "SCN-AUD"
        elif clean_modality.startswith('video'):
            prefix = "SCN-VID"
        else:
            prefix = "SCN"

        scan_id = f"{prefix}-{uuid.uuid4().hex[:10].upper()}"

        # Sanitize any NUL (0x00) characters to ensure compatibility across PostgreSQL and SQLite
        clean_msg = (submitted_message or '').replace('\x00', '')
        clean_class = (threat_classification or '').replace('\x00', '')
        clean_risk = (risk_level or '').replace('\x00', '')
        clean_action = (recommended_action or '').replace('\x00', '')
        clean_fname = (file_name or '').replace('\x00', '')
        clean_fhash = (file_hash or '').replace('\x00', '')
        clean_reasons = [r.replace('\x00', '') if isinstance(r, str) else r for r in (detection_reasons or [])]
        clean_indicators = suspicious_indicators if suspicious_indicators is not None else []
        clean_tech = technical_details if technical_details is not None else {}

        reasons_json = json.dumps(clean_reasons).replace('\x00', '')
        indicators_json = json.dumps(clean_indicators).replace('\x00', '')
        tech_json = json.dumps(clean_tech).replace('\x00', '')

        cursor.execute(f"""
            INSERT INTO scans (
                scan_id, user_id, submitted_message, risk_score, risk_level,
                threat_classification, detection_reasons, suspicious_indicators,
                recommended_action, modality, file_name, file_hash, technical_details
            ) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
        """, (
            scan_id, user_id, clean_msg, int(risk_score), clean_risk,
            clean_class, reasons_json, indicators_json, clean_action,
            clean_modality, clean_fname, clean_fhash, tech_json
        ))
    return scan_id


def get_user_scans(user_id: int, limit: int = 50, modality: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves past scans strictly belonging to user_id, optionally filtered by modality.
    Guarantees cross-tenant data isolation.
    """
    if not user_id:
        return []
    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        return []

    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        if modality and modality.lower() not in ('all', ''):
            cursor.execute(f"""
                SELECT scan_id, submitted_message, risk_score, risk_level,
                       threat_classification, detection_reasons, suspicious_indicators,
                       recommended_action, modality, file_name, file_hash, technical_details, created_at
                FROM scans
                WHERE user_id = {p} AND LOWER(modality) = LOWER({p})
                ORDER BY created_at DESC
                LIMIT {p}
            """, (user_id, modality.lower(), limit))
        else:
            cursor.execute(f"""
                SELECT scan_id, submitted_message, risk_score, risk_level,
                       threat_classification, detection_reasons, suspicious_indicators,
                       recommended_action, modality, file_name, file_hash, technical_details, created_at
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
        if isinstance(d.get('detection_reasons'), str):
            try:
                d['detection_reasons'] = json.loads(d['detection_reasons'])
            except Exception:
                d['detection_reasons'] = []
        elif not isinstance(d.get('detection_reasons'), list):
            d['detection_reasons'] = []

        if isinstance(d.get('suspicious_indicators'), str):
            try:
                d['suspicious_indicators'] = json.loads(d['suspicious_indicators'])
            except Exception:
                d['suspicious_indicators'] = []
        elif not isinstance(d.get('suspicious_indicators'), list):
            d['suspicious_indicators'] = []

        if isinstance(d.get('technical_details'), str):
            try:
                d['technical_details'] = json.loads(d['technical_details'])
            except Exception:
                d['technical_details'] = {}
        elif not isinstance(d.get('technical_details'), dict):
            d['technical_details'] = {}

        # Message preview
        raw_msg = d.get('submitted_message', '')
        d['message_preview'] = raw_msg[:90] + ('...' if len(raw_msg) > 90 else '')
        d['created_at'] = str(d.get('created_at', ''))
        d['date'] = d['created_at'][:19]
        d['scanned_at'] = d['date']
        d['classification'] = d.get('threat_classification', 'Unknown')
        d['confidence'] = d.get('risk_score', 0)
        d['modality'] = d.get('modality') or 'text'
        results.append(d)

    return results


def get_scan_by_id(scan_id: str, user_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieves a single scan by scan_id ONLY if it belongs to user_id.
    Strictly prevents User B from accessing User A's scans.
    """
    if not user_id or not scan_id:
        return None
    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        return None

    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT scan_id, user_id, submitted_message, risk_score, risk_level,
                   threat_classification, detection_reasons, suspicious_indicators,
                   recommended_action, modality, file_name, file_hash, technical_details, created_at
            FROM scans
            WHERE scan_id = {p} AND user_id = {p}
        """, (scan_id, user_id))
        row = cursor.fetchone()
        if not row:
            return None

        d = dict(row)
        if isinstance(d.get('detection_reasons'), str):
            try:
                d['detection_reasons'] = json.loads(d['detection_reasons'])
            except Exception:
                d['detection_reasons'] = []
        elif not isinstance(d.get('detection_reasons'), list):
            d['detection_reasons'] = []

        if isinstance(d.get('suspicious_indicators'), str):
            try:
                d['suspicious_indicators'] = json.loads(d['suspicious_indicators'])
            except Exception:
                d['suspicious_indicators'] = []
        elif not isinstance(d.get('suspicious_indicators'), list):
            d['suspicious_indicators'] = []

        if isinstance(d.get('technical_details'), str):
            try:
                d['technical_details'] = json.loads(d['technical_details'])
            except Exception:
                d['technical_details'] = {}
        elif not isinstance(d.get('technical_details'), dict):
            d['technical_details'] = {}

        d['created_at'] = str(d.get('created_at', ''))
        d['date'] = d['created_at'][:19]
        d['scanned_at'] = d['date']
        d['classification'] = d.get('threat_classification', 'Unknown')
        d['confidence'] = d.get('risk_score', 0)
        d['modality'] = d.get('modality') or 'text'
        return d


def clear_user_scans(user_id: int) -> Dict[str, Any]:
    """
    Purges all scan history strictly belonging to user_id without deleting account.
    """
    if not user_id:
        return {"success": False, "message": "Invalid user ID."}
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM scans WHERE user_id = {p}", (user_id,))
    return {"success": True, "message": "Scan history cleared successfully."}


def export_user_data(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Exports full user profile information and complete scan history for GDPR/privacy compliance.
    """
    user = get_user_by_id(user_id)
    if not user:
        return None
    scans = get_user_scans(user_id, limit=1000)
    privacy = get_user_privacy_settings(user_id)
    return {
        "export_generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "SecureSync – Multi Detection System",
        "user_profile": {
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "full_name": user.get('full_name'),
            "role": user.get('role'),
            "created_at": user.get('created_at')
        },
        "privacy_preferences": privacy,
        "total_scans_recorded": len(scans),
        "scan_records": scans
    }


def get_user_privacy_settings(user_id: int) -> Dict[str, Any]:
    """Retrieves user's privacy and data governance settings."""
    default_settings = {
        "auto_quarantine_links": True,
        "sanitize_metadata": True,
        "retention_days": 90,
        "allow_telemetry": False
    }
    if not user_id:
        return default_settings
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT privacy_settings FROM users WHERE id = {p}", (user_id,))
        row = cursor.fetchone()
        if row and row['privacy_settings']:
            try:
                saved = json.loads(row['privacy_settings'])
                default_settings.update(saved)
            except Exception:
                pass
    return default_settings


def update_user_privacy_settings(user_id: int, settings: Dict[str, Any]) -> Dict[str, Any]:
    """Updates user's privacy and security preferences."""
    if not user_id:
        return {"success": False, "message": "Invalid user ID."}
    current = get_user_privacy_settings(user_id)
    current.update(settings)
    settings_json = json.dumps(current)
    p = placeholder()
    with DBConnection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET privacy_settings = {p} WHERE id = {p}", (settings_json, user_id))
    return {"success": True, "message": "Security and privacy preferences updated successfully.", "settings": current}


def get_user_stats(user_id: int) -> Dict[str, Any]:
    """
    Computes summary statistics specifically for a single user across all detection modalities.
    Guarantees cross-database compatibility with zero unescaped SQL percent signs (preventing
    psycopg2 'tuple index out of range' errors on PostgreSQL/Neon).
    """
    default_stats = {
        "total_scanned": 0,
        "threats_detected": 0,
        "suspicious_count": 0,
        "safe_verified": 0,
        "legitimate_count": 0,
        "average_risk": 0
    }
    if not user_id:
        return default_stats
    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        return default_stats

    p = placeholder()
    try:
        with DBConnection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE 
                        WHEN risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'SUSPICIOUS')
                             OR threat_classification IN (
                                 'Suspicious/Scam', 
                                 'Suspicious / Threat Detected', 
                                 'Suspicious / Potential Risk', 
                                 'Synthetic Deepfake Voice', 
                                 'Suspicious Acoustic Anomaly', 
                                 'Deepfake / Synthetic Manipulation', 
                                 'Suspicious Video Stream'
                             )
                        THEN 1 ELSE 0 END) as scams,
                    SUM(CASE 
                        WHEN risk_level IN ('LOW', 'SAFE', 'CLEAN')
                             OR threat_classification IN (
                                 'Legitimate', 
                                 'Clean / Legitimate', 
                                 'Authentic Video Stream', 
                                 'Legitimate Natural Audio'
                             )
                        THEN 1 ELSE 0 END) as safe,
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
    except Exception as e:
        logger.warning(f"Error computing user stats for user {user_id}: {e}")
        return default_stats

    return default_stats


if __name__ == '__main__':
    print("[*] Initializing SecureSync Database...")
    init_db()
    print("[+] Database ready. Target:", "PostgreSQL" if is_postgres() else "SQLite")
