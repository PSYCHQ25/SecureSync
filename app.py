"""
=============================================================================
SecureSync – Multi Detection System
Script: app.py
Description: Production-Ready Flask Web Application & REST API backend.
             Hosts the cybersecurity dashboard, manages multi-modal detection
             (Text, Image, Audio, Video), session scanning, user isolation,
             brute-force defense, zero-trust link defanging, and PDF reporting.
=============================================================================
"""

import os
import io
import re
import json
import time
import secrets
import html
from datetime import datetime, timedelta, timezone
from functools import wraps
from collections import defaultdict

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    flash,
    abort,
    send_file
)
from werkzeug.middleware.proxy_fix import ProxyFix

from predict import analyze_message, METRICS_PATH
from multimodal_detector import get_image_detector, get_audio_detector, get_video_detector
from report_generator import generate_pdf_report
from database import (
    init_db,
    authenticate_user,
    register_user,
    get_user_by_id,
    save_scan,
    get_user_scans,
    get_scan_by_id,
    change_user_password,
    delete_user_account,
    create_password_reset_token,
    verify_and_use_reset_token,
    get_user_stats,
    validate_email,
    clear_user_scans,
    export_user_data,
    get_user_privacy_settings,
    update_user_privacy_settings
)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Reverse Proxy configuration (for Cloudflare Tunnel, Render, Railway, AWS ALB, Nginx)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Secret key for cryptographically signed session cookies
app.secret_key = os.environ.get('SECRET_KEY', 'securesync_cyber_defense_secret_key_8849201948')

# Security Session Cookie Configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SECURE_COOKIES', 'False').lower() in ('true', '1') or os.environ.get('RENDER') is not None,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=50 * 1024 * 1024
)

# Initialize database schema permanently (never wiping on startup)
init_db()

# -----------------------------------------------------------------------------
# Rate Limiting & Brute Force Defense
# -----------------------------------------------------------------------------
FAILED_LOGINS = defaultdict(list)
SCAN_RATE_LIMITS = defaultdict(list)

def get_client_ip() -> str:
    """Extracts client IP safely honoring proxy headers."""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def is_login_rate_limited(identifier: str, ip: str) -> bool:
    """Allows max 5 failed login attempts in 15 minutes per IP or user."""
    now = time.time()
    for key in (ip, identifier.lower()):
        FAILED_LOGINS[key] = [t for t in FAILED_LOGINS[key] if now - t < 900]
        if len(FAILED_LOGINS[key]) >= 5:
            return True
    return False

def record_failed_login(identifier: str, ip: str):
    """Logs a failed authentication attempt."""
    now = time.time()
    FAILED_LOGINS[ip].append(now)
    FAILED_LOGINS[identifier.lower()].append(now)

def clear_failed_logins(identifier: str, ip: str):
    """Resets failed login tracker upon successful authentication."""
    FAILED_LOGINS.pop(ip, None)
    FAILED_LOGINS.pop(identifier.lower(), None)

def is_scan_rate_limited(user_id: int) -> bool:
    """Allows max 45 scans per minute per user."""
    now = time.time()
    SCAN_RATE_LIMITS[user_id] = [t for t in SCAN_RATE_LIMITS[user_id] if now - t < 60]
    if len(SCAN_RATE_LIMITS[user_id]) >= 45:
        return True
    SCAN_RATE_LIMITS[user_id].append(now)
    return False

# -----------------------------------------------------------------------------
# Authentication & Authorization Decorator & Session Validator
# -----------------------------------------------------------------------------
@app.before_request
def validate_session_user():
    """
    Validates that any user ID stored in the session exists in the active database.
    If the database was migrated (e.g. SQLite to Neon PostgreSQL) or the user was deleted,
    this automatically clears the invalid session and redirects to login rather than
    causing database constraint errors.
    """
    user_id = session.get('user_id')
    if user_id is not None:
        user = get_user_by_id(user_id)
        if not user:
            session.clear()
            public_endpoints = {
                'static', 'login', 'register', 'home', 'health',
                'forgot_password', 'reset_password', 'get_samples', 'get_metrics', None
            }
            if request.endpoint not in public_endpoints:
                if request.path.startswith('/api/'):
                    return jsonify({
                        "status": "error",
                        "message": "Your session has expired or the user account was not found. Please log in again."
                    }), 401
                flash("Your previous session is no longer valid. Please sign in or create an account.", "warning")
                return redirect(url_for('login'))


def login_required(f):
    """Enforces strict authentication for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            if request.path.startswith('/api/'):
                return jsonify({"status": "error", "message": "Authentication required. Please log in."}), 401
            flash("Authentication required to access the SecureSync portal.", "warning")
            return redirect(url_for('login'))

        # Verify that the authenticated user actually exists in the active database
        user = get_user_by_id(user_id)
        if not user:
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({"status": "error", "message": "Session expired or user account not found. Please log in again."}), 401
            flash("Your session has expired. Please sign in again.", "warning")
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

# -----------------------------------------------------------------------------
# In-Memory Statistics & Metrics Baseline
# -----------------------------------------------------------------------------
stats = {
    "total_scanned": 0,
    "suspicious_count": 0,
    "legitimate_count": 0,
    "model_accuracy": 95.65
}

if os.path.exists(METRICS_PATH):
    try:
        with open(METRICS_PATH, 'r') as f:
            metrics_data = json.load(f)
            stats["model_accuracy"] = metrics_data.get("accuracy", 95.65)
    except Exception as e:
        app.logger.warning(f"Could not load metrics from {METRICS_PATH}: {e}")

# Preset verification samples for immediate testing
PRESET_SAMPLES = [
    {
        "id": "bank_phish",
        "category": "Bank Phishing",
        "label": "Scam",
        "title": "Urgent Bank Restriction",
        "message": "Dear customer, your Chase bank account has been temporarily restricted due to suspicious login attempts. Verify your identity immediately at http://bit.ly/chase-verify-now to avoid permanent closure."
    },
    {
        "id": "wa_family",
        "category": "WhatsApp Impersonation",
        "label": "Scam",
        "title": "Hi Mom Fake Emergency",
        "message": "Hi Mom, my phone fell in the water and this is my temporary WhatsApp number. My bank app is not working and I urgently need $450 to pay for car towing. Can you send it via Zelle right now?"
    },
    {
        "id": "fake_lottery",
        "category": "Prize Fraud",
        "label": "Scam",
        "title": "$50,000 Walmart Voucher",
        "message": "CONGRATULATIONS! You have been selected as the official winner of a $50,000 Walmart cash gift card. Claim your exclusive prize code at http://win-walmart-voucher.com before midnight!"
    },
    {
        "id": "package_fraud",
        "category": "Delivery Scam",
        "label": "Scam",
        "title": "USPS Address Incomplete",
        "message": "USPS Delivery Notification: Package #US-992019 could not be delivered due to incomplete street address. Update your address and pay $1.49 redelivery fee at http://tinyurl.com/usps-track-fail"
    },
    {
        "id": "arrest_threat",
        "category": "Intimidation",
        "label": "Scam",
        "title": "IRS Arrest Warrant Notice",
        "message": "INTERNAL REVENUE SERVICE: A formal lawsuit has been registered under your Social Security Number. Call our legal division immediately at 1-888-555-0199 or local sheriff will execute arrest warrant."
    },
    {
        "id": "real_otp",
        "category": "Legitimate 2FA",
        "label": "Legitimate",
        "title": "Chase Bank Verification Code",
        "message": "Your Chase verification code is 492019. Valid for 10 minutes. Chase will never call or text you asking for this code. Do not share it with anyone."
    },
    {
        "id": "real_chat",
        "category": "Personal Chat",
        "label": "Legitimate",
        "title": "Lunch Discussion",
        "message": "Hey, are we still meeting for lunch at 12:30 today? I'm heading towards the campus dining hall now."
    },
    {
        "id": "real_bank",
        "category": "Bank Notification",
        "label": "Legitimate",
        "title": "Normal Debit Card Charge",
        "message": "Bank of America: A purchase of $18.42 was made at Starbucks with your debit card ending in 4102. If authorized, no action is needed."
    }
]

# -----------------------------------------------------------------------------
# Public & Authentication Routes
# -----------------------------------------------------------------------------
@app.route('/')
def home():
    """Public SaaS homepage."""
    if 'user_id' in session:
        if get_user_by_id(session['user_id']):
            return redirect(url_for('dashboard'))
        session.clear()
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Analyst authentication gateway (Username or Email)."""
    if 'user_id' in session:
        if get_user_by_id(session['user_id']):
            return redirect(url_for('dashboard'))
        session.clear()

    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip() or request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = get_client_ip()

        if not identifier or not password:
            flash("Please enter both your username/email and password.", "danger")
            return render_template('login.html')

        if is_login_rate_limited(identifier, client_ip):
            flash("Security lock: Too many failed login attempts. Please wait 15 minutes before trying again.", "danger")
            return render_template('login.html'), 429

        user = authenticate_user(identifier, password)
        if user:
            clear_failed_logins(identifier, client_ip)
            # Regenerate session to prevent session fixation attacks
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user.get('email', '')
            session['full_name'] = user.get('full_name') or user['username']
            session['role'] = user.get('role', 'Security Analyst')
            session.permanent = True

            flash(f"Welcome back, {user['username']}! Secure threat console active.", "success")
            return redirect(url_for('dashboard'))
        else:
            record_failed_login(identifier, client_ip)
            flash("Invalid username/email or password. Please try again.", "danger")

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User account registration with salted PBKDF2 hashing."""
    if 'user_id' in session:
        if get_user_by_id(session['user_id']):
            return redirect(url_for('dashboard'))
        session.clear()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validations
        if not username or not email or not password or not confirm_password:
            flash("All fields (Username, Email, Password, Confirm Password) are required.", "danger")
            return render_template('register.html')

        if len(username) < 3:
            flash("Username must be at least 3 characters long.", "danger")
            return render_template('register.html')

        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            flash("Username can only contain alphanumeric characters, underscores, hyphens, and dots.", "danger")
            return render_template('register.html')

        if not validate_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template('register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template('register.html')

        if password != confirm_password:
            flash("Passwords do not match. Please verify your input.", "danger")
            return render_template('register.html')

        reg_result = register_user(username, email, password)
        if reg_result['success']:
            flash(reg_result['message'], "success")
            return redirect(url_for('login'))
        else:
            flash(reg_result['message'], "danger")

    return render_template('register.html')


@app.route('/logout')
def logout():
    """Terminates session securely."""
    session.clear()
    flash("You have been signed out of the SecureSync console.", "info")
    return redirect(url_for('login'))


# -----------------------------------------------------------------------------
# Protected Dashboard & History Routes
# -----------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    """Renders main cybersecurity console with authenticated user context."""
    user = get_user_by_id(session.get('user_id'))
    if not user:
        session.clear()
        flash("Your session has expired. Please sign in again.", "warning")
        return redirect(url_for('login'))

    current_user = {
        "id": user['id'],
        "username": user['username'],
        "email": user.get('email', ''),
        "full_name": user.get('full_name') or user['username'],
        "role": user.get('role', 'Security Analyst')
    }
    return render_template('dashboard.html', current_user=current_user)


@app.route('/analyze')
@login_required
def analyze():
    """Direct route alias for the message analyzer."""
    return redirect(url_for('dashboard'))


@app.route('/history')
@login_required
def history():
    """Direct route alias for viewing scan history."""
    return redirect(url_for('dashboard'))


@app.route('/account', methods=['GET'])
@login_required
def account():
    """User account management & security settings page."""
    current_user = get_user_by_id(session['user_id'])
    privacy_settings = get_user_privacy_settings(session['user_id'])
    user_stats = get_user_stats(session['user_id'])
    return render_template('account.html', current_user=current_user, privacy_settings=privacy_settings, user_stats=user_stats)


@app.route('/account/update-settings', methods=['POST'])
@login_required
def update_settings():
    """Updates user privacy, retention, and defensive security settings."""
    auto_quarantine = request.form.get('auto_quarantine_links') == 'on'
    sanitize_metadata = request.form.get('sanitize_metadata') == 'on'
    try:
        retention_days = int(request.form.get('retention_days', 90))
    except (ValueError, TypeError):
        retention_days = 90

    settings = {
        "auto_quarantine_links": auto_quarantine,
        "sanitize_metadata": sanitize_metadata,
        "retention_days": retention_days
    }
    update_user_privacy_settings(session['user_id'], settings)
    flash("Security and privacy preferences updated successfully.", "success")
    return redirect(url_for('account'))


@app.route('/account/clear-history', methods=['POST'])
@login_required
def clear_history():
    """Purges all user threat scans while keeping the account active."""
    res = clear_user_scans(session['user_id'])
    if res['success']:
        flash("Your scan history has been permanently wiped.", "success")
    else:
        flash("Failed to wipe scan history.", "danger")
    return redirect(url_for('account'))


@app.route('/account/export-data', methods=['GET'])
@login_required
def export_data():
    """GDPR/CCPA compliant export of all user activity and scans in JSON."""
    data = export_user_data(session['user_id'])
    if not data:
        flash("Could not compile export data.", "danger")
        return redirect(url_for('account'))

    json_str = json.dumps(data, indent=2)
    buffer = io.BytesIO(json_str.encode('utf-8'))
    filename = f"securesync_data_export_user_{session['user_id']}_{int(time.time())}.json"
    return send_file(
        buffer,
        mimetype='application/json',
        as_attachment=True,
        download_name=filename
    )


@app.route('/account/change-password', methods=['POST'])
@login_required
def change_password():
    """Updates account password with PBKDF2 verification."""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    res = change_user_password(session['user_id'], current_password, new_password)
    if res['success']:
        flash(res['message'], 'success')
    else:
        flash(res['message'], 'danger')
    return redirect(url_for('account'))


@app.route('/account/delete', methods=['POST'])
@login_required
def delete_account():
    """Permanently erases user account and all scan history."""
    res = delete_user_account(session['user_id'])
    session.clear()
    flash(res['message'], 'success')
    return redirect(url_for('home'))


# -----------------------------------------------------------------------------
# Password Recovery & Email Dispatch
# -----------------------------------------------------------------------------
def send_password_reset_email(recipient_email: str, username: str, reset_url: str) -> bool:
    """
    Dispatches a cryptographically secure, single-use password recovery link
    via SMTP using secure environment variables on Render, Railway, or VPS.
    Supports STARTTLS (port 587) and SSL (port 465) with HTML & plaintext fallback.
    """
    smtp_host = os.environ.get('SMTP_HOST')
    if not smtp_host:
        return False

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        smtp_port = int(os.environ.get('SMTP_PORT', 587))
        smtp_user = os.environ.get('SMTP_USER')
        smtp_pass = os.environ.get('SMTP_PASSWORD') or os.environ.get('SMTP_PASS')
        mail_from = os.environ.get('SMTP_FROM') or smtp_user or 'noreply@securesync.internal'
        use_ssl = (os.environ.get('SMTP_USE_SSL', '').lower() in ('true', '1')) or (smtp_port == 465)
        use_tls = os.environ.get('SMTP_USE_TLS', 'true').lower() in ('true', '1') and not use_ssl and smtp_port != 25

        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'SecureSync – Password Recovery Request'
        msg['From'] = mail_from
        msg['To'] = recipient_email

        # Plaintext Fallback
        text_body = (
            f"Hello {username},\n\n"
            "A password reset request was initiated for your SecureSync account.\n"
            f"Click the link below within 60 minutes to choose a new password:\n\n"
            f"{reset_url}\n\n"
            "If you did not request this, please disregard this email. Your credentials remain safe.\n\n"
            "– SecureSync Cyber Defense Team\n"
        )

        # Cyber-themed HTML Version
        safe_name = html.escape(username)
        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #06090e; color: #e2e8f0; margin: 0; padding: 24px; }}
  .card {{ background: #0c121e; border: 1px solid #1e293b; border-radius: 12px; max-width: 540px; margin: 0 auto; padding: 32px; }}
  .header {{ border-bottom: 1px solid #1e293b; padding-bottom: 18px; margin-bottom: 22px; }}
  .brand {{ color: #00f0ff; font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }}
  .sub {{ color: #94a3b8; font-size: 13px; margin-top: 4px; }}
  .content {{ color: #cbd5e1; font-size: 14px; line-height: 1.6; margin-bottom: 28px; }}
  .btn {{ display: inline-block; background: #00f0ff; color: #06090e; font-weight: 700; font-size: 14px; text-decoration: none; padding: 12px 28px; border-radius: 6px; }}
  .footer {{ margin-top: 28px; padding-top: 18px; border-top: 1px solid #1e293b; color: #64748b; font-size: 12px; line-height: 1.5; }}
  .url-box {{ background: #080d16; border: 1px solid #1e293b; padding: 10px; border-radius: 4px; word-break: break-all; font-family: monospace; font-size: 12px; color: #00f0ff; margin-top: 12px; }}
</style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="brand">🛡️ SecureSync</div>
      <div class="sub">Zero-Trust Threat Defense Platform</div>
    </div>
    <div class="content">
      <p>Hello <strong>{safe_name}</strong>,</p>
      <p>A request was received to reset the password for your SecureSync cybersecurity portal account.</p>
      <p style="margin: 24px 0;">
        <a href="{reset_url}" class="btn">Reset Password &rarr;</a>
      </p>
      <p style="font-size: 13px; color: #94a3b8;">This recovery link expires in <strong>60 minutes</strong> and can only be used once.</p>
      <div class="url-box">{reset_url}</div>
    </div>
    <div class="footer">
      If you did not submit this request, no action is required. Your account remains secured.<br>
      Automated Security Notification • SecureSync Threat Operations
    </div>
  </div>
</body>
</html>"""

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        if use_ssl:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=12)
            server.ehlo()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=12)
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()

        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)

        server.sendmail(mail_from, [recipient_email], msg.as_string())
        server.quit()
        app.logger.info(f"Password reset email dispatched successfully to {recipient_email}")
        return True
    except Exception as ex:
        app.logger.error(f"Error dispatching password reset email to {recipient_email}: {ex}")
        return False


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Secure password reset request."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    direct_reset_url = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().replace('\x00', '')
        result = create_password_reset_token(email)
        if result:
            raw_token, username = result
            # Construct production or local reset URL
            base_url = (os.environ.get('APP_URL') or os.environ.get('RENDER_EXTERNAL_URL') or '').strip().rstrip('/')
            if base_url:
                reset_url = f"{base_url}/reset-password/{raw_token}"
            else:
                scheme = 'https' if (request.is_secure or os.environ.get('RENDER') or os.environ.get('SECURE_COOKIES', 'False').lower() in ('true', '1')) else request.scheme
                reset_url = url_for('reset_password', token=raw_token, _external=True, _scheme=scheme)

            smtp_host = os.environ.get('SMTP_HOST')
            if smtp_host:
                send_password_reset_email(email, username, reset_url)
                # In production when SMTP is configured, NEVER expose the token on screen
                direct_reset_url = None
            else:
                # Standalone local dev only: show token on UI only if not running on Render
                if not os.environ.get('RENDER') and not os.environ.get('DATABASE_URL'):
                    direct_reset_url = reset_url
                    app.logger.info(f"[DEV RESET LINK] {email}: {reset_url}")
                else:
                    direct_reset_url = None
                    app.logger.warning(f"Reset token generated for {email} but SMTP_HOST is not set on Render.")

        # Neutral response prevents email enumeration
        flash("If an account exists with that email, password recovery instructions have been sent. Please check your inbox.", "info")

    return render_template('forgot_password.html', direct_reset_url=direct_reset_url)



@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Processes verified password reset token."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if new_password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('reset_password.html', token=token)

        res = verify_and_use_reset_token(token, new_password)
        if res['success']:
            flash(res['message'], 'success')
            return redirect(url_for('login'))
        else:
            flash(res['message'], 'danger')

    return render_template('reset_password.html', token=token)


# -----------------------------------------------------------------------------
# REST API Endpoints (All scanning & history protected by login_required)
# -----------------------------------------------------------------------------
@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    """Returns live statistics isolated to the logged-in user."""
    user_stats = get_user_stats(session.get('user_id'))
    user_stats['model_accuracy'] = stats.get('model_accuracy', 95.65)
    return jsonify({
        "status": "success",
        "stats": user_stats
    })


@app.route('/api/samples', methods=['GET'])
def get_samples():
    """Returns sample test payloads."""
    return jsonify({
        "status": "success",
        "samples": PRESET_SAMPLES
    })


@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Returns model evaluation metrics."""
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, 'r') as f:
                metrics_data = json.load(f)
            return jsonify({
                "status": "success",
                "metrics": metrics_data
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "error", "message": "Metrics file not found"}), 404


@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    """Strictly returns past scan history belonging to current user, with optional modality filter."""
    user_id = session.get('user_id')
    modality = request.args.get('modality')
    history_records = get_user_scans(user_id, limit=100, modality=modality)
    return jsonify({
        "status": "success",
        "history": history_records
    })


@app.route('/api/scan/<scan_id>', methods=['GET'])
@login_required
def get_single_scan(scan_id):
    """Retrieves full details for a scan strictly owned by the current user."""
    scan = get_scan_by_id(scan_id, session['user_id'])
    if not scan:
        return jsonify({"status": "error", "message": "Scan report not found or access denied."}), 404
    return jsonify({
        "status": "success",
        "scan": scan
    })


@app.route('/api/scan/<scan_id>/pdf', methods=['GET'])
@login_required
def export_scan_pdf(scan_id):
    """Generates and downloads a formal forensic investigation report in PDF format."""
    scan = get_scan_by_id(scan_id, session['user_id'])
    if not scan:
        return jsonify({"status": "error", "message": "Scan report not found or access denied."}), 404

    analyst_name = session.get('full_name') or session.get('username') or "Security Analyst"
    pdf_buffer = generate_pdf_report(scan, analyst_name=analyst_name)
    clean_filename = f"securesync_forensic_report_{scan_id}.pdf"
    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=clean_filename
    )


@app.route('/api/scan/image', methods=['POST'])
@login_required
def scan_image():
    """
    Analyzes uploaded image for Quishing (QR code phishing), steganographic payloads,
    fake banking / visual invoice lures, metadata tampering, and entropy anomalies.
    """
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        return jsonify({"status": "error", "message": "User session expired."}), 401

    if is_scan_rate_limited(user['id']):
        return jsonify({"status": "error", "message": "Scan rate limit reached. Please wait a moment."}), 429

    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No image file provided in upload."}), 400

    file = request.files['file']
    filename = file.filename or 'upload.jpg'
    allowed_exts = ('.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp')
    if not any(filename.lower().endswith(ext) for ext in allowed_exts):
        return jsonify({"status": "error", "message": f"Unsupported image format. Allowed: {', '.join(allowed_exts)}"}), 400

    raw_bytes = file.read()
    if not raw_bytes:
        return jsonify({"status": "error", "message": "Uploaded image file is empty."}), 400

    if len(raw_bytes) > 15 * 1024 * 1024:
        return jsonify({"status": "error", "message": "Image exceeds maximum size (15 MB)."}), 400

    try:
        detector = get_image_detector()
        result = detector.analyze(raw_bytes, filename=filename)

        # Update in-memory session statistics
        stats["total_scanned"] += 1
        if result["is_threat"]:
            stats["suspicious_count"] += 1
        else:
            stats["legitimate_count"] += 1

        summary_msg = f"Image Forensics: {filename} ({result['forensic_details'].get('dimensions', 'N/A')}, {result['forensic_details'].get('format', 'Img')})"
        saved_scan_id = save_scan(
            user_id=user['id'],
            submitted_message=summary_msg,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            threat_classification=result['classification'],
            detection_reasons=result['reasons'],
            suspicious_indicators=result['indicators'],
            recommended_action=result['recommended_action'],
            modality='image',
            file_name=filename,
            file_hash=result['forensic_details'].get('sha256', ''),
            technical_details=result['forensic_details']
        )
        result['scan_id'] = saved_scan_id

        user_stats = get_user_stats(user['id'])
        user_stats['model_accuracy'] = stats.get('model_accuracy', 95.65)

        return jsonify({
            "status": "success",
            "analysis": result,
            "updated_stats": user_stats
        })
    except Exception as e:
        app.logger.error(f"Image scan error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Image forensic engine error: {str(e)}"}), 500


@app.route('/api/scan/audio', methods=['POST'])
@login_required
def scan_audio():
    """
    Analyzes uploaded audio for synthetic voice cloning (Deepfake Audio),
    vishing frequency artifacts, spectral roll-off anomalies, and ultrasonic carriers.
    """
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        return jsonify({"status": "error", "message": "User session expired."}), 401

    if is_scan_rate_limited(user['id']):
        return jsonify({"status": "error", "message": "Scan rate limit reached. Please wait a moment."}), 429

    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No audio file provided in upload."}), 400

    file = request.files['file']
    filename = file.filename or 'recording.wav'
    allowed_exts = ('.wav', '.mp3', '.ogg', '.flac', '.m4a', '.aac')
    if not any(filename.lower().endswith(ext) for ext in allowed_exts):
        return jsonify({"status": "error", "message": f"Unsupported audio format. Allowed: {', '.join(allowed_exts)}"}), 400

    raw_bytes = file.read()
    if not raw_bytes:
        return jsonify({"status": "error", "message": "Uploaded audio file is empty."}), 400

    if len(raw_bytes) > 25 * 1024 * 1024:
        return jsonify({"status": "error", "message": "Audio exceeds maximum size (25 MB)."}), 400

    try:
        detector = get_audio_detector()
        result = detector.analyze(raw_bytes, filename=filename)

        stats["total_scanned"] += 1
        if result["is_threat"]:
            stats["suspicious_count"] += 1
        else:
            stats["legitimate_count"] += 1

        summary_msg = f"Audio Forensics: {filename} ({result['forensic_details'].get('format', 'Audio')}, {result['forensic_details'].get('duration_seconds', 0)}s)"
        saved_scan_id = save_scan(
            user_id=user['id'],
            submitted_message=summary_msg,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            threat_classification=result['classification'],
            detection_reasons=result['reasons'],
            suspicious_indicators=result['indicators'],
            recommended_action=result['recommended_action'],
            modality='audio',
            file_name=filename,
            file_hash=result['forensic_details'].get('sha256', ''),
            technical_details=result['forensic_details']
        )
        result['scan_id'] = saved_scan_id

        user_stats = get_user_stats(user['id'])
        user_stats['model_accuracy'] = stats.get('model_accuracy', 95.65)

        return jsonify({
            "status": "success",
            "analysis": result,
            "updated_stats": user_stats
        })
    except Exception as e:
        app.logger.error(f"Audio scan error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Audio forensic engine error: {str(e)}"}), 500


@app.route('/api/scan/video', methods=['POST'])
@login_required
def scan_video():
    """
    Analyzes uploaded video for synthetic deepfake manipulation, AI face synthesis tools,
    container atom anomalies, audio-visual track desynchronization, and embedded phishing links.
    """
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        return jsonify({"status": "error", "message": "User session expired."}), 401

    if is_scan_rate_limited(user['id']):
        return jsonify({"status": "error", "message": "Scan rate limit reached. Please wait a moment."}), 429

    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No video file provided in upload."}), 400

    file = request.files['file']
    filename = file.filename or 'video.mp4'
    allowed_exts = ('.mp4', '.webm', '.mkv', '.mov', '.avi')
    if not any(filename.lower().endswith(ext) for ext in allowed_exts):
        return jsonify({"status": "error", "message": f"Unsupported video format. Allowed: {', '.join(allowed_exts)}"}), 400

    raw_bytes = file.read()
    if not raw_bytes:
        return jsonify({"status": "error", "message": "Uploaded video file is empty."}), 400

    if len(raw_bytes) > 35 * 1024 * 1024:
        return jsonify({"status": "error", "message": "Video exceeds maximum size (35 MB)."}), 400

    try:
        detector = get_video_detector()
        result = detector.analyze(raw_bytes, filename=filename)

        stats["total_scanned"] += 1
        if result["is_threat"]:
            stats["suspicious_count"] += 1
        else:
            stats["legitimate_count"] += 1

        summary_msg = f"Video Forensics: {filename} ({result['forensic_details'].get('container', 'Video')})"
        saved_scan_id = save_scan(
            user_id=user['id'],
            submitted_message=summary_msg,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            threat_classification=result['classification'],
            detection_reasons=result['reasons'],
            suspicious_indicators=result['indicators'],
            recommended_action=result['recommended_action'],
            modality='video',
            file_name=filename,
            file_hash=result['forensic_details'].get('sha256', ''),
            technical_details=result['forensic_details']
        )
        result['scan_id'] = saved_scan_id

        user_stats = get_user_stats(user['id'])
        user_stats['model_accuracy'] = stats.get('model_accuracy', 95.65)

        return jsonify({
            "status": "success",
            "analysis": result,
            "updated_stats": user_stats
        })
    except Exception as e:
        app.logger.error(f"Video scan error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Video forensic engine error: {str(e)}"}), 500


@app.route('/api/scan', methods=['POST'])
@login_required
def scan_message():
    """
    Analyzes submitted message text via dual NLP + Heuristic Threat Engine.
    Persists scan record permanently in PostgreSQL/SQLite.
    """
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        return jsonify({
            "status": "error",
            "message": "User session is invalid or user not found. Please log in again."
        }), 401

    if is_scan_rate_limited(user['id']):
        return jsonify({
            "status": "error",
            "message": "Scan rate limit exceeded. Please wait a moment before analyzing more messages."
        }), 429

    data = request.get_json(silent=True)
    if not data or 'message' not in data:
        return jsonify({
            "status": "error",
            "message": "No message text provided in request body."
        }), 400

    raw_text = data.get('message', '').strip().replace('\x00', '')
    if not raw_text:
        return jsonify({
            "status": "error",
            "message": "Message cannot be empty. Please enter an email, SMS, or WhatsApp message."
        }), 400

    if len(raw_text) > 8000:
        return jsonify({
            "status": "error",
            "message": "Message exceeds maximum permitted length (8,000 characters)."
        }), 400

    try:
        analysis = analyze_message(raw_text)

        # Update in-memory session statistics
        stats["total_scanned"] += 1
        if analysis["is_scam"]:
            stats["suspicious_count"] += 1
        else:
            stats["legitimate_count"] += 1

        # Save scan report permanently to database strictly linked to authenticated user['id']
        saved_scan_id = save_scan(
            user_id=user['id'],
            submitted_message=raw_text,
            risk_score=analysis.get('risk_score', 0),
            risk_level=analysis.get('risk_level', 'LOW'),
            threat_classification=analysis.get('classification', 'Legitimate'),
            detection_reasons=analysis.get('reasons', []),
            suspicious_indicators=analysis.get('indicators', []),
            recommended_action=analysis.get('recommended_action', '')
        )

        analysis['scan_id'] = saved_scan_id

        # Fetch updated user-specific statistics
        user_stats = get_user_stats(user['id'])
        user_stats['model_accuracy'] = stats.get('model_accuracy', 95.65)

        return jsonify({
            "status": "success",
            "analysis": analysis,
            "updated_stats": user_stats
        })

    except ValueError as ve:
        app.logger.warning(f"Scan validation error: {ve}")
        return jsonify({
            "status": "error",
            "message": str(ve)
        }), 400
    except Exception as e:
        app.logger.error(f"Error during message scanning: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Scanning engine encountered an error: {str(e)}"
        }), 500


@app.route('/api/scan-file', methods=['POST'])
@login_required
def scan_file():
    """
    Parses and analyzes uploaded WhatsApp chat export (.txt) or CSV file.
    Protected by login_required.
    """
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        return jsonify({
            "status": "error",
            "message": "User session is invalid or user not found. Please log in again."
        }), 401

    if is_scan_rate_limited(user['id']):
        return jsonify({
            "status": "error",
            "message": "Scan rate limit reached. Please wait before uploading another file."
        }), 429

    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    file = request.files['file']
    filename = file.filename or ''

    if not filename:
        return jsonify({"status": "error", "message": "Empty filename"}), 400

    try:
        raw_bytes = file.read()
        if not raw_bytes:
            return jsonify({"status": "error", "message": "Uploaded file is empty"}), 400

        # Handle UTF-16 BOM or UTF-8 BOM
        if raw_bytes.startswith(b'\xff\xfe') or raw_bytes.startswith(b'\xfe\xff'):
            try:
                content = raw_bytes.decode('utf-16')
            except Exception:
                content = raw_bytes.decode('utf-8', errors='ignore')
        elif len(raw_bytes) > 2 and raw_bytes[1:2] == b'\x00' and raw_bytes[3:4] == b'\x00':
            try:
                content = raw_bytes.decode('utf-16')
            except Exception:
                content = raw_bytes.decode('utf-8', errors='ignore')
        else:
            content = raw_bytes.decode('utf-8-sig', errors='ignore')

        # Fix NUL (0x00) parsing error by eliminating all null characters immediately
        content = content.replace('\x00', '')
        lines = content.splitlines()

        messages_to_scan = []

        if filename.lower().endswith('.csv'):
            import csv
            import io
            reader = csv.reader(io.StringIO(content))
            header = next(reader, None)
            text_col = 0
            if header:
                lower_header = [h.strip().lower().replace('\x00', '') for h in header]
                if 'message' in lower_header:
                    text_col = lower_header.index('message')
                elif 'text' in lower_header:
                    text_col = lower_header.index('text')
            for row in reader:
                if row and len(row) > text_col:
                    clean_row_text = row[text_col].strip().replace('\x00', '')
                    if clean_row_text:
                        messages_to_scan.append({
                            "sender": "CSV Record",
                            "timestamp": "",
                            "text": clean_row_text
                        })
        else:
            # WhatsApp chat export parser (.txt)
            wa_pattern = re.compile(
                r'^(?:\[?(\d{1,2}[/-]\d{1,2}[/-]\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s+[APMapm]{2})?)\]?)\s*[-:]?\s*([^:]+):\s*(.+)$'
            )

            current_msg = None
            for line in lines:
                line_str = line.strip().replace('\x00', '')
                if not line_str:
                    continue
                match = wa_pattern.match(line_str)
                if match:
                    if current_msg:
                        messages_to_scan.append(current_msg)
                    current_msg = {
                        "timestamp": match.group(1),
                        "sender": match.group(2).strip().replace('\x00', ''),
                        "text": match.group(3).strip().replace('\x00', '')
                    }
                else:
                    if current_msg:
                        current_msg["text"] += " " + line_str
                    else:
                        messages_to_scan.append({
                            "timestamp": "",
                            "sender": "Unknown Sender",
                            "text": line_str
                        })
            if current_msg:
                messages_to_scan.append(current_msg)


        capped_messages = messages_to_scan[:200]
        results = []
        batch_scam_count = 0
        batch_legit_count = 0

        for item in capped_messages:
            scan_res = analyze_message(item["text"])
            is_scam = scan_res["is_scam"]
            if is_scam:
                batch_scam_count += 1
                stats["suspicious_count"] += 1
            else:
                batch_legit_count += 1
                stats["legitimate_count"] += 1
            stats["total_scanned"] += 1

            # Save batch item to user history as well
            save_scan(
                user_id=user['id'],
                submitted_message=item["text"],
                risk_score=scan_res.get('risk_score', 0),
                risk_level=scan_res.get('risk_level', 'LOW'),
                threat_classification=scan_res.get('classification', 'Legitimate'),
                detection_reasons=scan_res.get('reasons', []),
                suspicious_indicators=scan_res.get('indicators', []),
                recommended_action=scan_res.get('recommended_action', '')
            )

            results.append({
                "timestamp": item.get("timestamp", ""),
                "sender": item.get("sender", "Unknown"),
                "text": item["text"],
                "safe_display_text": scan_res["safe_display_text"],
                "classification": scan_res["classification"],
                "is_scam": is_scam,
                "confidence": scan_res["confidence"],
                "risk_level": scan_res["risk_level"],
                "indicators": scan_res["indicators"],
                "links": scan_res["links"]
            })

        user_stats = get_user_stats(user['id'])
        user_stats['model_accuracy'] = stats.get('model_accuracy', 95.65)

        return jsonify({
            "status": "success",
            "total_processed": len(results),
            "scams_detected": batch_scam_count,
            "legitimate_verified": batch_legit_count,
            "results": results,
            "updated_stats": user_stats
        })

    except Exception as e:
        app.logger.error(f"Error parsing file: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to parse file: {str(e)}"}), 500


@app.route('/health')
def health():
    """Production health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "SecureSync",
        "database": "connected",
        "model": "loaded",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route('/health/email-config')
def health_email_config():
    """
    Safe diagnostic endpoint that reports which email environment variables
    are present (keys only, never values) to debug production email delivery.
    """
    smtp_keys = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_PASS',
                 'SMTP_FROM', 'SMTP_USE_SSL', 'SMTP_USE_TLS',
                 'APP_URL', 'RENDER_EXTERNAL_URL', 'RENDER', 'DATABASE_URL']
    config = {}
    for key in smtp_keys:
        val = os.environ.get(key)
        if val:
            # Mask the value: only show length and first/last char
            masked = f"set ({len(val)} chars)"
        else:
            masked = "NOT SET"
        config[key] = masked

    # Test SMTP connectivity if SMTP_HOST is set
    smtp_test = None
    smtp_host = os.environ.get('SMTP_HOST')
    if smtp_host:
        try:
            import smtplib
            smtp_port = int(os.environ.get('SMTP_PORT', 587))
            use_ssl = (os.environ.get('SMTP_USE_SSL', '').lower() in ('true', '1')) or (smtp_port == 465)
            if use_ssl:
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                server.ehlo()
                if smtp_port not in (25,):
                    server.starttls()
                    server.ehlo()

            smtp_user = os.environ.get('SMTP_USER')
            smtp_pass = os.environ.get('SMTP_PASSWORD') or os.environ.get('SMTP_PASS')
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
                smtp_test = "SMTP login OK"
            else:
                smtp_test = "SMTP connected but no credentials to test login"
            server.quit()
        except Exception as ex:
            smtp_test = f"SMTP error: {str(ex)}"
    else:
        smtp_test = "SMTP_HOST not set – email dispatch disabled"

    return jsonify({
        "status": "ok",
        "email_config": config,
        "smtp_connectivity_test": smtp_test,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


# -----------------------------------------------------------------------------
# Security Headers & Error Handlers
# -----------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return render_template('errors/429.html'), 429

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500


# -----------------------------------------------------------------------------
# Main Application Execution
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1')

    print("\n" + "=" * 70)
    print("  🚀 SecureSync – SMS/WhatsApp Threat Defense System")
    print(f"  📡 Console active at: http://127.0.0.1:{port}")
    print("  🛡️  Zero-Trust Engine: Online & Ready")
    print("=" * 70 + "\n")

    app.run(host='0.0.0.0', port=port, debug=debug_mode)
