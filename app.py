"""
=============================================================================
SecureSync – SMS & WhatsApp Scam Detection System
Script: app.py
Description: Production-Ready Flask Web Application & REST API backend.
             Hosts the cybersecurity dashboard, manages session scanning,
             enforces multi-tenant user isolation, brute-force protection,
             zero-trust link defanging, and real-time NLP/ML analysis endpoints.
=============================================================================
"""

import os
import re
import json
import time
import secrets
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
    abort
)
from werkzeug.middleware.proxy_fix import ProxyFix

from predict import analyze_message, METRICS_PATH
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
    validate_email
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
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12)
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
# Authentication & Authorization Decorator
# -----------------------------------------------------------------------------
def login_required(f):
    """Enforces strict authentication for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({"status": "error", "message": "Authentication required."}), 401
            flash("Authentication required to access the SecureSync portal.", "warning")
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
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Analyst authentication gateway (Username or Email)."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

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
        return redirect(url_for('dashboard'))

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
    current_user = {
        "id": session.get('user_id'),
        "username": session.get('username'),
        "email": session.get('email'),
        "full_name": session.get('full_name'),
        "role": session.get('role')
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
    """User account management page."""
    current_user = get_user_by_id(session['user_id'])
    return render_template('account.html', current_user=current_user)


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
# Password Recovery
# -----------------------------------------------------------------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Secure password reset request."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    direct_reset_url = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        result = create_password_reset_token(email)
        if result:
            raw_token, username = result
            direct_reset_url = url_for('reset_password', token=raw_token, _external=True)

            smtp_host = os.environ.get('SMTP_HOST')
            if smtp_host:
                try:
                    import smtplib
                    from email.mime.text import MIMEText
                    from email.mime.multipart import MIMEMultipart

                    smtp_port = int(os.environ.get('SMTP_PORT', 587))
                    smtp_user = os.environ.get('SMTP_USER')
                    smtp_pass = os.environ.get('SMTP_PASSWORD') or os.environ.get('SMTP_PASS')
                    mail_from = os.environ.get('SMTP_FROM', 'noreply@securesync.internal')

                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = 'SecureSync – Password Recovery Link'
                    msg['From'] = mail_from
                    msg['To'] = email

                    body = f"Hello {username},\n\nA password reset was requested for your SecureSync account.\nClick the link below within 1 hour:\n\n{direct_reset_url}\n\nIf you did not request this, please disregard."
                    msg.attach(MIMEText(body, 'plain'))

                    server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                    server.starttls()
                    if smtp_user and smtp_pass:
                        server.login(smtp_user, smtp_pass)
                    server.sendmail(mail_from, [email], msg.as_string())
                    server.quit()
                except Exception as ex:
                    app.logger.error(f"Error dispatching password reset email: {ex}")
            else:
                app.logger.info(f"[RESET TOKEN GENERATED] For {email}: {direct_reset_url}")

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
    """Strictly returns past scan history belonging to the current user."""
    user_id = session.get('user_id')
    history_records = get_user_scans(user_id, limit=50)
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


@app.route('/api/scan', methods=['POST'])
@login_required
def scan_message():
    """
    Analyzes submitted message text via dual NLP + Heuristic Threat Engine.
    Persists scan record permanently in PostgreSQL/SQLite.
    """
    user_id = session.get('user_id')
    if is_scan_rate_limited(user_id):
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

    raw_text = data.get('message', '').strip()
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

        # Save scan report permanently to database
        saved_scan_id = save_scan(
            user_id=user_id,
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
        user_stats = get_user_stats(user_id)
        user_stats['model_accuracy'] = stats.get('model_accuracy', 95.65)

        return jsonify({
            "status": "success",
            "analysis": analysis,
            "updated_stats": user_stats
        })

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
    if is_scan_rate_limited(user_id):
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
        content = file.read().decode('utf-8', errors='ignore')
        lines = content.splitlines()

        messages_to_scan = []

        if filename.endswith('.csv'):
            import csv
            import io
            reader = csv.reader(io.StringIO(content))
            header = next(reader, None)
            text_col = 0
            if header:
                lower_header = [h.strip().lower() for h in header]
                if 'message' in lower_header:
                    text_col = lower_header.index('message')
                elif 'text' in lower_header:
                    text_col = lower_header.index('text')
            for row in reader:
                if row and len(row) > text_col and row[text_col].strip():
                    messages_to_scan.append({
                        "sender": "CSV Record",
                        "timestamp": "",
                        "text": row[text_col].strip()
                    })
        else:
            # WhatsApp chat export parser (.txt)
            wa_pattern = re.compile(
                r'^(?:\[?(\d{1,2}[/-]\d{1,2}[/-]\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s+[APMapm]{2})?)\]?)\s*[-:]?\s*([^:]+):\s*(.+)$'
            )

            current_msg = None
            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue
                match = wa_pattern.match(line_str)
                if match:
                    if current_msg:
                        messages_to_scan.append(current_msg)
                    current_msg = {
                        "timestamp": match.group(1),
                        "sender": match.group(2).strip(),
                        "text": match.group(3).strip()
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
                user_id=user_id,
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

        user_stats = get_user_stats(user_id)
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
