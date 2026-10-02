"""
=============================================================================
SecureSync – Automated Test & Verification Suite
Script: test_pipeline.py
Description: Full-spectrum verification suite testing:
             1. NLP text preprocessing and clean_text
             2. Zero-trust URL quarantine & defanging
             3. 10 Heuristic Scam Indicator rules
             4. Machine Learning model inference & probability calibration
             5. Verification of zero data leakage
             6. Database multi-tenant isolation, password hashing, and audit logging
             7. Flask REST API endpoints and authentication barriers
=============================================================================
"""

import os
import sys
import unittest
import json
import joblib
import math
import struct
import wave
from PIL import Image

# Ensure application modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import io
from unittest.mock import patch, MagicMock

from predict import ScamDetector, analyze_message, MODEL_PATH, METRICS_PATH
from multimodal_detector import (
    get_image_detector,
    get_audio_detector,
    get_video_detector,
    calculate_entropy,
    ImageThreatDetector,
    AudioThreatDetector,
    VideoThreatDetector
)
from report_generator import generate_pdf_report
from database import (
    init_db,
    register_user,
    authenticate_user,
    save_scan,
    get_user_scans,
    get_scan_by_id,
    get_user_stats,
    delete_user_account,
    change_user_password,
    create_password_reset_token,
    verify_and_use_reset_token,
    get_database_url,
    clear_user_scans,
    export_user_data,
    update_user_privacy_settings,
    get_user_privacy_settings
)
from app import app, send_password_reset_email



class TestSecureSyncPipeline(unittest.TestCase):
    """Core test cases for the SecureSync detection pipeline."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment and database."""
        init_db()
        cls.detector = ScamDetector()

    # -------------------------------------------------------------------------
    # 1. Text Preprocessing & Tokenization Tests
    # -------------------------------------------------------------------------
    def test_text_cleaning_urls_and_currencies(self):
        raw = "Check http://bit.ly/deal now and pay $50.00 or call +1 555-019-9944"
        cleaned = self.detector.clean_text(raw)
        self.assertIn("<url>", cleaned)
        self.assertIn("<currency>", cleaned)
        self.assertIn("<phone>", cleaned)
        self.assertNotIn("http://", cleaned)
        self.assertNotIn("$50.00", cleaned)

    def test_clean_text_handles_empty_and_none(self):
        self.assertEqual(self.detector.clean_text(""), "")
        self.assertEqual(self.detector.clean_text(None), "")
        self.assertEqual(self.detector.clean_text("   "), "")

    # -------------------------------------------------------------------------
    # 2. Zero-Trust URL Defanging & Quarantine Tests
    # -------------------------------------------------------------------------
    def test_url_defanging_policy(self):
        url = "http://malicious-phish.xyz/login"
        defanged = self.detector.defang_url(url)
        self.assertEqual(defanged, "hxxp://malicious-phish[.]xyz/login")
        self.assertNotIn("http://", defanged)
        self.assertNotIn(".xyz", defanged)

    def test_extract_and_quarantine_urls(self):
        msg = "Verify your account at http://bit.ly/chase-lock and http://192.168.1.1/test"
        links, safe_text = self.detector.extract_and_analyze_urls(msg)
        self.assertEqual(len(links), 2)
        self.assertTrue(links[0]['is_shortener'])
        self.assertTrue(links[1]['is_ip_address'])
        self.assertIn("[QUARANTINED LINK:", safe_text)
        self.assertNotIn("http://bit.ly", safe_text)

    # -------------------------------------------------------------------------
    # 3. 10 Heuristic Threat Indicator Tests
    # -------------------------------------------------------------------------
    def test_indicator_urgent_money_request(self):
        msg = "Hi Mom, my phone fell in water. I urgently need $450 via Zelle right now."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Urgent Money Request", names)

    def test_indicator_fake_prize_lottery(self):
        msg = "CONGRATULATIONS! You have been selected as the official winner of a $50,000 Walmart voucher."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Fake Prize or Reward", names)

    def test_indicator_credential_otp_solicitation(self):
        msg = "We noticed unusual login. Reply with your 6-digit OTP and password immediately."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Credential & OTP Solicitation", names)

    def test_indicator_otp_with_never_share_exception(self):
        # Genuine 2FA messages tell users NEVER to share
        msg = "Your Chase verification code is 492019. Never share this code with anyone."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertNotIn("Credential & OTP Solicitation", names)

    def test_indicator_suspicious_phishing_link(self):
        msg = "Verify your account at http://chase-security-login.xyz"
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Suspicious Phishing Link", names)

    def test_indicator_deceptive_banking_alert(self):
        msg = "Your Citibank account has been locked due to an unauthorized withdrawal."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Deceptive Banking / Security Alert", names)

    def test_indicator_url_shortener(self):
        msg = "Check update at http://tinyurl.com/account-status"
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Shortened / Obfuscated Link", names)

    def test_indicator_legal_intimidation(self):
        msg = "Sheriff department alert: An arrest warrant has been issued for you. Call immediately."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Coercive / Threatening Language", names)

    def test_indicator_delivery_fraud(self):
        msg = "USPS: Package could not be delivered due to incomplete street address. Pay redelivery fee."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Delivery & Package Impersonation", names)

    def test_indicator_job_crypto_fraud(self):
        msg = "Earn $500 daily from home as an online rating assistant. Guaranteed profit in 24 hours."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Job & Investment Fraud", names)

    def test_indicator_utility_disconnection(self):
        msg = "Your electricity power supply will be disconnected at 5:00 PM today due to unpaid balance."
        links, _ = self.detector.extract_and_analyze_urls(msg)
        indicators = self.detector.detect_indicators(msg, links)
        names = [ind['name'] for ind in indicators]
        self.assertIn("Service / Utility Disconnection Threat", names)

    # -------------------------------------------------------------------------
    # 4. End-to-End Classification & Bug Fix Regression Tests
    # -------------------------------------------------------------------------
    def test_legitimate_message_no_unbound_local_error(self):
        """Verifies that legitimate messages never crash with UnboundLocalError."""
        msg = "Hey Alex, are we still meeting for lunch at 12:30 today at the student center?"
        res = self.detector.analyze_message(msg)
        self.assertEqual(res['classification'], "Legitimate")
        self.assertFalse(res['is_scam'])
        self.assertEqual(res['risk_level'], "LOW")
        self.assertIn("Verified", res['warning_message'])
        self.assertIn("scan_id", res)
        self.assertIn("recommended_action", res)

    def test_phishing_scam_detection(self):
        msg = "Dear customer, your Chase account is suspended. Verify immediately at http://bit.ly/chase-lock or debit card will be canceled."
        res = self.detector.analyze_message(msg)
        self.assertEqual(res['classification'], "Suspicious/Scam")
        self.assertTrue(res['is_scam'])
        self.assertIn(res['risk_level'], ["HIGH", "CRITICAL"])
        self.assertIn("Warning", res['warning_message'])
        self.assertGreater(len(res['indicators']), 0)
        self.assertGreater(len(res['links']), 0)

    # -------------------------------------------------------------------------
    # 5. Machine Learning Pipeline & Zero Data Leakage Tests
    # -------------------------------------------------------------------------
    def test_model_pipeline_loads_and_predicts_probabilities(self):
        self.assertTrue(os.path.exists(MODEL_PATH))
        pipeline = joblib.load(MODEL_PATH)
        sample = ["congratulations winner claim free gift card <url>"]
        probs = pipeline.predict_proba(sample)[0]
        self.assertEqual(len(probs), 2)
        self.assertAlmostEqual(sum(probs), 1.0, places=4)
        # Malicious text should have high scam probability
        self.assertGreater(probs[1], probs[0])

    def test_metrics_json_structure_and_benchmark_comparison(self):
        self.assertTrue(os.path.exists(METRICS_PATH))
        with open(METRICS_PATH, 'r') as f:
            data = json.load(f)
        self.assertIn("model_name", data)
        self.assertIn("accuracy", data)
        self.assertIn("recall", data)
        self.assertIn("confusion_matrix", data)
        self.assertIn("model_comparison", data)
        self.assertGreaterEqual(len(data['model_comparison']), 4)
        
        # Verify 100% recall for champion
        self.assertEqual(data['recall'], 100.0)

    # -------------------------------------------------------------------------
    # 6. Database Multi-Tenant Isolation & Security Tests
    # -------------------------------------------------------------------------
    def test_database_user_lifecycle_and_tenant_isolation(self):
        # Register user A and User B
        u1_name = "test_analyst_alpha"
        u1_email = "alpha@example.internal"
        u2_name = "test_analyst_beta"
        u2_email = "beta@example.internal"

        # Cleanup existing test users if present
        reg1 = register_user(u1_name, u1_email, "SecurePassword123!")
        reg2 = register_user(u2_name, u2_email, "SecurePassword123!")
        
        user1 = authenticate_user(u1_name, "SecurePassword123!")
        user2 = authenticate_user(u2_name, "SecurePassword123!")
        self.assertIsNotNone(user1)
        self.assertIsNotNone(user2)

        # Save scan strictly for User 1
        scan_id_1 = save_scan(
            user_id=user1['id'],
            submitted_message="URGENT: account suspended",
            risk_score=92,
            risk_level="HIGH",
            threat_classification="Suspicious/Scam",
            detection_reasons=["Deceptive banking alert"],
            suspicious_indicators=[{"name": "Bank Impersonation", "severity": "HIGH"}],
            recommended_action="Do not respond."
        )

        # User 1 CAN access their own scan
        u1_scans = get_user_scans(user1['id'])
        self.assertGreaterEqual(len(u1_scans), 1)
        found_scan = get_scan_by_id(scan_id_1, user1['id'])
        self.assertIsNotNone(found_scan)
        self.assertEqual(found_scan['scan_id'], scan_id_1)

        # User 2 CANNOT access User 1's scan (strict cross-tenant isolation)
        forbidden_scan = get_scan_by_id(scan_id_1, user2['id'])
        self.assertIsNone(forbidden_scan)

        # Verify stats consistency
        u1_stats = get_user_stats(user1['id'])
        self.assertIn("suspicious_count", u1_stats)
        self.assertIn("legitimate_count", u1_stats)
        self.assertGreaterEqual(u1_stats['suspicious_count'], 1)

        # Cleanup
        delete_user_account(user1['id'])
        delete_user_account(user2['id'])

    # -------------------------------------------------------------------------
    # 7. Flask REST API Integration Tests
    # -------------------------------------------------------------------------
    def test_api_public_and_protected_routes(self):
        client = app.test_client()

        # Public endpoints
        res_health = client.get('/health')
        self.assertEqual(res_health.status_code, 200)

        res_samples = client.get('/api/samples')
        self.assertEqual(res_samples.status_code, 200)
        self.assertIn('samples', res_samples.get_json())

        res_metrics = client.get('/api/metrics')
        self.assertEqual(res_metrics.status_code, 200)
        self.assertIn('metrics', res_metrics.get_json())

        # Protected endpoints without session should return 401
        res_stats_anon = client.get('/api/stats')
        self.assertEqual(res_stats_anon.status_code, 401)

        res_scan_anon = client.post('/api/scan', json={"message": "hello"})
        self.assertEqual(res_scan_anon.status_code, 401)

        # Authenticate session
        test_uname = "api_test_user"
        test_email = "api_test@internal.test"
        register_user(test_uname, test_email, "TestPass789!")
        auth_u = authenticate_user(test_uname, "TestPass789!")

        with client.session_transaction() as sess:
            sess['user_id'] = auth_u['id']
            sess['username'] = auth_u['username']
            sess['email'] = auth_u['email']

        # Scan via API
        res_scan = client.post('/api/scan', json={
            "message": "INTERNAL REVENUE SERVICE: Lawsuit filed under SSN. Call 888-555-0199 or local sheriff will execute arrest warrant."
        })
        self.assertEqual(res_scan.status_code, 200)
        data = res_scan.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertTrue(data['analysis']['is_scam'])
        self.assertIn('scan_id', data['analysis'])
        self.assertIn('updated_stats', data)

        # Fetch history via API
        res_history = client.get('/api/history')
        self.assertEqual(res_history.status_code, 200)
        h_data = res_history.get_json()
        self.assertGreaterEqual(len(h_data['history']), 1)

        # Fetch single scan via API
        scan_id = data['analysis']['scan_id']
        res_single = client.get(f'/api/scan/{scan_id}')
        self.assertEqual(res_single.status_code, 200)

        # Cleanup
        delete_user_account(auth_u['id'])

    def test_ghost_session_invalidation_and_recovery(self):
        """Tests that an obsolete session cookie (e.g. from an old database or migration) is safely cleared."""
        client = app.test_client()

        with client.session_transaction() as sess:
            sess['user_id'] = 9999999
            sess['username'] = 'obsolete_analyst'

        # API scan must return 401 and invalidate session without database foreign key crash
        res = client.post('/api/scan', json={"message": "Urgent verification needed"})
        self.assertEqual(res.status_code, 401)

        # Dashboard navigation must redirect to login rather than rendering with ghost ID
        with client.session_transaction() as sess:
            sess['user_id'] = 9999999
        res_dash = client.get('/dashboard')
        self.assertEqual(res_dash.status_code, 302)
        self.assertIn('/login', res_dash.headers.get('Location', ''))

    # -------------------------------------------------------------------------
    # 8. Password Recovery & SMTP Production Tests
    # -------------------------------------------------------------------------
    @patch('smtplib.SMTP')
    def test_smtp_password_reset_email_dispatch(self, mock_smtp_cls):
        """Verifies that send_password_reset_email connects via SMTP, uses TLS, and sends email."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        with patch.dict(os.environ, {
            'SMTP_HOST': 'smtp.render.internal',
            'SMTP_PORT': '587',
            'SMTP_USER': 'notifications@securesync.internal',
            'SMTP_PASSWORD': 'super_secret_smtp_pass',
            'SMTP_FROM': 'security@securesync.io'
        }):
            sent = send_password_reset_email(
                recipient_email="analyst@example.internal",
                username="SecAnalyst",
                reset_url="https://securesync.onrender.com/reset-password/abc123token"
            )
            self.assertTrue(sent)
            mock_smtp_cls.assert_called_with('smtp.render.internal', 587, timeout=12)
            mock_server.starttls.assert_called()
            mock_server.login.assert_called_with('notifications@securesync.internal', 'super_secret_smtp_pass')
            mock_server.sendmail.assert_called()
            mock_server.quit.assert_called()

    @patch('app.send_password_reset_email')
    def test_forgot_password_production_render_neutral_no_token_leak(self, mock_send_email):
        """Verifies that in production/Render with SMTP, reset links are emailed and NEVER exposed in UI."""
        mock_send_email.return_value = True
        client = app.test_client()

        # Register test account
        u_name = "smtp_prod_user"
        u_email = "smtp_prod@internal.test"
        register_user(u_name, u_email, "OldPassword123!")

        with patch.dict(os.environ, {
            'RENDER': 'true',
            'SMTP_HOST': 'smtp.sendgrid.net',
            'RENDER_EXTERNAL_URL': 'https://securesync.onrender.com'
        }):
            res = client.post('/forgot-password', data={'email': u_email}, follow_redirects=True)
            self.assertEqual(res.status_code, 200)
            html_text = res.get_data(as_text=True)

            # Security: Reset link must NEVER be present in the webpage response in production
            self.assertNotIn('Password Reset Token Issued', html_text)
            self.assertNotIn('/reset-password/', html_text)
            # Must show neutral confirmation message
            self.assertIn("password recovery instructions have been sent", html_text)

            # Verify email was actually dispatched with the correct URL
            self.assertTrue(mock_send_email.called)
            call_args = mock_send_email.call_args[0]
            self.assertEqual(call_args[0], u_email)
            self.assertEqual(call_args[1], u_name)
            reset_url = call_args[2]
            self.assertTrue(reset_url.startswith('https://securesync.onrender.com/reset-password/'))

            # Extract token from the reset URL and verify reset works
            token = reset_url.split('/reset-password/')[-1]
            res_reset = client.post(f'/reset-password/{token}', data={
                'password': 'NewPassword456!',
                'confirm_password': 'NewPassword456!'
            }, follow_redirects=True)
            self.assertEqual(res_reset.status_code, 200)

            # Old password must fail authentication
            old_auth = authenticate_user(u_name, "OldPassword123!")
            self.assertIsNone(old_auth)

            # New password must succeed
            new_auth = authenticate_user(u_name, "NewPassword456!")
            self.assertIsNotNone(new_auth)

            # Single-use: Reusing token must fail
            res_reuse = client.post(f'/reset-password/{token}', data={
                'password': 'AnotherPassword789!',
                'confirm_password': 'AnotherPassword789!'
            }, follow_redirects=True)
            self.assertIn("already been used", res_reuse.get_data(as_text=True))

            # Cleanup
            delete_user_account(new_auth['id'])

    # -------------------------------------------------------------------------
    # 9. Batch Scan NUL (0x00) Parsing Tests
    # -------------------------------------------------------------------------
    def test_batch_scan_csv_with_nul_bytes(self):
        """Verifies that CSV files containing NUL (0x00) bytes are sanitized and parsed without error."""
        client = app.test_client()

        u_name = "batch_nul_user"
        u_email = "batch_nul@internal.test"
        register_user(u_name, u_email, "Password123!")
        user = authenticate_user(u_name, "Password123!")

        with client.session_transaction() as sess:
            sess['user_id'] = user['id']
            sess['username'] = user['username']

        # Construct CSV with embedded NUL (0x00) characters
        csv_data = (
            "id,message\x00,status\n"
            "1,Dear customer\x00 your account is locked. Verify at http://bit.ly/bank-fake\x00 now.,alert\n"
            "2,Hey\x00 are we having dinner at 7pm tonight?,chat\n"
        ).encode('utf-8')

        res = client.post('/api/scan-file', data={
            'file': (io.BytesIO(csv_data), 'batch_scans\x00.csv')
        }, content_type='multipart/form-data')

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['total_processed'], 2)
        self.assertGreaterEqual(data['scams_detected'], 1)

        # Scans must be in user's history
        history = get_user_scans(user['id'])
        self.assertEqual(len(history), 2)
        # NUL bytes must be absent in saved message text
        for item in history:
            self.assertNotIn('\x00', item['submitted_message'])

        delete_user_account(user['id'])

    def test_batch_scan_whatsapp_txt_with_nul_bytes(self):
        """Verifies that WhatsApp .txt exports containing NUL (0x00) bytes parse correctly."""
        client = app.test_client()

        u_name = "wa_nul_user"
        u_email = "wa_nul@internal.test"
        register_user(u_name, u_email, "Password123!")
        user = authenticate_user(u_name, "Password123!")

        with client.session_transaction() as sess:
            sess['user_id'] = user['id']
            sess['username'] = user['username']

        # Construct WhatsApp transcript with NUL characters
        txt_data = (
            "[12/05/2026, 14:30:15] Unknown: Hi Mom\x00 I lost my phone. Urgently Zelle me $450 to pay tow truck.\n"
            "[12/05/2026, 14:32:00] Alice: Sounds good\x00 see you tomorrow!\n"
        ).encode('utf-8')

        res = client.post('/api/scan-file', data={
            'file': (io.BytesIO(txt_data), 'chat_export.txt')
        }, content_type='multipart/form-data')

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['total_processed'], 2)

        delete_user_account(user['id'])

    # -------------------------------------------------------------------------
    # 10. Multi-User Isolation Tests
    # -------------------------------------------------------------------------
    def test_multi_user_isolation_strict(self):
        """
        Rigorous multi-tenant test: User A and User B must only see their own Scan History.
        User B must never be able to access User A's history or individual scan records.
        """
        client_a = app.test_client()
        client_b = app.test_client()

        # Register User A & User B
        u_a = register_user("analyst_alpha_iso", "alpha_iso@securesync.internal", "PassAlpha123!")
        u_b = register_user("analyst_beta_iso", "beta_iso@securesync.internal", "PassBeta123!")
        user_a = authenticate_user("analyst_alpha_iso", "PassAlpha123!")
        user_b = authenticate_user("analyst_beta_iso", "PassBeta123!")

        # Log in User A and scan 2 distinct messages
        with client_a.session_transaction() as sess:
            sess['user_id'] = user_a['id']
            sess['username'] = user_a['username']

        res_a1 = client_a.post('/api/scan', json={
            "message": "Alpha Scam 1: IRS lawsuit alert. Call 800-555-0101 immediately."
        })
        scan_id_a1 = res_a1.get_json()['analysis']['scan_id']

        res_a2 = client_a.post('/api/scan', json={
            "message": "Alpha Scam 2: Your package is stuck. Pay $1.99 at http://tinyurl.com/pkg"
        })
        scan_id_a2 = res_a2.get_json()['analysis']['scan_id']

        # Log in User B and scan 1 message
        with client_b.session_transaction() as sess:
            sess['user_id'] = user_b['id']
            sess['username'] = user_b['username']

        res_b1 = client_b.post('/api/scan', json={
            "message": "Beta Scam 1: Congratulations! You won $10,000 Walmart gift card."
        })
        scan_id_b1 = res_b1.get_json()['analysis']['scan_id']

        # 1. Check User A history: must contain ONLY a1 and a2; zero b1
        hist_a_res = client_a.get('/api/history')
        self.assertEqual(hist_a_res.status_code, 200)
        hist_a_ids = [s['scan_id'] for s in hist_a_res.get_json()['history']]
        self.assertIn(scan_id_a1, hist_a_ids)
        self.assertIn(scan_id_a2, hist_a_ids)
        self.assertNotIn(scan_id_b1, hist_a_ids)

        # 2. Check User B history: must contain ONLY b1; zero a1 or a2
        hist_b_res = client_b.get('/api/history')
        self.assertEqual(hist_b_res.status_code, 200)
        hist_b_ids = [s['scan_id'] for s in hist_b_res.get_json()['history']]
        self.assertIn(scan_id_b1, hist_b_ids)
        self.assertNotIn(scan_id_a1, hist_b_ids)
        self.assertNotIn(scan_id_a2, hist_b_ids)

        # 3. Direct ID access isolation: User B attempting to view User A's scan MUST return 404
        forbidden_res = client_b.get(f'/api/scan/{scan_id_a1}')
        self.assertEqual(forbidden_res.status_code, 404)

        # 4. User A can view their own scan
        allowed_res = client_a.get(f'/api/scan/{scan_id_a1}')
        self.assertEqual(allowed_res.status_code, 200)

        # 5. Isolated user stats
        stats_a = client_a.get('/api/stats').get_json()['stats']
        stats_b = client_b.get('/api/stats').get_json()['stats']
        self.assertEqual(stats_a['total_scanned'], 2)
        self.assertEqual(stats_b['total_scanned'], 1)

        # Cleanup
        delete_user_account(user_a['id'])
        delete_user_account(user_b['id'])

    # -------------------------------------------------------------------------
    # 11. Complete Production Flow Test
    # -------------------------------------------------------------------------
    def test_complete_production_flow_persistence(self):
        """
        Tests the complete production cycle:
        Register -> Login -> Analyze -> History -> Logout -> Login again -> Data persists
        """
        client = app.test_client()

        # Step 1: Register
        res_reg = client.post('/register', data={
            'username': 'prod_lifecycle_user',
            'email': 'lifecycle@securesync.internal',
            'password': 'SecurePassword888!',
            'confirm_password': 'SecurePassword888!',
            'full_name': 'Lifecycle Analyst'
        }, follow_redirects=False)
        # Should redirect to login or dashboard
        self.assertIn(res_reg.status_code, (302, 200))

        # Step 2: Login
        res_login = client.post('/login', data={
            'identifier': 'prod_lifecycle_user',
            'password': 'SecurePassword888!'
        }, follow_redirects=True)
        self.assertEqual(res_login.status_code, 200)

        # Step 3: Analyze message
        test_msg = "URGENT: Citibank security lockout alert. Confirm your account immediately at http://bit.ly/citi-fix"
        res_scan = client.post('/api/scan', json={"message": test_msg})
        self.assertEqual(res_scan.status_code, 200)
        scan_data = res_scan.get_json()
        scan_id = scan_data['analysis']['scan_id']

        # Step 4: Verify in History
        res_hist1 = client.get('/api/history')
        self.assertEqual(res_hist1.status_code, 200)
        hist_ids1 = [s['scan_id'] for s in res_hist1.get_json()['history']]
        self.assertIn(scan_id, hist_ids1)

        # Step 5: Logout
        res_logout = client.get('/logout', follow_redirects=True)
        self.assertEqual(res_logout.status_code, 200)

        # Verify session is terminated (access to history must fail)
        res_unauth = client.get('/api/history')
        self.assertEqual(res_unauth.status_code, 401)

        # Step 6: Login again
        res_relogin = client.post('/login', data={
            'identifier': 'lifecycle@securesync.internal',
            'password': 'SecurePassword888!'
        }, follow_redirects=True)
        self.assertEqual(res_relogin.status_code, 200)

        # Step 7: Verify data persists across login sessions
        res_hist2 = client.get('/api/history')
        self.assertEqual(res_hist2.status_code, 200)
        hist_ids2 = [s['scan_id'] for s in res_hist2.get_json()['history']]
        self.assertIn(scan_id, hist_ids2)

        # Clean up
        user = authenticate_user('prod_lifecycle_user', 'SecurePassword888!')
        if user:
            delete_user_account(user['id'])

    # -------------------------------------------------------------------------
    # 12. Neon PostgreSQL & Database Migrations Tests
    # -------------------------------------------------------------------------
    def test_database_migrations_and_neon_url_sslmode(self):
        """Verifies database initialization idempotency and Neon PostgreSQL URL normalization."""
        # Database init must be safe to run multiple times without raising errors
        init_db()
        init_db()

        # Test Neon URL normalization with sslmode=require
        neon_url = "postgres://user:pass@ep-cool-sample.us-east-2.aws.neon.tech/neondb"
        with patch.dict(os.environ, {'DATABASE_URL': neon_url}):
            normalized = get_database_url()
            self.assertTrue(normalized.startswith('postgresql://'))
            self.assertIn('sslmode=require', normalized)

    # -------------------------------------------------------------------------
    # 13. Stale Session Handling on Public Routes
    # -------------------------------------------------------------------------
    def test_stale_session_allows_public_routes(self):
        """Verifies that an obsolete session does not block access to public pages like forgot-password."""
        client = app.test_client()

        with client.session_transaction() as sess:
            sess['user_id'] = 8888888  # Non-existent user ID

        # Must allow viewing forgot-password page
        res_forgot = client.get('/forgot-password')
        self.assertEqual(res_forgot.status_code, 200)

        # Must allow viewing samples API
        with client.session_transaction() as sess:
            sess['user_id'] = 8888888
        res_samples = client.get('/api/samples')
        self.assertEqual(res_samples.status_code, 200)

    # -------------------------------------------------------------------------
    # 14. Multi-Modal Forensic Detection Engines
    # -------------------------------------------------------------------------
    def test_calculate_entropy_mathematical_properties(self):
        """Verifies Shannon entropy calculation on deterministic byte sequences."""
        # Empty payload
        self.assertEqual(calculate_entropy(b''), 0.0)
        # Uniform zero bytes -> zero entropy
        self.assertEqual(calculate_entropy(b'\x00' * 500), 0.0)
        # High entropy: all 256 byte values distributed uniformly
        full_spectrum = bytes(range(256)) * 4
        entropy = calculate_entropy(full_spectrum)
        self.assertAlmostEqual(entropy, 8.0, places=2)

    def test_image_threat_detector_clean_and_stego(self):
        """Verifies image analysis on clean images and detects trailing steganographic payloads."""
        detector = get_image_detector()

        # 1. Clean image
        clean_img = Image.new('RGB', (80, 80), color=(30, 90, 150))
        clean_buf = io.BytesIO()
        clean_img.save(clean_buf, format='PNG')
        clean_bytes = clean_buf.getvalue()

        clean_res = detector.analyze(clean_bytes, 'clean_badge.png')
        self.assertEqual(clean_res['modality'], 'image')
        self.assertEqual(clean_res['risk_level'], 'LOW')
        self.assertFalse(clean_res['is_threat'])
        self.assertLess(clean_res['risk_score'], 30)

        # 2. JPEG with trailing hidden steganographic payload & phishing domain
        stego_img = Image.new('RGB', (80, 80), color=(100, 50, 50))
        stego_buf = io.BytesIO()
        stego_img.save(stego_buf, format='JPEG')
        stego_bytes = stego_buf.getvalue() + b"\r\nCONFIDENTIAL PAYLOAD: https://fake-credential-update.secure-bank.xyz/verify-now"

        stego_res = detector.analyze(stego_bytes, 'invoice_scan.jpg')
        self.assertEqual(stego_res['modality'], 'image')
        self.assertGreaterEqual(stego_res['risk_score'], 50)
        indicator_names = [ind.get('name', '') for ind in stego_res['indicators']]
        self.assertTrue(
            any('Steganographic' in n or 'URL' in n or 'Phishing' in n for n in indicator_names),
            f"Expected stego or URL indicator, got: {indicator_names}"
        )

    def test_audio_threat_detector_signal_processing(self):
        """Verifies synthetic voice detection heuristics using WAV signal analysis."""
        detector = get_audio_detector()

        # Synthesize 0.5s 440Hz sine wave tone in standard PCM WAV
        wav_buf = io.BytesIO()
        with wave.open(wav_buf, 'wb') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(16000)
            sample_count = 8000
            samples = bytearray()
            for i in range(sample_count):
                sample_val = int(12000 * math.sin(2 * math.pi * 440 * i / 16000))
                samples.extend(struct.pack('<h', sample_val))
            wav_file.writeframes(samples)

        wav_bytes = wav_buf.getvalue()
        audio_res = detector.analyze(wav_bytes, 'customer_call.wav')

        self.assertEqual(audio_res['modality'], 'audio')
        self.assertIn('spectral_rolloff_hz', audio_res['forensic_details'])
        self.assertIn('zero_crossing_rate', audio_res['forensic_details'])
        self.assertIn('rms_volume', audio_res['forensic_details'])
        self.assertIn('risk_score', audio_res)

    def test_video_threat_detector_container_and_markers(self):
        """Verifies ISO BMFF MP4 container inspection and synthetic generator marker detection."""
        detector = get_video_detector()

        # Construct synthetic MP4 container with ftyp and moov containing SadTalker tag
        ftyp_payload = b'isom\x00\x00\x02\x00isomiso2mp41'
        ftyp_box = struct.pack('>I4s', len(ftyp_payload) + 8, b'ftyp') + ftyp_payload
        moov_payload = b'mvhd....SadTalker AI Deepfake Generator V2.0....'
        moov_box = struct.pack('>I4s', len(moov_payload) + 8, b'moov') + moov_payload
        mdat_payload = b'mdat_raw_video_frames_stream_data_test_12345678'
        mdat_box = struct.pack('>I4s', len(mdat_payload) + 8, b'mdat') + mdat_payload
        mp4_bytes = ftyp_box + moov_box + mdat_box

        video_res = detector.analyze(mp4_bytes, 'executive_interview.mp4')
        self.assertEqual(video_res['modality'], 'video')
        self.assertEqual(video_res['forensic_details'].get('encoder_software'), 'SADTALKER')
        self.assertGreaterEqual(video_res['risk_score'], 50)
        indicator_names = [ind.get('name', '') for ind in video_res['indicators']]
        self.assertTrue(any('Synthesis' in n or 'Deepfake' in n for n in indicator_names))

    # -------------------------------------------------------------------------
    # 15. PDF Threat Report Generation
    # -------------------------------------------------------------------------
    def test_generate_pdf_report_structure(self):
        """Verifies PDF report synthesis produces a valid, secure PDF document."""
        mock_scan = {
            'scan_id': 'TEST-SEC-99887',
            'timestamp': '2026-10-03 02:00:00 UTC',
            'modality': 'image',
            'risk_score': 82,
            'verdict': 'MALICIOUS',
            'confidence': 0.94,
            'submitted_message': 'suspicious_payload.jpg [SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069]',
            'defanged_message': 'suspicious_payload.jpg',
            'indicators': [
                {'name': 'Steganographic Trailing Data', 'severity': 'CRITICAL', 'explanation': 'Hidden bytes detected past EOF.'},
                {'name': 'Embedded Phishing URL', 'severity': 'HIGH', 'explanation': 'Phishing domain reference identified.'}
            ],
            'technical_details': {
                'file_name': 'suspicious_payload.jpg',
                'file_hash': '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
                'entropy': 7.91,
                'metrics': {'format': 'JPEG', 'trailing_bytes_detected': True}
            }
        }
        user_profile = {'username': 'lead_investigator', 'email': 'investigator@securesync.internal'}

        pdf_stream = generate_pdf_report(mock_scan, user_profile)
        self.assertTrue(hasattr(pdf_stream, 'getvalue'))
        pdf_bytes = pdf_stream.getvalue()
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))
        self.assertGreater(len(pdf_bytes), 1500)

    # -------------------------------------------------------------------------
    # 16. Multi-Modal Upload API Endpoints & History Filtering
    # -------------------------------------------------------------------------
    def test_multimodal_api_scans_and_modality_filtering(self):
        """Verifies /api/scan/image, audio, and video upload endpoints and modality filtering."""
        client = app.test_client()

        # Register and login user
        u_name = "multimodal_analyst"
        u_email = "multimodal@securesync.internal"
        register_user(u_name, u_email, "SecurePassword123!")
        user = authenticate_user(u_name, "SecurePassword123!")

        with client.session_transaction() as sess:
            sess['user_id'] = user['id']
            sess['username'] = user['username']

        # 1. Image upload scan
        img = Image.new('RGB', (60, 60), color=(10, 50, 100))
        img_buf = io.BytesIO()
        img.save(img_buf, format='PNG')
        img_bytes = img_buf.getvalue()

        res_img = client.post('/api/scan/image', data={
            'file': (io.BytesIO(img_bytes), 'test_sample.png')
        }, content_type='multipart/form-data')
        self.assertEqual(res_img.status_code, 200)
        data_img = res_img.get_json()
        self.assertEqual(data_img['status'], 'success')
        self.assertEqual(data_img['analysis']['modality'], 'image')
        img_scan_id = data_img['analysis']['scan_id']

        # 2. Audio upload scan
        wav_buf = io.BytesIO()
        with wave.open(wav_buf, 'wb') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(16000)
            wav_file.writeframes(struct.pack('<h', 0) * 1000)
        aud_bytes = wav_buf.getvalue()

        res_aud = client.post('/api/scan/audio', data={
            'file': (io.BytesIO(aud_bytes), 'voice_memo.wav')
        }, content_type='multipart/form-data')
        self.assertEqual(res_aud.status_code, 200)
        data_aud = res_aud.get_json()
        self.assertEqual(data_aud['analysis']['modality'], 'audio')

        # 3. Video upload scan
        ftyp_payload = b'isom\x00\x00\x02\x00isomiso2mp41'
        ftyp_box = struct.pack('>I4s', len(ftyp_payload) + 8, b'ftyp') + ftyp_payload
        mdat_payload = b'video_data_sample_12345678'
        mdat_box = struct.pack('>I4s', len(mdat_payload) + 8, b'mdat') + mdat_payload
        vid_bytes = ftyp_box + mdat_box

        res_vid = client.post('/api/scan/video', data={
            'file': (io.BytesIO(vid_bytes), 'briefing.mp4')
        }, content_type='multipart/form-data')
        self.assertEqual(res_vid.status_code, 200)
        data_vid = res_vid.get_json()
        self.assertEqual(data_vid['analysis']['modality'], 'video')

        # 4. Modality filter test in /api/history
        res_hist_img = client.get('/api/history?modality=image')
        self.assertEqual(res_hist_img.status_code, 200)
        hist_items = res_hist_img.get_json()['history']
        self.assertGreaterEqual(len(hist_items), 1)
        for item in hist_items:
            self.assertEqual(item['modality'], 'image')

        # 5. PDF download test for this scan
        res_pdf = client.get(f'/api/scan/{img_scan_id}/pdf')
        self.assertEqual(res_pdf.status_code, 200)
        self.assertEqual(res_pdf.content_type, 'application/pdf')
        self.assertTrue(res_pdf.data.startswith(b'%PDF-'))

        # Cleanup
        delete_user_account(user['id'])

    # -------------------------------------------------------------------------
    # 17. Multi-Tenant PDF Isolation Test
    # -------------------------------------------------------------------------
    def test_pdf_report_multi_tenant_isolation(self):
        """Verifies User B cannot access User A's PDF report."""
        client_a = app.test_client()
        client_b = app.test_client()

        u_a = register_user("pdf_alpha_user", "alpha_pdf@internal.test", "AlphaPass123!")
        u_b = register_user("pdf_beta_user", "beta_pdf@internal.test", "BetaPass123!")
        user_a = authenticate_user("pdf_alpha_user", "AlphaPass123!")
        user_b = authenticate_user("pdf_beta_user", "BetaPass123!")

        with client_a.session_transaction() as sess:
            sess['user_id'] = user_a['id']
            sess['username'] = user_a['username']

        res_scan = client_a.post('/api/scan', json={
            "message": "Alpha Confidential: Urgent wire transfer needed immediately."
        })
        scan_id_a = res_scan.get_json()['analysis']['scan_id']

        with client_b.session_transaction() as sess:
            sess['user_id'] = user_b['id']
            sess['username'] = user_b['username']

        # User B attempting to download User A's PDF must return 404
        res_b_attempt = client_b.get(f'/api/scan/{scan_id_a}/pdf')
        self.assertEqual(res_b_attempt.status_code, 404)

        # Cleanup
        delete_user_account(user_a['id'])
        delete_user_account(user_b['id'])

    # -------------------------------------------------------------------------
    # 18. Privacy Settings & Data Governance Endpoints
    # -------------------------------------------------------------------------
    def test_privacy_settings_and_data_governance(self):
        """Verifies privacy preferences updating, data export (GDPR), and scan clearing."""
        client = app.test_client()

        u_name = "privacy_officer"
        u_email = "privacy@securesync.internal"
        register_user(u_name, u_email, "PrivacyPass123!")
        user = authenticate_user(u_name, "PrivacyPass123!")

        with client.session_transaction() as sess:
            sess['user_id'] = user['id']
            sess['username'] = user['username']

        # 1. Update privacy settings
        res_update = client.post('/account/update-settings', data={
            'retention_days': '60',
            'auto_quarantine_links': 'on',
            'sanitize_metadata': 'on'
        }, follow_redirects=True)
        self.assertEqual(res_update.status_code, 200)

        # Verify updated settings in database
        updated_settings = get_user_privacy_settings(user['id'])
        self.assertEqual(updated_settings['retention_days'], 60)
        self.assertTrue(updated_settings['auto_quarantine_links'])
        self.assertTrue(updated_settings['sanitize_metadata'])

        # 2. Perform a scan to ensure history exists
        client.post('/api/scan', json={"message": "Security check: account update required."})
        self.assertGreater(len(get_user_scans(user['id'])), 0)

        # 3. Export data (GDPR archive)
        res_export = client.get('/account/export-data')
        self.assertEqual(res_export.status_code, 200)
        self.assertIn('application/json', res_export.content_type)
        export_payload = json.loads(res_export.data)
        self.assertIn('user_profile', export_payload)
        self.assertIn('scan_records', export_payload)
        self.assertEqual(export_payload['user_profile']['username'], u_name)

        # 4. Clear history
        res_clear = client.post('/account/clear-history', follow_redirects=True)
        self.assertEqual(res_clear.status_code, 200)

        # Verify scan history is now empty while user account remains intact
        scans_after_clear = get_user_scans(user['id'])
        self.assertEqual(len(scans_after_clear), 0)
        self.assertIsNotNone(authenticate_user(u_name, "PrivacyPass123!"))

        # Cleanup
        delete_user_account(user['id'])


if __name__ == '__main__':
    unittest.main()


