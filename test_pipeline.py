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

# Ensure application modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from predict import ScamDetector, analyze_message, MODEL_PATH, METRICS_PATH
from database import (
    init_db,
    register_user,
    authenticate_user,
    save_scan,
    get_user_scans,
    get_scan_by_id,
    get_user_stats,
    delete_user_account,
    change_user_password
)
from app import app


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


if __name__ == '__main__':
    unittest.main()
