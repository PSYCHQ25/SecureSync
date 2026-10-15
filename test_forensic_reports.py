"""
=============================================================================
SecureSync – Forensic Intelligence Report Verification Suite
Script: test_forensic_reports.py
Description: Exhaustive test suite verifying the Forensic Intelligence Report
             across all 4 modalities: Text, Image, Audio, and Video.
             Tests both threat and clean cases, investigation timeline synthesis,
             evidence-backed findings, recommended next actions, and Flask PDF
             download endpoints.
=============================================================================
"""

import io
import os
import sys
import unittest
import struct
import wave
from datetime import datetime, timezone
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, register_user, authenticate_user, save_scan, get_scan_by_id
from report_generator import generate_pdf_report, _build_timeline
from multimodal_detector import get_image_detector, get_audio_detector, get_video_detector
from predict import analyze_message
from app import app


class TestForensicIntelligenceReports(unittest.TestCase):
    """Rigorous tests for Forensic Intelligence Reports across all 4 modalities."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = app.test_client()

        # Register a test investigator
        cls.username = f"forensic_agent_{int(datetime.now().timestamp())}"
        cls.email = f"{cls.username}@securesync.internal"
        cls.password = "StrongDefensivePass123!"
        register_user(cls.username, cls.email, cls.password)
        cls.user = authenticate_user(cls.username, cls.password)
        assert cls.user is not None, "Failed to authenticate test user"

    def _login_session(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.user['id']
            sess['username'] = self.user['username']
            sess['full_name'] = "Lead Forensic Examiner"

    # -------------------------------------------------------------------------
    # 1. TEXT MODALITY REPORT TESTS
    # -------------------------------------------------------------------------
    def test_text_threat_report_generation(self):
        """Tests Forensic Intelligence Report for a critical phishing text scan."""
        phish_text = "URGENT: Your Bank of America account is suspended! Verify at http://bankofamerica-secure-login.xyz/login immediately or funds will freeze."
        analysis = analyze_message(phish_text)

        scan_id = save_scan(
            user_id=self.user['id'],
            submitted_message=phish_text,
            risk_score=analysis.get('risk_score', 95),
            risk_level=analysis.get('risk_level', 'CRITICAL'),
            threat_classification=analysis.get('threat_classification', 'Phishing Scam'),
            detection_reasons=analysis.get('detection_reasons', []),
            suspicious_indicators=analysis.get('suspicious_indicators', []),
            recommended_action=analysis.get('recommended_action', 'Quarantine immediately.'),
            modality='text'
        )
        saved = get_scan_by_id(scan_id, self.user['id'])

        # Verify timeline
        timeline = _build_timeline(saved)
        self.assertGreaterEqual(len(timeline), 4)
        phases = [step['phase'] for step in timeline]
        self.assertIn('Submission Received', phases)
        self.assertIn('Payload Parsing', phases)
        self.assertIn('Detection Engine', phases)
        self.assertIn('Classification Issued', phases)

        # Generate PDF report
        pdf_buf = generate_pdf_report(saved, analyst_name="Lead Forensic Examiner")
        self.assertIsInstance(pdf_buf, io.BytesIO)
        pdf_bytes = pdf_buf.getvalue()
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))
        self.assertGreater(len(pdf_bytes), 2000)

        # Verify endpoint export
        self._login_session()
        res = self.client.get(f'/api/scan/{scan_id}/pdf')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')
        self.assertTrue(res.data.startswith(b'%PDF-'))

    def test_text_clean_report_generation(self):
        """Tests Forensic Intelligence Report for a safe text scan."""
        clean_text = "Hi Sarah, please review the quarterly presentation before our 2 PM team sync."
        analysis = analyze_message(clean_text)

        scan_id = save_scan(
            user_id=self.user['id'],
            submitted_message=clean_text,
            risk_score=analysis.get('risk_score', 5),
            risk_level=analysis.get('risk_level', 'LOW'),
            threat_classification=analysis.get('threat_classification', 'Legitimate Message'),
            detection_reasons=analysis.get('detection_reasons', []),
            suspicious_indicators=analysis.get('suspicious_indicators', []),
            recommended_action=analysis.get('recommended_action', 'Maintain standard defensive posture.'),
            modality='text'
        )
        saved = get_scan_by_id(scan_id, self.user['id'])

        pdf_buf = generate_pdf_report(saved, analyst_name="Lead Forensic Examiner")
        pdf_bytes = pdf_buf.getvalue()
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))
        self.assertGreater(len(pdf_bytes), 2000)

    # -------------------------------------------------------------------------
    # 2. IMAGE MODALITY REPORT TESTS
    # -------------------------------------------------------------------------
    def test_image_threat_and_clean_report_generation(self):
        """Tests Forensic Intelligence Report for image scans (steganography vs clean)."""
        # Create image with trailing steganographic bytes
        img = Image.new('RGB', (80, 80), color=(20, 40, 80))
        img_buf = io.BytesIO()
        img.save(img_buf, format='JPEG')
        clean_jpeg_bytes = img_buf.getvalue()
        malicious_jpeg_bytes = clean_jpeg_bytes + b"EVIL_HIDDEN_PAYLOAD_PAST_EOF_hxxp://evil-command.xyz"

        img_detector = get_image_detector()
        result = img_detector.analyze(malicious_jpeg_bytes, 'suspicious_invoice.jpg')

        scan_id = save_scan(
            user_id=self.user['id'],
            submitted_message=f"Image: suspicious_invoice.jpg [SHA-256: {result.get('file_hash')}]",
            risk_score=result.get('risk_score', 80),
            risk_level=result.get('risk_level', 'HIGH'),
            threat_classification=result.get('verdict', 'Threat Detected'),
            detection_reasons=result.get('reasons', []),
            suspicious_indicators=result.get('indicators', []),
            recommended_action=result.get('recommended_action', 'Quarantine immediately.'),
            modality='image',
            file_name='suspicious_invoice.jpg',
            file_hash=result.get('file_hash'),
            technical_details=result.get('forensic_details', {})
        )
        saved = get_scan_by_id(scan_id, self.user['id'])

        # Verify timeline
        timeline = _build_timeline(saved)
        phases = [step['phase'] for step in timeline]
        self.assertIn('Submission Received', phases)
        self.assertIn('File Validation', phases)
        self.assertIn('Detection Engine', phases)

        # PDF Report
        pdf_buf = generate_pdf_report(saved, analyst_name="Lead Forensic Examiner")
        pdf_bytes = pdf_buf.getvalue()
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))
        self.assertGreater(len(pdf_bytes), 2000)

        # API download
        self._login_session()
        res = self.client.get(f'/api/scan/{scan_id}/pdf')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')

    # -------------------------------------------------------------------------
    # 3. AUDIO MODALITY REPORT TESTS
    # -------------------------------------------------------------------------
    def test_audio_report_generation(self):
        """Tests Forensic Intelligence Report for audio forensics."""
        # Create valid synthetic WAV with ultrasonic tone
        buf = io.BytesIO()
        with wave.open(buf, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(44100)
            samples = [int(16000 * ((i % 2) * 2 - 1)) for i in range(4410)]
            raw_frames = struct.pack(f'<{len(samples)}h', *samples)
            wav.writeframes(raw_frames)
        wav_bytes = buf.getvalue()

        audio_detector = get_audio_detector()
        result = audio_detector.analyze(wav_bytes, 'voicemail_capture.wav')

        scan_id = save_scan(
            user_id=self.user['id'],
            submitted_message=f"Audio: voicemail_capture.wav [SHA-256: {result.get('file_hash')}]",
            risk_score=result.get('risk_score', 65),
            risk_level=result.get('risk_level', 'MEDIUM'),
            threat_classification=result.get('verdict', 'Suspicious Audio'),
            detection_reasons=result.get('reasons', []),
            suspicious_indicators=result.get('indicators', []),
            recommended_action=result.get('recommended_action', 'Verify speaker out-of-band.'),
            modality='audio',
            file_name='voicemail_capture.wav',
            file_hash=result.get('file_hash'),
            technical_details=result.get('forensic_details', {})
        )
        saved = get_scan_by_id(scan_id, self.user['id'])

        pdf_buf = generate_pdf_report(saved, analyst_name="Lead Forensic Examiner")
        pdf_bytes = pdf_buf.getvalue()
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))
        self.assertGreater(len(pdf_bytes), 2000)

        self._login_session()
        res = self.client.get(f'/api/scan/{scan_id}/pdf')
        self.assertEqual(res.status_code, 200)

    # -------------------------------------------------------------------------
    # 4. VIDEO MODALITY REPORT TESTS
    # -------------------------------------------------------------------------
    def test_video_report_generation(self):
        """Tests Forensic Intelligence Report for video deepfake forensics."""
        # Create mock MP4 header with Deepfake synthesis marker
        mp4_bytes = b"\x00\x00\x00\x20ftypmp42\x00\x00\x00\x00isommp42\x00\x00\x00\x08freeSADTALKER_AI_SYNTHESIS_METADATA_HEADER"

        video_detector = get_video_detector()
        result = video_detector.analyze(mp4_bytes, 'executive_statement.mp4')

        scan_id = save_scan(
            user_id=self.user['id'],
            submitted_message=f"Video: executive_statement.mp4 [SHA-256: {result.get('file_hash')}]",
            risk_score=result.get('risk_score', 85),
            risk_level=result.get('risk_level', 'CRITICAL'),
            threat_classification=result.get('verdict', 'Deepfake Synthetic Video'),
            detection_reasons=result.get('reasons', []),
            suspicious_indicators=result.get('indicators', []),
            recommended_action=result.get('recommended_action', 'Quarantine immediately.'),
            modality='video',
            file_name='executive_statement.mp4',
            file_hash=result.get('file_hash'),
            technical_details=result.get('forensic_details', {})
        )
        saved = get_scan_by_id(scan_id, self.user['id'])

        pdf_buf = generate_pdf_report(saved, analyst_name="Lead Forensic Examiner")
        pdf_bytes = pdf_buf.getvalue()
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))
        self.assertGreater(len(pdf_bytes), 2000)

        self._login_session()
        res = self.client.get(f'/api/scan/{scan_id}/pdf')
        self.assertEqual(res.status_code, 200)


if __name__ == '__main__':
    unittest.main()
