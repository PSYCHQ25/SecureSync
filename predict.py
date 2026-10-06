"""
=============================================================================
SecureSync – SMS/WhatsApp Scam Detection System
Script: predict.py
Description: Standalone inference engine and threat explainability module.
             Combines Machine Learning classification with heuristic indicator
             detection and safe link analysis.
=============================================================================
"""

import os
import re
import json
import html
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple
import joblib

# -----------------------------------------------------------------------------
# Configuration Paths
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model', 'scam_model.pkl')
METRICS_PATH = os.path.join(BASE_DIR, 'model', 'metrics.json')

# URL shorteners frequently abused by attackers to disguise phishing destinations
KNOWN_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'ow.ly',
    'buff.ly', 'rb.gy', 'shorte.st', 'goo.gl', 't.me', 'wa.me'
}

# Top-level domains with statistically higher abuse in disposable scam campaigns
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz',
    '.work', '.click', '.loan', '.racing', '.fit', '.support'
}

# Major brand keywords often spoofed in smishing/phishing campaigns
TARGETED_BRANDS = [
    'chase', 'wellsfargo', 'citi', 'bofa', 'bankofamerica', 'paypal',
    'apple', 'amazon', 'netflix', 'usps', 'fedex', 'dhl', 'ups',
    'whatsapp', 'google', 'facebook', 'instagram', 'cashapp', 'venmo'
]


class ScamDetector:
    """
    Production-grade detection class encapsulating:
    1. ML Inference via TF-IDF + Logistic Regression
    2. Heuristic Scam Indicator Pattern Matching
    3. Safe Link Defanging & Domain Quarantine
    4. Plain-English Threat Explanations
    """

    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.pipeline = self._load_model()

    def _load_model(self):
        """Loads the serialized scikit-learn pipeline."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model file not found at {self.model_path}. "
                "Please execute 'python train_model.py' first to train and generate the model."
            )
        try:
            return joblib.load(self.model_path)
        except Exception as e:
            raise RuntimeError(f"Error loading model from {self.model_path}: {e}")

    @staticmethod
    def clean_text(text: str) -> str:
        """
        Normalizes input text identically to the training pipeline:
        - Lowcase conversion
        - Tagging URLs, phone numbers, and currencies
        - Stripping noisy punctuation
        """
        if not isinstance(text, str):
            return ""
        text = text.replace('\x00', '').lower().strip()
        text = re.sub(r'https?://\S+|www\.\S+', ' <url> ', text)
        text = re.sub(r'\+?\d[\d -]{7,}\d', ' <phone> ', text)
        text = re.sub(r'[\$£€₹]\s?\d+(?:,\d+)*(?:\.\d+)?', ' <currency> ', text)
        text = re.sub(r'[^a-z0-9\s<>]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    @staticmethod
    def defang_url(url: str) -> str:
        """
        Defangs URLs to prevent accidental clicking or execution by users/analysts.
        Example: 'http://bit.ly/malware' -> 'hxxp://bit[.]ly/malware'
        """
        defanged = url.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
        defanged = defanged.replace('.', '[.]')
        return defanged

    def extract_and_analyze_urls(self, text: str) -> Tuple[List[Dict[str, Any]], str]:
        """
        Extracts URLs, analyzes domain safety indicators, and produces safe defanged text.
        IMPORTANT: No links are ever fetched, resolved, or executed.
        """
        url_pattern = r'(?:https?://|www\.)[^\s<>"\'{}|\\^`\[\]]+|[a-zA-Z0-9.-]+\.(?:com|org|net|xyz|top|info|biz|co|us|uk|de|io|me|tv|xyz)(?:/[^\s<>"\'{}|\\^`\[\]]*)?'
        found_urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for u in found_urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        link_reports = []
        clean_text_for_urls = text.replace('\x00', '')
        # HTML-escape the text first to neutralize any injected HTML/script tags (XSS defense)
        safe_display_text = html.escape(clean_text_for_urls)

        for raw_url in unique_urls:
            # Parse domain safely
            parsed_target = raw_url if raw_url.startswith(('http://', 'https://')) else f'http://{raw_url}'
            try:
                parsed = urlparse(parsed_target)
                domain = (parsed.netloc or parsed.path).lower().split(':')[0]
            except Exception:
                domain = raw_url.lower()

            defanged = self.defang_url(raw_url)
            is_shortener = any(shortener in domain for shortener in KNOWN_SHORTENERS)
            has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
            is_ip_address = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
            
            # Check for brand spoofing (e.g. chase-verify-online.com)
            brand_spoof = False
            for brand in TARGETED_BRANDS:
                if brand in domain and not (domain.endswith(f'.{brand}.com') or domain == f'{brand}.com'):
                    brand_spoof = True
                    break

            link_reports.append({
                "original_raw": raw_url,
                "defanged": defanged,
                "domain": domain,
                "is_shortener": is_shortener,
                "has_suspicious_tld": has_suspicious_tld,
                "is_ip_address": is_ip_address,
                "brand_spoofing": brand_spoof
            })

            # Replace link in safe display text with quarantined tag
            # Since safe_display_text is HTML-escaped, replace both raw and escaped forms
            escaped_url = html.escape(raw_url)
            safe_display_text = safe_display_text.replace(escaped_url, f"[QUARANTINED LINK: {defanged}]")

        return link_reports, safe_display_text

    def detect_indicators(self, text: str, links: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Heuristic rule-based detection for 7 common scam indicators:
          1. Urgent requests for money
          2. Fake prizes / rewards
          3. Requests for passwords, OTPs, or personal info
          4. Phishing links
          5. Fake banking / payment messages
          6. Suspicious shortened URLs
          7. Threatening or pressure-based language
        """
        text_lower = text.lower()
        indicators = []

        # 1. Urgent requests for money
        money_patterns = [
            r'urgently\s+need', r'emergency\s+cash', r'transfer\s+(?:urgently|immediately|right\s+now)',
            r'wire\s+(?:money|funds|\$\d+)', r'send\s+(?:money|\$\d+|cash)', r'zelle', r'cashapp',
            r'need\s+\$\d+\s+(?:urgently|right\s+now)', r'pay\s+(?:me\s+back|immediately)',
            r'fell\s+in\s+water', r'temporary\s+(?:number|phone)'
        ]
        matched_money = [p for p in money_patterns if re.search(p, text_lower)]
        if matched_money:
            indicators.append({
                "name": "Urgent Money Request",
                "severity": "HIGH",
                "tag": "Financial Demand",
                "explanation": "Requests urgent money transfer or peer-to-peer payment (Zelle/CashApp), a common impersonation tactic."
            })

        # 2. Fake prizes/rewards
        prize_patterns = [
            r'congratulations', r'you\s+have\s+been\s+selected', r'official\s+winner',
            r'you\s+(?:have\s+)?won', r'jackpot', r'free\s+(?:gift\s+card|voucher|reward)',
            r'shopping\s+spree', r'claim\s+(?:your\s+)?(?:prize|reward|funds|voucher)',
            r'prize\s+draw', r'promo\s+winner'
        ]
        matched_prize = [p for p in prize_patterns if re.search(p, text_lower)]
        if matched_prize:
            indicators.append({
                "name": "Fake Prize or Reward",
                "severity": "HIGH",
                "tag": "Bait & Lottery Scam",
                "explanation": "Offers unsolicited lottery winnings, free gift cards, or shopping rewards to manipulate the victim."
            })

        # 3. Requests for passwords, OTPs, or personal information
        auth_patterns = [
            r'otp', r'verification\s+code', r'6-digit\s+code', r'enter\s+your\s+(?:password|pin)',
            r'social\s+security', r'ssn', r'cvv', r'passcode', r'reply\s+with\s+(?:the\s+)?code',
            r'share\s+this\s+code', r'identity\s+verification', r'aadhaar'
        ]
        # Exceptions: Legitimate OTP notices usually instruct "Never share" or "Do not share"
        has_auth_kw = any(re.search(p, text_lower) for p in auth_patterns)
        has_never_share = bool(re.search(r'(?:never|do\s+not)\s+share', text_lower))
        if has_auth_kw and not has_never_share:
            indicators.append({
                "name": "Credential & OTP Solicitation",
                "severity": "CRITICAL",
                "tag": "Credential Harvesting",
                "explanation": "Asks for secret one-time passcodes (OTP), passwords, or personal credentials. Legitimate organizations never request your codes."
            })

        # 4. Phishing links
        has_phishing_link = any(
            link['brand_spoofing'] or link['has_suspicious_tld'] or link['is_ip_address']
            for link in links
        )
        if has_phishing_link:
            indicators.append({
                "name": "Suspicious Phishing Link",
                "severity": "CRITICAL",
                "tag": "Phishing URL",
                "explanation": "Contains a web address mimicking a known organization, an IP-based link, or a suspicious high-risk top-level domain."
            })

        # 5. Fake banking/payment messages
        bank_patterns = [
            r'account\s+(?:is|was|has\s+been|will\s+be)?\s*(?:temporarily\s+)?(?:locked|restricted|suspended|deactivated|blocked|closed)',
            r'unauthorized\s+(?:withdrawal|access|login|device|activity)', r'unrecognized\s+purchase',
            r'(?:debit|credit)\s+card\s+(?:is|was|has\s+been|will\s+be)?\s*(?:temporarily\s+)?(?:deactivated|cancelled|canceled|blocked|suspended)',
            r'kyc\s+(?:update|compliance|non-compliance)',
            r'card\s+ending\s+in\s+\d{4}.*?(?:suspended|locked|blocked)', r'fraud\s+(?:team|desk|department)',
            r'(?:bank|checking)\s+account\s+(?:is|was|has\s+been|will\s+be)'
        ]
        # Distinguish from legitimate bank notices (which state "If authorized, no action needed")
        matched_bank = [p for p in bank_patterns if re.search(p, text_lower)]
        if matched_bank:
            indicators.append({
                "name": "Deceptive Banking / Security Alert",
                "severity": "HIGH",
                "tag": "Bank Impersonation",
                "explanation": "Simulates a false banking crisis or account freeze to provoke anxiety and immediate panic action."
            })

        # 6. Suspicious shortened URLs
        has_shortener = any(link['is_shortener'] for link in links)
        if has_shortener:
            indicators.append({
                "name": "Shortened / Obfuscated Link",
                "severity": "MEDIUM",
                "tag": "URL Shortener",
                "explanation": "Uses a link-shortening service (e.g., bit.ly, tinyurl) to obscure the true destination server."
            })

        # 7. Threatening or pressure-based language
        threat_patterns = [
            r'arrest\s+warrant', r'lawsuit', r'sheriff', r'police', r'court\s+summons',
            r'asset\s+seizure', r'legal\s+action', r'final\s+(?:notice|warning)',
            r'disconnected\s+(?:today|at|in)', r'within\s+\d+\s+hours', r'expire\s+in\s+\d+\s+hours',
            r'penalty\s+of', r'legal\s+penalty'
        ]
        matched_threat = [p for p in threat_patterns if re.search(p, text_lower)]
        if matched_threat:
            indicators.append({
                "name": "Coercive / Threatening Language",
                "severity": "HIGH",
                "tag": "Social Engineering",
                "explanation": "Uses intimidating threats of legal prosecution, arrest, or severe penalties to eliminate deliberate thinking."
            })

        # 8. Delivery & Postal Impersonation Fraud
        delivery_patterns = [
            r'delivery\s+notification', r'package.*?(?:cannot|could\s+not)\s+be\s+delivered',
            r'incomplete\s+(?:street\s+)?address', r'redelivery\s+fee',
            r'customs\s+(?:duty|clearance)', r'reschedule\s+(?:your\s+)?delivery',
            r'missing\s+(?:postal\s+)?(?:zip\s+)?code', r'package\s+is\s+awaiting'
        ]
        if any(re.search(p, text_lower) for p in delivery_patterns):
            indicators.append({
                "name": "Delivery & Package Impersonation",
                "severity": "HIGH",
                "tag": "Delivery Scam",
                "explanation": "Impersonates postal couriers (USPS, FedEx, DHL, UPS) claiming failed delivery to demand addresses or fees."
            })

        # 9. Job Offer & Crypto Investment Fraud
        investment_patterns = [
            r'earn\s+[\$£€₹]?\d+.*?daily', r'work\s+(?:from\s+home|\d+\s+hour)',
            r'rating\s+assistant', r'guaranteed\s+(?:\d+%\s+)?profit',
            r'bitcoin\s+(?:and|&)\s+forex', r'crypto\s+(?:master|vip|gains)',
            r'sugar\s+daddy', r'double\s+your\s+money', r'smart\s+contract\s+mining'
        ]
        if any(re.search(p, text_lower) for p in investment_patterns):
            indicators.append({
                "name": "Job & Investment Fraud",
                "severity": "HIGH",
                "tag": "Advance-Fee Fraud",
                "explanation": "Lures victims with unrealistic work-from-home salaries, fake investment clubs, or guaranteed crypto payouts."
            })

        # 10. Utility & Service Disconnection Threats
        utility_patterns = [
            r'(?:power|electricity)\s+supply.*?(?:disconnect|disconnected)',
            r'sim\s+card.*?(?:deactivated|disconnected)',
            r'kyc\s+non-compliance', r'storage.*?(?:100%\s+full|permanently\s+deleted)'
        ]
        if any(re.search(p, text_lower) for p in utility_patterns):
            indicators.append({
                "name": "Service / Utility Disconnection Threat",
                "severity": "HIGH",
                "tag": "Panic Exploitation",
                "explanation": "Threatens immediate cutoff of essential services (electricity, phone line, cloud storage) to provoke panicked payment."
            })

        return indicators

    def analyze_message(self, text: str) -> Dict[str, Any]:
        """
        Main entry point for scanning and analyzing a message.
        Returns a complete, structured analysis report.
        """
        if not text or not text.strip():
            return {
                "error": "Message is empty. Please enter text to scan."
            }

        original_text = text.replace('\x00', '').strip()
        cleaned_text = self.clean_text(original_text)

        # 1. Extract and quarantine links safely
        links, safe_display_text = self.extract_and_analyze_urls(original_text)

        # 2. Heuristic Scam Indicator Detection
        indicators = self.detect_indicators(original_text, links)

        # 3. Machine Learning Inference
        # Obtain class probabilities safely: index 0 is Legitimate, index 1 is Scam
        raw_probs = self.pipeline.predict_proba([cleaned_text])
        if len(raw_probs) > 0 and len(raw_probs[0]) >= 2:
            prob_legit = float(raw_probs[0][0])
            prob_scam = float(raw_probs[0][1])
        elif len(raw_probs) > 0 and len(raw_probs[0]) == 1:
            prob_scam = float(raw_probs[0][0])
            prob_legit = 1.0 - prob_scam
        else:
            prob_legit, prob_scam = 0.5, 0.5

        # 4. Hybrid Classification Logic:
        # A message is classified as Suspicious/Scam if:
        #   a) The ML model gives it >= 50% scam probability, OR
        #   b) High-severity heuristic indicators are triggered (e.g. credential phishing + link)
        high_severity_indicators = [
            ind for ind in indicators if ind['severity'] in ('CRITICAL', 'HIGH')
        ]
        
        # Determine classification
        if prob_scam >= 0.50 or len(high_severity_indicators) >= 1:
            classification = "Suspicious/Scam"
            is_scam = True
            # Adjust confidence score based on multi-factor evidence
            confidence = max(prob_scam, 0.70) if len(high_severity_indicators) > 0 else prob_scam
            # Scale to percentage
            confidence_percentage = round(confidence * 100, 1)
            
            if confidence_percentage >= 85 or len(high_severity_indicators) >= 2:
                risk_level = "CRITICAL"
            elif confidence_percentage >= 65:
                risk_level = "HIGH"
            else:
                risk_level = "MEDIUM"
                
            warning_message = "⚠ Warning: This message may be a scam."
        else:
            classification = "Legitimate"
            is_scam = False
            confidence = prob_legit
            confidence_percentage = round(confidence * 100, 1)
            risk_level = "LOW"
            warning_message = "✔ Verified: This message appears legitimate."
        # Determine Risk Score (0 - 100) and Recommendation
        if is_scam:
            risk_score = min(99, max(50, int(round(confidence_percentage))))
            if risk_level == "CRITICAL":
                recommended_action = "🚨 CRITICAL: Do NOT click any links, send funds, or reply with OTP/passwords. Block and report the sender immediately."
            elif risk_level == "HIGH":
                recommended_action = "⚠ HIGH RISK: This message exhibits high-threat social engineering tactics. Never disclose credentials or send money. Contact the institution via official phone numbers."
            else:
                recommended_action = "⚠ CAUTION: Suspicious link or urgency detected. Confirm directly with the apparent sender using a known, trusted phone number."
        else:
            risk_score = max(5, min(45, int(round(prob_scam * 100))))
            recommended_action = "✔ LOW RISK: No immediate threat signatures detected. Standard safe communication patterns observed."

        # Build comprehensive detection reasons
        reasons = []
        if is_scam:
            reasons.append(f"Machine learning NLP engine evaluated a {round(prob_scam * 100, 1)}% likelihood of deceptive intent.")
            for ind in indicators:
                reasons.append(f"Identified {ind['name']}: {ind['explanation']}")
            if links:
                reasons.append(f"Identified {len(links)} external hyperlink(s) requiring containment.")
        else:
            reasons.append(f"Machine learning NLP engine evaluated a {round(prob_legit * 100, 1)}% pattern match with benign communications.")
            if not indicators:
                reasons.append("No urgent social engineering, suspicious keywords, or unauthorized link shorteners detected.")

        # Unique scan ID and UTC timestamp
        import uuid
        from datetime import datetime, timezone
        scan_id = f"SCN-{uuid.uuid4().hex[:12].upper()}"
        timestamp_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        return {
            "scan_id": scan_id,
            "timestamp": timestamp_str,
            "original_text": original_text,
            "safe_display_text": safe_display_text,
            "classification": classification,
            "threat_classification": classification,
            "is_scam": is_scam,
            "confidence": confidence_percentage,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_action": recommended_action,
            "warning_message": warning_message,
            "probabilities": {
                "legitimate": round(prob_legit * 100, 1),
                "scam": round(prob_scam * 100, 1)
            },
            "links": links,
            "indicators": indicators,
            "suspicious_indicators": indicators,
            "reasons": reasons,
            "detection_reasons": reasons,
            "char_count": len(original_text),
            "word_count": len(original_text.split())
        }


# Global detector instance for fast reuse in Flask
_detector_instance = None

def get_detector() -> ScamDetector:
    """Singleton getter to reuse the model in memory across requests."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = ScamDetector()
    return _detector_instance


def analyze_message(text: str) -> Dict[str, Any]:
    """Public helper function."""
    detector = get_detector()
    return detector.analyze_message(text)


if __name__ == '__main__':
    import sys
    print("=" * 70)
    print("SecureSync – CLI Message Scanner")
    print("=" * 70)

    # Allow testing via command line: python predict.py "Your message here"
    if len(sys.argv) > 1:
        test_msg = " ".join(sys.argv[1:])
    else:
        test_msg = "URGENT: Your Chase bank account is suspended. Verify immediately at http://bit.ly/chase-lock or card will be blocked."

    print(f"\n[+] Input Message:\n\"{test_msg}\"\n")
    detector = ScamDetector()
    result = detector.analyze_message(test_msg)

    print(f"Classification:   {result['classification']}")
    print(f"Confidence Score: {result['confidence']}%")
    print(f"Risk Level:       {result['risk_level']}")
    print(f"User Alert:       {result['warning_message']}")
    print(f"\nDetected Indicators ({len(result['indicators'])}):")
    for ind in result['indicators']:
        print(f"  - [{ind['severity']}] {ind['name']}: {ind['explanation']}")
    print(f"\nQuarantined Links ({len(result['links'])}):")
    for l in result['links']:
        print(f"  - Defanged: {l['defanged']} (Domain: {l['domain']})")
    print(f"\nReasons:")
    for r in result['reasons']:
        print(f"  * {r}")
    print("=" * 70)
