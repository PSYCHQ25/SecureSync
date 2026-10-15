"""
=============================================================================
SecureSync – SMS/WhatsApp Scam Detection System
Script: predict.py
Description: Standalone inference engine and threat explainability module.
             Combines Machine Learning classification with heuristic indicator
             detection, domain safety evaluation, and context-aware scoring
             to eliminate false positives on legitimate academic papers,
             resumes, and technical documents.
=============================================================================
"""

import os
import re
import json
import html
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple, Set, Optional
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

# Official domain namespaces for targeted brands (to prevent false positive brand spoofing)
OFFICIAL_BRAND_DOMAINS = {
    'chase': {'chase.com', 'jpmorganchase.com', 'chasepaymentech.com'},
    'wellsfargo': {'wellsfargo.com'},
    'citi': {'citi.com', 'citigroup.com', 'citibank.com'},
    'bofa': {'bofa.com', 'bankofamerica.com'},
    'bankofamerica': {'bankofamerica.com', 'bofa.com'},
    'paypal': {'paypal.com', 'paypal.me'},
    'apple': {'apple.com', 'icloud.com'},
    'amazon': {'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.in', 'amazon.jobs', 'aws.amazon.com'},
    'netflix': {'netflix.com'},
    'usps': {'usps.com', 'usps.gov'},
    'fedex': {'fedex.com'},
    'dhl': {'dhl.com', 'dhl.de'},
    'ups': {'ups.com'},
    'whatsapp': {'whatsapp.com', 'wa.me'},
    'google': {'google.com', 'google.co.uk', 'google.org', 'google.co.in', 'googledrive.com', 'gmail.com'},
    'facebook': {'facebook.com', 'fb.com'},
    'instagram': {'instagram.com'},
    'cashapp': {'cash.app'},
    'venmo': {'venmo.com'}
}

# Reputable academic, developer, scholarly, and reference domains that should never be flagged as phishing
REPUTABLE_DOMAINS = {
    'github.com', 'github.io', 'gitlab.com', 'linkedin.com', 'arxiv.org',
    'doi.org', 'ieee.org', 'acm.org', 'springer.com', 'nature.com',
    'researchgate.net', 'scholar.google.com', 'biorxiv.org', 'medrxiv.org',
    'wikipedia.org', 'w3.org', 'ietf.org', 'sciencedirect.com', 'nih.gov',
    'pypi.org', 'kaggle.com', 'stackoverflow.com', 'medium.com', 'python.org',
    'apache.org', 'huggingface.co', 'openreview.net', 'semanticscholar.org',
    'neurips.cc', 'icml.cc', 'aclweb.org', 'cv-foundation.org'
}

ACADEMIC_GOV_TLDS = ('.edu', '.ac.uk', '.gov', '.mil')


class ScamDetector:
    """
    Production-grade detection class encapsulating:
    1. ML Inference via TF-IDF + Logistic Regression
    2. Context-Aware Scam Indicator Pattern Matching (distinguishing malice from discourse)
    3. Safe Link Defanging & Domain Quarantine with Brand Disambiguation
    4. Multi-Tier Verdict Classification (Legitimate, Inconclusive, Suspicious/Scam)
    5. Plain-English Threat Explanations & Evidence Metrics
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

    @staticmethod
    def is_reputable_domain(domain: str) -> bool:
        """Checks if a domain is a known reputable academic, government, or developer domain."""
        domain = domain.lower()
        if any(domain.endswith(tld) for tld in ACADEMIC_GOV_TLDS):
            return True
        for rep in REPUTABLE_DOMAINS:
            if domain == rep or domain.endswith('.' + rep):
                return True
        return False

    @staticmethod
    def check_brand_spoofing(domain: str) -> Tuple[bool, Optional[str]]:
        """
        Token-aware brand spoofing check.
        Ensures words like 'startups.org' or 'meetups.com' are not falsely flagged as spoofing 'ups',
        and recognizes official international domains like 'amazon.co.uk' or 'citigroup.com'.
        """
        domain_clean = domain.lower().split(':')[0]
        
        # Reputable scholarly/government domains are exempt
        if ScamDetector.is_reputable_domain(domain_clean):
            return False, None

        # Check official namespaces first
        for brand, official_set in OFFICIAL_BRAND_DOMAINS.items():
            for off in official_set:
                if domain_clean == off or domain_clean.endswith('.' + off):
                    return False, None

        # Split domain into discrete alphanumeric tokens
        tokens = [t for t in re.split(r'[\.\-_]', domain_clean) if t]
        
        for brand in TARGETED_BRANDS:
            # Only flag if the brand appears as a discrete token in the host
            if brand in tokens:
                # Exclude if it is an exact official domain
                official_set = OFFICIAL_BRAND_DOMAINS.get(brand, set())
                is_official = any(domain_clean == off or domain_clean.endswith('.' + off) for off in official_set)
                if not is_official:
                    return True, brand

        return False, None

    def extract_and_analyze_urls(self, text: str) -> Tuple[List[Dict[str, Any]], str]:
        """
        Extracts URLs, analyzes domain safety indicators, and produces safe defanged text.
        IMPORTANT: No links are ever fetched, resolved, or executed.
        """
        url_pattern = r'(?:https?://|www\.)[^\s<>"\'{}|\\^`\[\]]+|[a-zA-Z0-9.-]+\.(?:com|org|net|xyz|top|info|biz|co|us|uk|de|io|me|tv|xyz|edu|gov)(?:/[^\s<>"\'{}|\\^`\[\]]*)?'
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
            is_reputable = self.is_reputable_domain(domain)
            is_shortener = (not is_reputable) and any(shortener in domain for shortener in KNOWN_SHORTENERS)
            has_suspicious_tld = (not is_reputable) and any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
            is_ip_address = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
            
            # Context-aware brand spoofing check
            brand_spoof, spoofed_brand = self.check_brand_spoofing(domain)

            link_reports.append({
                "original_raw": raw_url,
                "defanged": defanged,
                "domain": domain,
                "is_reputable": is_reputable,
                "is_shortener": is_shortener,
                "has_suspicious_tld": has_suspicious_tld,
                "is_ip_address": is_ip_address,
                "brand_spoofing": brand_spoof,
                "spoofed_brand": spoofed_brand
            })

            # Replace link in safe display text with quarantined tag
            escaped_url = html.escape(raw_url)
            safe_display_text = safe_display_text.replace(escaped_url, f"[QUARANTINED LINK: {defanged}]")

        return link_reports, safe_display_text

    @staticmethod
    def detect_document_context(text: str) -> Dict[str, Any]:
        """
        Determines whether the analyzed text exhibits the structural characteristics
        of an Academic Paper, Resume / CV, Technical Report, or Legal/Policy Document.
        """
        text_lower = text.lower()
        words = text.split()
        word_count = len(words)

        academic_markers = [
            r'abstract\s*[:\.\-]', r'in\s+this\s+(?:paper|research|study|work|article|report)',
            r'we\s+(?:present|propose|examine|analyze|evaluate|investigate|demonstrate|formulate)',
            r'introduction\b', r'methodology\b', r'related\s+work\b', r'conclusion\b',
            r'references\b', r'proceedings\b', r'ieee\b', r'acm\b', r'arxiv\b', r'doi:\s*\d+',
            r'et\s+al\.', r'university\b', r'department\s+of\b', r'experiments?\s+(?:show|demonstrate|on)',
            r'(?:law\s+review|journal\s+of|springer|nature|sciencedirect|openreview)',
            r'citation\b', r'benchmark\s+dataset', r'state-of-the-art\b', r'bleu\s+score',
            r'neural\s+network', r'deep\s+learning', r'residual\s+learning'
        ]
        academic_hits = sum(1 for m in academic_markers if re.search(m, text_lower))

        resume_markers = [
            r'experience\b', r'education\b', r'skills\b', r'projects\b', r'certifications?\b',
            r'bachelor\b', r'master\s+of\s+science', r'curriculum\s+vitae\b', r'summary\s+of\b',
            r'gpa\s*[:\d]', r'technologies\s*[:\b]', r'work\s+experience\b', r'technical\s+skills\b',
            r'professional\s+summary\b', r'magna\s+cum\s+laude', r'github\.com\/', r'linkedin\.com\/in\/'
        ]
        resume_hits = sum(1 for m in resume_markers if re.search(m, text_lower))

        security_discourse_markers = [
            r'phishing\s+attack', r'credential\s+harvesting', r'malware\s+distribution',
            r'unauthorized\s+access', r'vulnerability\b', r'zero-trust\b', r'access\s+control\b',
            r'penetration\s+test', r'threat\s+modeling\b', r'cryptography\b', r'security\s+advisory',
            r'session\s+hijacking', r'countermeasures?\b', r'attack\s+vectors?'
        ]
        security_discourse_hits = sum(1 for m in security_discourse_markers if re.search(m, text_lower))

        is_academic = (academic_hits >= 2) or (bool(re.search(r'abstract\s*[:\.\-]', text_lower)) and academic_hits >= 1)
        is_resume = (resume_hits >= 2)
        is_security_discourse = (security_discourse_hits >= 1)
        is_document = is_academic or is_resume or (word_count >= 100)

        doc_type = "short_message"
        if is_academic:
            doc_type = "academic_paper"
        elif is_resume:
            doc_type = "resume_cv"
        elif is_document:
            doc_type = "technical_document"

        return {
            "is_document": is_document,
            "document_type": doc_type,
            "is_academic": is_academic,
            "is_resume": is_resume,
            "is_security_discourse": is_security_discourse,
            "academic_score": academic_hits,
            "resume_score": resume_hits,
            "security_discourse_score": security_discourse_hits
        }

    def detect_indicators(self, text: str, links: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Context-aware heuristic rule-based detection for scam indicators:
          1. Urgent requests for money (extortion / impersonation demand)
          2. Fake prizes / rewards (lottery / voucher bait)
          3. Requests for passwords, OTPs, or personal info (credential solicitation)
          4. Phishing links (brand spoofing / high-risk disposable domains)
          5. Deceptive banking / payment messages (simulated crisis)
          6. Suspicious shortened URLs
          7. Coercive or threatening language (law enforcement intimidation)
          8. Delivery & Postal Impersonation
          9. Job Offer & Crypto Investment Fraud
          10. Utility & Service Disconnection Threats

        CRITICAL DESIGN RULE:
        Differentiates predatory calls-to-action targeting the reader from
        educational, academic, or professional discourse describing technologies.
        """
        text_lower = text.lower()
        indicators = []

        # Check for legitimate 2FA instructions ("Never share" / "Do not share")
        has_never_share = bool(re.search(r'(?:never|do\s+not)\s+share', text_lower))

        # 1. Urgent requests for money
        money_patterns = [
            r'(?:urgently|immediately|right\s+now)\s+(?:need|send|wire|transfer)\s+(?:money|funds|cash|\$[\d,]+)',
            r'(?:need|send|wire|transfer)\s+(?:money|funds|cash|\$[\d,]+)\s+(?:urgently|immediately|right\s+now)',
            r'(?:emergency|urgent)\s+(?:cash|funds|money\s+transfer)',
            r'(?:send|transfer|wire|pay)\s+(?:via\s+|through\s+)?(?:zelle|cashapp|venmo|western\s+union|wire\s+transfer)',
            r'(?:cashapp|zelle|venmo)\s*(?:handle|tag|account)?:\s*[\$\w]+',
            r'transfer\s+immediately\s+to\s+this\s+cashapp',
            r'fell\s+in\s+(?:the\s+)?water.*?temporary\s+(?:number|phone)',
            r'temporary\s+(?:number|phone).*?(?:urgently\s+need|send\s+money|wire)',
            r'lost\s+(?:my\s+)?phone\s+and\s+wallet.*?(?:wire|send\s+\$)',
        ]
        if any(re.search(p, text_lower) for p in money_patterns):
            indicators.append({
                "name": "Urgent Money Request",
                "severity": "HIGH",
                "tag": "Financial Demand",
                "explanation": "Requests urgent money transfer or peer-to-peer payment (Zelle/CashApp), a common impersonation tactic."
            })

        # 2. Fake prizes/rewards
        prize_patterns = [
            r'(?:official|lucky|promo)\s+winner',
            r'congratulations!?[^.!?\n]*?(?:you\s+(?:have\s+)?been\s+selected|you\s+(?:have\s+)?won|claim\s+(?:your\s+)?(?:prize|reward|voucher|gift\s*card))',
            r'you\s+(?:have\s+)?won\s+[\$£€₹]?[\d,]+\s+(?:in\s+the|cash|dollars|jackpot|prize|lottery)',
            r'(?:claim|collect)\s+(?:your\s+)?(?:exclusive\s+)?(?:prize|reward|jackpot|funds|voucher|gift\s*card)',
            r'free\s+(?:\$\d+\s+)?(?:walmart|target|amazon|apple)\s+(?:cash\s+)?(?:gift\s*card|voucher)',
            r'(?:international\s+)?mega\s+millions\s+lottery',
            r'jackpot\s+funds',
            r'prize\s+draw:\s*you\s+are\s+our\s+lucky',
        ]
        if any(re.search(p, text_lower) for p in prize_patterns):
            indicators.append({
                "name": "Fake Prize or Reward",
                "severity": "HIGH",
                "tag": "Bait & Lottery Scam",
                "explanation": "Offers unsolicited lottery winnings, free gift cards, or shopping rewards to manipulate the victim."
            })

        # 3. Requests for passwords, OTPs, or personal information (Solicitation)
        auth_patterns = [
            r'(?:reply|send|text|share|submit|enter|provide|input|confirm|verify)\s+(?:with\s+)?(?:your\s+)?(?:the\s+)?(?:6-digit\s+|one-time\s+|verification\s+)?(?:otp|passcode|code|password|pin|cvv|secret\s+code)',
            r'enter\s+(?:your\s+)?(?:current\s+)?(?:password|pin|passcode|credentials)',
            r'(?:submit|provide|verify)\s+your\s+(?:6-digit\s+)?(?:otp|code|ssn|social\s+security\s+number)',
            r'share\s+this\s+code',
            r'reply\s+(?:immediately\s+)?with\s+your\s+(?:\d+-digit\s+)?(?:sms\s+)?code',
            r'(?:enter|verify)\s+your\s+apple\s+id\s+credentials',
            r'update\s+your\s+credit\s+card\s+number,\s*cvv',
        ]
        if any(re.search(p, text_lower) for p in auth_patterns) and not has_never_share:
            indicators.append({
                "name": "Credential & OTP Solicitation",
                "severity": "CRITICAL",
                "tag": "Credential Harvesting",
                "explanation": "Asks for secret one-time passcodes (OTP), passwords, or personal credentials. Legitimate organizations never request your codes."
            })

        # 4. Phishing links
        has_phishing_link = any(
            link.get('brand_spoofing') or link.get('has_suspicious_tld') or link.get('is_ip_address')
            for link in links
        )
        if has_phishing_link:
            indicators.append({
                "name": "Suspicious Phishing Link",
                "severity": "CRITICAL",
                "tag": "Phishing URL",
                "explanation": "Contains a web address mimicking a known organization, an IP-based link, or a suspicious high-risk top-level domain."
            })

        # 5. Deceptive banking/payment messages
        bank_patterns = [
            r'(?:your|our)\s+(?:bank\s+)?(?:account|card|online\s+access|online\s+banking)\s+(?:is|was|has\s+been|will\s+be)\s*(?:temporarily\s+)?(?:locked|restricted|suspended|deactivated|blocked|closed)',
            r'(?:your\s+)?(?:chase|wells\s*fargo|citi|citibank|bofa|bank\s+of\s+america|paypal)\s+(?:bank\s+)?(?:account|debit\s+card|card|access)\s+(?:is|was|has\s+been|will\s+be)\s*(?:temporarily\s+)?(?:locked|restricted|suspended|deactivated|blocked|canceled|cancelled)',
            r'detected\s+(?:an\s+)?unauthorized\s+(?:withdrawal|transaction|charge|purchase|login|device)',
            r'unauthorized\s+withdrawal\s+of\s+[\$£€₹]?\d+',
            r'unauthorized\s+withdrawal',
            r'(?:debit|credit)\s+card\s+has\s+been\s+deactivated',
            r'card\s+ending\s+in\s+\d{4}.*?(?:suspended|locked|blocked|deactivated)',
            r'(?:bank|fraud)\s+(?:security\s+)?alert:\s*.*?unauthorized',
            r'paypal\s+fraud\s+team:\s*you\s+sent\s+[\$£€₹]?\d+',
            r'kyc\s+(?:update|compliance|non-compliance).*?(?:mandatory|suspend|block|freeze|deactivate)',
        ]
        if any(re.search(p, text_lower) for p in bank_patterns):
            indicators.append({
                "name": "Deceptive Banking / Security Alert",
                "severity": "HIGH",
                "tag": "Bank Impersonation",
                "explanation": "Simulates a false banking crisis or account freeze to provoke anxiety and immediate panic action."
            })

        # 6. Suspicious shortened URLs
        has_shortener = any(link.get('is_shortener') for link in links)
        if has_shortener:
            indicators.append({
                "name": "Shortened / Obfuscated Link",
                "severity": "MEDIUM",
                "tag": "URL Shortener",
                "explanation": "Uses a link-shortening service (e.g., bit.ly, tinyurl) to obscure the true destination server."
            })

        # 7. Threatening or pressure-based language
        threat_patterns = [
            r'(?:arrest\s+warrant|warrant\s+for\s+your\s+arrest)\s+(?:has\s+been\s+issued|issued)',
            r'warrant\s+has\s+been\s+issued\s+for\s+(?:you|your\s+arrest)',
            r'lawsuit\s+has\s+been\s+registered\s+under\s+your\s+social\s+security',
            r'(?:local\s+)?sheriff\s+will\s+execute\s+arrest\s+warrant',
            r'before\s+deputies\s+are\s+dispatched',
            r'face\s+immediate\s+(?:arrest|asset\s+seizure|law\s+enforcement\s+action)',
            r'clear\s+your\s+outstanding\s+legal\s+penalty\s+or\s+face',
            r'final\s+(?:notice|warning):.*?(?:online\s+access\s+will\s+expire|will\s+expire\s+in\s+\d+\s+hours|service\s+will\s+be\s+terminated)',
            r'disconnected\s+(?:today\s+at|in\s+\d+\s+hours)',
        ]
        if any(re.search(p, text_lower) for p in threat_patterns):
            indicators.append({
                "name": "Coercive / Threatening Language",
                "severity": "HIGH",
                "tag": "Social Engineering",
                "explanation": "Uses intimidating threats of legal prosecution, arrest, or severe penalties to eliminate deliberate thinking."
            })

        # 8. Delivery & Postal Impersonation Fraud
        delivery_patterns = [
            r'(?:package|parcel|shipment)\s+#?[\w-]*\s*could\s+not\s+be\s+delivered',
            r'redelivery\s+fee',
            r'incomplete\s+(?:street\s+)?address.*?(?:update|pay|confirm)',
            r'pay\s+customs\s+duty\s+of\s+[\$£€₹]?\d+',
            r'package\s+is\s+awaiting\s+your\s+confirmation.*?missing\s+postal',
            r'missing\s+(?:postal\s+)?(?:zip\s+)?code.*?(?:within\s+\d+\s+hours|prevent\s+return)',
            r'attempted\s+delivery\s+of\s+your\s+parcel\s+today.*?reschedule',
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
            r'earn\s+[\$£€₹]?\d+(?:-\$[\d,]+)?\s+(?:daily|per\s+day|an\s+hour).*?(?:from\s+home|whatsapp|no\s+experience)',
            r'rating\s+assistant',
            r'guaranteed\s+(?:\d+%\s+)?profit\s+in\s+\d+\s+hours',
            r'crypto\s+(?:master\s+trader|vip\s+gains|doubler)',
            r'double\s+your\s+(?:money|bitcoin|crypto)',
            r'sugar\s+(?:daddy|mommy)',
            r'work\s+1\s+hour\s+per\s+day\s+on\s+whatsapp',
            r'smart\s+contract\s+mining\s+pool.*?guaranteed',
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
            r'(?:electricity|power)\s+power\s+supply.*?disconnect',
            r'electricity\s+(?:power\s+)?supply\s+will\s+be\s+disconnected',
            r'sim\s+card.*?(?:deactivated|disconnected)',
            r'kyc\s+non-compliance',
            r'storage.*?(?:100%\s+full|permanently\s+deleted)'
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
        Main entry point for scanning and analyzing a message or document.
        Combines ML classification with heuristic indicator detection,
        context awareness, safe link isolation, and calibrated verdict logic.
        """
        if not text or not text.strip():
            return {
                "error": "Message is empty. Please enter text to scan."
            }

        original_text = text.replace('\x00', '').strip()

        # 1. Extract and quarantine links safely
        links, safe_display_text = self.extract_and_analyze_urls(original_text)

        # 2. Context Analysis (Academic paper, resume, or short message)
        doc_context = self.detect_document_context(original_text)
        is_document = doc_context["is_document"]

        # Prepare text for ML inference:
        # For reputable links (e.g. GitHub, arXiv, LinkedIn, university sites),
        # replace with domain token so they do not trigger SMS phishing <url> artifact.
        inference_text = original_text
        if links:
            for l in links:
                if l.get('is_reputable'):
                    inference_text = inference_text.replace(l['original_raw'], ' ' + l['domain'].split('.')[0] + ' ')
        cleaned_text = self.clean_text(inference_text)

        # 3. Heuristic Scam Indicator Detection
        indicators = self.detect_indicators(original_text, links)

        # 4. Machine Learning Inference
        raw_probs = self.pipeline.predict_proba([cleaned_text])
        if len(raw_probs) > 0 and len(raw_probs[0]) >= 2:
            prob_legit = float(raw_probs[0][0])
            prob_scam = float(raw_probs[0][1])
        elif len(raw_probs) > 0 and len(raw_probs[0]) == 1:
            prob_scam = float(raw_probs[0][0])
            prob_legit = 1.0 - prob_scam
        else:
            prob_legit, prob_scam = 0.5, 0.5

        # 5. Score Calibration for Out-of-Distribution Long Documents & Academic Texts
        # The ML model was trained strictly on ~20-word SMS messages. In long texts,
        # benign URLs (like GitHub, arXiv) and dollar amounts inflate the TF-IDF logit.
        # When no genuine indicators are present and all links are reputable, adjust prob_scam.
        calibrated_prob_scam = prob_scam
        reputable_links_only = bool(links) and all(l.get('is_reputable') for l in links)
        no_suspicious_links = not any(
            l.get('brand_spoofing') or l.get('has_suspicious_tld') or l.get('is_ip_address') or l.get('is_shortener')
            for l in links
        )

        if (is_document or doc_context["is_academic"] or doc_context["is_resume"]) and not indicators and no_suspicious_links:
            # Document has no scam indicators and no suspicious links
            # Downweight SMS model probability artifact
            calibrated_prob_scam = min(0.20, prob_scam * 0.35)
            prob_legit = 1.0 - calibrated_prob_scam
        elif not indicators and no_suspicious_links and (reputable_links_only or not links):
            # Text with no scam indicators and zero suspicious links
            if calibrated_prob_scam > 0.35:
                calibrated_prob_scam = min(0.35, prob_scam * 0.70)
                prob_legit = 1.0 - calibrated_prob_scam

        high_severity_indicators = [
            ind for ind in indicators if ind['severity'] in ('CRITICAL', 'HIGH')
        ]
        has_critical = any(ind['severity'] == 'CRITICAL' for ind in indicators)
        has_phishing_link = any(ind['name'] == 'Suspicious Phishing Link' for ind in indicators)
        has_credential_solicitation = any(ind['name'] == 'Credential & OTP Solicitation' for ind in indicators)
        has_money_extortion = any(ind['name'] == 'Urgent Money Request' for ind in indicators)
        has_fake_prize = any(ind['name'] == 'Fake Prize or Reward' for ind in indicators)
        has_threat = any(ind['name'] == 'Coercive / Threatening Language' for ind in indicators)
        has_bank_alert = any(ind['name'] == 'Deceptive Banking / Security Alert' for ind in indicators)
        has_delivery = any(ind['name'] == 'Delivery & Package Impersonation' for ind in indicators)
        has_job_fraud = any(ind['name'] == 'Job & Investment Fraud' for ind in indicators)
        has_utility = any(ind['name'] == 'Service / Utility Disconnection Threat' for ind in indicators)

        # 6. Multi-Tier Verdict Classification Logic:
        # A) SUSPICIOUS / SCAM:
        #    - Any high-severity social engineering indicator or verified phishing link, OR
        #    - Machine learning probability >= 65%
        # B) INCONCLUSIVE / REVIEW RECOMMENDED:
        #    - Ambiguous evidence (borderline score 45% - 65% with unconfirmed signals,
        #      or weak indicators present without proof of fraudulent intent).
        # C) LEGITIMATE:
        #    - Clean indicators, low scam score (< 40%), legitimate document / benign message.

        is_confirmed_threat = (
            has_phishing_link or
            has_credential_solicitation or
            has_money_extortion or
            has_fake_prize or
            has_threat or
            has_bank_alert or
            has_delivery or
            has_job_fraud or
            has_utility or
            has_critical or
            (len(high_severity_indicators) >= 1) or
            (calibrated_prob_scam >= 0.65)
        )

        is_inconclusive = False
        is_scam = False

        if is_confirmed_threat:
            classification = "Suspicious/Scam"
            threat_classification = "Suspicious/Scam"
            is_scam = True
            confidence = max(calibrated_prob_scam, 0.70) if high_severity_indicators else calibrated_prob_scam
            confidence_percentage = round(confidence * 100, 1)

            if confidence_percentage >= 85 or len(high_severity_indicators) >= 2 or has_critical:
                risk_level = "CRITICAL"
                risk_score = min(99, max(85, int(round(confidence_percentage))))
                recommended_action = "🚨 CRITICAL: Do NOT click any links, send funds, or reply with OTP/passwords. Block and report the sender immediately."
            elif confidence_percentage >= 65:
                risk_level = "HIGH"
                risk_score = min(84, max(65, int(round(confidence_percentage))))
                recommended_action = "⚠ HIGH RISK: This payload exhibits high-threat social engineering tactics. Never disclose credentials or send money. Contact the institution via official channels."
            else:
                risk_level = "MEDIUM"
                risk_score = min(64, max(50, int(round(confidence_percentage))))
                recommended_action = "⚠ CAUTION: Suspicious link or urgency detected. Confirm directly with the apparent sender using a known, trusted phone number."

            warning_message = "⚠ Warning: This message may be a scam."

        elif (calibrated_prob_scam >= 0.45 and calibrated_prob_scam < 0.65) or (len(indicators) > 0 and not is_confirmed_threat):
            # Ambiguous evidence -> INCONCLUSIVE (Requirement 6)
            classification = "Inconclusive"
            threat_classification = "Inconclusive"
            is_inconclusive = True
            is_scam = False
            risk_level = "MEDIUM"
            confidence_percentage = round(max(calibrated_prob_scam, prob_legit) * 100, 1)
            risk_score = int(round(calibrated_prob_scam * 100))
            risk_score = max(35, min(55, risk_score))
            warning_message = "⚠ Inconclusive: Evidence is insufficient to confirm deceptive intent. Review highlighted indicators."
            recommended_action = "ℹ INCONCLUSIVE ASSESSMENT: Automated evidence is insufficient to verify deceptive intent. Contextual manual review by a qualified analyst is recommended."

        else:
            # LEGITIMATE / CLEAN
            classification = "Legitimate"
            threat_classification = "Legitimate"
            is_scam = False
            risk_level = "LOW"
            confidence_percentage = round(prob_legit * 100, 1)
            risk_score = max(5, min(30, int(round(calibrated_prob_scam * 100))))
            warning_message = "✔ Verified: This message appears legitimate."
            recommended_action = "✔ LOW RISK: No immediate threat signatures detected. Standard safe communication patterns observed."

        # 7. Threat Category Assignment
        if is_scam:
            if has_credential_solicitation:
                threat_category = "Credential Theft & OTP Harvesting"
            elif any(ind['name'] == 'Deceptive Banking / Security Alert' for ind in indicators):
                threat_category = "Bank Impersonation Phishing"
            elif has_phishing_link:
                threat_category = "Brand Spoofing & Phishing Link"
            elif has_money_extortion:
                threat_category = "Impersonation & Urgent Extortion"
            elif any(ind['name'] == 'Delivery & Package Impersonation' for ind in indicators):
                threat_category = "Delivery / Postal Smishing"
            elif has_fake_prize:
                threat_category = "Advance-Fee Lottery & Prize Fraud"
            elif any(ind['name'] == 'Job & Investment Fraud' for ind in indicators):
                threat_category = "Cryptocurrency & Job Offer Fraud"
            elif any(ind['name'] == 'Service / Utility Disconnection Threat' for ind in indicators):
                threat_category = "Utility & Service Extortion Threat"
            elif has_threat:
                threat_category = "Law Enforcement & Intimidation Scam"
            elif links:
                threat_category = "Obfuscated Link Phishing"
            else:
                threat_category = "Social Engineering & Deceptive Intent"
        elif is_inconclusive:
            threat_category = "Inconclusive / Review Required"
        else:
            if doc_context["is_academic"]:
                threat_category = "Academic Research Publication (Legitimate)"
            elif doc_context["is_resume"]:
                threat_category = "Professional Resume / Curriculum Vitae (Legitimate)"
            elif doc_context["is_document"]:
                threat_category = "Legitimate Document / Technical Report"
            else:
                threat_category = "Benign Communication / Legitimate"

        # 8. Detection Explanations (Why Flagged)
        reasons = []
        if is_scam:
            reasons.append(f"Machine learning NLP engine evaluated a {round(prob_scam * 100, 1)}% likelihood of deceptive intent.")
            for ind in indicators:
                reasons.append(f"Identified {ind['name']}: {ind['explanation']}")
            if links:
                reasons.append(f"Identified {len(links)} external hyperlink(s) requiring containment.")
        elif is_inconclusive:
            reasons.append(f"Machine learning inference evaluated borderline confidence ({round(prob_scam * 100, 1)}% scam / {round(prob_legit * 100, 1)}% legitimate).")
            if indicators:
                for ind in indicators:
                    reasons.append(f"Flagged heuristic indicator: {ind['name']} ({ind['explanation']}) without confirmed malicious payload.")
            else:
                reasons.append("Uncertain semantic signal: input lacks clear malicious calls-to-action but warrants analyst confirmation.")
            if links:
                reasons.append(f"Identified {len(links)} external link(s); domains lack documented high-risk signatures.")
        else:
            reasons.append(f"Machine learning NLP engine evaluated a {round(prob_legit * 100, 1)}% pattern match with benign communications.")
            if doc_context["is_academic"]:
                reasons.append("Document exhibits standard scholarly structure (abstract, methodology, citations) with zero predatory indicators.")
            elif doc_context["is_resume"]:
                reasons.append("Document exhibits standard professional resume structure (experience, credentials, contact details) with zero deceptive indicators.")
            elif not indicators:
                reasons.append("No urgent social engineering, suspicious keywords, or unauthorized link shorteners detected.")
            if doc_context["is_security_discourse"]:
                reasons.append("Informational cybersecurity/technical terminology observed in educational context without malicious solicitation.")

        # Unique scan ID and UTC timestamp
        import uuid
        from datetime import datetime, timezone
        scan_id = f"SCN-{uuid.uuid4().hex[:12].upper()}"
        timestamp_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        evidence = {
            "matched_indicators": indicators,
            "quarantined_urls": links,
            "document_context": doc_context,
            "linguistic_metrics": {
                "character_count": len(original_text),
                "word_count": len(original_text.split()),
                "scam_intent_probability": round(calibrated_prob_scam * 100, 1),
                "raw_model_scam_probability": round(prob_scam * 100, 1)
            }
        }

        return {
            "scan_id": scan_id,
            "timestamp": timestamp_str,
            "original_text": original_text,
            "safe_display_text": safe_display_text,
            "classification": classification,
            "threat_classification": threat_classification,
            "threat_category": threat_category,
            "is_scam": is_scam,
            "is_inconclusive": is_inconclusive,
            "confidence": confidence_percentage,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_action": recommended_action,
            "warning_message": warning_message,
            "probabilities": {
                "legitimate": round(prob_legit * 100, 1),
                "scam": round(calibrated_prob_scam * 100, 1)
            },
            "links": links,
            "indicators": indicators,
            "suspicious_indicators": indicators,
            "reasons": reasons,
            "detection_reasons": reasons,
            "why_flagged": reasons,
            "evidence": evidence,
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
