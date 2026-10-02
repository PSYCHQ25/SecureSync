# 🛡️ SecureSync – Multi Detection System

**SecureSync** is an enterprise-grade, multi-modal cybersecurity detection and forensic intelligence platform. Engineered with a zero-trust architecture, SecureSync analyzes threats across four distinct digital modalities — **Text**, **Image**, **Audio**, and **Video** — to detect phishing, social engineering, synthetic media (deepfakes), voice cloning (vishing), and file steganography.

[![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.1-black.svg)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%20(Neon)%20%7C%20SQLite3-00BFFF.svg)](https://neon.tech)
[![Tests](https://img.shields.io/badge/Test%20Suite-38%2F38%20Passing%20(100%25)-green.svg)](test_pipeline.py)
[![License](https://img.shields.io/badge/License-Proprietary%20%2F%20Educational-purple.svg)]()

---

## 🌐 The 4 Multi-Modal Detection Engines

SecureSync unifies four specialized forensic engines into a single Security Operations Center (SOC) interface:

```
                                  ┌───────────────────────────┐
                                  │ SecureSync Gateway & Auth │
                                  └─────────────┬─────────────┘
                                                │
         ┌──────────────────┬───────────────────┼───────────────────┬──────────────────┐
         │                  │                   │                   │                  │
         ▼                  ▼                   ▼                   ▼                  ▼
┌─────────────────┐┌─────────────────┐┌─────────────────┐┌─────────────────┐┌─────────────────┐
│  Text Modality  ││ Image Modality  ││ Audio Modality  ││ Video Modality  ││ Bulk Inspector  │
├─────────────────┤├─────────────────┤├─────────────────┤├─────────────────┤├─────────────────┤
│ • NLP TF-IDF    ││ • Shannon       ││ • FFT Spectral  ││ • ISO BMFF MP4  ││ • WhatsApp .txt │
│ • Calibrated LR ││   Byte Entropy  ││   Roll-off (Hz) ││   Container     ││ • CSV Batch Log │
│ • 10 Heuristic  ││ • Steganography ││ • Zero-Crossing ││ • Deepfake Tag  ││ • Multi-Message │
│   Rule Engines  ││   Trailing Data ││   Rate (ZCR)    ││   Fingerprints  ││   Sanitization  │
│ • Link Defanging││ • EXIF Software ││ • Neural Vocoder││ • Atom Order    ││ • Zero-Leakage  │
│ • Zero-Trust URL││ • Quishing URLs ││   Cutoff (<9kHz)││   ('moov' post) ││   Batch Parser  │
└────────┬────────┘└────────┬────────┘└────────┬────────┘└────────┬────────┘└────────┬────────┘
         │                  │                   │                   │                  │
         └──────────────────┴───────────────────┼───────────────────┴──────────────────┘
                                                │
                                                ▼
                                ┌───────────────────────────────┐
                                │ Incident Assessment & Scoring │
                                └───────────────┬───────────────┘
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     ▼                                                     ▼
      ┌─────────────────────────────┐                       ┌─────────────────────────────┐
      │ Interactive SOC Dashboard   │                       │ Executive PDF Threat Dossier│
      │ • Live Forensic Badges      │                       │ • Digital Verification Seal │
      │ • Quarantine Preview        │                       │ • Forensic Breakdown Grid   │
      │ • Indicators & Recommendations│                     │ • Incident Playbook         │
      └─────────────────────────────┘                       └─────────────────────────────┘
```

---

### 1. 📝 Text Threat Engine (Smishing & Phishing)
- **Natural Language Processing (NLP):** Tokenizes incoming strings, strips zero-width non-printing characters, and extracts unigrams and bigrams via `TfidfVectorizer`.
- **Calibrated Logistic Regression:** Evaluates mathematical feature weights through a calibrated sigmoidal transfer function to output deterministic probabilities (0–100%).
- **10 Heuristic Scam Indicator Engines:**
  1. *Urgent Money Transfers* (Zelle, CashApp, wire fraud, family emergency lures)
  2. *Fake Prizes & Lottery Winnings* (unsolicited sweepstakes, advance-fee lures)
  3. *Credential & 2FA Harvesting* (OTP theft, password reset impersonation)
  4. *Phishing Domain Recognition* (brand spoofing, high-risk TLDs like `.xyz`, `.top`, raw IP endpoints)
  5. *Deceptive Banking Lockout Alerts* (manufactured panic regarding suspended accounts)
  6. *Shortened URL Cloaking* (`bit.ly`, `tinyurl.com`, `is.gd`, `t.co`)
  7. *Legal & Coercive Intimidation* (fake arrest warrants, sheriff summons, IRS litigation)
  8. *Delivery & Courier Impersonation* (USPS, FedEx, DHL parcel redelivery lures)
  9. *Job Offer & Pyramid Investment Schemes* (cryptocurrency VIP returns, task rating traps)
  10. *Critical Utility Disconnection Threats* (electricity, water, cellular SIM deactivation)
- **Bulk Batch Inspector:** Ingests CSV transcripts or WhatsApp chat export files (`.txt`), automatically cleans embedded NUL (`0x00`) bytes, and processes individual lines with zero data loss.

---

### 2. 🖼️ Image Forensic Engine (Quishing & Steganography)
- **Shannon Byte Entropy Analysis:** Calculates information density across byte distributions to distinguish standard compressed graphics ($H \approx 6.0\text{--}7.4$) from encrypted/concealed payloads ($H > 7.8$).
- **Steganography & Trailing Payload Discovery:** Inspects image files past standard End-Of-File delimiters (e.g. JPEG `FF D9`, PNG `IEND`) to detect polyglot binaries, hidden zip archives, and malicious executables.
- **EXIF Metadata & Software Fingerprinting:** Analyzes header tags (`Software`, `Artist`, `ImageDescription`) for evidence of manipulation suites (`Photoshop`, `GIMP`, `Canva`, `DeepFaceLab`).
- **Quishing (QR Phishing) & Lure Detection:** Scans embedded byte streams for deceptive links and phishing vectors cloaked inside graphics.

---

### 3. 🎙️ Audio Forensic Engine (Synthetic Voice & Vishing)
- **Neural Vocoder Spectral Roll-off:** AI voice cloners (e.g., Tortoise, Bark, ElevenLabs, VALL-E) frequently display unnatural high-frequency attenuation cutoffs below 9.0 kHz. SecureSync calculates the 85% energy roll-off threshold via Fast Fourier Transform (FFT).
- **Zero-Crossing Rate (ZCR) & Energy Dynamics:** Measures synthetic waveform smoothing and lack of natural organic room reverberation.
- **Ultrasonic Carrier Beaconing:** Scans inaudible frequency bands (>18.5 kHz) for acoustic steganography or surveillance beacon signals.
- **Voice Social Engineering Keywords:** Scans extracted container stream strings for high-urgency vishing scripts ("social security", "wire money", "arrest warrant").

---

### 4. 🎥 Video Forensic Engine (Deepfakes & Container Forensics)
- **ISO Base Media File Format (ISO BMFF) Inspection:** Traverses top-level media atoms (`ftyp`, `moov`, `mdat`) in MP4 and QuickTime containers.
- **Synthetic Pipeline Signatures:** Scans container metadata and encoder libraries for signatures of AI deepfake generation software (`SadTalker`, `Wav2Lip`, `Roop`, `DeepFaceLab`, `FaceFusion`).
- **Post-Export Atom Hierarchy:** Flags unoptimized rendering layouts (e.g., `moov` header atom trailing at the end of the file rather than the beginning), characteristic of freshly generated neural avatars prior to web transmuxing.
- **Embedded Phishing Vectors:** Unpacks embedded subtitles and data tracks to intercept malicious links placed inside video reels.

---

## 📄 Executive PDF Threat Intelligence Reports

Every scan across any modality can be instantly exported into an **Executive Threat Intelligence Report** powered by `ReportLab Platypus`:

- **Official Digital Verification Seal:** Includes a cryptographically verifiable SHA-256 fingerprint and unique Scan Reference ID.
- **Structured Threat Breakdown:** Visual score gauges, risk rating badges (CRITICAL, HIGH, MEDIUM, LOW), and executive assessment summaries.
- **Forensic Indicators Table:** Vector breakdown, severity tags, and technical rationales.
- **Incident Response Playbook:** Dynamic containment actions based on detected vectors (e.g., credential rotation, host isolation, out-of-band banking verification).
- **Zero Data Leakage:** Generated entirely in-memory using `io.BytesIO` streams — no temporary files are ever stored on disk.

---

## 🔒 Security, Privacy & Data Governance

SecureSync is built around strict data privacy and enterprise compliance:

- **GDPR / CCPA Data Portability:** Users can download a complete JSON archive of their profile and scan history at any time (`GET /account/export-data`).
- **Zero-Trace Scan History Wiping:** One-click scan history purge (`POST /account/clear-history`) completely removes telemetry logs while preserving the user account.
- **Configurable Data Retention:** Automated audit trail lifespan settings (30, 60, 90, 180, or 365 days).
- **Zero-Trust URL Quarantine & Defanging:** URLs are rewritten (`hxxp://`, `hxxps://`, `[.]`) and sanitized so analysts never execute live malicious endpoints.
- **Multi-Tenant Isolation:** PostgreSQL and SQLite database queries strictly filter by authenticated `session['user_id']`. User B can never read or query User A's scans or download their PDF dossiers.
- **Cryptographic Password Security:** Salting and key derivation via PBKDF2:SHA-256 (600,000 rounds).
- **Session Security:** `HttpOnly`, `SameSite=Lax`, and conditional `Secure` cookies for HTTPS environments.

---

## 🏗️ Architecture & Database Layer

- **Primary Cloud Database:** **Neon PostgreSQL** via `DATABASE_URL` (automatic `sslmode=require` configuration and connection pooling).
- **Local Fallback:** **SQLite3** (`database.db`) for rapid local development with zero external configuration.
- **Idempotent Database Migrations:** `init_db()` dynamically verifies and migrates schema columns (`modality`, `file_name`, `file_hash`, `technical_details`, `privacy_settings`) on boot without data loss.

---

## 🔌 REST API Reference

| Endpoint | Method | Authentication | Description |
|---|---|---|---|
| `/api/scan` | `POST` | Optional | Analyze text message for smishing/phishing indicators |
| `/api/scan/image` | `POST` | Optional | Upload and forensic-scan image file (PNG, JPG, WEBP) |
| `/api/scan/audio` | `POST` | Optional | Upload and analyze audio file (WAV, MP3, OGG) |
| `/api/scan/video` | `POST` | Optional | Upload and analyze video file (MP4, MOV, MKV) |
| `/api/scan-file` | `POST` | Required | Bulk scan CSV or WhatsApp `.txt` export |
| `/api/scan/<scan_id>/pdf` | `GET` | Required | Download official Threat Intelligence PDF report |
| `/api/history` | `GET` | Required | Retrieve user scan history (supports `?modality=image`) |
| `/api/stats` | `GET` | Required | Fetch isolated metrics for the authenticated user |
| `/account/update-settings` | `POST` | Required | Update retention, auto-quarantine, and privacy rules |
| `/account/clear-history` | `POST` | Required | Permanently purge all scan logs for the current account |
| `/account/export-data` | `GET` | Required | Export complete GDPR JSON audit archive |

---

## 🧪 Comprehensive Verification Suite

SecureSync includes 38 rigorous automated unit and integration tests covering the entire pipeline:

```bash
# Run the automated test suite
python3 -m unittest test_pipeline.py -v
```

### Test Suite Coverage:
- **1. Text Preprocessing & Cleaning:** Normalization, zero-width space removal, link extraction.
- **2. URL Quarantine & Defanging:** Conversion to `hxxp://`, IP de-obfuscation.
- **3. Heuristic Rules (10 vectors):** Urgency, lottery, 2FA theft, legal threats, shorteners, package alerts, etc.
- **4. Machine Learning Inference:** TF-IDF feature extraction, probability thresholding.
- **5. Multi-Modal Detectors:** Image entropy, stego trailing data, audio FFT roll-off, video ISO BMFF atoms and deepfake markers.
- **6. Executive PDF Generation:** Structure, tables, metadata seals, styling.
- **7. Multi-Tenant Isolation:** Guarantees cross-tenant boundary security between distinct user accounts.
- **8. Authentication & Password Security:** Registration, PBKDF2 hashing, single-use password recovery tokens.
- **9. Data Governance & Privacy:** GDPR JSON export, scan history purge, retention preference persistence.
- **10. Batch Ingestion:** NUL (`0x00`) byte handling in CSV and WhatsApp exports.

---

## 🚀 Quickstart & Installation

### 1. Clone & Setup
```bash
git clone https://github.com/PSYCHQ25/SecureSync.git
cd SecureSync
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Verification Suite
```bash
python3 -m unittest test_pipeline.py
```

### 3. Launch the Server
```bash
python3 app.py
```
Open [http://127.0.0.1:5001](http://127.0.0.1:5001) in your browser.

---

## ☁️ Deployment

### Render Deployment
This repository is configured for zero-downtime deployment on Render via `render.yaml`:
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `gunicorn -c gunicorn.conf.py app:app`
- **Environment Variables:**
  - `SECRET_KEY`: Random 64-character secret
  - `DATABASE_URL`: Neon PostgreSQL connection string
  - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`: (Optional) for email resets

---

## 👨‍💻 Project Information
- **Project:** SecureSync – Multi Detection System
- **Authors:** SecureSync Cyber Defense Team
- **Repository:** [https://github.com/PSYCHQ25/SecureSync.git](https://github.com/PSYCHQ25/SecureSync.git)
- **License:** MIT / Academic Cybersecurity Research
