# 🛡️ SecureSync – SMS/WhatsApp Scam Detection System

**SecureSync** is an educational, beginner-friendly cybersecurity project designed for first-year college students and security enthusiasts. It combines **Natural Language Processing (NLP)**, **Machine Learning (Scikit-Learn)**, and **Heuristic Threat Indicators** to inspect SMS and WhatsApp-style messages and classify them as either **"Legitimate"** or **"Suspicious/Scam"**.

---

## 🎯 Project Goal

With the rapid proliferation of smishing (SMS phishing), WhatsApp impersonation scams, and credential theft, everyday mobile users are heavily targeted by social engineering attacks. 

The goal of **SecureSync** is to:
1. Provide a clean, modern **Security Operations Center (SOC)**-style dashboard for scanning suspicious messages.
2. Accurately detect social engineering indicators (urgent money requests, fake lotteries, credential/OTP theft, shortened URLs, and intimidation tactics).
3. Safely quarantine and defang all hyperlinks so users and security analysts never execute malicious links.
4. Explain in clear, plain English **why** a message was flagged as suspicious.
5. Teach cybersecurity and computer science students how end-to-end machine learning pipelines operate in threat detection.

---

## 🔄 Core Workflow

```
[ Data Collection ]
       │
       ▼
[ Data Preprocessing ]  --> Lowercasing, noise cleaning, URL/currency tokenization
       │
       ▼
[ NLP Feature Extraction ]  --> TF-IDF Vectorizer (Unigrams & Bigrams)
       │
       ▼
[ Model Training ]  --> Logistic Regression (Calibrated Sigmoidal Probabilities)
       │
       ▼
[ Model Testing ]  --> Evaluated on unseen 20% test split (Accuracy, Precision, Recall, F1)
       │
       ▼
[ Scam Detection ]  --> Hybrid Engine (ML Probability + 7 Heuristic Scam Indicators)
       │
       ▼
[ User Alert ]  --> Real-time Dashboard with Warning Banners, Confidence Meter & Link Quarantine
```

---

## 🧠 Machine Learning & NLP Concepts Explained Simply

### 1. What is TF-IDF?
Computers cannot understand raw English words directly; they only understand numbers.
- **Term Frequency (TF)**: Measures how frequently a word appears in a message. For example, if the word `"urgent"` appears multiple times, its TF score increases.
- **Inverse Document Frequency (IDF)**: Measures how rare or informative a word is across the *entire* dataset. Common words like `"the"`, `"is"`, or `"at"` appear everywhere and receive very low IDF weights. Rare words strongly linked to fraud (such as `"warrant"`, `"deactivated"`, or `"winner"`) receive high IDF weights.
- **N-Grams (1, 2)**: SecureSync looks at single words (unigrams, e.g., `"transfer"`) as well as word pairs (bigrams, e.g., `"urgent transfer"`, `"arrest warrant"`) to capture contextual intent.

### 2. Why Logistic Regression?
Logistic Regression is an industry standard for binary classification (0 = Legitimate, 1 = Scam). It computes a weighted sum of the input TF-IDF features and applies the **Sigmoid function** to output a calibrated probability between 0% and 100%:

$$\sigma(z) = \frac{1}{1 + e^{-z}}$$

This makes it easy to explain to users: "The model is 94.2% confident that this pattern represents a scam."

### 3. Understanding Evaluation Metrics in Cybersecurity
When evaluating a security model, accuracy alone is not enough:
- **Accuracy (95.65%)**: The percentage of all test messages classified correctly.
- **Precision (91.67%)**: When SecureSync flags an alert, how often is it truly a scam? High precision avoids "alert fatigue" (we don't want real family chats or real bank alerts blocked as scams).
- **Recall (100.0%)**: Out of all actual scams, how many did the system catch? In cybersecurity, **Recall is the most critical metric** because a False Negative means a phishing attack slips through to the user's phone!
- **F1-Score (95.65%)**: The harmonic mean balancing Precision and Recall.

---

## 🚨 The 10 Scam Indicators Detected

In addition to statistical machine learning, SecureSync includes a heuristic rule engine that flags 10 common social engineering vectors:

| Indicator | Common Attack Signatures | Explanation for Students |
|---|---|---|
| **1. Urgent Money Requests** | `"urgently need"`, `"wire money"`, `"zelle"`, `"cashapp"`, `"fell in water"` | Attackers impersonate family members in fake emergencies or claim payments are due immediately. |
| **2. Fake Prizes & Rewards** | `"congratulations"`, `"winner"`, `"jackpot"`, `"$50,000 voucher"`, `"claim prize"` | Lures victims into paying fake "processing fees" or providing banking credentials. |
| **3. OTP / Password Harvesting** | `"enter OTP"`, `"verification code"`, `"share this code"`, `"password"`, `"ssn"` | Direct credential theft. Legitimate banks state that they will **never** ask for your OTP. |
| **4. Phishing Links** | Brand spoofing (`chase-verify-portal.net`), high-risk TLDs (`.xyz`, `.top`), raw IP links | Directs victims to fake clone websites designed to harvest logins and credit card details. |
| **5. Fake Banking / Account Alerts** | `"account suspended"`, `"debit card deactivated"`, `"unauthorized access"` | Uses manufactured panic to force immediate action before the user can verify. |
| **6. Suspicious Shortened URLs** | `bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, `cutt.ly` | Attackers hide the true malicious destination hostname behind URL shorteners. |
| **7. Coercive / Legal Pressure** | `"arrest warrant"`, `"sheriff"`, `"lawsuit"`, `"asset seizure"`, `"final notice"` | Intimidation tactics designed to frighten victims into immediate financial compliance. |
| **8. Delivery & Postal Impersonation** | `"package could not be delivered"`, `"redelivery fee"`, `"incomplete address"`, `"customs clearance"` | Impersonates couriers (USPS, FedEx, DHL, UPS) to harvest credit card details for tiny "redelivery fees". |
| **9. Job Offer & Crypto Investment Fraud** | `"earn $500 daily"`, `"rating assistant"`, `"guaranteed profit"`, `"crypto VIP"`, `"sugar daddy"` | Uses advance-fee fraud and pyramid schemes targeting students seeking part-time income. |
| **10. Utility & Service Disconnection** | `"power supply disconnected"`, `"SIM card deactivated"`, `"KYC non-compliance"`, `"storage full"` | Threatens cutoff of basic utilities to induce irrational urgency and immediate compliance. |

---

## 🔒 Safe Link Handling Policy

> [!IMPORTANT]
> **Zero-Execution Sandbox:** SecureSync extracts web addresses for domain analysis but **never** sends automated web requests to, resolves, or executes links found in messages.
> 
> Furthermore, all URLs displayed on the user interface are **defanged**:
> - `http://` is rewritten as `hxxp://`
> - `https://` is rewritten as `hxxps://`
> - Domain dots are escaped (e.g. `bit[.]ly`)
> - Hyperlinks are disabled to prevent accidental clicks.

---

## 📁 Project Structure

```
SecureSync/
├── app.py                     # Flask web server, auth sessions & REST API endpoints
├── database.py                # Multi-tenant PostgreSQL / SQLite manager & PBKDF2 hashing
├── database.db                # SQLite database with user isolation & scan audit logs
├── train_model.py             # Multi-model benchmarking (5 ML algorithms) with zero test leakage
├── predict.py                 # Core inference, 10 heuristic indicator matching & link defanging
├── test_pipeline.py           # Comprehensive 21-test automated suite (100% pass)
├── dataset/
│   └── messages.csv           # Curated balanced dataset of 110+ SMS & WhatsApp messages
├── model/
│   ├── scam_model.pkl         # Serialized Scikit-Learn pipeline (TF-IDF + Logistic Regression)
│   └── metrics.json           # Benchmark metrics comparing all 5 algorithms & confusion matrix
├── templates/
│   ├── home.html              # Modern cybersecurity SaaS landing page
│   ├── dashboard.html         # SOC threat console, bulk inspector & architecture education
│   ├── login.html             # User authentication gateway (Username / Email)
│   ├── register.html          # Registration with salted PBKDF2:SHA-256 hashing
│   ├── account.html           # User profile & credentials management
│   ├── forgot_password.html   # Password recovery request
│   └── reset_password.html    # Secure token-based password reset
├── static/
│   ├── style.css              # Dark-mode cybersecurity CSS with glassmorphism & neon accents
│   └── script.js              # Real-time scan interactions, bulk chat parser & history modal
├── requirements.txt           # Project dependencies
├── run.sh                     # One-click startup script
├── Dockerfile                 # Containerized deployment specification
├── render.yaml                # Render cloud deployment config
└── README.md                  # Complete documentation and student guide
```

---

## 🚀 Installation & Setup Guide

### 1. Prerequisites
- Python 3.9+ (Python 3.10, 3.11, 3.12, 3.13, 3.14 supported)
- Terminal / Command Line access

### 2. Create and Activate a Virtual Environment
Navigate to the `SecureSync` project directory in your terminal:

```bash
cd /Users/akarshnsharma/.gemini/antigravity/scratch/SecureSync
```

Create a virtual environment:
```bash
python3 -m venv venv
```

Activate the virtual environment:
- **macOS / Linux:**
  ```bash
  source venv/bin/activate
  ```
- **Windows:**
  ```cmd
  venv\Scripts\activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Train the Model
Train the machine learning pipeline on the balanced dataset:
```bash
python train_model.py
```
*You will see the step-by-step training output, candidate comparison, precision/recall metrics, and confirmation that `model/scam_model.pkl` was generated.*

### 5. Launch the Web Application
Start the Flask cybersecurity dashboard:
```bash
python app.py
```

Open your web browser and navigate to:
```
http://127.0.0.1:5001
```

---

## 🧪 Testing with Sample Messages

You can use the built-in preset buttons in the dashboard, or test messages from your terminal using `predict.py`.

### 🚨 Scam Test Messages

#### Sample 1: Banking Phishing
```text
Dear customer, your Chase bank account has been temporarily restricted due to suspicious login attempts. Verify your identity immediately at http://bit.ly/chase-verify-now to avoid permanent closure.
```
- **Expected Classification:** `Suspicious/Scam`
- **Detected Indicators:** Shortened URL, Deceptive Banking Alert, High Threat Score.

#### Sample 2: WhatsApp Family Impersonation ("Hi Mom")
```text
Hi Mom, my phone fell in the water and this is my temporary WhatsApp number. My bank app is not working and I urgently need $450 to pay for car towing. Can you send it via Zelle right now?
```
- **Expected Classification:** `Suspicious/Scam`
- **Detected Indicators:** Urgent Money Request, Social Engineering Impersonation.

#### Sample 3: Prize Scam
```text
CONGRATULATIONS! You have been selected as the official winner of a $50,000 Walmart cash gift card. Claim your exclusive prize code at http://win-walmart-voucher.com before midnight!
```
- **Expected Classification:** `Suspicious/Scam`
- **Detected Indicators:** Fake Prize or Reward, Unsolicited Lottery.

#### Sample 4: Arrest & Law Enforcement Threat
```text
INTERNAL REVENUE SERVICE: A formal lawsuit has been registered under your Social Security Number. Call our legal division immediately at 1-888-555-0199 or local sheriff will execute arrest warrant.
```
- **Expected Classification:** `Suspicious/Scam`
- **Detected Indicators:** Coercive / Threatening Language, False Authority.

---

### ✔️ Legitimate Test Messages

#### Sample 5: Genuine Bank 2FA Code
```text
Your Chase verification code is 492019. Valid for 10 minutes. Chase will never call or text you asking for this code. Do not share it with anyone.
```
- **Expected Classification:** `Legitimate`
- **Reasons:** Contains standard security advice instructing recipient never to share codes; no fraudulent URLs.

#### Sample 6: Casual Everyday Chat
```text
Hey, are we still meeting for lunch at 12:30 today? I'm heading towards the campus dining hall now.
```
- **Expected Classification:** `Legitimate`
- **Reasons:** Natural conversational cadence; zero scam indicators detected.

#### Sample 7: Official Debit Card Purchase Notice
```text
Bank of America: A purchase of $18.42 was made at Starbucks with your debit card ending in 4102. If authorized, no action is needed.
```
- **Expected Classification:** `Legitimate`
- **Reasons:** Standard notification phrasing; states "no action is needed", unlike phishing alerts which demand urgent clicks.

---

## 💻 Testing via Terminal CLI

You can also run instant command-line scans without opening a browser:

```bash
python predict.py "URGENT: Your Wells Fargo debit card is deactivated. Update credentials at http://bit.ly/wf-login immediately."
```

```bash
python predict.py "Hey, don't forget our presentation for cybersecurity class is due this Thursday."
```

---

## ⚠️ System Limitations & Ethical Considerations

1. **Probabilistic Nature of Machine Learning:**
   Machine learning models compute statistical likelihoods based on trained patterns. A classification of `"Legitimate"` **does not guarantee 100% safety**. Novel scam formats that look entirely conversational may occasionally bypass the filter.
2. **Adversarial Evasion:**
   Real-world cybercriminals continuously evolve their tactics. They may use intentional typos, leetspeak (`"w1nner"`, `"cl!ck"`), zero-width unicode spaces, or image-based messages (QR codes) to evade text-based NLP filters.
3. **Defense-in-Depth Principle:**
   Automated scam filters should always be viewed as one layer of a broader defense-in-depth strategy. Users must always combine automated tools with **out-of-band verification** (e.g. calling their bank using the official phone number on the back of their physical card).
4. **Privacy & Data Ethics:**
   The training dataset contains exclusively synthetic and generalized educational templates. It contains **no private messages or real personal information** from real individuals.

---

## 👨‍💻 Author & Acknowledgements
- **Project:** SecureSync – SMS/WhatsApp Scam Detection System
- **Intended Audience:** First-Year Undergraduate Cybersecurity & Computer Science Students
- **Technologies:** Python 3, Flask, Scikit-Learn, Pandas, NumPy, HTML5, CSS3, Vanilla JS
