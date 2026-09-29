# 🎓 Academic Project Report: SecureSync – SMS/WhatsApp Scam Detection System

**Course:** Introduction to Cybersecurity / Applied Machine Learning  
**Project Title:** SecureSync: A Hybrid Machine Learning and Heuristic Scam Detection System for Mobile Messaging Platforms  
**Target Domain:** Mobile Security, Social Engineering Mitigation, Natural Language Processing  

---

## 1. Abstract

Mobile communication platforms like SMS and WhatsApp have become the primary vectors for financial fraud, credential theft, and social engineering attacks (commonly termed *smishing* and *WhatsApp impersonation*). Traditional signature-based security mechanisms fail against dynamic, socially engineered messages that employ artificial urgency, psychological pressure, and obfuscated URLs. 

This project presents **SecureSync**, an intelligent scam detection system designed for mobile messaging ecosystems. SecureSync implements a **hybrid architecture** combining statistical Natural Language Processing (NLP via TF-IDF with unigrams and bigrams) and supervised Machine Learning (Logistic Regression) with a deterministic heuristic indicator engine. The system achieves **95.65% classification accuracy** and **100% scam recall** on an unseen test dataset of mobile messages. To safeguard end-users and analysts, SecureSync includes a **zero-execution link quarantining subsystem** that defangs malicious URLs (`hxxp://`) and provides plain-English threat explainability through a cybersecurity-style Security Operations Center (SOC) dashboard.

---

## 2. Introduction & Problem Statement

### 2.1 The Rising Threat of Mobile Scams
Unlike traditional email spam, SMS and WhatsApp messages enjoy open rates exceeding 95%, with most recipients reading incoming messages within three minutes of delivery. Threat actors exploit this inherent user trust through several primary vectors:
- **Urgent Financial Impersonation:** Pretending to be family members in distress ("Hi Mom, my phone is broken, send money via Zelle").
- **Account Suspension Phishing:** Impersonating trusted banking institutions with fraudulent urgency ("Your account is locked; verify immediately").
- **Credential & 2FA Harvesting:** Coercing users into disclosing one-time passcodes (OTPs) under the guise of security verifications.
- **Advance-Fee / Lottery Scams:** Promising substantial prizes or lottery vouchers conditioned upon upfront processing fees.

### 2.2 Shortcomings of Existing Solutions
- **Pure Rule-Based Regex Filters:** Highly brittle; easily bypassed by minor character substitutions (e.g. `"w1nner"`, `"cl!ck"`).
- **Pure "Black-Box" Deep Learning:** Computationally expensive for client-side/edge deployment, prone to hallucination, and critically lacking in **explainability**—failing to inform the user *why* a message is hazardous.

### 2.3 Proposed Solution
SecureSync addresses these challenges through a lightweight, interpretable, hybrid pipeline:
1. **Statistical NLP:** Converts arbitrary text into numerical feature representations using Term Frequency-Inverse Document Frequency (TF-IDF).
2. **Supervised Classifier:** Applies a calibrated Logistic Regression model to compute probabilistic risk.
3. **Deterministic Heuristic Engine:** Extracts contextual indicators (urgency, prize claims, OTP requests, shortened URLs, brand impersonation).
4. **Interactive SOC Dashboard:** Displays real-time metrics, risk severity, defanged links, and plain-English threat rationale.

---

## 3. System Architecture & Workflow

The SecureSync processing pipeline follows a 7-stage workflow:

```
[ Incoming Message ] 
       │
       ▼
[ Stage 1: Data Preprocessing ]  --> Case normalization, regex entity tagging (<URL>, <PHONE>, <CURRENCY>)
       │
       ▼
[ Stage 2: Feature Extraction ]  --> TF-IDF Vectorization (Unigrams + Bigrams, Sublinear Scaling)
       │
       ▼
[ Stage 3: Supervised Inference ]  --> Logistic Regression computes class probability P(Scam|X)
       │
       ▼
[ Stage 4: Heuristic Matching ]  --> Rule engine scans for 7 social engineering signatures
       │
       ▼
[ Stage 5: Link Quarantine ]  --> URLs extracted, domains inspected, defanged (hxxp://)
       │
       ▼
[ Stage 6: Decision Aggregation ]  --> Hybrid thresholding computes final Risk Level & Confidence
       │
       ▼
[ Stage 7: Alert & Dashboard ]  --> Web UI presents Warning Banner, Confidence Meter & Reasons
```

---

## 4. Mathematical Methodology

### 4.1 Term Frequency - Inverse Document Frequency (TF-IDF)
Raw text strings cannot be processed directly by numerical algorithms. TF-IDF reflects how important a word is to a document within a collection:

$$\text{TF}(t, d) = \frac{f_{t,d}}{\sum_{t' \in d} f_{t',d}}$$

$$\text{IDF}(t, D) = \log\left(\frac{1 + |D|}{1 + |\{d \in D : t \in d\}|}\right) + 1$$

$$\text{TF-IDF}(t, d, D) = \text{TF}(t, d) \times \text{IDF}(t, D)$$

By including **bigrams** ($n=2$), the model captures semantic pairs such as `"urgent transfer"` and `"arrest warrant"`, differentiating them from neutral occurrences of the individual words.

### 4.2 Supervised Classification via Logistic Regression
Logistic Regression models the probability that an incoming message vector $\mathbf{x}$ belongs to the malicious class ($y = 1$):

$$P(y = 1 \mid \mathbf{x}) = \sigma(\mathbf{w}^T \mathbf{x} + b) = \frac{1}{1 + e^{-(\mathbf{w}^T \mathbf{x} + b)}}$$

Where:
- $\mathbf{w}$ is the learned weight vector for each TF-IDF feature.
- $b$ is the bias term.
- $\sigma(z)$ is the sigmoidal activation function bounding outputs between $0.0$ and $1.0$.

---

## 5. Experimental Dataset & Results

### 5.1 Dataset Composition
A balanced dataset of 111 real-world representative mobile messages was compiled:
- **Legitimate (Class 0):** 56 samples (genuine 2FA notifications with security advice, daily personal chats, package delivery confirmations, flight schedules).
- **Scam / Suspicious (Class 1):** 55 samples (bank suspensions, fake lottery rewards, delivery fee scams, IRS warrants, WhatsApp family emergencies).

### 5.2 Multi-Algorithm Benchmark Comparison on Unseen Test Split (20%)

To determine the optimal classification engine without data leakage, five distinct supervised classification algorithms were trained within an encapsulated scikit-learn Pipeline and evaluated using both 5-fold stratified cross-validation on the training set and rigorous evaluation on the unseen test partition:

| Classification Model | Test Accuracy | Precision | Test Recall | F1-Score | 5-Fold Stratified CV F1 | Selection Status |
|---|---|---|---|---|---|---|
| **Logistic Regression (Champion)** | **95.65%** | **91.67%** | **100.00%** | **95.65%** | **92.82%** | **★ Selected Champion** |
| **Linear Support Vector (Calibrated)** | 95.65% | 91.67% | 100.00% | 95.65% | 91.65% | Candidate Baseline |
| **Multinomial Naive Bayes** | 91.30% | 84.62% | 100.00% | 91.67% | 90.71% | High-Speed Baseline |
| **Random Forest Classifier** | 91.30% | 100.00% | 81.82% | 90.00% | 88.29% | Ensemble Candidate |
| **Decision Tree Classifier** | 91.30% | 100.00% | 81.82% | 90.00% | 79.14% | Interpretable Tree |

> [!IMPORTANT]
> **Why Recall is Prioritized in Cybersecurity:**
> - In cybersecurity, **False Negatives (missed phishing attacks) are catastrophic**, leading to credential theft and financial losses.
> - Logistic Regression and Linear SVM both achieved **100.00% Recall** with 0 false negatives on the test partition.
> - Logistic Regression was selected as the **Champion Model** due to its superior 5-Fold Cross-Validation score (**92.82%** vs 91.65%) and well-calibrated sigmoid posterior probabilities.

### 5.3 Confusion Matrix (Champion Model)
$$\begin{pmatrix} 
TN = 11 & FP = 1 \\ 
FN = 0 & TP = 11 
\end{pmatrix}$$

- **True Negatives ($TN = 11$):** Legitimate messages correctly identified as safe.
- **False Positives ($FP = 1$):** Legitimate message flagged due to cautionary security terminology.
- **False Negatives ($FN = 0$):** Zero phishing/scam messages evaded the system (100% Recall).
- **True Positives ($TP = 11$):** All malicious messages in test partition accurately detected.

---

## 6. Heuristic Explainability & Zero-Trust Link Quarantining

To bridge the gap between machine learning output and end-user comprehension, SecureSync integrates:
1. **10 Social Engineering Threat Indicators:**
   - **1. Urgent Money Requests:** Emergency funds, Zelle/CashApp, fake family crisis ("phone fell in water").
   - **2. Fake Prizes & Rewards:** Unsolicited lottery winnings, $50,000 vouchers, gift card bait.
   - **3. Credential & OTP Harvesting:** Requests for 6-digit OTP, passwords, SSN, PIN (with built-in exception for legitimate bank "never share" advice).
   - **4. Deceptive Phishing URLs:** Brand spoofing (`chase-verify.xyz`), high-risk TLDs, raw IP destinations.
   - **5. Fake Banking & Account Alerts:** Manufactured panic claiming accounts locked or cards deactivated.
   - **6. Shortened / Obfuscated Links:** Disguised endpoints hiding real destinations behind `bit.ly`, `tinyurl.com`, `t.co`.
   - **7. Coercive Legal Pressure:** Intimidation claiming arrest warrants, lawsuits, or sheriff asset seizure.
   - **8. Delivery & Postal Impersonation:** Fake courier alerts (USPS, FedEx, DHL, UPS) requesting address redelivery fees.
   - **9. Job Offer & Crypto Investment Fraud:** Unrealistic work-from-home salaries, fake task ratings, and guaranteed crypto returns.
   - **10. Utility & Service Disconnection Threats:** Manufactured deadlines threatening immediate electricity or cellular SIM termination.
2. **Safe Link Quarantining Policy:**
   - External links are **never clicked, resolved, or requested** by the backend.
   - Protocols and dots are defanged (`http://` $\rightarrow$ `hxxp://`, `.` $\rightarrow$ `[.]`).
   - Hyperlinks are disabled in the web DOM to prevent accidental click-throughs.
3. **Automated Verification:**
   - Complete 21-test automated suite (`test_pipeline.py`) validating zero data leakage, text normalization, heuristic triggers, tenant isolation, and REST APIs with 100% pass rate.

---

## 7. System Limitations & Future Scope

### 7.1 Limitations
- **Adversarial Typography:** Intentional character substitutions (`"p@ssword"`, `"w1nner"`) can decrease n-gram similarity.
- **Image-Based Scams:** Phishing messages transmitted as images or QR codes (Quishing) require Optical Character Recognition (OCR).
- **Probabilistic Nature:** Statistical models cannot guarantee 100% infallibility on novel, previously unseen zero-day fraud templates.

### 7.2 Future Enhancements
- Integration of a lightweight Levenshtein distance preprocessor to defeat adversarial typosquatting.
- Expansion to multilingual support for regional phishing variants.
- On-device mobile deployment via TensorFlow Lite / ONNX runtime for Android and iOS.

---

## 8. Conclusion

SecureSync demonstrates that a hybrid architecture combining statistical machine learning with deterministic threat heuristics provides a powerful, interpretable, and lightweight defense against mobile social engineering. With 95.65% test accuracy, 100% recall on test scams, safe link defanging, and an accessible cybersecurity dashboard, the project fulfills all objectives for a robust, educational cybersecurity system.
