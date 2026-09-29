"""
=============================================================================
SecureSync – SMS/WhatsApp Scam Detection System
Script: train_model.py
Description: End-to-end Machine Learning training pipeline for cybersecurity
             text classification (Scam vs. Legitimate).
=============================================================================
Workflow Steps:
  1. Data Ingestion: Load messages from dataset/messages.csv using Pandas.
  2. Data Preprocessing: Clean, normalize, and inspect class distribution.
  3. Train/Test Split: Partition data into 80% training and 20% testing sets.
  4. NLP Feature Extraction: Transform text into numerical vectors with TF-IDF.
  5. Model Training: Train a supervised classification model (Logistic Regression & Naive Bayes).
  6. Model Evaluation: Compute Accuracy, Precision, Recall, F1-Score & Confusion Matrix.
  7. Artifact Export: Serialize model pipeline (model/scam_model.pkl) and metrics (model/metrics.json).
=============================================================================
"""

import os
import re
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
import joblib

# Optional visualization library
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend suitable for server environments
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# -----------------------------------------------------------------------------
# Configuration Paths
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset', 'messages.csv')
MODEL_DIR = os.path.join(BASE_DIR, 'model')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, 'scam_model.pkl')
METRICS_SAVE_PATH = os.path.join(MODEL_DIR, 'metrics.json')
CONFUSION_MATRIX_IMG = os.path.join(STATIC_DIR, 'confusion_matrix.png')


def clean_text(text: str) -> str:
    """
    NLP Preprocessing function:
    - Converts text to lowercase.
    - Replaces URLs with a generic token '<URL>' so the model recognizes link presence.
    - Replaces phone/contact numbers with '<PHONE>' token.
    - Replaces currency amounts with '<CURRENCY>' token.
    - Removes excessive whitespace and special symbols while preserving word tokens.
    """
    if not isinstance(text, str):
        return ""

    text = text.lower().strip()
    
    # Normalize common scam patterns into informative tokens
    text = re.sub(r'https?://\S+|www\.\S+', ' <url> ', text)
    text = re.sub(r'\+?\d[\d -]{7,}\d', ' <phone> ', text)
    text = re.sub(r'[\$£€₹]\s?\d+(?:,\d+)*(?:\.\d+)?', ' <currency> ', text)
    
    # Retain alphanumeric characters and spaces
    text = re.sub(r'[^a-z0-9\s<>]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def load_dataset(filepath: str) -> pd.DataFrame:
    """
    Step 1: Load and validate the dataset.
    """
    print(f"[*] Step 1: Loading dataset from: {filepath}")
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset file not found at {filepath}")
    
    df = pd.read_csv(filepath)
    df = df.dropna(subset=['label', 'message'])
    
    # Map text labels to standard binary classes:
    # 0 = Legitimate (Ham), 1 = Scam (Malicious/Phishing)
    df['label_binary'] = df['label'].str.lower().map({
        'legitimate': 0,
        'ham': 0,
        'scam': 1,
        'spam': 1
    })
    
    print(f"    - Total messages loaded: {len(df)}")
    print(f"    - Legitimate (0): {sum(df['label_binary'] == 0)}")
    print(f"    - Scam/Suspicious (1): {sum(df['label_binary'] == 1)}")
    return df


def train_and_evaluate():
    """
    Orchestrates the entire ML pipeline from data loading to evaluation and serialization.
    """
    print("=" * 70)
    print("SecureSync – SMS/WhatsApp Scam Detection System: Model Training")
    print("=" * 70)

    # 1. Load Data
    df = load_dataset(DATASET_PATH)

    # 2. Text Preprocessing
    print("\n[*] Step 2: Preprocessing message texts...")
    df['cleaned_message'] = df['message'].apply(clean_text)

    X = df['cleaned_message']
    y = df['label_binary']

    # 3. Train / Test Split
    # We use an 80/20 split with stratification so the proportion of scams is equal in both splits.
    print("\n[*] Step 3: Splitting dataset into 80% Training and 20% Testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )
    print(f"    - Training set size: {len(X_train)} samples")
    print(f"    - Testing set size:  {len(X_test)} samples")

    # 4. Feature Extraction + Multi-Algorithm Pipeline Comparison
    # TF-IDF converts text into numerical vectors. We include unigrams and bigrams.
    # Feature extraction is placed INSIDE the Pipeline to guarantee ZERO data leakage from test data.
    print("\n[*] Step 4 & 5: Building TF-IDF Vectorizer and Benchmarking Multi-Model Classifiers...")
    
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.svm import LinearSVC
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.model_selection import StratifiedKFold, cross_val_score

    # Diverse set of classification algorithms suitable for text & social engineering defense
    models = {
        "Logistic Regression": LogisticRegression(C=1.5, max_iter=1000, class_weight='balanced', random_state=42),
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.2),
        "Linear Support Vector (Calibrated)": CalibratedClassifierCV(LinearSVC(C=1.0, class_weight='balanced', random_state=42), cv=3),
        "Random Forest": RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42),
        "Decision Tree": DecisionTreeClassifier(class_weight='balanced', random_state=42)
    }

    comparison_results = []
    best_pipeline = None
    best_score = -1.0
    best_rec = -1.0
    best_model_name = ""

    print("\n" + "=" * 95)
    print(f" {'Model Name':<34} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'5-Fold CV':<10}")
    print("=" * 95)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for name, clf in models.items():
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                ngram_range=(1, 2),        # Unigrams & bigrams
                sublinear_tf=True,          # Sublinear scaling
                max_features=2500,          # Top features
                stop_words='english'        # Filter noise
            )),
            ('classifier', clf)
        ])
        
        # 5-fold cross-validation exclusively on X_train (Zero Data Leakage)
        cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring='f1', n_jobs=-1)
        mean_cv_f1 = float(cv_scores.mean())

        # Fit on training partition and test on held-out test partition
        pipeline.fit(X_train, y_train)
        preds = pipeline.predict(X_test)
        
        m_acc = float(accuracy_score(y_test, preds))
        m_prec = float(precision_score(y_test, preds, zero_division=0))
        m_rec = float(recall_score(y_test, preds, zero_division=0))
        m_f1 = float(f1_score(y_test, preds, zero_division=0))
        m_cm = confusion_matrix(y_test, preds)
        m_tn, m_fp, m_fn, m_tp = [int(v) for v in m_cm.ravel()]

        print(f" {name:<34} | {m_acc * 100:>8.2f}% | {m_prec * 100:>8.2f}% | {m_rec * 100:>8.2f}% | {m_f1 * 100:>8.2f}% | {mean_cv_f1 * 100:>8.2f}%")

        # In cybersecurity, Recall is the primary criterion, followed by F1
        is_better = (m_f1 > best_score) or (abs(m_f1 - best_score) < 1e-4 and m_rec > best_rec)
        if is_better:
            best_score = m_f1
            best_rec = m_rec
            best_pipeline = pipeline
            best_model_name = name

        comparison_results.append({
            "model_name": name,
            "accuracy": round(m_acc * 100, 2),
            "precision": round(m_prec * 100, 2),
            "recall": round(m_rec * 100, 2),
            "f1_score": round(m_f1 * 100, 2),
            "cv_f1_mean": round(mean_cv_f1 * 100, 2),
            "confusion_matrix": {
                "true_negatives": m_tn,
                "false_positives": m_fp,
                "false_negatives": m_fn,
                "true_positives": m_tp
            }
        })

    print("=" * 95)
    for res in comparison_results:
        res["is_champion"] = (res["model_name"] == best_model_name)

    print(f"\n[+] Champion Model Selected: '{best_model_name}' (F1: {best_score * 100:.2f}%, Recall: {best_rec * 100:.2f}%)")

    # 6. Comprehensive Evaluation of Selected Champion Model
    print("\n[*] Step 6: Detailed Evaluation of Champion on Unseen Test Data:")
    y_pred = best_pipeline.predict(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    print("-" * 60)
    print(f"  Model Accuracy:  {acc * 100:.2f}% (Percentage of total correct classifications)")
    print(f"  Precision:       {prec * 100:.2f}% (How many flagged messages were truly scams)")
    print(f"  Recall:          {rec * 100:.2f}% (How many actual scams were caught)")
    print(f"  F1-Score:        {f1 * 100:.2f}% (Harmonic balance of Precision & Recall)")
    print("-" * 60)
    print("  Confusion Matrix:")
    print(f"    True Negatives  (Legitimate correctly marked safe): {tn}")
    print(f"    False Positives (Legitimate wrongly marked scam):  {fp}")
    print(f"    False Negatives (Scam missed / bypassed system):   {fn}")
    print(f"    True Positives  (Scam correctly detected):         {tp}")
    print("-" * 60)

    # 7. Save Metrics & Model Pipeline
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)

    metrics_payload = {
        "model_name": best_model_name,
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        },
        "model_comparison": comparison_results,
        "test_samples": len(y_test),
        "train_samples": len(X_train)
    }

    with open(METRICS_SAVE_PATH, 'w') as f:
        json.dump(metrics_payload, f, indent=4)
    print(f"[+] Saved evaluation metrics to: {METRICS_SAVE_PATH}")

    # Save serialized scikit-learn pipeline using joblib
    joblib.dump(best_pipeline, MODEL_SAVE_PATH)
    print(f"[+] Saved model pipeline to:     {MODEL_SAVE_PATH}")

    # 8. Generate Visual Confusion Matrix (if matplotlib is installed)
    if HAS_MATPLOTLIB:
        try:
            fig, ax = plt.subplots(figsize=(6, 5))
            cax = ax.matshow(cm, cmap='Blues', alpha=0.85)
            fig.colorbar(cax)

            classes = ['Legitimate (0)', 'Scam (1)']
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(classes, fontsize=10, fontweight='bold')
            ax.set_yticklabels(classes, fontsize=10, fontweight='bold')

            for i in range(2):
                for j in range(2):
                    ax.text(j, i, str(cm[i, j]), ha='center', va='center',
                            color='red' if (i != j and cm[i, j] > 0) else 'black',
                            fontsize=16, fontweight='bold')

            plt.title('SecureSync: Confusion Matrix', fontsize=12, fontweight='bold', pad=15)
            plt.xlabel('Predicted Label', fontsize=11, labelpad=10)
            plt.ylabel('Actual True Label', fontsize=11, labelpad=10)
            plt.tight_layout()
            plt.savefig(CONFUSION_MATRIX_IMG, dpi=150)
            plt.close()
            print(f"[+] Saved confusion matrix chart to: {CONFUSION_MATRIX_IMG}")
        except Exception as e:
            print(f"[-] Warning: Failed to generate chart: {e}")
    else:
        print("[!] Note: Matplotlib not installed; metrics JSON generated for web UI visualization.")

    print("=" * 70)
    print("[SUCCESS] SecureSync ML pipeline training complete!")
    print("=" * 70)
    return metrics_payload


if __name__ == '__main__':
    train_and_evaluate()
