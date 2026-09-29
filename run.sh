#!/usr/bin/env bash
# =============================================================================
# SecureSync – One-Click Startup Script
# Automatically verifies environment, model training, and launches dashboard
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "  🛡️  SecureSync – SMS/WhatsApp Scam Detection System"
echo "======================================================================"

# 1. Determine Python binary
if [ -d "venv" ] && [ -f "venv/bin/python" ]; then
    PYTHON_CMD="./venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
else
    echo "[-] Error: Python 3 not found. Please install Python 3."
    exit 1
fi

echo "[*] Using Python: $($PYTHON_CMD --version)"

# 2. Check if model is trained
if [ ! -f "model/scam_model.pkl" ]; then
    echo "[*] Model artifact not found. Starting training pipeline..."
    $PYTHON_CMD train_model.py
else
    echo "[+] Trained model artifact found: model/scam_model.pkl"
fi

# 3. Launch Flask application
echo "[*] Launching SecureSync dashboard on http://127.0.0.1:5001 ..."
echo "[*] Press Ctrl + C to stop the server at any time."
echo "======================================================================"

$PYTHON_CMD app.py
