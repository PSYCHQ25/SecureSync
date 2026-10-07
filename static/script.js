/**
 * =============================================================================
 * SecureSync – Multi Detection System
 * File: static/script.js
 * Description: Client-side engine orchestrating multi-modal threat analysis
 *              (Text, Image, Audio, Video), live statistics, PDF report dispatch,
 *              audit history filtering, and real-time forensic visualizations.
 * =============================================================================
 */

document.addEventListener('DOMContentLoaded', () => {
    // -------------------------------------------------------------------------
    // DOM Elements - Text Mode
    // -------------------------------------------------------------------------
    const messageInput = document.getElementById('message-input');
    const charCountEl = document.getElementById('char-count');
    const wordCountEl = document.getElementById('word-count');
    const btnScan = document.getElementById('btn-scan');
    const btnClear = document.getElementById('btn-clear');
    const btnPaste = document.getElementById('btn-paste');
    const presetsContainer = document.getElementById('presets-pills');

    // -------------------------------------------------------------------------
    // DOM Elements - Media Files (Image, Audio, Video)
    // -------------------------------------------------------------------------
    const imageDropzone = document.getElementById('image-dropzone');
    const imageFileInput = document.getElementById('image-file-input');
    const imagePreviewBox = document.getElementById('image-preview-box');
    const imagePreviewThumb = document.getElementById('image-preview-thumb');
    const imagePreviewName = document.getElementById('image-preview-name');
    const imagePreviewSize = document.getElementById('image-preview-size');
    const btnScanImage = document.getElementById('btn-scan-image');
    const btnClearImage = document.getElementById('btn-clear-image');

    const audioDropzone = document.getElementById('audio-dropzone');
    const audioFileInput = document.getElementById('audio-file-input');
    const audioPreviewBox = document.getElementById('audio-preview-box');
    const audioPreviewPlayer = document.getElementById('audio-preview-player');
    const audioPreviewName = document.getElementById('audio-preview-name');
    const audioPreviewSize = document.getElementById('audio-preview-size');
    const btnScanAudio = document.getElementById('btn-scan-audio');
    const btnClearAudio = document.getElementById('btn-clear-audio');

    const videoDropzone = document.getElementById('video-dropzone');
    const videoFileInput = document.getElementById('video-file-input');
    const videoPreviewBox = document.getElementById('video-preview-box');
    const videoPreviewPlayer = document.getElementById('video-preview-player');
    const videoPreviewName = document.getElementById('video-preview-name');
    const videoPreviewSize = document.getElementById('video-preview-size');
    const btnScanVideo = document.getElementById('btn-scan-video');
    const btnClearVideo = document.getElementById('btn-clear-video');

    let currentSelectedImage = null;
    let currentSelectedAudio = null;
    let currentSelectedVideo = null;
    let lastAnalysisReport = null;

    // -------------------------------------------------------------------------
    // States & Output Panels
    // -------------------------------------------------------------------------
    const idleState = document.getElementById('idle-state');
    const loadingState = document.getElementById('loading-state');
    const loadingStatusText = document.getElementById('loading-status-text');
    const resultState = document.getElementById('result-state');

    // Stats
    const statTotalEl = document.getElementById('stat-total');
    const statScamEl = document.getElementById('stat-scam');
    const statLegitEl = document.getElementById('stat-legit');
    const statAccuracyEl = document.getElementById('stat-accuracy');

    // Result Header & Banners
    const resultModalityBadge = document.getElementById('result-modality-badge');
    const scanTimestampEl = document.getElementById('scan-timestamp');
    const scanIdText = document.getElementById('scan-id-text');
    const targetAssetName = document.getElementById('target-asset-name');
    const primaryBanner = document.getElementById('primary-banner');
    const bannerIcon = document.getElementById('banner-icon');
    const bannerHeading = document.getElementById('banner-heading');
    const bannerSubtext = document.getElementById('banner-subtext');

    // Metrics
    const resultClassification = document.getElementById('result-classification');
    const resultThreatCategory = document.getElementById('result-threat-category');
    const resultConfidence = document.getElementById('result-confidence');
    const confidenceBar = document.getElementById('confidence-bar');
    const resultRisk = document.getElementById('result-risk');
    const recommendedActionText = document.getElementById('recommended-action-text');
    const recommendedActionBox = document.getElementById('recommended-action-box');

    // Dynamic Sections
    const probabilitySection = document.getElementById('probability-section');
    const probRatioText = document.getElementById('prob-ratio-text');
    const probLegitBar = document.getElementById('prob-legit-bar');
    const probScamBar = document.getElementById('prob-scam-bar');

    const technicalForensicsGrid = document.getElementById('technical-forensics-grid');
    const indicatorsList = document.getElementById('indicators-list');
    const linksSection = document.getElementById('links-section');
    const linksContainer = document.getElementById('links-container');
    const reasonsList = document.getElementById('reasons-list');

    // Action Buttons
    const btnDownloadPdf = document.getElementById('btn-download-pdf');
    const btnExportJson = document.getElementById('btn-export-json');
    const btnCopyScanId = document.getElementById('btn-copy-scan-id');

    // Educational Section
    const toggleEduBtn = document.getElementById('toggle-edu-btn');
    const eduContent = document.getElementById('edu-content');

    // -------------------------------------------------------------------------
    // Error Toast Helper – replaces raw alert() for scan errors
    // -------------------------------------------------------------------------
    function showScanError(message, errorType) {
        // errorType: 'quota' | 'validation' | 'auth' | 'error'
        const existing = document.querySelector('.scan-error-toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = 'scan-error-toast';

        let icon = '⚠️';
        let title = 'Scan Error';
        let bgColor = 'var(--red-threat, #ff3366)';

        if (errorType === 'quota') {
            icon = '🔒';
            title = 'Daily Scan Limit Reached';
            bgColor = '#f59e0b';
        } else if (errorType === 'validation') {
            icon = '📄';
            title = 'Invalid File';
            bgColor = '#ef4444';
        } else if (errorType === 'auth') {
            icon = '🔑';
            title = 'Authentication Required';
        }

        toast.style.cssText = `
            position: fixed; top: 20px; right: 20px; z-index: 100000;
            max-width: 420px; padding: 16px 20px;
            background: ${bgColor}; color: #fff;
            border-radius: 10px; box-shadow: 0 8px 30px rgba(0,0,0,0.25);
            font-family: var(--font-body, sans-serif); font-size: 0.9rem;
            display: flex; align-items: flex-start; gap: 12px;
            animation: slideInRight 0.35s ease;
        `;

        toast.innerHTML = `
            <span style="font-size: 1.4rem; flex-shrink: 0;">${icon}</span>
            <div style="flex: 1;">
                <div style="font-weight: 700; margin-bottom: 4px;">${title}</div>
                <div style="opacity: 0.9; font-size: 0.84rem; line-height: 1.4;">${escapeHTML(message)}</div>
            </div>
            <button onclick="this.parentElement.remove()" style="background:none; border:none; color:#fff; font-size:1.2rem; cursor:pointer; padding:0; opacity:0.7;">&times;</button>
        `;

        document.body.appendChild(toast);
        setTimeout(() => { if (toast.parentElement) toast.remove(); }, 8000);
    }

    // -------------------------------------------------------------------------
    // 1. Initialization
    // -------------------------------------------------------------------------
    async function init() {
        await Promise.all([
            fetchStats(),
            fetchSamples()
        ]);
        updateCounters();
        setupModalityTabs();
        setupDragAndDrop();
        setupDemoSamples();
        setupHistoryModal();

        // Wire the Clear Results button in the report header
        const btnClearResults = document.getElementById('btn-clear-results');
        if (btnClearResults) {
            btnClearResults.addEventListener('click', resetResultState);
        }
    }

    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            if (data.status === 'success') {
                updateStatsUI(data.stats);
            }
        } catch (err) {
            console.warn('Could not fetch stats:', err);
        }
    }

    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics');
            const data = await res.json();
            if (data.status === 'success' && data.metrics) {
                const m = data.metrics;
                if (statAccuracyEl) statAccuracyEl.textContent = `${m.accuracy}%`;
            }
        } catch (err) {
            console.warn('Could not fetch metrics:', err);
        }
    }

    async function fetchSamples() {
        try {
            const res = await fetch('/api/samples');
            const data = await res.json();
            if (data.status === 'success' && Array.isArray(data.samples) && presetsContainer) {
                presetsContainer.innerHTML = '';
                data.samples.forEach(sample => {
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = `pill ${sample.label === 'Scam' ? 'pill-scam' : 'pill-legit'}`;
                    btn.textContent = `${sample.label === 'Scam' ? '🚨' : '✔'} ${sample.title}`;
                    btn.addEventListener('click', () => {
                        messageInput.value = sample.message;
                        updateCounters();
                        scanTextMessage();
                    });
                    presetsContainer.appendChild(btn);
                });
            }
        } catch (err) {
            console.warn('Could not fetch preset samples:', err);
        }
    }

    function updateStatsUI(stats) {
        if (!stats) return;
        if (statTotalEl) statTotalEl.textContent = stats.total_scanned ?? 0;
        if (statScamEl) statScamEl.textContent = stats.threats_detected ?? stats.suspicious_count ?? 0;
        if (statLegitEl) statLegitEl.textContent = stats.safe_verified ?? stats.legitimate_count ?? 0;
        if (statAccuracyEl && stats.model_accuracy) statAccuracyEl.textContent = `${stats.model_accuracy}%`;
    }

    // -------------------------------------------------------------------------
    // 2. Modality Tab Switching
    // -------------------------------------------------------------------------
    function setupModalityTabs() {
        const tabs = document.querySelectorAll('.workspace-tabs .tab-btn');
        const panels = {
            'text': document.getElementById('panel-text'),
            'image': document.getElementById('panel-image'),
            'audio': document.getElementById('panel-audio'),
            'video': document.getElementById('panel-video')
        };

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                const mode = tab.getAttribute('data-mode');
                Object.keys(panels).forEach(key => {
                    if (panels[key]) {
                        if (key === mode) {
                            panels[key].classList.remove('hidden');
                        } else {
                            panels[key].classList.add('hidden');
                        }
                    }
                });

                // Update badge placeholder
                if (resultModalityBadge) {
                    resultModalityBadge.textContent = mode.toUpperCase();
                    resultModalityBadge.className = `modality-badge-indicator modality-badge-${mode}`;
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // 3. Text Message Scanning Logic
    // -------------------------------------------------------------------------
    function updateCounters() {
        if (!messageInput) return;
        const text = messageInput.value;
        if (charCountEl) charCountEl.textContent = text.length;
        if (wordCountEl) wordCountEl.textContent = text.trim() ? text.trim().split(/\s+/).length : 0;
    }

    if (messageInput) {
        messageInput.addEventListener('input', updateCounters);
    }

    if (btnPaste && messageInput) {
        btnPaste.addEventListener('click', async () => {
            try {
                const clipboardText = await navigator.clipboard.readText();
                if (clipboardText) {
                    messageInput.value = clipboardText;
                    updateCounters();
                }
            } catch (e) {
                alert('Clipboard access denied or unsupported. Please use Ctrl+V / Cmd+V.');
            }
        });
    }

    if (btnClear && messageInput) {
        btnClear.addEventListener('click', () => {
            messageInput.value = '';
            updateCounters();
            resetResultState();
        });
    }

    async function scanTextMessage() {
        const text = messageInput.value.trim();
        if (!text) {
            alert('Please paste or type an SMS, email, or WhatsApp message to inspect.');
            messageInput.focus();
            return;
        }

        setLoading(true, "Tokenizing text & running dual ML + Heuristic engines...");
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text })
            });

            if (response.status === 401) {
                showScanError('Session expired. Please sign in again.', 'auth');
                window.location.href = '/login';
                return;
            }

            const data = await response.json();
            if (data.status === 'success') {
                data.analysis.modality = 'text';
                renderResult(data.analysis);
                if (data.updated_stats) updateStatsUI(data.updated_stats);
            } else {
                showScanError(data.message || 'Analysis failed.', response.status === 429 ? 'quota' : (response.status === 400 ? 'validation' : 'error'));
                setLoading(false);
            }
        } catch (err) {
            console.error('Scan request error:', err);
            showScanError('Network error while communicating with SecureSync backend.', 'error');
            setLoading(false);
        }
    }

    if (btnScan) {
        btnScan.addEventListener('click', scanTextMessage);
    }

    // -------------------------------------------------------------------------
    // 4. File Drag & Drop Handlers (Image, Audio, Video)
    // -------------------------------------------------------------------------
    function setupDragAndDrop() {
        // Image setup
        if (imageDropzone && imageFileInput) {
            imageDropzone.addEventListener('click', () => imageFileInput.click());
            imageFileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files[0]) handleImageFile(e.target.files[0]);
            });
            bindDropzoneEvents(imageDropzone, handleImageFile);
        }

        // Audio setup
        if (audioDropzone && audioFileInput) {
            audioDropzone.addEventListener('click', () => audioFileInput.click());
            audioFileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files[0]) handleAudioFile(e.target.files[0]);
            });
            bindDropzoneEvents(audioDropzone, handleAudioFile);
        }

        // Video setup
        if (videoDropzone && videoFileInput) {
            videoDropzone.addEventListener('click', () => videoFileInput.click());
            videoFileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files[0]) handleVideoFile(e.target.files[0]);
            });
            bindDropzoneEvents(videoDropzone, handleVideoFile);
        }

        // Bulk chat dropzone
        const bulkDropzone = document.getElementById('bulk-dropzone');
        const bulkFileInput = document.getElementById('bulk-file-input');
        if (bulkDropzone && bulkFileInput) {
            bulkDropzone.addEventListener('click', () => bulkFileInput.click());
            bulkFileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files[0]) processUploadedFile(e.target.files[0]);
            });
            bindDropzoneEvents(bulkDropzone, processUploadedFile);
        }
    }

    function bindDropzoneEvents(zone, handler) {
        ['dragenter', 'dragover'].forEach(eventName => {
            zone.addEventListener(eventName, (e) => {
                e.preventDefault();
                zone.classList.add('dragover');
            });
        });
        ['dragleave', 'drop'].forEach(eventName => {
            zone.addEventListener(eventName, (e) => {
                e.preventDefault();
                zone.classList.remove('dragover');
            });
        });
        zone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                handler(e.dataTransfer.files[0]);
            }
        });
    }

    function formatBytes(bytes) {
        if (!bytes) return '0 KB';
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    // Handle Image
    function handleImageFile(file) {
        currentSelectedImage = file;
        if (imagePreviewBox && imagePreviewThumb && imagePreviewName && imagePreviewSize) {
            imagePreviewName.textContent = file.name;
            imagePreviewSize.textContent = formatBytes(file.size);
            const url = URL.createObjectURL(file);
            imagePreviewThumb.src = url;
            imagePreviewBox.classList.add('active');
        }
        if (btnScanImage) btnScanImage.disabled = false;
    }

    if (btnClearImage) {
        btnClearImage.addEventListener('click', () => {
            currentSelectedImage = null;
            if (imageFileInput) imageFileInput.value = '';
            if (imagePreviewBox) imagePreviewBox.classList.remove('active');
            if (btnScanImage) btnScanImage.disabled = true;
            resetResultState();
        });
    }

    if (btnScanImage) {
        btnScanImage.addEventListener('click', async () => {
            if (!currentSelectedImage) return;
            setLoading(true, "Scanning image for Quishing QR, steganography & trailing bytes...");
            const formData = new FormData();
            formData.append('file', currentSelectedImage);

            try {
                const res = await fetch('/api/scan/image', { method: 'POST', body: formData });
                if (res.status === 401) { window.location.href = '/login'; return; }
                const data = await res.json();
                if (data.status === 'success') {
                    renderResult(data.analysis);
                    if (data.updated_stats) updateStatsUI(data.updated_stats);
                } else {
                    showScanError(data.message || 'Image scan failed.', res.status === 429 ? 'quota' : (res.status === 400 ? 'validation' : 'error'));
                    setLoading(false);
                }
            } catch (err) {
                console.error(err);
                showScanError('Network error during image inspection.', 'error');
                setLoading(false);
            }
        });
    }

    // Handle Audio
    function handleAudioFile(file) {
        currentSelectedAudio = file;
        if (audioPreviewBox && audioPreviewPlayer && audioPreviewName && audioPreviewSize) {
            audioPreviewName.textContent = file.name;
            audioPreviewSize.textContent = formatBytes(file.size);
            const url = URL.createObjectURL(file);
            audioPreviewPlayer.src = url;
            audioPreviewBox.classList.add('active');
        }
        if (btnScanAudio) btnScanAudio.disabled = false;
    }

    if (btnClearAudio) {
        btnClearAudio.addEventListener('click', () => {
            currentSelectedAudio = null;
            if (audioFileInput) audioFileInput.value = '';
            if (audioPreviewBox) audioPreviewBox.classList.remove('active');
            if (btnScanAudio) btnScanAudio.disabled = true;
            resetResultState();
        });
    }

    if (btnScanAudio) {
        btnScanAudio.addEventListener('click', async () => {
            if (!currentSelectedAudio) return;
            setLoading(true, "Computing FFT spectral roll-off & synthetic voice signatures...");
            const formData = new FormData();
            formData.append('file', currentSelectedAudio);

            try {
                const res = await fetch('/api/scan/audio', { method: 'POST', body: formData });
                if (res.status === 401) { window.location.href = '/login'; return; }
                const data = await res.json();
                if (data.status === 'success') {
                    renderResult(data.analysis);
                    if (data.updated_stats) updateStatsUI(data.updated_stats);
                } else {
                    showScanError(data.message || 'Audio scan failed.', res.status === 429 ? 'quota' : (res.status === 400 ? 'validation' : 'error'));
                    setLoading(false);
                }
            } catch (err) {
                console.error(err);
                showScanError('Network error during audio forensic scan.', 'error');
                setLoading(false);
            }
        });
    }

    // Handle Video
    function handleVideoFile(file) {
        currentSelectedVideo = file;
        if (videoPreviewBox && videoPreviewPlayer && videoPreviewName && videoPreviewSize) {
            videoPreviewName.textContent = file.name;
            videoPreviewSize.textContent = formatBytes(file.size);
            const url = URL.createObjectURL(file);
            videoPreviewPlayer.src = url;
            videoPreviewBox.classList.add('active');
        }
        if (btnScanVideo) btnScanVideo.disabled = false;
    }

    if (btnClearVideo) {
        btnClearVideo.addEventListener('click', () => {
            currentSelectedVideo = null;
            if (videoFileInput) videoFileInput.value = '';
            if (videoPreviewBox) videoPreviewBox.classList.remove('active');
            if (btnScanVideo) btnScanVideo.disabled = true;
            resetResultState();
        });
    }

    if (btnScanVideo) {
        btnScanVideo.addEventListener('click', async () => {
            if (!currentSelectedVideo) return;
            setLoading(true, "Parsing ISO BMFF atoms & deepfake encoder signatures...");
            const formData = new FormData();
            formData.append('file', currentSelectedVideo);

            try {
                const res = await fetch('/api/scan/video', { method: 'POST', body: formData });
                if (res.status === 401) { window.location.href = '/login'; return; }
                const data = await res.json();
                if (data.status === 'success') {
                    renderResult(data.analysis);
                    if (data.updated_stats) updateStatsUI(data.updated_stats);
                } else {
                    showScanError(data.message || 'Video scan failed.', res.status === 429 ? 'quota' : (res.status === 400 ? 'validation' : 'error'));
                    setLoading(false);
                }
            } catch (err) {
                console.error(err);
                showScanError('Network error during video forensic scan.', 'error');
                setLoading(false);
            }
        });
    }

    // -------------------------------------------------------------------------
    // 5. Interactive Demo Samples for Media
    // -------------------------------------------------------------------------
    function setupDemoSamples() {
        // Image Demos
        const btnDemoImgQuishing = document.getElementById('demo-img-quishing');
        if (btnDemoImgQuishing) {
            btnDemoImgQuishing.addEventListener('click', () => {
                const canvas = document.createElement('canvas');
                canvas.width = 400; canvas.height = 300;
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = '#0f172a'; ctx.fillRect(0, 0, 400, 300);
                ctx.fillStyle = '#ef4444'; ctx.fillRect(20, 20, 360, 40);
                ctx.fillStyle = '#ffffff'; ctx.font = 'bold 16px sans-serif';
                ctx.fillText('URGENT: BANK OF AMERICA SECURITY', 35, 46);
                ctx.fillStyle = '#00f0ff';
                ctx.font = '13px monospace';
                ctx.fillText('Scan QR Code or visit: http://bit.ly/bofa-lock', 35, 120);
                // Draw simulated QR finder pattern squares
                ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 4;
                ctx.strokeRect(150, 150, 80, 80);
                ctx.fillStyle = '#ffffff'; ctx.fillRect(170, 170, 40, 40);

                canvas.toBlob((blob) => {
                    const file = new File([blob], 'quishing_chase_lure.png', { type: 'image/png' });
                    handleImageFile(file);
                    if (btnScanImage) btnScanImage.click();
                }, 'image/png');
            });
        }

        const btnDemoImgBank = document.getElementById('demo-img-bank');
        if (btnDemoImgBank) {
            btnDemoImgBank.addEventListener('click', () => {
                const canvas = document.createElement('canvas');
                canvas.width = 400; canvas.height = 260;
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = '#1e293b'; ctx.fillRect(0, 0, 400, 260);
                ctx.fillStyle = '#f59e0b'; ctx.font = 'bold 18px sans-serif';
                ctx.fillText('PAYPAL INVOICE OVERDUE', 30, 45);
                ctx.fillStyle = '#ffffff'; ctx.font = '13px monospace';
                ctx.fillText('Claim $50,000 refund at http://win-walmart.com', 30, 100);
                ctx.fillText('Photoshop CC 2026 Forensic Layer Attached', 30, 180);

                canvas.toBlob((blob) => {
                    const file = new File([blob], 'paypal_fake_invoice.jpg', { type: 'image/jpeg' });
                    handleImageFile(file);
                    if (btnScanImage) btnScanImage.click();
                }, 'image/jpeg');
            });
        }

        const btnDemoImgSafe = document.getElementById('demo-img-safe');
        if (btnDemoImgSafe) {
            btnDemoImgSafe.addEventListener('click', () => {
                const canvas = document.createElement('canvas');
                canvas.width = 400; canvas.height = 240;
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = '#064e3b'; ctx.fillRect(0, 0, 400, 240);
                ctx.fillStyle = '#34d399'; ctx.font = 'bold 18px sans-serif';
                ctx.fillText('ACADEMIC REPORT DIAGRAM', 30, 50);
                ctx.fillStyle = '#ffffff'; ctx.font = '13px sans-serif';
                ctx.fillText('Normal university research chart. No deceptive links.', 30, 110);

                canvas.toBlob((blob) => {
                    const file = new File([blob], 'authentic_chart.png', { type: 'image/png' });
                    handleImageFile(file);
                    if (btnScanImage) btnScanImage.click();
                }, 'image/png');
            });
        }

        // Audio Demos
        const btnDemoAudDeepfake = document.getElementById('demo-aud-deepfake');
        if (btnDemoAudDeepfake) {
            btnDemoAudDeepfake.addEventListener('click', () => {
                const sampleRate = 22050;
                const duration = 3.5;
                const totalSamples = Math.floor(sampleRate * duration);
                const buffer = new ArrayBuffer(44 + totalSamples * 2);
                const view = new DataView(buffer);

                // Build WAV Header
                writeString(view, 0, 'RIFF');
                view.setUint32(4, 36 + totalSamples * 2, true);
                writeString(view, 8, 'WAVE');
                writeString(view, 12, 'fmt ');
                view.setUint32(16, 16, true);
                view.setUint16(20, 1, true); // PCM
                view.setUint16(22, 1, true); // Mono
                view.setUint32(24, sampleRate, true);
                view.setUint32(28, sampleRate * 2, true);
                view.setUint16(32, 2, true);
                view.setUint16(34, 16, true);
                writeString(view, 36, 'data');
                view.setUint32(40, totalSamples * 2, true);

                // Synthesize audio with artificial neural cutoff
                let offset = 44;
                for (let i = 0; i < totalSamples; i++) {
                    const t = i / sampleRate;
                    const sample = Math.sin(2 * Math.PI * 440 * t) * 0.4 + Math.sin(2 * Math.PI * 880 * t) * 0.2;
                    view.setInt16(offset, sample * 32767, true);
                    offset += 2;
                }

                const blob = new Blob([buffer], { type: 'audio/wav' });
                const file = new File([blob], 'synthetic_voice_elevenlabs.wav', { type: 'audio/wav' });
                handleAudioFile(file);
                if (btnScanAudio) btnScanAudio.click();
            });
        }

        const btnDemoAudVishing = document.getElementById('demo-aud-vishing');
        if (btnDemoAudVishing) {
            btnDemoAudVishing.addEventListener('click', () => {
                const sampleRate = 22050;
                const totalSamples = sampleRate * 3;
                const buffer = new ArrayBuffer(44 + totalSamples * 2 + 100);
                const view = new DataView(buffer);
                writeString(view, 0, 'RIFF');
                view.setUint32(4, 36 + totalSamples * 2, true);
                writeString(view, 8, 'WAVEfmt ');
                view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true);
                view.setUint32(24, sampleRate, true); view.setUint32(28, sampleRate * 2, true);
                view.setUint16(32, 2, true); view.setUint16(34, 16, true);
                writeString(view, 36, 'data'); view.setUint32(40, totalSamples * 2, true);

                let offset = 44;
                for (let i = 0; i < totalSamples; i++) {
                    const sample = Math.sin(2 * Math.PI * 300 * (i / sampleRate)) * 0.5;
                    view.setInt16(offset, sample * 32767, true);
                    offset += 2;
                }
                // Append simulated vishing metadata tag
                writeString(view, offset, 'TAG_VISHING_BANK_TRANSFER_URGENT_WIRE_MONEY');

                const blob = new Blob([buffer], { type: 'audio/wav' });
                const file = new File([blob], 'vishing_irs_scam_call.wav', { type: 'audio/wav' });
                handleAudioFile(file);
                if (btnScanAudio) btnScanAudio.click();
            });
        }

        const btnDemoAudSafe = document.getElementById('demo-aud-safe');
        if (btnDemoAudSafe) {
            btnDemoAudSafe.addEventListener('click', () => {
                const sampleRate = 44100;
                const totalSamples = sampleRate * 3;
                const buffer = new ArrayBuffer(44 + totalSamples * 2);
                const view = new DataView(buffer);
                writeString(view, 0, 'RIFF'); view.setUint32(4, 36 + totalSamples * 2, true);
                writeString(view, 8, 'WAVEfmt '); view.setUint32(16, 16, true);
                view.setUint16(20, 1, true); view.setUint16(22, 1, true);
                view.setUint32(24, sampleRate, true); view.setUint32(28, sampleRate * 2, true);
                view.setUint16(32, 2, true); view.setUint16(34, 16, true);
                writeString(view, 36, 'data'); view.setUint32(40, totalSamples * 2, true);

                let offset = 44;
                for (let i = 0; i < totalSamples; i++) {
                    const t = i / sampleRate;
                    const sample = Math.sin(2 * Math.PI * 220 * t) * 0.3 * (1 - Math.cos(2 * Math.PI * t / 3));
                    view.setInt16(offset, sample * 32767, true);
                    offset += 2;
                }

                const blob = new Blob([buffer], { type: 'audio/wav' });
                const file = new File([blob], 'organic_speech_sample.wav', { type: 'audio/wav' });
                handleAudioFile(file);
                if (btnScanAudio) btnScanAudio.click();
            });
        }

        // Video Demos
        const btnDemoVidDeepfake = document.getElementById('demo-vid-deepfake');
        if (btnDemoVidDeepfake) {
            btnDemoVidDeepfake.addEventListener('click', () => {
                // Synthesize simulated MP4 container bytes with neural tool atom
                const buf = new Uint8Array(2048);
                const encoder = new TextEncoder();
                const fakeAtoms = '....ftypmp42....moov....mdat....encoder:Lavf58.20.100 tool:SADTALKER_AI_FACE_SWAP';
                buf.set(encoder.encode(fakeAtoms), 0);
                const blob = new Blob([buf], { type: 'video/mp4' });
                const file = new File([blob], 'deepfake_avatar_sadtalker.mp4', { type: 'video/mp4' });
                handleVideoFile(file);
                if (btnScanVideo) btnScanVideo.click();
            });
        }

        const btnDemoVidAvsync = document.getElementById('demo-vid-avsync');
        if (btnDemoVidAvsync) {
            btnDemoVidAvsync.addEventListener('click', () => {
                const buf = new Uint8Array(2048);
                const encoder = new TextEncoder();
                const fakeAtoms = '....ftypisom....mdat....moov....tool:WAV2LIP_SYNTHESIS_DRIFT';
                buf.set(encoder.encode(fakeAtoms), 0);
                const blob = new Blob([buf], { type: 'video/mp4' });
                const file = new File([blob], 'wav2lip_speech_drift.mp4', { type: 'video/mp4' });
                handleVideoFile(file);
                if (btnScanVideo) btnScanVideo.click();
            });
        }

        const btnDemoVidSafe = document.getElementById('demo-vid-safe');
        if (btnDemoVidSafe) {
            btnDemoVidSafe.addEventListener('click', () => {
                const buf = new Uint8Array(2048);
                const encoder = new TextEncoder();
                const fakeAtoms = '....ftypmp42....moov....mdat....genuine_camera_capture_avc1';
                buf.set(encoder.encode(fakeAtoms), 0);
                const blob = new Blob([buf], { type: 'video/mp4' });
                const file = new File([blob], 'genuine_camera_clip.mp4', { type: 'video/mp4' });
                handleVideoFile(file);
                if (btnScanVideo) btnScanVideo.click();
            });
        }
    }

    function writeString(view, offset, string) {
        for (let i = 0; i < string.length; i++) {
            view.setUint8(offset + i, string.charCodeAt(i));
        }
    }

    // -------------------------------------------------------------------------
    // 6. UI State Management & Threat Report Rendering
    // -------------------------------------------------------------------------
    function setLoading(isLoading, text = "Computing threat analysis...") {
        if (isLoading) {
            if (idleState) idleState.classList.add('hidden');
            if (resultState) resultState.classList.add('hidden');
            if (loadingState) loadingState.classList.remove('hidden');
            if (loadingStatusText) loadingStatusText.textContent = text;
        } else {
            if (loadingState) loadingState.classList.add('hidden');
        }
    }

    function resetResultState() {
        if (idleState) idleState.classList.remove('hidden');
        if (loadingState) loadingState.classList.add('hidden');
        if (resultState) resultState.classList.add('hidden');
        if (scanTimestampEl) scanTimestampEl.textContent = 'Standby';
        if (scanIdText) scanIdText.textContent = 'SCN-STANDBY';
        lastAnalysisReport = null;
    }

    function renderResult(report) {
        lastAnalysisReport = report;
        setLoading(false);
        if (resultState) resultState.classList.remove('hidden');
        if (scanTimestampEl) scanTimestampEl.textContent = new Date().toLocaleTimeString();

        const modality = (report.modality || 'text').toLowerCase();
        const isThreat = report.is_threat || report.is_scam;

        // Modality Badge
        if (resultModalityBadge) {
            resultModalityBadge.textContent = modality.toUpperCase();
            resultModalityBadge.className = `modality-badge-indicator modality-badge-${modality}`;
        }

        // Scan Reference ID & Target Label
        if (scanIdText && report.scan_id) {
            scanIdText.textContent = report.scan_id;
        }
        if (targetAssetName) {
            const fname = report.filename || (modality === 'text' ? 'Message Payload' : `${modality} Asset`);
            targetAssetName.textContent = `Target: ${escapeHTML(fname)}`;
        }

        // Primary Banner
        if (isThreat) {
            primaryBanner.className = 'alert-banner alert-scam';
            bannerIcon.innerHTML = `
                <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2.2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
            `;
            bannerHeading.textContent = `🚨 Warning: Suspicious ${modality.toUpperCase()} Threat Detected`;
            bannerSubtext.textContent = `High probability of malicious deception, social engineering, or synthetic manipulation.`;
        } else {
            primaryBanner.className = 'alert-banner alert-legit';
            bannerIcon.innerHTML = `
                <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2.2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <polyline points="9 12 11 14 15 10"/>
                </svg>
            `;
            bannerHeading.textContent = `✔ Verified: Clean ${modality.toUpperCase()} Asset`;
            bannerSubtext.textContent = `No malicious indicators, quishing links, or synthetic signatures identified.`;
        }

        // Metrics Grid
        const score = report.risk_score ?? report.confidence ?? 0;
        const level = (report.risk_level || (isThreat ? 'HIGH' : 'LOW')).toUpperCase();

        if (resultClassification) {
            resultClassification.textContent = report.classification || report.threat_classification || (isThreat ? 'Threat' : 'Clean');
            resultClassification.className = `metric-highlight ${isThreat ? 'threat-text' : 'safe-text'}`;
        }
        if (resultThreatCategory) {
            resultThreatCategory.textContent = report.threat_category || (isThreat ? 'Suspicious Vector' : 'Clean / Benign');
        }
        if (resultConfidence) {
            resultConfidence.textContent = `${score}%`;
        }
        if (confidenceBar) {
            confidenceBar.style.width = `${Math.min(100, Math.max(5, score))}%`;
            confidenceBar.style.backgroundColor = isThreat ? 'var(--red-threat)' : 'var(--green-safe)';
        }
        if (resultRisk) {
            resultRisk.textContent = level;
            resultRisk.className = `risk-badge risk-${level.toLowerCase()}`;
        }

        // Recommended Action Protocol
        if (recommendedActionText && report.recommended_action) {
            recommendedActionText.textContent = report.recommended_action;
        }
        if (recommendedActionBox) {
            recommendedActionBox.className = `recommended-action-box action-risk-${level.toLowerCase()}`;
        }

        // Text Probability vs Media Technical Forensics
        if (modality === 'text' && report.probabilities) {
            if (probabilitySection) probabilitySection.classList.remove('hidden');
            const pLegit = report.probabilities.legitimate;
            const pScam = report.probabilities.scam;
            if (probRatioText) probRatioText.textContent = `Legitimate: ${pLegit}% | Scam: ${pScam}%`;
            if (probLegitBar) probLegitBar.style.width = `${pLegit}%`;
            if (probScamBar) probScamBar.style.width = `${pScam}%`;
        } else {
            if (probabilitySection) probabilitySection.classList.add('hidden');
        }

        // Populate Technical Forensics Grid (for media or detailed scans)
        if (technicalForensicsGrid) {
            technicalForensicsGrid.innerHTML = '';
            const f = report.forensic_details || {};
            const metrics = [];

            if (f.format || f.container) metrics.push({ label: 'Format / Container', val: f.format || f.container });
            if (f.dimensions) metrics.push({ label: 'Dimensions', val: f.dimensions });
            if (f.duration_seconds !== undefined && f.duration_seconds !== null) metrics.push({ label: 'Duration', val: `${f.duration_seconds}s` });
            if (f.sample_rate) metrics.push({ label: 'Sample Rate', val: `${f.sample_rate} Hz` });
            if (f.entropy !== undefined) metrics.push({ label: 'Shannon Entropy', val: `${f.entropy} / 8.0` });
            if (f.encoder_software) metrics.push({ label: 'Encoder Tool', val: f.encoder_software });
            if (f.synthetic_voice_probability !== undefined) metrics.push({ label: 'Deepfake Probability', val: `${Math.round(f.synthetic_voice_probability * 100)}%` });
            if (f.file_size_formatted) metrics.push({ label: 'File Size', val: f.file_size_formatted });
            if (f.sha256) metrics.push({ label: 'SHA-256 Hash', val: `${f.sha256.substring(0, 16)}...` });

            if (metrics.length === 0) {
                metrics.push({ label: 'Payload Length', val: `${report.char_count || 0} chars` });
                metrics.push({ label: 'Word Count', val: `${report.word_count || 0} words` });
                metrics.push({ label: 'Quarantined Links', val: (report.links ? report.links.length : 0).toString() });
            }

            metrics.forEach(m => {
                const box = document.createElement('div');
                box.className = 'tech-metric-card';
                box.innerHTML = `
                    <span class="tech-metric-label">${escapeHTML(m.label)}</span>
                    <span class="tech-metric-val">${escapeHTML(m.val)}</span>
                `;
                technicalForensicsGrid.appendChild(box);
            });
        }

        // Render Forensic Indicators
        if (indicatorsList) {
            indicatorsList.innerHTML = '';
            const indicators = report.indicators || report.suspicious_indicators || [];
            if (indicators.length > 0) {
                indicators.forEach(ind => {
                    const card = document.createElement('div');
                    card.className = 'indicator-card';
                    const sev = (ind.severity || 'HIGH').toLowerCase();
                    card.innerHTML = `
                        <div class="indicator-header">
                            <span class="indicator-name">${escapeHTML(ind.name)}</span>
                            <span class="severity-pill sev-${sev}">${escapeHTML(ind.severity || 'HIGH')}</span>
                        </div>
                        <p class="indicator-desc">${escapeHTML(ind.explanation)}</p>
                    `;
                    indicatorsList.appendChild(card);
                });
            } else {
                indicatorsList.innerHTML = `
                    <div class="no-indicators-box">
                        ✔ No malicious indicators, steganographic payloads, or social engineering patterns detected.
                    </div>
                `;
            }
        }

        // Render Quarantined Links
        if (linksSection && linksContainer) {
            linksContainer.innerHTML = '';
            const links = report.links || [];
            if (links.length > 0) {
                linksSection.classList.remove('hidden');
                links.forEach(l => {
                    const box = document.createElement('div');
                    box.className = 'link-box';
                    let badges = '';
                    if (l.is_shortener) badges += `<span class="flag-badge flag-alert">Shortener (${escapeHTML(l.domain)})</span>`;
                    if (l.brand_spoofing) badges += `<span class="flag-badge flag-alert">Brand Spoofing</span>`;
                    if (l.has_suspicious_tld) badges += `<span class="flag-badge flag-alert">Suspicious TLD</span>`;
                    if (l.is_ip_address) badges += `<span class="flag-badge flag-alert">Raw IP Destination</span>`;
                    if (!badges) badges = `<span class="flag-badge flag-info">Domain: ${escapeHTML(l.domain)}</span>`;

                    box.innerHTML = `
                        <div class="link-defanged">${escapeHTML(l.defanged)}</div>
                        <div class="link-flags">${badges}</div>
                    `;
                    linksContainer.appendChild(box);
                });
            } else {
                linksSection.classList.add('hidden');
            }
        }

        // Render Explainability Reasons
        if (reasonsList) {
            reasonsList.innerHTML = '';
            let reasons = report.why_flagged || report.reasons || report.detection_reasons || [];
            if (typeof reasons === 'string') reasons = [reasons];
            if (reasons.length > 0) {
                reasons.forEach(r => {
                    const li = document.createElement('li');
                    li.textContent = r;
                    reasonsList.appendChild(li);
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 7. Action Bar: Download PDF & Export JSON
    // -------------------------------------------------------------------------
    if (btnDownloadPdf) {
        btnDownloadPdf.addEventListener('click', () => {
            if (!lastAnalysisReport || !lastAnalysisReport.scan_id) {
                alert('No active scan report to download.');
                return;
            }
            window.location.href = `/api/scan/${encodeURIComponent(lastAnalysisReport.scan_id)}/pdf`;
        });
    }

    if (btnExportJson) {
        btnExportJson.addEventListener('click', () => {
            if (!lastAnalysisReport) {
                alert('No scan findings available to export.');
                return;
            }
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastAnalysisReport, null, 2));
            const dl = document.createElement('a');
            dl.setAttribute("href", dataStr);
            dl.setAttribute("download", `securesync_${lastAnalysisReport.scan_id || 'report'}.json`);
            document.body.appendChild(dl);
            dl.click();
            dl.remove();
        });
    }

    if (btnCopyScanId) {
        btnCopyScanId.addEventListener('click', async () => {
            if (scanIdText && scanIdText.textContent && scanIdText.textContent !== 'SCN-STANDBY') {
                try {
                    await navigator.clipboard.writeText(scanIdText.textContent);
                    const orig = btnCopyScanId.textContent;
                    btnCopyScanId.textContent = '✓';
                    setTimeout(() => { btnCopyScanId.textContent = orig; }, 2000);
                } catch (e) {
                    prompt('Copy Scan ID:', scanIdText.textContent);
                }
            }
        });
    }

    // -------------------------------------------------------------------------
    // 8. Bulk Chat Analysis
    // -------------------------------------------------------------------------
    const btnLoadDemoChat = document.getElementById('btn-load-demo-chat');
    const bulkResultsPanel = document.getElementById('bulk-results-panel');
    const bulkTableBody = document.getElementById('bulk-table-body');
    const bulkTotalEl = document.getElementById('bulk-total');
    const bulkScamsEl = document.getElementById('bulk-scams');
    const bulkLegitEl = document.getElementById('bulk-legit');
    const bulkThreatLevelEl = document.getElementById('bulk-threat-level');
    const countAllEl = document.getElementById('count-all');
    const countScamEl = document.getElementById('count-scam');
    const countLegitEl = document.getElementById('count-legit');
    const btnExportBulkResults = document.getElementById('btn-export-bulk-results');
    const filterBtns = document.querySelectorAll('.filter-btn');

    let currentBatchResults = [];

    if (btnLoadDemoChat) {
        btnLoadDemoChat.addEventListener('click', () => {
            const demoChat = `[15/09/2026, 09:15:22] John: Good morning! Are you heading to the lab today?
[15/09/2026, 09:18:40] Alex: Yes, don't forget your laptop.
[15/09/2026, 10:45:11] Unknown Contact (+1 555-019-8821): URGENT: Your Chase checking account is locked. Verify immediately at http://bit.ly/chase-lock or card will be blocked.
[15/09/2026, 12:05:49] Unknown Contact (+1 555-014-7722): CONGRATULATIONS! You have been selected as the winner of $50,000 Walmart voucher. Claim at http://win-walmart.com!
[15/09/2026, 14:02:33] Unknown Contact (+1 555-019-3329): Hi Mom, my phone fell in the water. I urgently need $450 to pay for car towing. Can you send via Zelle right now?
[15/09/2026, 15:30:12] Sarah: Meeting at 3pm today.`;
            const blob = new Blob([demoChat], { type: 'text/plain' });
            const file = new File([blob], 'demo_chat_transcript.txt', { type: 'text/plain' });
            processUploadedFile(file);
        });
    }

    async function processUploadedFile(file) {
        setLoading(true, "Ingesting chat transcript & batch scanning entries...");
        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await fetch('/api/scan-file', { method: 'POST', body: formData });
            if (res.status === 401) { window.location.href = '/login'; return; }
            const data = await res.json();
            if (data.status === 'success') {
                currentBatchResults = data.results || [];
                renderBulkResults(data);
                if (data.updated_stats) updateStatsUI(data.updated_stats);
            } else {
                showScanError(data.message || 'Failed to parse file.', res.status === 429 ? 'quota' : (res.status === 400 ? 'validation' : 'error'));
            }
        } catch (err) {
            console.error('File scan failed:', err);
            showScanError('Network error while processing chat transcript.', 'error');
        } finally {
            setLoading(false);
        }
    }

    function renderBulkResults(data) {
        if (!bulkResultsPanel) return;
        bulkResultsPanel.classList.remove('hidden');

        const total = data.total_processed || 0;
        const scams = data.scams_detected || 0;
        const legit = data.legitimate_verified || 0;
        const threatPct = total > 0 ? Math.round((scams / total) * 100) : 0;

        if (bulkTotalEl) bulkTotalEl.textContent = total;
        if (bulkScamsEl) bulkScamsEl.textContent = scams;
        if (bulkLegitEl) bulkLegitEl.textContent = legit;
        if (bulkThreatLevelEl) bulkThreatLevelEl.textContent = `${threatPct}%`;

        if (countAllEl) countAllEl.textContent = total;
        if (countScamEl) countScamEl.textContent = scams;
        if (countLegitEl) countLegitEl.textContent = legit;

        renderFilteredTable('all');
    }

    function renderFilteredTable(filter) {
        if (!bulkTableBody) return;
        bulkTableBody.innerHTML = '';

        const filtered = currentBatchResults.filter(item => {
            if (filter === 'scam') return item.is_scam;
            if (filter === 'legit') return !item.is_scam;
            return true;
        });

        if (filtered.length === 0) {
            bulkTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 20px; color: var(--text-muted);">No records match filter.</td></tr>`;
            return;
        }

        filtered.forEach(msg => {
            const tr = document.createElement('tr');
            const badgeClass = msg.is_scam ? 'status-badge-scam' : 'status-badge-legit';
            const badgeIcon = msg.is_scam ? '🚨' : '✔';

            tr.innerHTML = `
                <td><span class="status-badge ${badgeClass}">${badgeIcon} ${escapeHTML(msg.classification)}</span></td>
                <td><strong>${escapeHTML(msg.sender)}</strong><br><small style="color:var(--text-muted); font-family:var(--font-mono);">${escapeHTML(msg.timestamp || 'Direct')}</small></td>
                <td style="max-width: 320px; word-break: break-word;"><span style="font-size:0.82rem;">${escapeHTML(msg.safe_display_text || msg.text)}</span></td>
                <td><span class="risk-badge risk-${(msg.risk_level || 'low').toLowerCase()}">${escapeHTML(msg.risk_level)}</span><br><small style="font-family:var(--font-mono); color:var(--text-secondary);">${msg.confidence}%</small></td>
                <td>${msg.indicators && msg.indicators.length > 0 ? msg.indicators.map(i => `<span class="severity-pill sev-${(i.severity || 'high').toLowerCase()}">${escapeHTML(i.name)}</span>`).join(' ') : '<span style="color:var(--text-muted); font-size:0.75rem;">None</span>'}</td>
            `;
            bulkTableBody.appendChild(tr);
        });
    }

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderFilteredTable(btn.getAttribute('data-filter'));
        });
    });

    if (btnExportBulkResults) {
        btnExportBulkResults.addEventListener('click', () => {
            if (!currentBatchResults.length) return;
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentBatchResults, null, 2));
            const dl = document.createElement('a');
            dl.setAttribute("href", dataStr);
            dl.setAttribute("download", `securesync_batch_findings_${Date.now()}.json`);
            document.body.appendChild(dl);
            dl.click();
            dl.remove();
        });
    }

    // -------------------------------------------------------------------------
    // 9. Scan History Modal with Modality Filtering & Direct PDF Downloads
    // -------------------------------------------------------------------------
    const historyModal = document.getElementById('history-modal');
    const btnOpenHistory = document.getElementById('btn-open-history');
    const btnCloseHistory = document.getElementById('btn-close-history');
    const historyLoading = document.getElementById('history-loading');
    const historyTableBody = document.getElementById('history-table-body');
    const historyModBtns = document.querySelectorAll('.history-mod-btn');
    const historySearchInput = document.getElementById('history-search-input');

    let cachedHistoryItems = [];
    let currentHistoryModFilter = 'all';

    function setupHistoryModal() {
        if (btnOpenHistory && historyModal) {
            btnOpenHistory.addEventListener('click', () => {
                historyModal.classList.remove('hidden');
                loadHistoryData();
            });
        }

        if (btnCloseHistory && historyModal) {
            btnCloseHistory.addEventListener('click', () => historyModal.classList.add('hidden'));
            historyModal.addEventListener('click', (e) => {
                if (e.target === historyModal) historyModal.classList.add('hidden');
            });
        }

        historyModBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                historyModBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentHistoryModFilter = btn.getAttribute('data-mod');
                renderFilteredHistory();
            });
        });

        if (historySearchInput) {
            historySearchInput.addEventListener('input', () => renderFilteredHistory());
        }
    }

    async function loadHistoryData() {
        if (!historyLoading || !historyTableBody) return;
        historyLoading.classList.remove('hidden');
        historyTableBody.innerHTML = '';

        try {
            const res = await fetch('/api/history');
            if (res.status === 401) { window.location.href = '/login'; return; }
            const data = await res.json();
            if (data.status === 'success' && Array.isArray(data.history)) {
                cachedHistoryItems = data.history;
                renderFilteredHistory();
            } else {
                historyTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:20px; color:var(--text-muted);">No scan logs found.</td></tr>`;
            }
        } catch (err) {
            console.error('History fetch error:', err);
            historyTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:20px; color:var(--red-threat);">Failed to load history from database.</td></tr>`;
        } finally {
            historyLoading.classList.add('hidden');
        }
    }

    function renderFilteredHistory() {
        if (!historyTableBody) return;
        historyTableBody.innerHTML = '';

        const searchTerm = historySearchInput ? historySearchInput.value.toLowerCase().trim() : '';

        const filtered = cachedHistoryItems.filter(item => {
            const mod = (item.modality || 'text').toLowerCase();
            const matchesMod = (currentHistoryModFilter === 'all') || (mod === currentHistoryModFilter);
            if (!matchesMod) return false;

            if (searchTerm) {
                const scanId = (item.scan_id || '').toLowerCase();
                const text = (item.submitted_message || item.message_preview || '').toLowerCase();
                const classification = (item.threat_classification || item.classification || '').toLowerCase();
                return scanId.includes(searchTerm) || text.includes(searchTerm) || classification.includes(searchTerm);
            }
            return true;
        });

        if (filtered.length === 0) {
            historyTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--text-muted);">No scans matching filter.</td></tr>`;
            return;
        }

        filtered.forEach(h => {
            const tr = document.createElement('tr');
            const mod = (h.modality || 'text').toLowerCase();
            const isThreat = (h.risk_level === 'CRITICAL' || h.risk_level === 'HIGH' || (h.classification || '').toLowerCase().includes('scam'));
            const badgeClass = isThreat ? 'status-badge-scam' : 'status-badge-legit';

            tr.innerHTML = `
                <td><small style="font-family:var(--font-mono); color:var(--text-muted);">${escapeHTML(h.date || h.created_at || '')}</small></td>
                <td><span class="modality-badge-indicator modality-badge-${mod}">${escapeHTML(mod.toUpperCase())}</span></td>
                <td><code style="color:var(--cyan); font-size:0.8rem;">${escapeHTML(h.scan_id)}</code></td>
                <td><span class="risk-badge risk-${(h.risk_level || 'low').toLowerCase()}">${escapeHTML(h.risk_level || 'LOW')}</span></td>
                <td><span style="font-family:var(--font-mono); color:var(--text-primary); font-weight:700;">${h.risk_score ?? h.confidence}%</span></td>
                <td><span class="status-badge ${badgeClass}">${escapeHTML(h.classification || h.threat_classification)}</span></td>
                <td style="max-width:200px; word-break:break-word;"><span style="font-size:0.82rem;">${escapeHTML(h.message_preview || h.submitted_message || '')}</span></td>
                <td style="white-space: nowrap;">
                    <button type="button" class="btn-history-details btn-table-action" data-scan-id="${escapeHTML(h.scan_id)}" style="margin-right: 4px;">
                        View
                    </button>
                    <a href="/api/scan/${encodeURIComponent(h.scan_id)}/pdf" class="btn-table-action" style="text-decoration:none; padding: 4px 8px;" title="Download PDF Report">
                        📥 PDF
                    </a>
                </td>
            `;

            const btnDetails = tr.querySelector('.btn-history-details');
            if (btnDetails) {
                btnDetails.addEventListener('click', (e) => {
                    e.stopPropagation();
                    openScanDetails(h.scan_id);
                });
            }
            historyTableBody.appendChild(tr);
        });
    }

    // -------------------------------------------------------------------------
    // 10. Scan Detail Modal
    // -------------------------------------------------------------------------
    const scanDetailModal = document.getElementById('scan-detail-modal');
    const btnCloseScanDetail = document.getElementById('btn-close-scan-detail');
    const scanDetailBody = document.getElementById('scan-detail-body');
    const modalScanIdTitle = document.getElementById('modal-scan-id-title');

    if (btnCloseScanDetail && scanDetailModal) {
        btnCloseScanDetail.addEventListener('click', () => scanDetailModal.classList.add('hidden'));
        scanDetailModal.addEventListener('click', (e) => {
            if (e.target === scanDetailModal) scanDetailModal.classList.add('hidden');
        });
    }

    async function openScanDetails(scanId) {
        if (!scanDetailModal || !scanDetailBody) return;
        scanDetailModal.classList.remove('hidden');
        scanDetailBody.innerHTML = `
            <div class="state-container">
                <div class="radar-spinner"></div>
                <p class="loading-text">Loading forensic report for ${escapeHTML(scanId)}...</p>
            </div>
        `;
        if (modalScanIdTitle) modalScanIdTitle.textContent = `Forensic Report: ${scanId}`;

        try {
            const res = await fetch(`/api/scan/${encodeURIComponent(scanId)}`);
            if (res.status === 401) { window.location.href = '/login'; return; }
            const data = await res.json();
            if (data.status === 'success' && data.scan) {
                renderScanDetailReport(data.scan);
            } else {
                scanDetailBody.innerHTML = `<p style="color:var(--red-threat); text-align:center; padding:20px;">${escapeHTML(data.message || 'Report not found.')}</p>`;
            }
        } catch (err) {
            console.error('Failed to load scan report:', err);
            scanDetailBody.innerHTML = `<p style="color:var(--red-threat); text-align:center; padding:20px;">Network error loading forensic report.</p>`;
        }
    }

    function renderScanDetailReport(s) {
        const isThreat = (s.risk_level === 'CRITICAL' || s.risk_level === 'HIGH' || (s.threat_classification || '').toLowerCase().includes('scam'));
        const badgeClass = isThreat ? 'status-badge-scam' : 'status-badge-legit';
        const mod = (s.modality || 'text').toUpperCase();

        let indListHtml = '';
        if (Array.isArray(s.suspicious_indicators) && s.suspicious_indicators.length > 0) {
            indListHtml = s.suspicious_indicators.map(ind => `
                <div class="indicator-card" style="margin-bottom:8px;">
                    <div class="indicator-header">
                        <span class="indicator-name">${escapeHTML(ind.name || 'Threat Vector')}</span>
                        <span class="severity-pill sev-${(ind.severity || 'high').toLowerCase()}">${escapeHTML(ind.severity || 'HIGH')}</span>
                    </div>
                    <p class="indicator-desc">${escapeHTML(ind.explanation || '')}</p>
                </div>
            `).join('');
        } else {
            indListHtml = '<p style="color:var(--green-safe); font-size:0.9rem;">✔ No suspicious heuristic signatures detected in this submission.</p>';
        }

        let reasonsHtml = '';
        if (Array.isArray(s.detection_reasons) && s.detection_reasons.length > 0) {
            reasonsHtml = s.detection_reasons.map(r => `<li>${escapeHTML(r)}</li>`).join('');
        } else {
            reasonsHtml = '<li>Standard verification completed.</li>';
        }

        scanDetailBody.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:20px; padding-bottom:14px; border-bottom:1px solid var(--border-color);">
                <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                    <span class="modality-badge-indicator modality-badge-${(s.modality || 'text').toLowerCase()}">${mod}</span>
                    <span class="status-badge ${badgeClass}" style="font-size:0.95rem; padding:6px 14px;">${escapeHTML(s.threat_classification || s.classification)}</span>
                    <span class="panel-badge" style="background:var(--bg-subtle); border:1px solid var(--border-color); color:var(--text-secondary); font-size:0.75rem;">${escapeHTML(s.threat_category || 'General Assessment')}</span>
                </div>
                <div style="display:flex; gap:16px; align-items:center;">
                    <span class="risk-badge risk-${(s.risk_level || 'low').toLowerCase()}">Risk: ${escapeHTML(s.risk_level)}</span>
                    <span style="font-family:var(--font-mono); font-weight:700; color:var(--primary); font-size:1.1rem;">Score: ${s.risk_score ?? s.confidence}%</span>
                </div>
            </div>

            <div style="margin-bottom:18px;">
                <label style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">Target Asset Payload / Evidence</label>
                <div style="background:var(--bg-subtle); border:1px solid var(--border-color); border-radius:var(--radius-sm); padding:14px; font-family:var(--font-mono); font-size:0.85rem; color:var(--text-primary); margin-top:6px; word-break:break-word; max-height:160px; overflow-y:auto;">
                    ${escapeHTML(s.submitted_message)}
                </div>
            </div>

            <div style="margin-bottom:18px;">
                <label style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">Recommended Protective Directive</label>
                <div style="background:var(--primary-light); border:1px solid var(--primary-border); border-radius:var(--radius-sm); padding:12px 14px; color:var(--text-primary); margin-top:6px; font-size:0.9rem;">
                    ${escapeHTML(s.recommended_action || 'No action required.')}
                </div>
            </div>

            <div style="margin-bottom:18px;">
                <label style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">Detection Reasoning</label>
                <ul class="reasons-list" style="margin-top:6px;">
                    ${reasonsHtml}
                </ul>
            </div>

            <div style="margin-bottom:20px;">
                <label style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">Forensic Threat Indicators</label>
                <div style="margin-top:8px;">
                    ${indListHtml}
                </div>
            </div>

            <div style="margin-top:20px; padding-top:16px; border-top:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
                <div style="font-size:0.8rem; color:var(--text-muted); font-family:var(--font-mono);">
                    <span>ID: ${escapeHTML(s.scan_id)}</span> • <span>${escapeHTML(s.created_at || s.scanned_at || '')}</span>
                </div>
                <div>
                    <a href="/api/scan/${encodeURIComponent(s.scan_id)}/pdf" class="btn-primary" style="padding:8px 18px; font-size:0.85rem; text-decoration:none; display:inline-flex; align-items:center; gap:6px;">
                        📥 Download PDF Investigation Report
                    </a>
                </div>
            </div>
        `;
    }

    // -------------------------------------------------------------------------
    // 11. Educational Toggle
    // -------------------------------------------------------------------------
    if (toggleEduBtn && eduContent) {
        toggleEduBtn.addEventListener('click', () => {
            if (eduContent.classList.contains('hidden')) {
                eduContent.classList.remove('hidden');
                toggleEduBtn.textContent = 'Hide Architecture';
            } else {
                eduContent.classList.add('hidden');
                toggleEduBtn.textContent = 'Show Architecture';
            }
        });
    }

    // Helper: HTML Escaping
    function escapeHTML(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    init();
});
