/**
 * =============================================================================
 * SecureSync – Frontend Application Logic
 * File: static/script.js
 * Description: Handles UI interactions, API calls to Flask backend, dynamic
 *              threat report rendering, and live statistics synchronization.
 * =============================================================================
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const messageInput = document.getElementById('message-input');
    const charCountEl = document.getElementById('char-count');
    const wordCountEl = document.getElementById('word-count');
    const btnScan = document.getElementById('btn-scan');
    const btnClear = document.getElementById('btn-clear');
    const btnPaste = document.getElementById('btn-paste');
    const presetsContainer = document.getElementById('presets-pills');

    // States
    const idleState = document.getElementById('idle-state');
    const loadingState = document.getElementById('loading-state');
    const resultState = document.getElementById('result-state');

    // Stats Elements
    const statTotalEl = document.getElementById('stat-total');
    const statScamEl = document.getElementById('stat-scam');
    const statLegitEl = document.getElementById('stat-legit');
    const statAccuracyEl = document.getElementById('stat-accuracy');

    // Result Elements
    const scanTimestampEl = document.getElementById('scan-timestamp');
    const primaryBanner = document.getElementById('primary-banner');
    const bannerIcon = document.getElementById('banner-icon');
    const bannerHeading = document.getElementById('banner-heading');
    const bannerSubtext = document.getElementById('banner-subtext');
    const resultClassification = document.getElementById('result-classification');
    const resultConfidence = document.getElementById('result-confidence');
    const confidenceBar = document.getElementById('confidence-bar');
    const resultRisk = document.getElementById('result-risk');
    const probRatioText = document.getElementById('prob-ratio-text');
    const probLegitBar = document.getElementById('prob-legit-bar');
    const probScamBar = document.getElementById('prob-scam-bar');
    const indicatorsList = document.getElementById('indicators-list');
    const linksSection = document.getElementById('links-section');
    const linksContainer = document.getElementById('links-container');
    const reasonsList = document.getElementById('reasons-list');

    // Educational Section Elements
    const toggleEduBtn = document.getElementById('toggle-edu-btn');
    const eduContent = document.getElementById('edu-content');
    const mAcc = document.getElementById('m-acc');
    const mPrec = document.getElementById('m-prec');
    const mRec = document.getElementById('m-rec');
    const mF1 = document.getElementById('m-f1');

    let presetCache = {};

    // -------------------------------------------------------------------------
    // 1. Initialize Page Data
    // -------------------------------------------------------------------------
    async function init() {
        await Promise.all([
            fetchStats(),
            fetchMetrics(),
            fetchSamples()
        ]);
        updateCounters();
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
                if (mAcc) mAcc.textContent = `${m.accuracy}%`;
                if (mPrec) mPrec.textContent = `${m.precision}%`;
                if (mRec) mRec.textContent = `${m.recall}%`;
                if (mF1) mF1.textContent = `${m.f1_score}%`;
                if (statAccuracyEl) statAccuracyEl.textContent = `${m.accuracy}%`;

                // Update visual confusion matrix grid
                if (m.confusion_matrix) {
                    const cmTn = document.getElementById('cm-tn');
                    const cmFp = document.getElementById('cm-fp');
                    const cmFn = document.getElementById('cm-fn');
                    const cmTp = document.getElementById('cm-tp');
                    if (cmTn) cmTn.textContent = m.confusion_matrix.true_negatives;
                    if (cmFp) cmFp.textContent = m.confusion_matrix.false_positives;
                    if (cmFn) cmFn.textContent = m.confusion_matrix.false_negatives;
                    if (cmTp) cmTp.textContent = m.confusion_matrix.true_positives;
                }

                // Render dynamic benchmark comparison table
                const modelTableBody = document.getElementById('model-comparison-table-body');
                if (modelTableBody && Array.isArray(m.model_comparison)) {
                    modelTableBody.innerHTML = '';
                    m.model_comparison.forEach(model => {
                        const tr = document.createElement('tr');
                        const isChamp = model.is_champion;
                        const statusBadge = isChamp
                            ? '<span class="severity-pill sev-low" style="background: rgba(0, 240, 255, 0.15); color: var(--cyan); border: 1px solid var(--cyan);">★ Champion</span>'
                            : '<span class="severity-pill sev-low">Candidate</span>';
                        
                        tr.innerHTML = `
                            <td><strong style="color: ${isChamp ? 'var(--cyan)' : '#ffffff'};">${escapeHTML(model.model_name)}</strong></td>
                            <td>${model.accuracy}%</td>
                            <td>${model.precision}%</td>
                            <td style="color: var(--green-safe); font-weight: 700;">${model.recall}%</td>
                            <td>${model.f1_score}%</td>
                            <td>${model.cv_f1_mean ?? model.f1_score}%</td>
                            <td>${statusBadge}</td>
                        `;
                        modelTableBody.appendChild(tr);
                    });
                }
            }
        } catch (err) {
            console.warn('Could not fetch metrics:', err);
        }
    }

    async function fetchSamples() {
        try {
            const res = await fetch('/api/samples');
            const data = await res.json();
            if (data.status === 'success' && Array.isArray(data.samples)) {
                presetsContainer.innerHTML = '';
                data.samples.forEach(sample => {
                    presetCache[sample.id] = sample.message;
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = `pill ${sample.label === 'Scam' ? 'pill-scam' : 'pill-legit'}`;
                    btn.setAttribute('data-sample', sample.id);
                    btn.textContent = `${sample.label === 'Scam' ? '🚨' : '✔'} ${sample.title}`;
                    btn.addEventListener('click', () => {
                        messageInput.value = sample.message;
                        updateCounters();
                        scanMessage();
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
        if (statScamEl) statScamEl.textContent = stats.suspicious_count ?? stats.threats_detected ?? 0;
        if (statLegitEl) statLegitEl.textContent = stats.legitimate_count ?? stats.safe_verified ?? 0;
        if (statAccuracyEl) statAccuracyEl.textContent = `${stats.model_accuracy}%`;
    }

    // -------------------------------------------------------------------------
    // 2. Textarea Character & Word Counters
    // -------------------------------------------------------------------------
    function updateCounters() {
        if (!messageInput) return;
        const text = messageInput.value;
        const charCount = text.length;
        const words = text.trim() ? text.trim().split(/\s+/).length : 0;
        if (charCountEl) charCountEl.textContent = charCount;
        if (wordCountEl) wordCountEl.textContent = words;
    }

    if (messageInput) {
        messageInput.addEventListener('input', updateCounters);
    }

    // Paste clipboard button
    if (btnPaste && messageInput) {
        btnPaste.addEventListener('click', async () => {
            try {
                const clipboardText = await navigator.clipboard.readText();
                if (clipboardText) {
                    messageInput.value = clipboardText;
                    updateCounters();
                }
            } catch (e) {
                alert('Clipboard access denied or unsupported. Please use Ctrl+V / Cmd+V to paste.');
            }
        });
    }

    // Clear button
    if (btnClear && messageInput) {
        btnClear.addEventListener('click', () => {
            messageInput.value = '';
            updateCounters();
            if (idleState) idleState.classList.remove('hidden');
            if (loadingState) loadingState.classList.add('hidden');
            if (resultState) resultState.classList.add('hidden');
            if (scanTimestampEl) scanTimestampEl.textContent = 'Standby';
            const scanIdDisplay = document.getElementById('scan-id-display');
            if (scanIdDisplay) scanIdDisplay.classList.add('hidden');
            const actionText = document.getElementById('recommended-action-text');
            if (actionText) actionText.textContent = '--';
        });
    }

    // Toggle Educational Section
    if (toggleEduBtn && eduContent) {
        toggleEduBtn.addEventListener('click', () => {
            if (eduContent.classList.contains('hidden')) {
                eduContent.classList.remove('hidden');
                toggleEduBtn.textContent = 'Hide Details';
            } else {
                eduContent.classList.add('hidden');
                toggleEduBtn.textContent = 'Show Details';
            }
        });
    }

    // Copy Scan ID Button
    const btnCopyScanId = document.getElementById('btn-copy-scan-id');
    if (btnCopyScanId) {
        btnCopyScanId.addEventListener('click', async () => {
            const scanIdText = document.getElementById('scan-id-text');
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
    // 3. Scan Message Handler
    // -------------------------------------------------------------------------
    async function scanMessage() {
        const text = messageInput.value.trim();
        if (!text) {
            alert('Please paste or type an SMS or WhatsApp message to scan.');
            messageInput.focus();
            return;
        }

        // Show loading state
        idleState.classList.add('hidden');
        resultState.classList.add('hidden');
        loadingState.classList.remove('hidden');
        btnScan.disabled = true;

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: text })
            });

            const data = await response.json();

            if (data.status === 'success') {
                renderResult(data.analysis);
                if (data.updated_stats) {
                    updateStatsUI(data.updated_stats);
                }
            } else {
                alert(`Error: ${data.message || 'Scan failed.'}`);
                idleState.classList.remove('hidden');
            }
        } catch (error) {
            console.error('Scan request error:', error);
            alert('Network error while communicating with the SecureSync backend.');
            idleState.classList.remove('hidden');
        } finally {
            loadingState.classList.add('hidden');
            btnScan.disabled = false;
        }
    }

    btnScan.addEventListener('click', scanMessage);

    // -------------------------------------------------------------------------
    // 4. Render Threat Report
    // -------------------------------------------------------------------------
    function renderResult(report) {
        resultState.classList.remove('hidden');
        scanTimestampEl.textContent = new Date().toLocaleTimeString();

        const isScam = report.is_scam;

        // Primary Banner Configuration
        if (isScam) {
            primaryBanner.className = 'alert-banner alert-scam';
            bannerIcon.innerHTML = `
                <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
            `;
            bannerHeading.textContent = "⚠ Warning: This message may be a scam.";
            bannerSubtext.textContent = "High probability of social engineering, fraudulent solicitation, or phishing.";
        } else {
            primaryBanner.className = 'alert-banner alert-legit';
            bannerIcon.innerHTML = `
                <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <polyline points="9 12 11 14 15 10"/>
                </svg>
            `;
            bannerHeading.textContent = "✔ Verified: This message appears legitimate.";
            bannerSubtext.textContent = "No deceptive indicators or known social engineering patterns detected.";
        }

        // Metrics Row
        resultClassification.textContent = report.classification;
        resultClassification.className = `metric-highlight ${isScam ? 'threat-text' : 'safe-text'}`;

        resultConfidence.textContent = `${report.confidence}%`;
        confidenceBar.style.width = `${report.confidence}%`;
        confidenceBar.style.backgroundColor = isScam ? 'var(--red-threat)' : 'var(--green-safe)';

        // Risk Level Badge
        resultRisk.textContent = report.risk_level;
        resultRisk.className = `risk-badge risk-${report.risk_level.toLowerCase()}`;

        // Probability Distribution Dual Bar
        const pLegit = report.probabilities.legitimate;
        const pScam = report.probabilities.scam;
        probRatioText.textContent = `Legitimate: ${pLegit}% | Scam: ${pScam}%`;
        probLegitBar.style.width = `${pLegit}%`;
        probScamBar.style.width = `${pScam}%`;

        // Render Scam Indicators
        indicatorsList.innerHTML = '';
        if (report.indicators && report.indicators.length > 0) {
            report.indicators.forEach(ind => {
                const card = document.createElement('div');
                card.className = 'indicator-card';
                card.innerHTML = `
                    <div class="indicator-header">
                        <span class="indicator-name">${escapeHTML(ind.name)}</span>
                        <span class="severity-pill sev-${ind.severity.toLowerCase()}">${escapeHTML(ind.severity)}</span>
                    </div>
                    <p class="indicator-desc">${escapeHTML(ind.explanation)}</p>
                `;
                indicatorsList.appendChild(card);
            });
        } else {
            indicatorsList.innerHTML = `
                <div class="no-indicators-box">
                    ✔ No known threat signatures or malicious indicators were found in this text.
                </div>
            `;
        }

        // Render Quarantined Links
        linksContainer.innerHTML = '';
        if (report.links && report.links.length > 0) {
            linksSection.classList.remove('hidden');
            report.links.forEach(l => {
                const box = document.createElement('div');
                box.className = 'link-box';

                let badgesHtml = '';
                if (l.is_shortener) {
                    badgesHtml += `<span class="flag-badge flag-alert">🚨 Shortener Disguise (${escapeHTML(l.domain)})</span>`;
                }
                if (l.brand_spoofing) {
                    badgesHtml += `<span class="flag-badge flag-alert">🚨 Suspicious Brand Impersonation</span>`;
                }
                if (l.has_suspicious_tld) {
                    badgesHtml += `<span class="flag-badge flag-alert">⚠ High-Risk TLD</span>`;
                }
                if (l.is_ip_address) {
                    badgesHtml += `<span class="flag-badge flag-alert">🚨 Raw IP Destination</span>`;
                }
                if (!badgesHtml) {
                    badgesHtml = `<span class="flag-badge flag-info">Domain: ${escapeHTML(l.domain)}</span>`;
                }

                box.innerHTML = `
                    <div class="link-defanged">${escapeHTML(l.defanged)}</div>
                    <div class="link-flags">${badgesHtml}</div>
                `;
                linksContainer.appendChild(box);
            });
        } else {
            linksSection.classList.add('hidden');
        }

        // Render Explainability Reasons
        reasonsList.innerHTML = '';
        if (report.reasons && report.reasons.length > 0) {
            report.reasons.forEach(r => {
                const li = document.createElement('li');
                li.textContent = r;
                reasonsList.appendChild(li);
            });
        }

        // Update Scan ID display & copy button
        const scanIdDisplay = document.getElementById('scan-id-display');
        const scanIdText = document.getElementById('scan-id-text');
        if (scanIdDisplay && scanIdText && report.scan_id) {
            scanIdText.textContent = report.scan_id;
            scanIdDisplay.classList.remove('hidden');
        }

        // Update Recommended Protective Action
        const actionText = document.getElementById('recommended-action-text');
        const actionBox = document.getElementById('recommended-action-box');
        if (actionText && report.recommended_action) {
            actionText.textContent = report.recommended_action;
        }
        if (actionBox) {
            actionBox.className = `recommended-action-box action-risk-${(report.risk_level || 'low').toLowerCase()}`;
        }
    }

    // -------------------------------------------------------------------------
    // 5. Workspace Tab Switching (Single vs Bulk)
    // -------------------------------------------------------------------------
    const tabSingle = document.getElementById('tab-btn-single');
    const tabBulk = document.getElementById('tab-btn-bulk');
    const singleWorkspace = document.getElementById('single-workspace');
    const bulkWorkspace = document.getElementById('bulk-workspace');

    if (tabSingle && tabBulk && singleWorkspace && bulkWorkspace) {
        tabSingle.addEventListener('click', () => {
            tabSingle.classList.add('active');
            tabBulk.classList.remove('active');
            singleWorkspace.classList.remove('hidden');
            bulkWorkspace.classList.add('hidden');
        });

        tabBulk.addEventListener('click', () => {
            tabBulk.classList.add('active');
            tabSingle.classList.remove('active');
            bulkWorkspace.classList.remove('hidden');
            singleWorkspace.classList.add('hidden');
        });
    }

    // -------------------------------------------------------------------------
    // 6. Bulk Chat Inspector Logic
    // -------------------------------------------------------------------------
    const bulkDropzone = document.getElementById('bulk-dropzone');
    const bulkFileInput = document.getElementById('bulk-file-input');
    const btnBrowseFile = document.getElementById('btn-browse-file');
    const btnLoadDemoChat = document.getElementById('btn-load-demo-chat');
    const bulkLoading = document.getElementById('bulk-loading');
    const bulkResults = document.getElementById('bulk-results');
    const bulkTableBody = document.getElementById('bulk-table-body');

    const bulkTotalEl = document.getElementById('bulk-total');
    const bulkScamsEl = document.getElementById('bulk-scams');
    const bulkLegitEl = document.getElementById('bulk-legit');
    const bulkThreatLevelEl = document.getElementById('bulk-threat-level');

    const countAllEl = document.getElementById('count-all');
    const countScamEl = document.getElementById('count-scam');
    const countLegitEl = document.getElementById('count-legit');
    const filterBtns = document.querySelectorAll('.filter-btn');
    const btnExportResults = document.getElementById('btn-export-results');

    let currentBatchResults = [];

    if (btnBrowseFile && bulkFileInput) {
        btnBrowseFile.addEventListener('click', () => bulkFileInput.click());
        bulkFileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files[0]) {
                processUploadedFile(e.target.files[0]);
            }
        });
    }

    if (bulkDropzone) {
        ['dragenter', 'dragover'].forEach(eventName => {
            bulkDropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                bulkDropzone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            bulkDropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                bulkDropzone.classList.remove('dragover');
            });
        });

        bulkDropzone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                processUploadedFile(e.dataTransfer.files[0]);
            }
        });
    }

    // Demo WhatsApp Chat Loader
    if (btnLoadDemoChat) {
        btnLoadDemoChat.addEventListener('click', async () => {
            const demoChatText = `[15/09/2026, 09:15:22] John Doe: Good morning! Are you heading to the cybersecurity lecture today?
[15/09/2026, 09:18:40] Alex: Yes, I am already near the lab. Don't forget your laptop.
[15/09/2026, 10:45:11] Unknown Contact (+1 555-019-8821): URGENT: Your Chase checking account is locked due to suspicious activity. Verify immediately at http://bit.ly/chase-lock-sec or your card will be canceled.
[15/09/2026, 11:20:05] Maria: Thanks for sharing the study notes for the operating systems midterm!
[15/09/2026, 12:05:49] Unknown Contact (+1 555-014-7722): CONGRATULATIONS! You have been selected as the winner of $50,000 Walmart voucher. Claim your prize code at http://win-walmart-voucher.com before midnight!
[15/09/2026, 13:10:18] David: Let's grab lunch at 1pm at the cafeteria.
[15/09/2026, 14:02:33] Unknown Contact (+1 555-019-3329): Hi Mom, my phone fell in the water and this is my temporary WhatsApp number. My bank app is not working and I urgently need $450 to pay for car towing. Can you send it via Zelle right now?
[15/09/2026, 15:30:12] Sarah: Class for tomorrow has been rescheduled to Hall B room 301.
[15/09/2026, 16:45:00] Unknown Contact (+1 888-555-0199): INTERNAL REVENUE SERVICE: A formal lawsuit has been registered under your SSN. Call our legal division immediately or local sheriff will execute arrest warrant.
[15/09/2026, 17:15:20] Kevin: See you guys at soccer practice this evening!`;

            const blob = new Blob([demoChatText], { type: 'text/plain' });
            const file = new File([blob], 'demo_whatsapp_chat.txt', { type: 'text/plain' });
            processUploadedFile(file);
        });
    }

    async function processUploadedFile(file) {
        if (!file) return;

        bulkLoading.classList.remove('hidden');
        bulkResults.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await fetch('/api/scan-file', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();
            if (data.status === 'success') {
                currentBatchResults = data.results || [];
                renderBulkResults(data);
                if (data.updated_stats) {
                    updateStatsUI(data.updated_stats);
                }
            } else {
                alert(`Batch scan error: ${data.message || 'Unknown error'}`);
            }
        } catch (err) {
            console.error('File scan failed:', err);
            alert('Network error while processing chat file.');
        } finally {
            bulkLoading.classList.add('hidden');
        }
    }

    function renderBulkResults(data) {
        bulkResults.classList.remove('hidden');

        const total = data.total_processed || 0;
        const scams = data.scams_detected || 0;
        const legit = data.legitimate_verified || 0;
        const threatPct = total > 0 ? Math.round((scams / total) * 100) : 0;

        if (bulkTotalEl) bulkTotalEl.textContent = total;
        if (bulkScamsEl) bulkScamsEl.textContent = scams;
        if (bulkLegitEl) bulkLegitEl.textContent = legit;
        if (bulkThreatLevelEl) {
            bulkThreatLevelEl.textContent = `${threatPct}%`;
            bulkThreatLevelEl.className = `bulk-stat-val ${threatPct > 30 ? 'threat-text' : threatPct > 0 ? 'cyan-text' : 'safe-text'}`;
        }

        if (countAllEl) countAllEl.textContent = total;
        if (countScamEl) countScamEl.textContent = scams;
        if (countLegitEl) countLegitEl.textContent = legit;

        renderFilteredTable('all');
    }

    function renderFilteredTable(filter) {
        bulkTableBody.innerHTML = '';

        const filtered = currentBatchResults.filter(item => {
            if (filter === 'scam') return item.is_scam;
            if (filter === 'legit') return !item.is_scam;
            return true;
        });

        if (filtered.length === 0) {
            bulkTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 20px; color: var(--text-muted);">No messages match the selected filter.</td></tr>`;
            return;
        }

        filtered.forEach(msg => {
            const tr = document.createElement('tr');
            
            const badgeClass = msg.is_scam ? 'status-badge-scam' : 'status-badge-legit';
            const badgeIcon = msg.is_scam ? '🚨' : '✔';
            
            let indicatorsHtml = '';
            if (msg.indicators && msg.indicators.length > 0) {
                indicatorsHtml = msg.indicators.map(ind => 
                    `<span class="severity-pill sev-${ind.severity.toLowerCase()}" style="margin-right: 4px;">${escapeHTML(ind.name)}</span>`
                ).join(' ');
            } else {
                indicatorsHtml = `<span style="font-size:0.75rem; color:var(--text-muted);">None detected</span>`;
            }

            tr.innerHTML = `
                <td>
                    <span class="status-badge ${badgeClass}">${badgeIcon} ${escapeHTML(msg.classification)}</span>
                </td>
                <td>
                    <strong style="color:#ffffff;">${escapeHTML(msg.sender)}</strong><br>
                    <small style="color:var(--text-muted); font-family:var(--font-mono);">${escapeHTML(msg.timestamp || 'Direct')}</small>
                </td>
                <td style="max-width: 320px; word-break: break-word;">
                    <span style="font-size:0.82rem;">${escapeHTML(msg.safe_display_text || msg.text)}</span>
                </td>
                <td>
                    <span class="risk-badge risk-${msg.risk_level.toLowerCase()}">${escapeHTML(msg.risk_level)}</span><br>
                    <small style="font-family:var(--font-mono); color:var(--text-secondary);">${msg.confidence}% Conf.</small>
                </td>
                <td>
                    ${indicatorsHtml}
                </td>
            `;
            bulkTableBody.appendChild(tr);
        });
    }

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const filterType = btn.getAttribute('data-filter');
            renderFilteredTable(filterType);
        });
    });

    // Export Findings Button
    if (btnExportResults) {
        btnExportResults.addEventListener('click', () => {
            if (!currentBatchResults || currentBatchResults.length === 0) {
                alert('No scan findings available to export.');
                return;
            }
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentBatchResults, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", `securesync_scan_report_${Date.now()}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        });
    }

    // -------------------------------------------------------------------------
    // 7. User Scan History Modal Logic
    // -------------------------------------------------------------------------
    const historyModal = document.getElementById('history-modal');
    const btnOpenHistory = document.getElementById('btn-open-history');
    const btnCloseHistory = document.getElementById('btn-close-history');
    const historyLoading = document.getElementById('history-loading');
    const historyTableBody = document.getElementById('history-table-body');

    if (btnOpenHistory && historyModal) {
        btnOpenHistory.addEventListener('click', async () => {
            historyModal.classList.remove('hidden');
            historyLoading.classList.remove('hidden');
            historyTableBody.innerHTML = '';

            try {
                const res = await fetch('/api/history');
                const data = await res.json();
                if (data.status === 'success' && Array.isArray(data.history)) {
                    renderHistoryTable(data.history);
                } else {
                    historyTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-muted);">No scan logs found in database.</td></tr>`;
                }
            } catch (err) {
                console.error('History fetch error:', err);
                historyTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--red-threat);">Failed to load history from database.</td></tr>`;
            } finally {
                historyLoading.classList.add('hidden');
            }
        });
    }

    if (btnCloseHistory && historyModal) {
        btnCloseHistory.addEventListener('click', () => {
            historyModal.classList.add('hidden');
        });
        historyModal.addEventListener('click', (e) => {
            if (e.target === historyModal) {
                historyModal.classList.add('hidden');
            }
        });
    }

    // Scan Details Modal Elements
    const scanDetailModal = document.getElementById('scan-detail-modal');
    const btnCloseScanDetail = document.getElementById('btn-close-scan-detail');
    const scanDetailBody = document.getElementById('scan-detail-body');
    const modalScanIdTitle = document.getElementById('modal-scan-id-title');

    if (btnCloseScanDetail && scanDetailModal) {
        btnCloseScanDetail.addEventListener('click', () => {
            scanDetailModal.classList.add('hidden');
        });
        scanDetailModal.addEventListener('click', (e) => {
            if (e.target === scanDetailModal) {
                scanDetailModal.classList.add('hidden');
            }
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
        const isScam = (s.threat_classification || s.classification || '').toLowerCase().includes('scam') || (s.risk_level || '').toUpperCase() !== 'LOW';
        const badgeClass = isScam ? 'status-badge-scam' : 'status-badge-legit';
        const badgeIcon = isScam ? '🚨' : '✔';

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
            reasonsHtml = '<li>Standard behavioral verification completed.</li>';
        }

        scanDetailBody.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:20px; padding-bottom:14px; border-bottom:1px solid var(--border-color);">
                <div>
                    <span class="status-badge ${badgeClass}" style="font-size:0.95rem; padding:6px 14px;">${badgeIcon} ${escapeHTML(s.threat_classification || s.classification)}</span>
                </div>
                <div style="display:flex; gap:16px; align-items:center;">
                    <span class="risk-badge risk-${(s.risk_level || 'low').toLowerCase()}">Risk: ${escapeHTML(s.risk_level)}</span>
                    <span style="font-family:var(--font-mono); font-weight:700; color:var(--cyan); font-size:1.1rem;">Score: ${s.risk_score ?? s.confidence}%</span>
                </div>
            </div>

            <div style="margin-bottom:18px;">
                <label style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">Submitted Message Payload</label>
                <div style="background:rgba(0,0,0,0.4); border:1px solid var(--border-color); border-radius:var(--radius-sm); padding:14px; font-family:var(--font-mono); font-size:0.85rem; color:var(--text-primary); margin-top:6px; word-break:break-word; max-height:160px; overflow-y:auto;">
                    ${escapeHTML(s.submitted_message)}
                </div>
            </div>

            <div style="margin-bottom:18px;">
                <label style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">Recommended Protective Action</label>
                <div style="background:rgba(0,240,255,0.06); border:1px solid rgba(0,240,255,0.2); border-radius:var(--radius-sm); padding:12px 14px; color:var(--text-primary); margin-top:6px; font-size:0.9rem;">
                    ${escapeHTML(s.recommended_action || 'No action required.')}
                </div>
            </div>

            <div style="margin-bottom:18px;">
                <label style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">Detection Reasons</label>
                <ul class="reasons-list" style="margin-top:6px;">
                    ${reasonsHtml}
                </ul>
            </div>

            <div>
                <label style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">Suspicious Threat Indicators</label>
                <div style="margin-top:8px;">
                    ${indListHtml}
                </div>
            </div>

            <div style="margin-top:20px; padding-top:12px; border-top:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center; font-size:0.8rem; color:var(--text-muted); font-family:var(--font-mono);">
                <span>Scan ID: ${escapeHTML(s.scan_id)}</span>
                <span>Timestamp: ${escapeHTML(s.created_at || s.scanned_at || '')}</span>
            </div>
        `;
    }

    function renderHistoryTable(items) {
        historyTableBody.innerHTML = '';
        if (items.length === 0) {
            historyTableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-muted);">No scans recorded yet. Try scanning a message!</td></tr>`;
            return;
        }

        items.forEach(h => {
            const tr = document.createElement('tr');
            const isScam = (h.classification || h.threat_classification || '').toLowerCase().includes('scam') || (h.classification || h.threat_classification || '').toLowerCase().includes('suspicious');
            const badgeClass = isScam ? 'status-badge-scam' : 'status-badge-legit';
            const badgeIcon = isScam ? '🚨' : '✔';

            tr.innerHTML = `
                <td><small style="font-family:var(--font-mono); color:var(--text-muted);">${escapeHTML(h.date || h.scanned_at || h.created_at || '')}</small></td>
                <td><code style="color:var(--cyan); font-size:0.8rem;">${escapeHTML(h.scan_id)}</code></td>
                <td><span class="risk-badge risk-${(h.risk_level || 'low').toLowerCase()}">${escapeHTML(h.risk_level || 'LOW')}</span></td>
                <td><span style="font-family:var(--font-mono); color:var(--text-primary); font-weight:700;">${h.risk_score ?? h.confidence}%</span></td>
                <td><span class="status-badge ${badgeClass}">${badgeIcon} ${escapeHTML(h.classification || h.threat_classification)}</span></td>
                <td style="max-width:240px; word-break:break-word;"><span style="font-size:0.82rem;">${escapeHTML(h.message_preview || h.submitted_message || '')}</span></td>
                <td>
                    <button type="button" class="btn-history-details" data-scan-id="${escapeHTML(h.scan_id)}" style="padding:4px 10px; font-size:0.75rem; background:rgba(0,240,255,0.1); border:1px solid rgba(0,240,255,0.3); color:var(--cyan); border-radius:4px; cursor:pointer;">
                        View
                    </button>
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

    // Helper: HTML Escaping for security against XSS
    function escapeHTML(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Run initialization
    init();
});

