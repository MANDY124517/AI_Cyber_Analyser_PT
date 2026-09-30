// CyberTriage Enterprise Security Operations Console Application Logic

let allFindings = [];
let selectedFindingId = null;
let currentFilters = {
    search: '',
    severity: 'ALL',
    category: 'ALL'
};

// DOM Elements: Metrics Ribbon
const valTotalFindings = document.getElementById('val-total-findings');
const valCritHigh = document.getElementById('val-crit-high');
const valCritPct = document.getElementById('val-crit-pct');
const valAnalyzedCount = document.getElementById('val-analyzed-count');
const valAvgConfidence = document.getElementById('val-avg-confidence');
const valPatchesCount = document.getElementById('val-patches-count');
const engineStatusDot = document.getElementById('engine-status-dot');
const engineStatusText = document.getElementById('engine-status-text');

// DOM Elements: Findings Queue
const findingsListEl = document.getElementById('findings-list');
const queueCountText = document.getElementById('queue-count-text');
const filterSearchEl = document.getElementById('filter-search');
const btnClearSearch = document.getElementById('btn-clear-search');
const filterCategoryEl = document.getElementById('filter-category');
const sevFilterBtns = document.querySelectorAll('.sev-filter-btn');
const btnClearQueue = document.getElementById('btn-clear-queue');

// DOM Elements: Inspector Pane
const inspectorEmptyEl = document.getElementById('inspector-empty');
const inspectorContentEl = document.getElementById('inspector-content');

const inspBadgeSev = document.getElementById('insp-badge-sev');
const inspBadgeId = document.getElementById('insp-badge-id');
const inspBadgeCat = document.getElementById('insp-badge-cat');
const inspBadgeCve = document.getElementById('insp-badge-cve');
const inspBadgeCvss = document.getElementById('insp-badge-cvss');
const inspStatusTag = document.getElementById('insp-status-tag');
const inspTitle = document.getElementById('insp-title');
const inspAsset = document.getElementById('insp-asset');
const inspEndpoint = document.getElementById('insp-endpoint');
const inspTool = document.getElementById('insp-tool');

const inspExecSummary = document.getElementById('insp-exec-summary');
const inspBizImpact = document.getElementById('insp-biz-impact');
const inspBlastRadius = document.getElementById('insp-blast-radius');
const inspPriority = document.getElementById('insp-priority');
const inspEffort = document.getElementById('insp-effort');
const inspConfidencePill = document.getElementById('insp-confidence-pill');

const inspDevExplanation = document.getElementById('insp-dev-explanation');
const inspRemImmediate = document.getElementById('insp-rem-immediate');
const inspRemPermanent = document.getElementById('insp-rem-permanent');
const inspCodePatch = document.getElementById('insp-code-patch');
const inspRemVerification = document.getElementById('insp-rem-verification');

const inspExplanation = document.getElementById('insp-explanation');
const inspTechImpact = document.getElementById('insp-tech-impact');
const inspEvidenceInterpretation = document.getElementById('insp-evidence-interpretation');
const inspRawEvidence = document.getElementById('insp-raw-evidence');

const inspConfBar = document.getElementById('insp-conf-bar');
const inspConfScoreText = document.getElementById('insp-conf-score-text');
const inspConfRatingText = document.getElementById('insp-conf-rating-text');
const inspConfReasoning = document.getElementById('insp-conf-reasoning');
const inspOwasp = document.getElementById('insp-owasp');
const inspMitre = document.getElementById('insp-mitre');
const inspModel = document.getElementById('insp-model');

// Action Buttons
const btnAnalyzeCurrent = document.getElementById('btn-analyze-current');
const btnAnalyzeText = document.getElementById('btn-analyze-text');
const btnBatchAnalyze = document.getElementById('btn-batch-analyze');
const btnBatchText = document.getElementById('btn-batch-text');
const btnCopyPatch = document.getElementById('btn-copy-patch');
const btnCopyText = document.getElementById('btn-copy-text');
const btnCopyTelemetry = document.getElementById('btn-copy-telemetry');

// Modals
const importModal = document.getElementById('import-modal');
const btnOpenImport = document.getElementById('btn-open-import');
const btnCloseImport = document.getElementById('btn-close-import');
const btnCancelImport = document.getElementById('btn-cancel-import');
const importFindingsForm = document.getElementById('import-findings-form');

const sandboxModal = document.getElementById('sandbox-modal');
const btnOpenSandbox = document.getElementById('btn-open-sandbox');
const btnCloseSandbox = document.getElementById('btn-close-sandbox');
const btnCancelSandbox = document.getElementById('btn-cancel-sandbox');
const customFindingForm = document.getElementById('custom-finding-form');

const exportModal = document.getElementById('export-modal');
const btnExportMenu = document.getElementById('btn-export-menu');
const btnCloseExport = document.getElementById('btn-close-export');

const logsModal = document.getElementById('logs-modal');
const btnOpenLogs = document.getElementById('btn-open-logs');
const btnCloseLogs = document.getElementById('btn-close-logs');
const btnRefreshLogs = document.getElementById('btn-refresh-logs');
const logsContent = document.getElementById('logs-content');

const tosModal = document.getElementById('tos-modal');
const btnOpenTos = document.getElementById('btn-open-tos');
const btnCloseTos = document.getElementById('btn-close-tos');

const privacyModal = document.getElementById('privacy-modal');
const btnOpenPrivacy = document.getElementById('btn-open-privacy');
const btnClosePrivacy = document.getElementById('btn-close-privacy');

// Tabs
const tabNavBtns = document.querySelectorAll('.tab-nav-btn');
const tabContentPanels = document.querySelectorAll('.tab-content-panel');

// INITIALIZATION
document.addEventListener('DOMContentLoaded', () => {
    fetchFindings();
    setupEventListeners();
});

function setupEventListeners() {
    // Search input
    filterSearchEl.addEventListener('input', (e) => {
        currentFilters.search = e.target.value.toLowerCase().trim();
        btnClearSearch.style.display = currentFilters.search ? 'block' : 'none';
        renderFindingsList();
    });

    btnClearSearch.addEventListener('click', () => {
        filterSearchEl.value = '';
        currentFilters.search = '';
        btnClearSearch.style.display = 'none';
        filterSearchEl.focus();
        renderFindingsList();
    });

    // Keyboard shortcut '/' to search
    document.addEventListener('keydown', (e) => {
        if (e.key === '/' && document.activeElement !== filterSearchEl && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
            e.preventDefault();
            filterSearchEl.focus();
            filterSearchEl.select();
        } else if (e.key === 'Escape') {
            closeAllModals();
        }
    });

    // Category filter
    filterCategoryEl.addEventListener('change', (e) => {
        currentFilters.category = e.target.value;
        renderFindingsList();
    });

    // Severity pills
    sevFilterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            sevFilterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilters.severity = btn.dataset.sev;
            renderFindingsList();
        });
    });

    // Clear Queue
    btnClearQueue.addEventListener('click', async () => {
        if (allFindings.length === 0) return;
        if (!confirm('Clear all findings from the active queue?')) return;
        try {
            await fetch('/api/findings', { method: 'DELETE' });
            allFindings = [];
            selectedFindingId = null;
            updateMetrics();
            renderFindingsList();
            inspectorContentEl.style.display = 'none';
            inspectorEmptyEl.style.display = 'flex';
        } catch (err) {
            console.error(err);
            alert('Failed to clear findings.');
        }
    });



    // Tab Switching
    tabNavBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabNavBtns.forEach(b => {
                b.classList.remove('active');
                b.setAttribute('aria-selected', 'false');
            });
            tabContentPanels.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            btn.setAttribute('aria-selected', 'true');
            const targetPane = document.getElementById(btn.dataset.tab);
            if (targetPane) targetPane.classList.add('active');
        });
    });

    // Analyze Single Finding
    btnAnalyzeCurrent.addEventListener('click', async () => {
        if (!selectedFindingId) return;
        setEngineStatus('busy', `Analyzing ${selectedFindingId}...`);
        btnAnalyzeCurrent.disabled = true;
        btnAnalyzeText.textContent = 'Analyzing...';

        try {
            const resp = await fetch(`/api/analyze/${selectedFindingId}`, { method: 'POST' });
            if (!resp.ok) throw new Error('Analysis pipeline execution failed');
            const enriched = await resp.json();

            // Update in local state
            const idx = allFindings.findIndex(f => f.finding.id === selectedFindingId);
            if (idx !== -1) allFindings[idx] = enriched;

            updateMetrics();
            renderFindingsList();
            renderInspector(enriched);
            setEngineStatus('idle', 'Pipeline: Ready');
        } catch (err) {
            console.error(err);
            setEngineStatus('error', 'Analysis Error');
            alert(`Analysis execution failed for ${selectedFindingId}. Check server logs.`);
        } finally {
            btnAnalyzeCurrent.disabled = false;
            btnAnalyzeText.textContent = 'Re-Analyze Finding';
        }
    });

    // Batch Analyze All
    btnBatchAnalyze.addEventListener('click', async () => {
        if (btnBatchAnalyze.disabled || allFindings.length === 0) return;
        btnBatchAnalyze.disabled = true;
        btnBatchText.textContent = 'Processing Batch...';
        setEngineStatus('busy', 'Running batch analysis...');

        try {
            const resp = await fetch('/api/analyze-all', { method: 'POST' });
            if (!resp.ok) throw new Error('Batch analysis failed');
            const report = await resp.json();
            allFindings = report.findings;

            updateMetrics();
            renderFindingsList();

            if (selectedFindingId) {
                const updated = allFindings.find(f => f.finding.id === selectedFindingId);
                if (updated) renderInspector(updated);
            }
            setEngineStatus('idle', 'Batch Complete (100% Analyzed)');
        } catch (err) {
            console.error(err);
            setEngineStatus('error', 'Batch Execution Failed');
            alert('Batch analysis request failed.');
        } finally {
            btnBatchAnalyze.disabled = false;
            btnBatchText.textContent = 'Batch Triage All';
        }
    });

    // Copy Patch
    btnCopyPatch.addEventListener('click', () => {
        const text = inspCodePatch.textContent;
        navigator.clipboard.writeText(text).then(() => {
            btnCopyText.textContent = 'Copied';
            setTimeout(() => { btnCopyText.textContent = 'Copy Patch'; }, 2000);
        });
    });

    // Copy Telemetry
    btnCopyTelemetry.addEventListener('click', () => {
        const text = inspRawEvidence.textContent;
        navigator.clipboard.writeText(text).then(() => {
            btnCopyTelemetry.textContent = 'Copied JSON';
            setTimeout(() => { btnCopyTelemetry.textContent = 'Copy JSON'; }, 2000);
        });
    });

    // Import Findings JSON Form
    importFindingsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const submitBtn = document.getElementById('btn-submit-import');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Ingesting...';

        const rawJson = document.getElementById('import-json-text').value.trim();
        let parsedList = [];
        try {
            const parsed = JSON.parse(rawJson);
            parsedList = Array.isArray(parsed) ? parsed : [parsed];
        } catch (err) {
            alert('Invalid JSON: ' + err.message);
            submitBtn.disabled = false;
            submitBtn.textContent = 'Ingest Findings';
            return;
        }

        try {
            const resp = await fetch('/api/findings/import', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(parsedList)
            });
            if (!resp.ok) throw new Error('Failed to import findings');
            const data = await resp.json();
            
            importModal.style.display = 'none';
            importFindingsForm.reset();
            await fetchFindings();
        } catch (err) {
            console.error(err);
            alert('Import failed: ' + err.message);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Ingest Findings';
        }
    });

    // Custom Finding Form
    customFindingForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const submitBtn = document.getElementById('btn-submit-sandbox');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Processing...';

        let parsedEvidence = {};
        const rawText = document.getElementById('cust-evidence').value.trim();
        try {
            parsedEvidence = JSON.parse(rawText);
        } catch (_) {
            parsedEvidence = { raw_payload: rawText };
        }

        const payload = {
            title: document.getElementById('cust-title').value.trim(),
            category: document.getElementById('cust-category').value.trim(),
            severity: document.getElementById('cust-severity').value,
            asset: document.getElementById('cust-asset').value.trim(),
            endpoint: document.getElementById('cust-endpoint').value.trim() || null,
            cve_id: document.getElementById('cust-cve').value.trim() || null,
            evidence: parsedEvidence
        };

        try {
            const resp = await fetch('/api/analyze-custom', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!resp.ok) throw new Error('Custom finding submission failed');
            const enriched = await resp.json();

            allFindings.unshift(enriched);
            selectedFindingId = enriched.finding.id;

            sandboxModal.style.display = 'none';
            customFindingForm.reset();

            updateMetrics();
            renderFindingsList();
            renderInspector(enriched);
        } catch (err) {
            console.error(err);
            alert('Custom finding analysis failed. Check server logs.');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Run Triage';
        }
    });

    // Modal Triggers
    btnOpenImport.addEventListener('click', () => openModal(importModal));
    btnCloseImport.addEventListener('click', () => closeModal(importModal));
    btnCancelImport.addEventListener('click', () => closeModal(importModal));

    btnOpenSandbox.addEventListener('click', () => openModal(sandboxModal));
    btnCloseSandbox.addEventListener('click', () => closeModal(sandboxModal));
    btnCancelSandbox.addEventListener('click', () => closeModal(sandboxModal));

    btnExportMenu.addEventListener('click', () => openModal(exportModal));
    btnCloseExport.addEventListener('click', () => closeModal(exportModal));

    btnOpenLogs.addEventListener('click', () => {
        openModal(logsModal);
        fetchLogs();
    });
    btnCloseLogs.addEventListener('click', () => closeModal(logsModal));
    btnRefreshLogs.addEventListener('click', fetchLogs);

    btnOpenTos.addEventListener('click', () => openModal(tosModal));
    btnCloseTos.addEventListener('click', () => closeModal(tosModal));

    btnOpenPrivacy.addEventListener('click', () => openModal(privacyModal));
    btnClosePrivacy.addEventListener('click', () => closeModal(privacyModal));

    // Close on backdrop click
    [importModal, sandboxModal, exportModal, logsModal, tosModal, privacyModal].forEach(modal => {
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) closeModal(modal);
            });
        }
    });
}

function openModal(modal) {
    if (modal) modal.style.display = 'flex';
}

function closeModal(modal) {
    if (modal) modal.style.display = 'none';
}

function closeAllModals() {
    [importModal, sandboxModal, exportModal, logsModal, tosModal, privacyModal].forEach(m => {
        if (m) m.style.display = 'none';
    });
}

function setEngineStatus(state, message) {
    engineStatusDot.className = `status-dot ${state}`;
    engineStatusText.textContent = message;
}

// FETCH FINDINGS
async function fetchFindings() {
    try {
        const resp = await fetch('/api/findings');
        if (!resp.ok) throw new Error('Failed to fetch findings');
        allFindings = await resp.json();

        updateMetrics();
        renderFindingsList();

        if (allFindings.length > 0) {
            if (!selectedFindingId || !allFindings.some(f => f.finding.id === selectedFindingId)) {
                selectFinding(allFindings[0].finding.id);
            }
        } else {
            selectedFindingId = null;
            inspectorContentEl.style.display = 'none';
            inspectorEmptyEl.style.display = 'flex';
        }
    } catch (err) {
        console.error(err);
        findingsListEl.innerHTML = `
            <div style="padding: 16px; color: var(--sev-critical-text); font-size: 11px; text-align: center;">
                Unable to load findings. Ensure FastAPI server is listening on port 8000.
            </div>
        `;
        setEngineStatus('error', 'Server Unreachable');
    }
}

// FETCH LOGS
async function fetchLogs() {
    logsContent.textContent = 'Fetching latest server logs...';
    try {
        const resp = await fetch('/api/logs?limit=150');
        if (!resp.ok) throw new Error('Failed to retrieve logs');
        const data = await resp.json();
        if (data.logs && data.logs.length > 0) {
            logsContent.textContent = data.logs.join('\n');
            logsContent.scrollTop = logsContent.scrollHeight;
        } else {
            logsContent.textContent = 'No server log entries recorded yet.';
        }
    } catch (err) {
        logsContent.textContent = 'Failed to load logs: ' + err.message;
    }
}

// UPDATE METRICS RIBBON
function updateMetrics() {
    const total = allFindings.length;
    const critHigh = allFindings.filter(f => ['CRITICAL', 'HIGH'].includes(f.finding.severity.toUpperCase())).length;
    const analyzed = allFindings.filter(f => f.analysis !== null).length;
    const patches = allFindings.filter(f => f.analysis && f.analysis.recommended_remediation && f.analysis.recommended_remediation.code_sample_patch).length;

    let confSum = 0;
    let confCount = 0;
    allFindings.forEach(f => {
        if (f.analysis && f.analysis.confidence_score !== undefined) {
            confSum += f.analysis.confidence_score;
            confCount++;
        }
    });

    const avgConf = confCount > 0 ? (confSum / confCount * 100).toFixed(1) : '--';
    const critPct = total > 0 ? Math.round((critHigh / total) * 100) : 0;

    valTotalFindings.textContent = total;
    valCritHigh.textContent = critHigh;
    valCritPct.textContent = `${critPct}% of total`;
    valAnalyzedCount.textContent = `${analyzed} / ${total}`;
    valAvgConfidence.textContent = avgConf !== '--' ? `${avgConf}%` : '--%';
    valPatchesCount.textContent = patches;
}

// RENDER FINDINGS LIST
function renderFindingsList() {
    if (allFindings.length === 0) {
        queueCountText.textContent = 'Queue is empty (0 findings)';
        findingsListEl.innerHTML = `
            <div style="padding: 24px 16px; color: var(--text-muted); font-size: 11.5px; text-align: center; display: flex; flex-direction: column; gap: 8px; align-items: center;">
                <p>No active security findings in queue.</p>
                <div style="display: flex; gap: 6px;">
                    <button class="btn btn-secondary btn-xs" onclick="document.getElementById('btn-open-import').click()">Import JSON</button>
                    <button class="btn btn-secondary btn-xs" onclick="document.getElementById('btn-open-sandbox').click()">Custom Finding</button>
                </div>
            </div>
        `;
        return;
    }

    const filtered = allFindings.filter(item => {
        const f = item.finding;
        const sevMatch = currentFilters.severity === 'ALL' || f.severity.toUpperCase() === currentFilters.severity;
        const catMatch = currentFilters.category === 'ALL' || f.category.toLowerCase().includes(currentFilters.category.toLowerCase());

        const q = currentFilters.search;
        const searchMatch = !q ||
            f.id.toLowerCase().includes(q) ||
            f.title.toLowerCase().includes(q) ||
            f.asset.toLowerCase().includes(q) ||
            (f.cve_id && f.cve_id.toLowerCase().includes(q)) ||
            (f.endpoint && f.endpoint.toLowerCase().includes(q));

        return sevMatch && catMatch && searchMatch;
    });

    queueCountText.textContent = `Showing ${filtered.length} of ${allFindings.length} findings`;

    if (filtered.length === 0) {
        findingsListEl.innerHTML = `
            <div style="padding: 24px 16px; color: var(--text-muted); font-size: 11.5px; text-align: center;">
                No findings match the applied filter criteria.
            </div>
        `;
        return;
    }

    findingsListEl.innerHTML = '';
    filtered.forEach(item => {
        const f = item.finding;
        const a = item.analysis;
        const sevLower = f.severity.toLowerCase();

        const card = document.createElement('div');
        card.className = `finding-card ${f.id === selectedFindingId ? 'active' : ''}`;
        card.id = `card-${f.id}`;
        card.onclick = () => selectFinding(f.id);

        const statusTag = a
            ? `<span class="status-indicator-tag status-analyzed">Triage Complete (${Math.round(a.confidence_score * 100)}%)</span>`
            : `<span class="status-indicator-tag status-pending">Pending AI</span>`;

        card.innerHTML = `
            <div class="card-top-row">
                <div style="display: flex; align-items: center; gap: 5px;">
                    <span class="badge badge-${sevLower}">${escapeHtml(f.severity)}</span>
                    <span class="card-id-tag">${escapeHtml(f.id)}</span>
                </div>
                ${statusTag}
            </div>
            <div class="card-title">${escapeHtml(f.title)}</div>
            <div class="card-footer-meta">
                <div class="card-asset">
                    <span class="icon"><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></span>
                    <span>${escapeHtml(f.asset)}</span>
                </div>
                <span>${escapeHtml(f.category)}</span>
            </div>
        `;

        findingsListEl.appendChild(card);
    });
}

// SELECT FINDING
function selectFinding(id) {
    selectedFindingId = id;

    // Highlight active card
    document.querySelectorAll('.finding-card').forEach(c => c.classList.remove('active'));
    const activeCard = document.getElementById(`card-${id}`);
    if (activeCard) activeCard.classList.add('active');

    const item = allFindings.find(f => f.finding.id === id);
    if (!item) return;

    renderInspector(item);
}

// RENDER INSPECTOR DETAILS
function renderInspector(item) {
    inspectorEmptyEl.style.display = 'none';
    inspectorContentEl.style.display = 'flex';

    const f = item.finding;
    const a = item.analysis;
    const sevLower = f.severity.toLowerCase();

    // Header Badges
    inspBadgeSev.className = `badge badge-${sevLower}`;
    inspBadgeSev.textContent = f.severity;
    inspBadgeId.textContent = f.id;
    inspBadgeCat.textContent = f.category;

    if (f.cve_id) {
        inspBadgeCve.style.display = 'inline-flex';
        inspBadgeCve.textContent = f.cve_id;
    } else {
        inspBadgeCve.style.display = 'none';
    }

    if (f.cvss_score) {
        inspBadgeCvss.style.display = 'inline-flex';
        inspBadgeCvss.textContent = `CVSS ${f.cvss_score}`;
    } else {
        inspBadgeCvss.style.display = 'none';
    }

    if (a) {
        inspStatusTag.className = 'status-indicator-tag status-analyzed';
        inspStatusTag.textContent = 'Analysis Complete';
        btnAnalyzeText.textContent = 'Re-Analyze Finding';
    } else {
        inspStatusTag.className = 'status-indicator-tag status-pending';
        inspStatusTag.textContent = 'Analysis Pending';
        btnAnalyzeText.textContent = 'Run AI Analysis';
    }

    inspTitle.textContent = f.title;
    inspAsset.textContent = f.asset;
    inspEndpoint.textContent = f.endpoint || f.component || 'N/A';
    inspTool.textContent = f.discovery_tool || 'Automated Telemetry';

    // Raw Telemetry JSON
    inspRawEvidence.textContent = JSON.stringify(f.evidence, null, 2);

    if (a) {
        // 1. Executive View
        inspExecSummary.textContent = a.executive_summary;
        inspBizImpact.textContent = a.impact.business_impact;
        inspBlastRadius.textContent = a.impact.blast_radius;
        inspPriority.textContent = a.suggested_priority;
        inspEffort.textContent = a.remediation_effort;
        inspConfidencePill.textContent = `${Math.round(a.confidence_score * 100)}% (${a.confidence_rating})`;

        // 2. Developer View
        inspDevExplanation.textContent = a.developer_oriented_explanation;
        inspRemImmediate.textContent = a.recommended_remediation.immediate_mitigation;
        inspRemPermanent.textContent = a.recommended_remediation.permanent_fix;
        inspCodePatch.textContent = a.recommended_remediation.code_sample_patch || '# No code patch specified for this finding';
        inspRemVerification.textContent = a.recommended_remediation.verification_steps;

        // 3. Technical View
        inspExplanation.textContent = a.explanation;
        inspTechImpact.textContent = a.impact.technical_impact;
        inspEvidenceInterpretation.textContent = a.evidence_interpretation;

        // 5. Confidence & Taxonomy
        const pct = Math.round(a.confidence_score * 100);
        inspConfBar.style.width = `${pct}%`;
        inspConfScoreText.textContent = `${pct}% Confidence Score`;
        inspConfRatingText.textContent = `Rating: ${a.confidence_rating}`;
        inspConfReasoning.textContent = a.confidence_reasoning;
        inspOwasp.textContent = a.owasp_category || 'N/A';
        inspModel.textContent = a.model_used || 'ai-cyber-analyzer-v1';

        inspMitre.innerHTML = '';
        if (a.mitre_tactics_techniques && a.mitre_tactics_techniques.length > 0) {
            a.mitre_tactics_techniques.forEach(t => {
                const tag = document.createElement('span');
                tag.className = 'taxonomy-pill';
                tag.textContent = t;
                inspMitre.appendChild(tag);
            });
        } else {
            inspMitre.innerHTML = '<span class="taxonomy-pill">N/A</span>';
        }
    } else {
        // Reset to pending
        inspExecSummary.textContent = 'Analysis has not been run for this finding. Click "Run AI Analysis" above to execute triage.';
        inspBizImpact.textContent = 'Pending analysis...';
        inspBlastRadius.textContent = 'Pending analysis...';
        inspPriority.textContent = 'Pending';
        inspEffort.textContent = 'Pending';
        inspConfidencePill.textContent = 'Pending';

        inspDevExplanation.textContent = 'Pending analysis...';
        inspRemImmediate.textContent = 'Pending analysis...';
        inspRemPermanent.textContent = 'Pending analysis...';
        inspCodePatch.textContent = '# Click "Run AI Analysis" to generate actionable code patch';
        inspRemVerification.textContent = 'Pending analysis...';

        inspExplanation.textContent = 'Pending analysis...';
        inspTechImpact.textContent = 'Pending analysis...';
        inspEvidenceInterpretation.textContent = 'Pending analysis...';

        inspConfBar.style.width = '0%';
        inspConfScoreText.textContent = '0% Confidence Score';
        inspConfRatingText.textContent = 'Rating: PENDING';
        inspConfReasoning.textContent = 'Pending analysis...';
        inspOwasp.textContent = 'Pending';
        inspMitre.innerHTML = '<span class="taxonomy-pill">Pending</span>';
        inspModel.textContent = 'ai-cyber-analyzer-v1';
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
