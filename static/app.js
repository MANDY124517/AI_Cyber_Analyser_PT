// CyberTriage AI Dashboard Application Logic

let allFindings = [];
let selectedFindingId = null;
let currentFilters = {
    search: '',
    severity: 'ALL',
    category: 'ALL'
};

// DOM Elements
const findingsListEl = document.getElementById('findings-list');
const inspectorEmptyEl = document.getElementById('inspector-empty');
const inspectorContentEl = document.getElementById('inspector-content');

const valTotalFindings = document.getElementById('val-total-findings');
const valCritHigh = document.getElementById('val-crit-high');
const valAnalyzedCount = document.getElementById('val-analyzed-count');
const valAvgConfidence = document.getElementById('val-avg-confidence');
const engineStatusEl = document.getElementById('engine-status');

// Filter Elements
const filterSearchEl = document.getElementById('filter-search');
const filterCategoryEl = document.getElementById('filter-category');
const sevPillBtns = document.querySelectorAll('.sev-pill');

// Inspector Elements
const inspBadgeSev = document.getElementById('insp-badge-sev');
const inspBadgeCat = document.getElementById('insp-badge-cat');
const inspBadgeId = document.getElementById('insp-badge-id');
const inspBadgeCve = document.getElementById('insp-badge-cve');
const inspBadgeCvss = document.getElementById('insp-badge-cvss');
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
const inspConfReasoning = document.getElementById('insp-conf-reasoning');
const inspOwasp = document.getElementById('insp-owasp');
const inspMitre = document.getElementById('insp-mitre');
const inspModel = document.getElementById('insp-model');

const btnAnalyzeCurrent = document.getElementById('btn-analyze-current');
const btnAnalyzeText = document.getElementById('btn-analyze-text');
const btnBatchAnalyze = document.getElementById('btn-batch-analyze');
const btnCopyPatch = document.getElementById('btn-copy-patch');

// Modals
const sandboxModal = document.getElementById('sandbox-modal');
const btnOpenSandbox = document.getElementById('btn-open-sandbox');
const btnCloseSandbox = document.getElementById('btn-close-sandbox');
const btnCancelSandbox = document.getElementById('btn-cancel-sandbox');
const customFindingForm = document.getElementById('custom-finding-form');

const exportModal = document.getElementById('export-modal');
const btnExportMenu = document.getElementById('btn-export-menu');
const btnCloseExport = document.getElementById('btn-close-export');

// Tabs
const tabBtns = document.querySelectorAll('.tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');

// INITIALIZATION
document.addEventListener('DOMContentLoaded', () => {
    fetchFindings();
    setupEventListeners();
});

function setupEventListeners() {
    // Search & Filter
    filterSearchEl.addEventListener('input', (e) => {
        currentFilters.search = e.target.value.toLowerCase().trim();
        renderFindingsList();
    });

    filterCategoryEl.addEventListener('change', (e) => {
        currentFilters.category = e.target.value;
        renderFindingsList();
    });

    sevPillBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            sevPillBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilters.severity = btn.dataset.sev;
            renderFindingsList();
        });
    });

    // Tab Switching
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const targetPane = document.getElementById(btn.dataset.tab);
            if (targetPane) targetPane.classList.add('active');
        });
    });

    // Analyze Single Finding
    btnAnalyzeCurrent.addEventListener('click', async () => {
        if (!selectedFindingId) return;
        btnAnalyzeCurrent.disabled = true;
        btnAnalyzeText.textContent = 'Analyzing...';
        engineStatusEl.textContent = `AI Engine: Analyzing ${selectedFindingId}...`;

        try {
            const resp = await fetch(`/api/analyze/${selectedFindingId}`, { method: 'POST' });
            if (!resp.ok) throw new Error('Analysis failed');
            const enriched = await resp.json();
            
            // Update in state
            const idx = allFindings.findIndex(f => f.finding.id === selectedFindingId);
            if (idx !== -1) allFindings[idx] = enriched;

            updateKPIs();
            renderFindingsList();
            renderInspector(enriched);
            engineStatusEl.textContent = 'AI Engine: Standby / Ready';
        } catch (err) {
            console.error(err);
            alert('Failed to analyze finding. Please check server logs.');
            engineStatusEl.textContent = 'AI Engine: Error';
        } finally {
            btnAnalyzeCurrent.disabled = false;
            btnAnalyzeText.textContent = 'Re-Analyze with AI';
        }
    });

    // Batch Analyze All
    btnBatchAnalyze.addEventListener('click', async () => {
        btnBatchAnalyze.disabled = true;
        btnBatchAnalyze.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-width:2px;"></span> Analyzing Batch...';
        engineStatusEl.textContent = 'AI Engine: Batch processing in progress...';

        try {
            const resp = await fetch('/api/analyze-all', { method: 'POST' });
            if (!resp.ok) throw new Error('Batch analysis failed');
            const report = await resp.json();
            allFindings = report.findings;

            updateKPIs();
            renderFindingsList();

            if (selectedFindingId) {
                const updated = allFindings.find(f => f.finding.id === selectedFindingId);
                if (updated) renderInspector(updated);
            }
            engineStatusEl.textContent = 'AI Engine: Batch Complete (100% Analyzed)';
        } catch (err) {
            console.error(err);
            alert('Batch analysis failed.');
            engineStatusEl.textContent = 'AI Engine: Error';
        } finally {
            btnBatchAnalyze.disabled = false;
            btnBatchAnalyze.innerHTML = '<span class="btn-icon">⚡</span> Analyze All Findings';
        }
    });

    // Copy Patch to Clipboard
    btnCopyPatch.addEventListener('click', () => {
        const patchText = inspCodePatch.textContent;
        navigator.clipboard.writeText(patchText).then(() => {
            btnCopyPatch.textContent = '✅ Copied!';
            setTimeout(() => { btnCopyPatch.textContent = '📋 Copy Patch'; }, 2000);
        });
    });

    // Modals Handlers
    btnOpenSandbox.addEventListener('click', () => sandboxModal.style.display = 'flex');
    btnCloseSandbox.addEventListener('click', () => sandboxModal.style.display = 'none');
    btnCancelSandbox.addEventListener('click', () => sandboxModal.style.display = 'none');

    btnExportMenu.addEventListener('click', () => exportModal.style.display = 'flex');
    btnCloseExport.addEventListener('click', () => exportModal.style.display = 'none');

    // Custom Finding Form Submission
    customFindingForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const submitBtn = document.getElementById('btn-submit-sandbox');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Analyzing...';

        let parsedEvidence = {};
        const rawEvidenceText = document.getElementById('cust-evidence').value.trim();
        try {
            parsedEvidence = JSON.parse(rawEvidenceText);
        } catch (_) {
            parsedEvidence = { raw_payload: rawEvidenceText };
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
            if (!resp.ok) throw new Error('Failed to analyze custom finding');
            const enriched = await resp.json();
            
            allFindings.unshift(enriched);
            selectedFindingId = enriched.finding.id;

            sandboxModal.style.display = 'none';
            customFindingForm.reset();

            updateKPIs();
            renderFindingsList();
            renderInspector(enriched);
        } catch (err) {
            console.error(err);
            alert('Custom finding analysis failed.');
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span>⚡</span> Run AI Analysis';
        }
    });

    // Close modal on click outside
    window.addEventListener('click', (e) => {
        if (e.target === sandboxModal) sandboxModal.style.display = 'none';
        if (e.target === exportModal) exportModal.style.display = 'none';
    });
}

// FETCH DATA
async function fetchFindings() {
    try {
        const resp = await fetch('/api/findings');
        if (!resp.ok) throw new Error('Failed to fetch findings');
        allFindings = await resp.json();
        
        updateKPIs();
        renderFindingsList();

        // Auto-select first finding
        if (allFindings.length > 0 && !selectedFindingId) {
            selectFinding(allFindings[0].finding.id);
        }
    } catch (err) {
        console.error(err);
        findingsListEl.innerHTML = `<div class="loading-spinner-box" style="color:#ef4444;">Failed to load findings. Ensure FastAPI server is running.</div>`;
    }
}

// UPDATE KPI METRICS
function updateKPIs() {
    const total = allFindings.length;
    const critHigh = allFindings.filter(f => ['CRITICAL', 'HIGH'].includes(f.finding.severity)).length;
    const analyzed = allFindings.filter(f => f.analysis !== null).length;

    let confSum = 0;
    let confCount = 0;
    allFindings.forEach(f => {
        if (f.analysis && f.analysis.confidence_score !== undefined) {
            confSum += f.analysis.confidence_score;
            confCount++;
        }
    });

    const avgConf = confCount > 0 ? (confSum / confCount * 100).toFixed(1) : '--';

    valTotalFindings.textContent = total;
    valCritHigh.textContent = critHigh;
    valAnalyzedCount.textContent = `${analyzed} / ${total}`;
    valAvgConfidence.textContent = `${avgConf}%`;
}

// RENDER FINDINGS LIST
function renderFindingsList() {
    const filtered = allFindings.filter(item => {
        const f = item.finding;
        const matchesSev = currentFilters.severity === 'ALL' || f.severity === currentFilters.severity;
        const matchesCat = currentFilters.category === 'ALL' || f.category.toLowerCase().includes(currentFilters.category.toLowerCase());
        
        const q = currentFilters.search;
        const matchesSearch = !q || 
            f.id.toLowerCase().includes(q) ||
            f.title.toLowerCase().includes(q) ||
            f.asset.toLowerCase().includes(q) ||
            (f.cve_id && f.cve_id.toLowerCase().includes(q)) ||
            (f.endpoint && f.endpoint.toLowerCase().includes(q));

        return matchesSev && matchesCat && matchesSearch;
    });

    if (filtered.length === 0) {
        findingsListEl.innerHTML = `<div class="loading-spinner-box">No findings match the current filter criteria.</div>`;
        return;
    }

    findingsListEl.innerHTML = '';
    filtered.forEach(item => {
        const f = item.finding;
        const a = item.analysis;
        const sevClass = f.severity.toLowerCase();

        const card = document.createElement('div');
        card.className = `finding-item-card border-${sevClass} ${f.id === selectedFindingId ? 'active' : ''}`;
        card.id = `card-${f.id}`;
        card.onclick = () => selectFinding(f.id);

        const statusHtml = a 
            ? `<span class="status-chip status-analyzed">🤖 AI Ready (${Math.round(a.confidence_score * 100)}%)</span>`
            : `<span class="status-chip status-pending">⏳ Pending AI</span>`;

        card.innerHTML = `
            <div class="item-header">
                <div>
                    <span class="badge badge-${sevClass}">${f.severity}</span>
                    <span class="badge badge-id">${f.id}</span>
                </div>
                ${statusHtml}
            </div>
            <div class="item-title">${escapeHtml(f.title)}</div>
            <div class="item-asset">
                <span>🌐 ${escapeHtml(f.asset)}</span>
            </div>
        `;

        findingsListEl.appendChild(card);
    });
}

// SELECT & DISPLAY FINDING
function selectFinding(id) {
    selectedFindingId = id;
    
    // Highlight in list
    document.querySelectorAll('.finding-item-card').forEach(c => c.classList.remove('active'));
    const activeCard = document.getElementById(`card-${id}`);
    if (activeCard) activeCard.classList.add('active');

    const item = allFindings.find(f => f.finding.id === id);
    if (!item) return;

    renderInspector(item);
}

// POPULATE INSPECTOR
function renderInspector(item) {
    inspectorEmptyEl.style.display = 'none';
    inspectorContentEl.style.display = 'flex';

    const f = item.finding;
    const a = item.analysis;
    const sevClass = f.severity.toLowerCase();

    // Badges & Header
    inspBadgeSev.className = `badge badge-${sevClass}`;
    inspBadgeSev.textContent = f.severity;
    inspBadgeCat.textContent = f.category;
    inspBadgeId.textContent = f.id;

    if (f.cve_id) {
        inspBadgeCve.style.display = 'inline-block';
        inspBadgeCve.textContent = f.cve_id;
    } else {
        inspBadgeCve.style.display = 'none';
    }

    if (f.cvss_score) {
        inspBadgeCvss.style.display = 'inline-block';
        inspBadgeCvss.textContent = `CVSS ${f.cvss_score}`;
    } else {
        inspBadgeCvss.style.display = 'none';
    }

    inspTitle.textContent = f.title;
    inspAsset.textContent = f.asset;
    inspEndpoint.textContent = f.endpoint || f.component || 'N/A';
    inspTool.textContent = f.discovery_tool || 'Automated Telemetry';

    btnAnalyzeText.textContent = a ? 'Re-Analyze with AI' : 'Analyze with AI';

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

        // Priority class
        const priKey = a.suggested_priority.substring(0, 2).toLowerCase();
        inspPriority.className = `triage-val priority-${priKey}`;

        // 2. Developer View
        inspDevExplanation.textContent = a.developer_oriented_explanation;
        inspRemImmediate.textContent = a.recommended_remediation.immediate_mitigation;
        inspRemPermanent.textContent = a.recommended_remediation.permanent_fix;
        inspCodePatch.textContent = a.recommended_remediation.code_sample_patch || '# No code patch specified';
        inspRemVerification.textContent = a.recommended_remediation.verification_steps;

        // 3. Technical View
        inspExplanation.textContent = a.explanation;
        inspTechImpact.textContent = a.impact.technical_impact;
        inspEvidenceInterpretation.textContent = a.evidence_interpretation;

        // 5. Confidence & Taxonomy
        const pct = Math.round(a.confidence_score * 100);
        inspConfBar.style.width = `${pct}%`;
        inspConfScoreText.textContent = `${pct}% Confidence Score (${a.confidence_rating})`;
        inspConfReasoning.textContent = a.confidence_reasoning;
        inspOwasp.textContent = a.owasp_category || 'N/A';
        inspModel.textContent = a.model_used;

        // MITRE
        inspMitre.innerHTML = '';
        if (a.mitre_tactics_techniques && a.mitre_tactics_techniques.length > 0) {
            a.mitre_tactics_techniques.forEach(t => {
                const tag = document.createElement('span');
                tag.className = 'tag';
                tag.textContent = t;
                inspMitre.appendChild(tag);
            });
        } else {
            inspMitre.innerHTML = '<span class="tag">N/A</span>';
        }
    } else {
        // Pending state reset
        inspExecSummary.textContent = 'AI analysis has not been executed on this finding yet. Click "Analyze with AI" above.';
        inspBizImpact.textContent = 'Pending AI execution...';
        inspBlastRadius.textContent = 'Pending AI execution...';
        inspPriority.textContent = 'Pending';
        inspPriority.className = 'triage-val';
        inspEffort.textContent = 'Pending';
        inspConfidencePill.textContent = 'Pending';

        inspDevExplanation.textContent = 'Pending AI execution...';
        inspRemImmediate.textContent = 'Pending AI execution...';
        inspRemPermanent.textContent = 'Pending AI execution...';
        inspCodePatch.textContent = '# Click "Analyze with AI" to generate code patch';
        inspRemVerification.textContent = 'Pending AI execution...';

        inspExplanation.textContent = 'Pending AI execution...';
        inspTechImpact.textContent = 'Pending AI execution...';
        inspEvidenceInterpretation.textContent = 'Pending AI execution...';

        inspConfBar.style.width = '0%';
        inspConfScoreText.textContent = '0% Confidence (Pending)';
        inspConfReasoning.textContent = 'Pending AI execution...';
        inspOwasp.textContent = 'Pending';
        inspMitre.innerHTML = '<span class="tag">Pending</span>';
        inspModel.textContent = 'ai-cyber-analyzer-v1';
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
