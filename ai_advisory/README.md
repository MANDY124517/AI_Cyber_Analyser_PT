# 🛡️ AI Advisory: Live Threat Intel & Risk Prioritization Engine

> **Phase 2 Implementation of the AI Advisory Layer Architecture**  
> Built strictly adhering to [AI_Advisory_Layer.md](file:///c:/AI_Advisory/AI_Advisory_Layer.md) (Sections 1, 2, 5, 6, and 9).

---

## 1. Overview & Problem Solved: Busting the "CVSS Trap"

Traditional security scanners flood engineering teams with hundreds of "Critical" (CVSS 9.0+) alerts. However, empirical industry research demonstrates that **less than 4% of all CVEs are ever weaponized in the wild**. This leads to:
1. **Developer Alert Fatigue**: Engineering teams waste sprint cycles patching non-exploitable theoretical vulnerabilities.
2. **Ignored Weaponized Vulnerabilities**: Medium CVSS vulnerabilities (e.g. CVSS 5.5 - 6.5) that are actively weaponized by ransomware gangs often slip past standard SLAs.

### The Advisory Solution
This engine implements a **deterministic risk prioritization layer** powered by real-time threat intelligence:
- **FIRST.org EPSS API**: Fetches daily probability (0.0 to 1.0) and percentile of real-world exploitation in the next 30 days.
- **CISA KEV Catalog**: Identifies human-confirmed active weaponization in the wild and ransomware campaign usage.
- **CISA SSVC Decision Trees**: Categorizes vulnerabilities into actionable decision states (`ACT`, `ATTEND`, `TRACK_STAR`, `TRACK`).
- **Grounded AI Narratives**: AI does **not** compute or alter the score; it drafts executive-grade justifications citing EPSS %, KEV confirmation, and asset exposure.

---

## 2. Architecture & Separation of Concerns

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. INGESTION LAYER                                                          │
│ Raw Telemetry / Scanner Findings (CVE ID, CVSS, Asset Name, Evidence PoC)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. THREAT INTEL RETRIEVAL LAYER (Live Tool-Calling + Caching)               │
│ • FIRST.org EPSS API (epss_score, percentile)                               │
│ • CISA KEV Catalog (known exploit flag, date added, due date, ransomware)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. DETERMINISTIC PRIORITIZATION ENGINE (Mathematical Source of Truth)       │
│ • Composite Risk = (CVSS * 0.3) + (EPSS/KEV * 0.4) + (Exposure * 0.2) + ... │
│ • SSVC Decision Tree: ACT (24h) | ATTEND (72h) | TRACK_STAR (14d)           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. GROUNDED AI NARRATIVE LAYER (Advisory Explanations Only)                 │
│ • Executive Headline for Leadership                                         │
│ • Exploitability Assessment contrasting theoretical CVSS vs empirical EPSS │
│ • Prescribed SLA & Action Plan                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Directory Structure

```
ai_advisory/
├── __init__.py                # Package exports
├── models.py                  # Pydantic v2 schemas (ThreatIntel, Prioritization, Narrative)
├── pipeline.py                # End-to-end advisory orchestration
├── cli.py                     # Rich CLI for lookups and batch triage
├── README.md                  # Complete architectural documentation
├── threat_intel/
│   ├── __init__.py
│   ├── epss_client.py         # FIRST.org EPSS REST client with disk/memory caching
│   ├── cisa_kev_client.py     # CISA KEV JSON catalog client with local indexing
│   └── intel_aggregator.py    # Unified aggregator
├── prioritization/
│   ├── __init__.py
│   └── matrix.py              # Deterministic SSVC matrix & composite scoring math
├── narrative/
│   ├── __init__.py
│   ├── prompts.py             # Schema-constrained advisory prompt templates
│   └── generator.py           # Multi-backend LLM adapter + expert offline heuristic
├── data/
│   ├── sample_findings.json   # Curated enterprise benchmark dataset
│   ├── epss_cache.json        # Cached EPSS responses
│   └── cisa_kev_catalog.json  # Cached CISA KEV catalog (1,700+ entries)
└── tests/
    ├── __init__.py
    └── test_advisory.py       # Unit & integration regression tests
```

---

## 4. How to Use

### 4.1 Quick Single CVE Threat Intel Lookup
```bash
python -m ai_advisory.cli --cve CVE-2021-44228
```

### 4.2 Run Triage on Sample Benchmark Dataset
```bash
python -m ai_advisory.cli
```

### 4.3 Run Triage on Existing Scanner Dataset & Export JSON
```bash
python -m ai_advisory.cli --file Security/data/findings.json --output advisory_report.json
```

### 4.4 Run Unit Test Suite
```bash
python -m unittest ai_advisory/tests/test_advisory.py
```
