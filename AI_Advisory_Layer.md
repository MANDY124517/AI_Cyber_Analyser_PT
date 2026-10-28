# AI as an Advisory Layer for an Evidence-Based Security Platform
### Research Report — AI/GenAI Integration Strategy

---

## Executive Summary

The platform's core differentiator — proving exploitability with evidence, not just reporting possible issues — is also the design constraint for AI. The industry is already validating this split: the leading agentic pentesting platforms in 2026 (XBOW, FireCompass, Pentera, Horizon3.ai) all separate AI reasoning/exploration from a **deterministic exploit-verification layer**, because that separation is what keeps false-positive rates low (some report under 2%, vs. 40–70% for signature-based scanners). Un-separated agentic systems, by contrast, are widely reported to hallucinate findings and produce false-positive exploits.

This maps directly onto the brief: AI should sit **on top of** deterministic detection/validation, never inside the verdict path. Its job is to explain, correlate, summarize, and suggest — always traceable back to evidence the deterministic engine produced.

The recommended approach is a **hybrid architecture**: retrieval-augmented generation (RAG) grounded in your own findings/asset/evidence store plus authoritative external sources (NVD, vendor advisories, EPSS, KEV), tool-calling so the LLM fetches real data instead of recalling it from memory, small classical ML models for narrow tasks like deduplication and false-positive scoring, and a hard boundary where deterministic code — not the model — owns severity scoring, exploitability verdicts, and any offensive action.

---

## 1. Key Cybersecurity Concepts the AI Needs to Understand

The AI doesn't need to "know" cybersecurity the way an LLM knows trivia — it needs the platform to **feed it the right structured concepts** so it reasons correctly instead of guessing. These are the load-bearing ones:

**Vulnerability identity & classification**
- **CVE** (Common Vulnerabilities and Exposures) — the identifier for a known vulnerability
- **CWE** (Common Weakness Enumeration) — the *type* of flaw (e.g., CWE-89 SQL Injection), useful for grouping and remediation-pattern matching
- **CPE** (Common Platform Enumeration) — standardized naming for the affected product/version
- **CVSS** (base / temporal / environmental) — theoretical severity, not real-world risk

**Real-world risk signals (this is what separates "possible" from "proven")**
- **EPSS** (Exploit Prediction Scoring System) — probability a CVE will be exploited in the wild in the next 30 days, recalculated daily
- **CISA KEV** — binary, human-confirmed: *has this actually been exploited in the wild*
- **SSVC** (Stakeholder-Specific Vulnerability Categorization) — decision-tree style prioritization that factors in exploitation state and mission impact rather than a single score
- The consistent finding across current research: CVSS alone is a poor predictor of real exploitation — a meaningful share of confirmed-exploited (KEV-listed) CVEs carry medium CVSS scores, while many "critical" CVSS 9+ findings are never exploited. Effective prioritization blends CVSS (impact) + EPSS (likelihood) + KEV (confirmation) + your own asset/exposure context.

**Attack modeling**
- **MITRE ATT&CK** — the standard taxonomy of attacker tactics/techniques (TTPs); useful for describing *how* a chained finding could be used, and for the "next check to run" reasoning
- **Cyber Kill Chain / attack path** concepts — how individually low-severity findings chain into high-impact access (credential reuse, lateral movement, privilege escalation)
- **OWASP Top 10 / API Security Top 10 / ASVS** — the standard web/app vulnerability classes and verification levels

**Evidence & validation concepts specific to *your* platform**
- Proof-of-concept evidence (request/response pairs, screenshots, command output), confidence levels (confirmed / likely / unconfirmed), false-positive vs. false-negative, blast radius, business/data impact, and — critically — **provenance**: which scan, which tool, which timestamp, which credential level produced this finding

**Remediation & organizational context**
- Patch availability and version-fix mapping, compensating controls (WAF rules, network segmentation, config hardening), patch SLAs, risk acceptance/exception workflows, and compliance mappings (SOC 2, ISO 27001, PCI-DSS, NIST CSF) that reporting content typically needs to reference

**AI-specific security concepts (new to security teams, but essential here)**
- **Prompt injection** (OWASP LLM01:2025, the #1 ranked LLM risk two editions running) — especially the *indirect* variant, where instructions are hidden inside content the model processes rather than typed by a user. This is directly relevant to you: if your AI ever summarizes a scanned page, an HTTP response, or a file the target returned, that content is attacker-controlled and must be treated as untrusted data, never as instructions.
- **Excessive agency** (LLM06) — giving a model more autonomy/tool access than the task needs
- **Misinformation/over-reliance** (LLM09, renamed from "Overreliance" in the 2025 OWASP revision) — the risk that users trust fluent AI output without verification
- Sensitive information disclosure and system-prompt leakage — relevant because findings/evidence often contain credentials, PII, or internal architecture detail

---

## 2. Recommended AI Use Cases

Ordered roughly by build priority (see Section 8 for phasing).

| # | Use case | What it does | Why it's advisory-safe |
|---|---|---|---|
| 1 | **Finding explainer** | Turns a raw finding (CVE/CWE/evidence) into a plain-language explanation of what it is, why it matters, and how it was proven | Grounded entirely in retrieved evidence + CVE data; never asserts new facts |
| 2 | **Remediation generator** | Drafts step-by-step fix guidance, config snippets, and references tailored to the affected stack | Text output only; a human/engineer applies it, nothing auto-executes |
| 3 | **Evidence summarizer** | Compresses long scan logs / exploit chains / HTTP transcripts into a readable narrative for a report or ticket | Pure summarization of platform-generated evidence, no independent claims |
| 4 | **Finding correlation & dedup** | Groups findings that share a root cause across assets/scans (e.g., one vulnerable library instance appearing on 40 hosts) | Can start as a classical similarity/clustering model; even the LLM-assisted version only groups existing deterministic findings, doesn't create new ones |
| 5 | **Prioritization narrative** | Explains *why* a finding ranks where it does, citing CVSS + EPSS + KEV + asset criticality | The ranking/score itself stays a deterministic formula; AI narrates it, doesn't compute it independently |
| 6 | **Next-check suggester** | Given current findings (e.g., an exposed service + version), suggests additional checks worth running | Suggestion only — a human or the deterministic scan scheduler decides whether to run it |
| 7 | **Executive/report drafting** | Auto-drafts exec summaries, pentest report sections, and remediation timelines from structured findings | Draft requires human sign-off before it leaves the platform, same as a junior analyst's draft would |
| 8 | **Natural-language query over findings** | "Show me all critical, internet-facing, unpatched findings from the last 30 days" translated into a structured query | LLM only generates the query/filter; the deterministic database executes it and returns real data — the model never fabricates results |
| 9 | **Attack-path narrative** | Stitches correlated findings into a written "here's how an attacker could chain these" story, mapped to ATT&CK | Narrative only, built from already-validated findings — does not itself perform exploitation |
| 10 | **Trend & posture analysis** | Summarizes how findings/risk have changed release-over-release or month-over-month | Reads from your own historical findings store; no external claims |

**Deliberately out of scope for the AI layer:** the AI never decides a vulnerability is exploitable, never triggers or sequences an offensive test, never emits a final pass/fail verdict, and never has write access to production systems. That responsibility (and per your brief, it already sits there) stays with the deterministic engine and human reviewers.

---

## 3. Data the AI Should Be Given

Structuring this well *now* is the single highest-leverage thing you can do to make the platform "AI-ready" — an LLM is only as good as the structured context it's handed.

**Finding record** (the atomic unit): type/class, CWE, CVE (if applicable), affected asset(s), evidence artifacts (request/response, logs, screenshots, PoC steps), CVSS vector, discovery method + tool, timestamp, validation status (confirmed/unconfirmed/suspected/false-positive), confidence score, scan mode (defensive/offensive), and a unique evidence ID every AI claim can cite back to.

**Asset context**: asset type, environment (prod/staging/dev), internet-facing vs. internal, business criticality/owner, data sensitivity classification, existing compensating controls.

**Vulnerability intelligence** (external, retrieved not memorized): current NVD/CVE record, vendor advisory text, current EPSS score, CISA KEV status, patch/fix version, known PoC or exploit-kit availability.

**Historical & feedback data**: prior findings on the same asset, remediation history, analyst overrides/corrections (this becomes your training signal for the false-positive classifier and your eval regression set).

**Organizational context**: risk appetite, patch SLAs, relevant compliance frameworks, any risk-acceptance/exception records.

**Scan/test metadata**: scan type, scope, credential/access level used, coverage, tool version — needed so the AI (and reviewers) can correctly caveat confidence.

Practical implication: build a clean, structured **findings + evidence schema first**, before investing heavily in AI. Every use case above depends on it, and retrofitting structure under an LLM later is far more expensive than designing for it now.

---

## 4. Preventing Hallucinations and Incorrect Conclusions

This is the section most likely to determine whether customers trust the AI layer, so it's worth being concrete rather than aspirational.

**Ground, don't recall.** No AI output about a specific vulnerability's existence, severity, or exploitability should ever come from the model's parametric memory. Everything must be retrieved: your own evidence store (RAG) plus live lookups against NVD/EPSS/KEV/vendor advisories via tool-calling. If the retrieval returns nothing relevant, the model should say so rather than fill the gap — this needs to be enforced by prompt design *and* checked by the eval pipeline below.

**Constrain the output format.** For anything that feeds a decision (prioritization, correlation, "next check"), require the model to return structured, schema-validated JSON (finding IDs, evidence IDs, confidence) rather than free text. Free text is fine for the human-readable explanation layered on top, but the structured layer underneath should be checkable by deterministic code.

**Require citation-level traceability.** Every factual claim in an AI explanation or report draft should be traceable to a specific evidence/finding ID, shown alongside the text in the UI. Current best practice (the "RAG triad": context relevance, groundedness, answer relevance) evaluates this at the **claim level, not the answer level** — a response can score high on an averaged groundedness metric while still containing unsupported individual claims, so your automated checks should decompose responses into atomic claims and verify each one against retrieved sources.

**Never let AI override the deterministic verdict.** The exploit-validation engine's confirmed/unconfirmed status is authoritative. The AI explains and contextualizes that status; it cannot upgrade a "suspected" finding to "confirmed," or vice versa, in anything shown to a user.

**Treat scanned content as untrusted input.** Any HTTP response, page content, file, or header text pulled from a target during a scan is attacker-influenceable. If it's ever passed into a prompt (e.g., to help explain what a target application does), isolate it clearly as data, strip anything that looks like an instruction, and never let it alter the model's task or trigger tool calls. This is a direct mitigation for indirect prompt injection (OWASP LLM01), which is specifically relevant because your platform, by design, ingests content from targets it doesn't control.

**Layer automated guardrails.** Production research from 2026 consistently shows that stacking mitigations — grounding-discipline prompting, RAG retrieval, citation enforcement, and real-time output monitoring — reduces unsupported/hallucinated claims dramatically versus an unguarded deployment. No single technique is sufficient on its own; the combination is what performs.

**Keep humans in the loop where it matters.** Anything that leaves the platform as a customer-facing report, or that could inform a remediation/patch decision, should carry a clear "AI-drafted, human-reviewed" status and a required sign-off step before publication — mirroring how the offensive-testing industry already treats autonomous agents (breadth and drafting are automated; validation and sign-off stay human).

**Track hallucination as a first-class metric**, not an afterthought — see Section 7.

---

## 5. Where AI Assists vs. Where Deterministic Code Must Own the Decision

| Responsibility | Owner | Why |
|---|---|---|
| Detecting a possible issue (scanning, fingerprinting, config checks) | **Deterministic** | Repeatable, auditable, must not vary by model version |
| Proving exploitability (running the actual authorized test) | **Deterministic** | This is your core IP and trust claim — it must be reproducible evidence, not a model's opinion |
| Final severity/exploitability verdict shown to the customer | **Deterministic** | The brief is explicit: AI must not make the final security verdict |
| Triggering or sequencing offensive actions | **Deterministic**, human-authorized | Safety-critical; no AI agency here |
| Prioritization score/ranking formula | **Deterministic** (CVSS+EPSS+KEV+asset-criticality logic) | Must be consistent, explainable, and auditable independent of any LLM |
| Explaining a finding in plain language | **AI**, grounded in evidence | Adds value without changing the underlying fact |
| Drafting remediation steps / report text | **AI**, human-reviewed before publish | Speeds analysts up; human owns final wording/accuracy |
| Correlating/deduplicating findings | **Hybrid** — classical ML/embedding similarity does the grouping; AI narrates *why* | Grouping logic should be deterministic/reproducible; explanation can be generative |
| Suggesting next checks | **AI suggests, deterministic scheduler/human approves execution** | Keeps AI advisory, not actuating |
| Natural-language search over findings | **AI translates intent → query; deterministic DB executes and returns real data** | Prevents the model from ever fabricating a "finding" that doesn't exist in the store |

---

## 6. Recommended AI Architecture

**Recommendation: a hybrid, tool-augmented RAG architecture — not a single frontier-model agent, and not classical ML alone.**

```
┌─────────────────────────────────────────────────────────────────┐
│  DETERMINISTIC CORE (unchanged, remains source of truth)        │
│  Scanners → Authenticated checks → Exploit validation engine    │
│  → Structured Findings + Evidence Store  → Prioritization score │
└───────────────────────────┬───────────────────────────────────--┘
                             │ (structured, schema-validated data)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  RETRIEVAL LAYER                                                 │
│  • Vector index over your own findings/evidence/remediation      │
│    playbooks/past reports (internal RAG)                         │
│  • Live tool-calls to NVD/CVE, EPSS, CISA KEV, vendor advisories │
│  • Classical ML: embedding-similarity clustering (dedup/         │
│    correlation), supervised false-positive classifier trained    │
│    on analyst feedback, anomaly detection on posture drift       │
└───────────────────────────┬───────────────────────────────────--┘
                             │ (retrieved, cited context only)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  LLM REASONING/GENERATION LAYER (tool-using, schema-constrained) │
│  Explains, summarizes, drafts remediation/reports, suggests      │
│  next checks, answers NL queries — via function calls into the   │
│  findings DB rather than free generation                         │
└───────────────────────────┬───────────────────────────────────--┘
                             │ (text + citations back to evidence IDs)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  HUMAN REVIEW / UI LAYER                                         │
│  AI output always shown next to its source evidence; sign-off    │
│  gate before anything customer-facing is published               │
└─────────────────────────────────────────────────────────────────┘
```

**Why this combination, not a single technique:**

- **LLM alone (no retrieval)** — fluent but ungrounded; will confidently invent CVE details, patch availability, or exploit likelihood from stale/incorrect parametric knowledge. Not acceptable for a platform whose whole value proposition is proof over guesswork.
- **RAG** is the right default for anything that needs to reference specific, current facts (CVE detail, your own past findings, remediation playbooks). It grounds generation in retrieved text and is the industry-standard fix for factual hallucination — though it's worth noting RAG *grounds* the model, it doesn't fully *secure* it against prompt injection from retrieved/ingested content, hence the untrusted-input handling in Section 4.
- **Tool-calling / function-calling** matters as much as RAG here: instead of asking the model to *remember* the EPSS score or *recall* what's in the findings DB, have it call a read-only API that returns the real, current value. This closes a large share of the hallucination surface by construction.
- **Small classical ML models** remain the right tool for narrow, structured problems: embedding-similarity clustering for dedup/correlation, and a supervised classifier for false-positive likelihood trained on your analysts' historical accept/reject decisions. These are cheaper, faster, more auditable, and more accurate than asking a generative model to do structured classification.
- **Frontier LLM via API** (used for reasoning, explanation, and drafting) is preferable to self-hosting/fine-tuning at this stage — you don't yet have the labeled data volume that fine-tuning needs, and API-based frontier models are stronger at nuanced technical writing and tool use out of the box. Keep the model access behind an internal abstraction layer so you can swap providers/models without rearchitecting, and re-run your eval suite (Section 7) on every model or prompt version change before deploying it.
- **Multi-agent/fully autonomous agent architectures** (the kind now used by autonomous offensive-testing products) are explicitly *not* recommended for your advisory layer at this stage — that pattern is for autonomous action-taking, which is outside your stated scope. If you ever explore an AI-assisted read-only server-side agent, keep it strictly read-only and tool-scoped, with the same evidence-citation discipline as the rest of the layer.

**Data sensitivity note:** findings and evidence often contain credentials, internal architecture detail, or customer data. Classify and redact before anything is sent to a third-party model API; log/audit all prompts; and for customers with strict data-residency requirements, plan for a VPC-hosted or on-prem model option as a later phase rather than a v1 requirement.

---

## 7. How to Evaluate Whether the AI Is Accurate and Useful

**Build a golden evaluation set early.** Curate a set of real (or realistic) findings with analyst-approved "correct" explanations, remediation text, and correlation groupings. Run every prompt/model/retrieval change against it before deployment — this is your regression suite, not a one-time benchmark.

**Measure groundedness at the claim level, not the answer level.** Decompose each AI response into atomic factual claims and check each one against the retrieved evidence it cites. This matters because answer-level averages can look healthy (e.g., a high aggregate "groundedness" score) while a meaningful fraction of individual claims are still unsupported — claim-level scoring is what current practice recommends specifically because it catches that gap. Set a minimum per-claim support threshold before anything ships to a customer-facing report.

**Track task-specific accuracy metrics**, not just generic quality scores:
- *Finding explainer / remediation generator*: analyst edit-distance (how much a human had to change before publishing) and periodic technical-accuracy spot checks by security staff
- *Correlation/dedup*: precision/recall against analyst-labeled duplicate groups
- *Remediation*: did the suggested fix pass a validation re-scan
- *Report drafting*: time-to-publish and number of factual corrections needed per report

**Run a live human feedback loop.** Thumbs up/down plus a reason code on every AI output, feeding a quality dashboard that drives both prompt/retrieval fixes and, eventually, fine-tuning or the false-positive classifier's training data.

**Explicitly count hallucination incidents** as a tracked metric — not folded into a generic "quality" score — so regressions are visible immediately after any model, prompt, or retrieval-source change.

**Red-team the AI layer itself**, separately from red-teaming the product's offensive-testing capability: attempt indirect prompt injection through scanned content, attempt to get the model to assert an unconfirmed finding as confirmed, attempt to extract system-prompt or other findings' data across tenants. Treat this as a standing part of the security program, not a one-off exercise.

**Watch latency and cost alongside quality** — they're part of "useful" for an advisory layer analysts will use dozens of times a day.

---

## 8. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Hallucinated CVE facts, patch status, or exploit likelihood | RAG grounding against authoritative sources (NVD/vendor/EPSS/KEV) + tool-calling instead of parametric recall; claim-level groundedness checks before publish |
| Indirect prompt injection via scanned target content (malicious page/response text designed to hijack the model) | Treat all scanned/fetched content as untrusted data, never instructions; isolate it in prompts; strip control-like text; sandbox tool access so injected content can't trigger unintended tool calls |
| Automation bias — analysts over-trusting fluent AI text | Label AI output clearly as AI-generated; always show cited evidence alongside it; require human sign-off before anything customer-facing publishes |
| Sensitive data (credentials, PII, internal architecture) sent to a third-party model | Classify/redact before sending to the LLM API; audit-log prompts; offer VPC-hosted/self-hosted option for high-sensitivity customers as a later phase |
| AI-suggested remediation causing harm if acted on directly | Remediation is text-only advisory output; never auto-applied; a human or a separately-authorized deterministic workflow executes changes |
| Excessive agency — AI given more tool access/autonomy than the task needs | Scope every tool call narrowly (read-only where possible); no AI-initiated offensive actions; explicit allow-list of callable tools per use case |
| Model or prompt-version drift silently changing behavior | Version-pin models; run the full eval suite on every model/prompt change before deploying; monitor production groundedness/accuracy metrics continuously |
| Cost/latency at scale as findings volume grows | Cache repeated explanations (e.g., a CVE explained once is reusable); tiered model use — cheaper/smaller model for routine triage, frontier model for complex reasoning and drafting |
| Bias or inconsistency in prioritization narratives | Keep the prioritization score itself a deterministic formula (CVSS+EPSS+KEV+asset criticality); the AI narrates that score, never computes an independent one |
| Cross-tenant data leakage through shared retrieval/prompt context | Strict tenant isolation in the vector store and retrieval layer; per-tenant scoping enforced in code, not just prompt instructions |

---

## 9. What to Build First vs. What to Defer

**Build now (Phase 1 — advisory MVP, depends on nothing autonomous):**
1. Structured findings + evidence schema with stable evidence IDs (prerequisite for everything else)
2. RAG-grounded finding explainer, citing evidence IDs
3. Remediation-content generator (draft-only, human-reviewed)
4. Report/executive-summary drafting from structured findings
5. Classical similarity-based correlation/dedup (doesn't require an LLM at all to start)
6. Golden eval set + claim-level groundedness checks in CI, before any of the above ships

**Build next (Phase 2 — once Phase 1 data and feedback exist):**
7. Prioritization narrative layer on top of the deterministic score
8. Next-check suggester (advisory only, human/scheduler approves execution)
9. Natural-language query over findings (LLM → structured query → deterministic DB executes)
10. Supervised false-positive classifier trained on accumulated analyst feedback
11. Attack-path narrative construction across correlated findings

**Defer / keep explicitly out of scope for now:**
- Any AI-initiated or AI-sequenced offensive action
- AI as the source of the final exploitability verdict or severity score
- Fully autonomous multi-agent workflows (the pattern used by some 2026 autonomous pentesting products) — valuable elsewhere in the market, but outside your stated advisory-only scope
- Self-hosted/fine-tuned models — revisit once you have enough labeled analyst-feedback data to make fine-tuning worthwhile; start with API-based frontier models behind an abstraction layer
- Read-only server-side agent AI assistance — get the agent itself shipped and trusted as a deterministic data source first; layer AI advisory on top once its output feeds the same findings schema as everything else

---

## Appendix: Reference Frameworks and Standards

- **Vulnerability identity/severity**: CVE, CWE, CPE, CVSS (base/temporal/environmental)
- **Real-world exploitation signals**: EPSS, CISA KEV, SSVC
- **Attack modeling**: MITRE ATT&CK, Cyber Kill Chain
- **Application security baselines**: OWASP Top 10, OWASP API Security Top 10, OWASP ASVS
- **AI/LLM-specific security**: OWASP Top 10 for LLM Applications (2025 edition — prompt injection, excessive agency, misinformation/overreliance, sensitive information disclosure, system prompt leakage, unbounded consumption, etc.)
- **AI governance**: NIST AI RMF 1.0 (Govern/Map/Measure/Manage) and its Generative AI Profile, NIST AI 600-1
- **RAG evaluation**: the "RAG triad" (context relevance, groundedness, answer relevance); claim-level faithfulness/entailment scoring
- **Compliance mappings commonly referenced in reporting**: SOC 2, ISO 27001, PCI-DSS, NIST CSF
