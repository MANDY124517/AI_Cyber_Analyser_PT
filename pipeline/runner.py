import json
import os
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime

from models import SecurityFinding, FindingAnalysis, EnrichedFinding, BatchReport, BatchReportMetrics
from pipeline.ai_engine import CybersecurityAIEngine


class FindingsPipelineRunner:
    """Pipeline orchestrator for loading findings, running AI analysis, and generating reports."""

    def __init__(self, data_path: str = "data/findings.json", provider: Optional[str] = None):
        self.data_path = data_path
        self.engine = CybersecurityAIEngine(provider=provider)
        self.cached_findings: List[SecurityFinding] = []
        self.enriched_results: List[EnrichedFinding] = []

    def load_findings(self) -> List[SecurityFinding]:
        """Load raw findings from disk."""
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"Dataset not found at {self.data_path}")
        with open(self.data_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        self.cached_findings = [SecurityFinding.model_validate(item) for item in raw_data]
        return self.cached_findings

    async def analyze_single(self, finding: SecurityFinding) -> EnrichedFinding:
        """Run AI processing on a single finding."""
        analysis = await self.engine.analyze_finding(finding)
        return EnrichedFinding(finding=finding, analysis=analysis)

    async def run_batch(self, findings: Optional[List[SecurityFinding]] = None, max_concurrency: Optional[int] = None) -> BatchReport:
        """Run full AI analysis pipeline over findings and compute aggregate report."""
        targets = findings or (self.cached_findings if self.cached_findings else self.load_findings())
        
        # Optimize local hardware: Ollama runs best with concurrency 1 to avoid VRAM overload / 500 errors
        if max_concurrency is None:
            if self.engine.provider == "ollama":
                max_concurrency = int(os.getenv("OLLAMA_CONCURRENCY", "1"))
            else:
                max_concurrency = int(os.getenv("BATCH_CONCURRENCY", "3"))

        sem = asyncio.Semaphore(max_concurrency)

        async def _bounded_analyze(f: SecurityFinding) -> EnrichedFinding:
            async with sem:
                return await self.analyze_single(f)

        tasks = [_bounded_analyze(f) for f in targets]
        self.enriched_results = await asyncio.gather(*tasks)
        return self.compile_report(self.enriched_results)

    def compile_report(self, enriched: List[EnrichedFinding]) -> BatchReport:
        """Calculate metrics and assemble BatchReport."""
        total = len(enriched)
        analyzed = sum(1 for e in enriched if e.analysis is not None)
        
        sev_counts: Dict[str, int] = {}
        pri_counts: Dict[str, int] = {}
        cat_counts: Dict[str, int] = {}
        effort_counts: Dict[str, int] = {}
        total_conf = 0.0
        crit_high = 0

        for item in enriched:
            sev = item.finding.severity
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev in ["CRITICAL", "HIGH"]:
                crit_high += 1

            cat = item.finding.category
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

            if item.analysis:
                pri = item.analysis.suggested_priority
                pri_counts[pri] = pri_counts.get(pri, 0) + 1

                eff = item.analysis.remediation_effort
                effort_counts[eff] = effort_counts.get(eff, 0) + 1

                total_conf += item.analysis.confidence_score

        avg_conf = round(total_conf / analyzed, 3) if analyzed > 0 else 0.0

        metrics = BatchReportMetrics(
            total_findings=total,
            analyzed_findings=analyzed,
            severity_breakdown=sev_counts,
            priority_breakdown=pri_counts,
            category_breakdown=cat_counts,
            average_confidence=avg_conf,
            critical_or_high_count=crit_high,
            remediation_effort_breakdown=effort_counts
        )

        return BatchReport(
            metrics=metrics,
            findings=enriched
        )

    def export_json(self, report: BatchReport, filepath: str = "report_output.json") -> str:
        """Export report as structured JSON."""
        data = report.model_dump(mode="json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return filepath

    def export_markdown(self, report: BatchReport) -> str:
        """Export report in comprehensive Markdown format."""
        m = report.metrics
        lines = [
            f"# {report.report_title}",
            f"*Generated on: {report.generated_at}*",
            "",
            "## Executive Summary & Metrics",
            "",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| **Total Findings** | {m.total_findings} |",
            f"| **Critical & High Severity** | {m.critical_or_high_count} |",
            f"| **Average AI Confidence** | {m.average_confidence * 100:.1f}% |",
            f"| **Analyzed Findings** | {m.analyzed_findings} / {m.total_findings} |",
            "",
            "### Severity Breakdown",
            "".join([f"- **{k}**: {v}\n" for k, v in m.severity_breakdown.items()]),
            "",
            "### Priority Breakdown",
            "".join([f"- **{k}**: {v}\n" for k, v in m.priority_breakdown.items()]),
            "",
            "---",
            "",
            "## Detailed Findings & AI Assessments",
            ""
        ]

        for item in report.findings:
            f = item.finding
            a = item.analysis
            lines.append(f"### [{f.id}] {f.title}")
            lines.append(f"- **Severity**: `{f.severity}` | **Category**: `{f.category}` | **Asset**: `{f.asset}`")
            if f.cve_id:
                lines.append(f"- **CVE**: `{f.cve_id}` (CVSS: {f.cvss_score})")
            lines.append(f"- **Endpoint / Component**: `{f.endpoint or f.component}`")
            lines.append("")

            if a:
                lines.append("#### Executive Overview")
                lines.append(f"> {a.executive_summary}")
                lines.append("")
                lines.append(f"**Suggested Priority**: `{a.suggested_priority}` | **Remediation Effort**: `{a.remediation_effort}` | **Confidence**: `{a.confidence_score * 100:.0f}% ({a.confidence_rating})`")
                lines.append(f"*{a.confidence_reasoning}*")
                lines.append("")
                lines.append("#### Technical Analysis & Impact")
                lines.append(f"- **Explanation**: {a.explanation}")
                lines.append(f"- **Technical Impact**: {a.impact.technical_impact}")
                lines.append(f"- **Business Impact**: {a.impact.business_impact}")
                lines.append(f"- **Blast Radius**: {a.impact.blast_radius}")
                lines.append(f"- **Evidence Interpretation**: {a.evidence_interpretation}")
                lines.append("")
                lines.append("#### Developer Explanation & Remediation")
                lines.append(f"**Developer Context**: {a.developer_oriented_explanation}")
                lines.append("")
                lines.append(f"**Immediate Mitigation**: {a.recommended_remediation.immediate_mitigation}")
                lines.append(f"**Permanent Fix**: {a.recommended_remediation.permanent_fix}")
                if a.recommended_remediation.code_sample_patch:
                    lines.append("\n**Code Patch / Configuration:**")
                    lines.append("```")
                    lines.append(a.recommended_remediation.code_sample_patch)
                    lines.append("```")
                lines.append(f"**Verification Steps**: {a.recommended_remediation.verification_steps}")
                lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def export_html(self, report: BatchReport) -> str:
        """Generate a sleek, standalone HTML report."""
        m = report.metrics
        cards_html = ""

        for item in report.findings:
            f = item.finding
            a = item.analysis
            sev_class = f.severity.lower()

            code_block = ""
            if a and a.recommended_remediation.code_sample_patch:
                code_block = f"""
                <div class="code-box">
                    <div class="code-title">Remediation Patch / Config</div>
                    <pre><code>{a.recommended_remediation.code_sample_patch.replace('<', '&lt;').replace('>', '&gt;')}</code></pre>
                </div>
                """

            analysis_body = ""
            if a:
                analysis_body = f"""
                <div class="exec-card">
                    <strong>Executive Summary:</strong> {a.executive_summary}
                </div>
                <div class="grid-2">
                    <div>
                        <h4>Technical Explanation</h4>
                        <p>{a.explanation}</p>
                        <h4>Evidence Interpretation</h4>
                        <p>{a.evidence_interpretation}</p>
                    </div>
                    <div>
                        <h4>Developer Guidance</h4>
                        <p>{a.developer_oriented_explanation}</p>
                        <h4>Impact Breakdown</h4>
                        <p><strong>Technical:</strong> {a.impact.technical_impact}</p>
                        <p><strong>Business:</strong> {a.impact.business_impact}</p>
                    </div>
                </div>
                <div class="remediation-section">
                    <h4>Remediation Plan</h4>
                    <p><strong>Immediate:</strong> {a.recommended_remediation.immediate_mitigation}</p>
                    <p><strong>Permanent:</strong> {a.recommended_remediation.permanent_fix}</p>
                    {code_block}
                    <p><strong>Verification:</strong> {a.recommended_remediation.verification_steps}</p>
                </div>
                """

            cards_html += f"""
            <div class="finding-card border-{sev_class}">
                <div class="card-header">
                    <div>
                        <span class="badge badge-{sev_class}">{f.severity}</span>
                        <span class="badge badge-cat">{f.category}</span>
                        <span class="badge badge-id">{f.id}</span>
                        {f'<span class="badge badge-cve">{f.cve_id}</span>' if f.cve_id else ''}
                    </div>
                    <div class="conf-badge">
                        Confidence: <strong>{int(a.confidence_score * 100) if a else 0}%</strong>
                    </div>
                </div>
                <h3 class="finding-title">{f.title}</h3>
                <div class="finding-meta">
                    <span><strong>Asset:</strong> {f.asset}</span>
                    <span><strong>Endpoint:</strong> {f.endpoint or f.component or 'N/A'}</span>
                    <span><strong>Priority:</strong> {a.suggested_priority if a else 'Pending'}</span>
                </div>
                {analysis_body}
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.report_title}</title>
    <style>
        :root {{
            --bg: #090d14;
            --surface: #111827;
            --surface-card: #151f32;
            --border: #1e2a3e;
            --border-medium: #2a3b56;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #2563eb;
            --crit-text: #fca5a5;
            --crit-bg: rgba(220, 38, 38, 0.16);
            --crit-border: rgba(239, 68, 68, 0.45);
            --high-text: #fdba74;
            --high-bg: rgba(234, 88, 12, 0.16);
            --high-border: rgba(249, 115, 22, 0.45);
            --med-text: #fde047;
            --med-bg: rgba(202, 138, 4, 0.16);
            --med-border: rgba(234, 179, 8, 0.45);
            --low-text: #93c5fd;
            --low-bg: rgba(37, 99, 235, 0.16);
            --low-border: rgba(59, 130, 246, 0.45);
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 24px;
            font-size: 13px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3, h4 {{ color: #ffffff; margin-top: 0; font-weight: 700; }}
        .header {{ border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
        .kpi-card {{ background: var(--surface); border: 1px solid var(--border); padding: 14px 16px; border-radius: 4px; }}
        .kpi-val {{ font-size: 22px; font-weight: 700; color: #ffffff; font-family: monospace; }}
        .kpi-label {{ color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 2px; }}
        .finding-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 16px; margin-bottom: 16px; }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .badge {{ padding: 2px 6px; border-radius: 2px; font-size: 10px; font-weight: 700; text-transform: uppercase; font-family: monospace; margin-right: 6px; }}
        .badge-critical {{ background: var(--crit-bg); color: var(--crit-text); border: 1px solid var(--crit-border); }}
        .badge-high {{ background: var(--high-bg); color: var(--high-text); border: 1px solid var(--high-border); }}
        .badge-medium {{ background: var(--med-bg); color: var(--med-text); border: 1px solid var(--med-border); }}
        .badge-low {{ background: var(--low-bg); color: var(--low-text); border: 1px solid var(--low-border); }}
        .badge-cat {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
        .badge-id {{ background: #0c121d; color: #f8fafc; border: 1px solid var(--border); font-family: monospace; }}
        .badge-cve {{ background: #2a1215; color: #fca5a5; border: 1px solid #5c1d24; }}
        .conf-badge {{ font-size: 11px; color: var(--text-muted); font-family: monospace; }}
        .finding-title {{ font-size: 14px; margin-bottom: 6px; }}
        .finding-meta {{ display: flex; gap: 16px; color: var(--text-muted); font-size: 11px; margin-bottom: 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
        .finding-meta strong {{ color: var(--text); }}
        .exec-card {{ background: var(--surface-card); border: 1px solid var(--border-medium); padding: 10px 14px; margin-bottom: 12px; border-radius: 4px; font-size: 12px; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 12px; }}
        .grid-2 p {{ margin: 4px 0 10px 0; font-size: 12px; color: #cbd5e1; }}
        .remediation-section {{ background: var(--surface-card); padding: 12px 14px; border-radius: 4px; border: 1px solid var(--border); font-size: 12px; }}
        .remediation-section p {{ margin: 4px 0 8px 0; color: #cbd5e1; }}
        .code-box {{ background: #070a10; border: 1px solid var(--border-medium); border-radius: 4px; padding: 10px; margin: 8px 0; font-family: monospace; font-size: 11px; overflow-x: auto; color: #93c5fd; }}
        .code-title {{ color: var(--text-muted); font-size: 10px; text-transform: uppercase; margin-bottom: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{report.report_title}</h1>
            <p style="color: var(--text-muted); font-size: 12px;">Generated: {report.generated_at} &bull; Security Operations Report</p>
        </div>
        
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-val">{m.total_findings}</div>
                <div class="kpi-label">Total Findings</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-val">{m.critical_or_high_count}</div>
                <div class="kpi-label">Critical & High</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-val">{m.average_confidence * 100:.1f}%</div>
                <div class="kpi-label">Average Confidence</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-val">{m.analyzed_findings}</div>
                <div class="kpi-label">AI Analyzed</div>
            </div>
        </div>

        <h2 style="font-size: 16px; margin-bottom: 14px;">Security Findings Matrix</h2>
        {cards_html}
    </div>
</body>
</html>
"""
        return html
