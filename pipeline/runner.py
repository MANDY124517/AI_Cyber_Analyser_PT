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

    async def run_batch(self, findings: Optional[List[SecurityFinding]] = None, max_concurrency: int = 3) -> BatchReport:
        """Run full AI analysis pipeline over findings and compute aggregate report."""
        targets = findings or (self.cached_findings if self.cached_findings else self.load_findings())
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
    <title>{report.report_title}</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111726;
            --border: #1f2a44;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --crit: #ef4444;
            --high: #f97316;
            --med: #eab308;
            --low: #3b82f6;
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3, h4 {{ color: #f8fafc; margin-top: 0; }}
        .header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .kpi-card {{ background: var(--surface); border: 1px solid var(--border); padding: 1.25rem; border-radius: 8px; }}
        .kpi-val {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
        .kpi-label {{ color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .finding-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .border-critical {{ border-left: 4px solid var(--crit); }}
        .border-high {{ border-left: 4px solid var(--high); }}
        .border-medium {{ border-left: 4px solid var(--med); }}
        .border-low {{ border-left: 4px solid var(--low); }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }}
        .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 0.5rem; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--crit); border: 1px solid var(--crit); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--med); border: 1px solid var(--med); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
        .badge-cat {{ background: #1e293b; color: #cbd5e1; }}
        .badge-id {{ background: #334155; color: #f8fafc; font-family: monospace; }}
        .badge-cve {{ background: #831843; color: #f472b6; }}
        .finding-title {{ font-size: 1.25rem; margin-bottom: 0.5rem; }}
        .finding-meta {{ display: flex; gap: 1.5rem; color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; }}
        .exec-card {{ background: rgba(56, 189, 248, 0.08); border-left: 3px solid var(--accent); padding: 0.75rem 1rem; margin-bottom: 1rem; border-radius: 4px; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1rem; }}
        .remediation-section {{ background: rgba(15, 23, 42, 0.6); padding: 1rem; border-radius: 6px; border: 1px solid var(--border); }}
        .code-box {{ background: #020617; border: 1px solid #1e293b; border-radius: 4px; padding: 0.75rem; margin: 0.75rem 0; font-family: monospace; font-size: 0.85rem; overflow-x: auto; }}
        .code-title {{ color: var(--accent); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ {report.report_title}</h1>
            <p style="color: var(--text-muted)">Generated: {report.generated_at}</p>
        </div>
        
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-val">{m.total_findings}</div>
                <div class="kpi-label">Total Findings</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-val" style="color: var(--crit);">{m.critical_or_high_count}</div>
                <div class="kpi-label">Critical & High</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-val">{m.average_confidence * 100:.1f}%</div>
                <div class="kpi-label">Average Confidence</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-val" style="color: #4ade80;">{m.analyzed_findings}</div>
                <div class="kpi-label">AI Analyzed</div>
            </div>
        </div>

        <h2>Security Findings Matrix</h2>
        {cards_html}
    </div>
</body>
</html>
"""
        return html
