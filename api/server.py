import os
import sys
import json
import time
import logging
from typing import List, Dict, Any, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOGS_DIR, "server.log")

# Configure logging to both console and file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("CyberTriageServer")

from fastapi import FastAPI, HTTPException, Body, Response, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models import SecurityFinding, FindingAnalysis, EnrichedFinding, BatchReport
from pipeline.runner import FindingsPipelineRunner
from pipeline.ai_engine import CybersecurityAIEngine
from schema.security_engine_schema import SecurityContextPayload
from schema.grounded_response_schema import GroundedAIResponse
from schema.normalizer import SecurityEngineNormalizer
from schema.json_schemas import get_security_context_json_schema, get_grounded_response_json_schema
from grounding.evaluator import GroundingEvaluator
from grounding.models import GroundingEvaluationResult
from benchmark.runner import BenchmarkRunner
from benchmark.metrics import ModelBenchmarkResult

app = FastAPI(
    title="CyberTriage AI Security Finding Analysis & Grounding API",
    description="Automated AI triage, deterministic grounding verification, formal schema validation, and Ollama model benchmarking",
    version="2.0.0"
)

# Request logging and no-cache middleware for local development
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)
    logger.info(f"{request.client.host if request.client else 'client'} - \"{request.method} {request.url.path}\" {response.status_code} ({duration_ms}ms)")
    
    # Invalidate cache for frontend assets in development so changes reflect immediately
    if request.url.path.endswith((".js", ".css", ".html")) or request.url.path == "/" or request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        
    return response

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_PATH = os.path.join(PROJECT_ROOT, "static")

# Global runner instance
runner = FindingsPipelineRunner()
grounding_evaluator = GroundingEvaluator()
benchmark_runner = BenchmarkRunner()

# In-memory store of enriched findings for interactive updates
state: Dict[str, EnrichedFinding] = {}


def _init_default_findings():
    """Load default findings if state is empty, pre-enriching with real-world threat intel and deterministic priority."""
    if not state:
        try:
            findings = runner.load_findings()
            for f in findings:
                intel_dict, prio_dict = runner.enrich_threat_intel(f)
                state[f.id] = EnrichedFinding(
                    finding=f,
                    analysis=None,
                    threat_intel=intel_dict,
                    prioritization=prio_dict
                )
            logger.info(f"Loaded {len(state)} security findings into active state with threat intel.")
        except Exception as e:
            logger.warning(f"Could not load default findings: {e}")

# Initialize on module import
_init_default_findings()


@app.on_event("startup")
async def startup_event():
    """Load default findings on server startup if state is empty."""
    _init_default_findings()


@app.get("/api/threat-intel/{cve_id}")
async def get_threat_intel_cve(cve_id: str):
    """Live threat intel lookup for a given CVE ID (FIRST.org EPSS + CISA KEV)."""
    intel = runner.advisory_intel.get_intel_for_cve(cve_id)
    return intel.model_dump(mode="json")


class CustomFindingRequest(BaseModel):
    title: str
    category: str = "General Vulnerability"
    severity: str = "HIGH"
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    asset: str = "target-service.internal"
    endpoint: Optional[str] = None
    component: Optional[str] = None
    evidence: Dict[str, Any] = {}
    description: Optional[str] = None


class GroundingEvaluationRequest(BaseModel):
    analysis: Dict[str, Any]
    context: Dict[str, Any]
    model_name: Optional[str] = None


@app.get("/api/findings", response_model=List[EnrichedFinding])
async def get_findings():
    """Retrieve all findings with their current analysis status."""
    return list(state.values())


@app.get("/api/findings/{finding_id}", response_model=EnrichedFinding)
async def get_finding(finding_id: str):
    """Retrieve a single finding and its analysis."""
    fid = finding_id.upper()
    if fid not in state:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return state[fid]

@app.post("/api/findings/import", response_model=Dict[str, Any])
async def import_findings(items: List[Dict[str, Any]]):
    """Import an array of raw findings or scanner output into the active session."""
    imported_count = 0
    errors = []
    import uuid

    for idx, item in enumerate(items):
        try:
            if not item.get("id"):
                item["id"] = f"INGEST-{uuid.uuid4().hex[:6].upper()}"
            if not item.get("timestamp"):
                from datetime import datetime, timezone
                item["timestamp"] = datetime.now(timezone.utc).isoformat()
            
            finding = SecurityFinding.model_validate(item)
            state[finding.id] = EnrichedFinding(finding=finding, analysis=None)
            imported_count += 1
        except Exception as e:
            errors.append(f"Item #{idx}: {str(e)}")

    logger.info(f"Imported {imported_count} findings via API.")
    return {
        "status": "success",
        "imported": imported_count,
        "total_active": len(state),
        "errors": errors
    }

@app.delete("/api/findings", response_model=Dict[str, Any])
async def clear_all_findings():
    """Clear all active findings from memory."""
    count = len(state)
    state.clear()
    logger.info(f"Cleared all {count} findings from memory.")
    return {"status": "success", "cleared": count}

@app.delete("/api/findings/{finding_id}", response_model=Dict[str, Any])
async def delete_finding(finding_id: str):
    """Delete a specific finding by ID."""
    fid = finding_id.upper()
    if fid in state:
        del state[fid]
        return {"status": "success", "deleted": fid}
    raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

@app.post("/api/analyze/{finding_id}", response_model=EnrichedFinding)
async def analyze_finding(
    finding_id: str,
    model: Optional[str] = Query(None, description="Target Ollama model")
):
    """Run AI analysis on a specific finding."""
    fid = finding_id.upper()
    if fid not in state:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    
    enriched = await runner.analyze_single(state[fid].finding, target_model=model)
    state[fid] = enriched
    return enriched

@app.post("/api/analyze-grounded/{finding_id}", response_model=GroundedAIResponse)
async def analyze_grounded(
    finding_id: str,
    model: Optional[str] = Query(None, description="Target Ollama model"),
    guardian: Optional[bool] = Query(None, description="Enable IBM Granite Guardian 3 verification")
):
    """Run AI analysis on a specific finding with deterministic grounding evaluation & Granite Guardian audit."""
    fid = finding_id.upper()
    if fid not in state:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    
    grounded_res = await runner.analyze_grounded(
        state[fid].finding,
        target_model=model,
        enable_guardian=guardian
    )
    intel_dict, prio_dict = runner.enrich_threat_intel(state[fid].finding)
    if grounded_res.analysis:
        grounded_res.analysis.epss_score = intel_dict.get("epss_score")
        grounded_res.analysis.epss_percentile = intel_dict.get("epss_percentile")
        grounded_res.analysis.cisa_kev_listed = intel_dict.get("cisa_kev_listed", False)
        grounded_res.analysis.ssvc_decision = prio_dict.get("ssvc_decision")
        grounded_res.analysis.composite_risk_score = prio_dict.get("composite_risk_score")
        grounded_res.analysis.remediation_sla_hours = prio_dict.get("remediation_sla_hours")
        grounded_res.analysis.prioritization_rationale = prio_dict.get("decision_rationale")

    state[fid] = EnrichedFinding(
        finding=state[fid].finding,
        analysis=grounded_res.analysis,
        threat_intel=intel_dict,
        prioritization=prio_dict
    )
    return grounded_res

@app.post("/api/guardian/audit/{finding_id}")
async def audit_finding_with_guardian(
    finding_id: str,
    guardian_model: Optional[str] = Query(None, description="Granite Guardian model")
):
    """Run IBM Granite Guardian 3 (8B) safety, grounding, and anti-jailbreak audit."""
    from grounding.guardian import GraniteGuardianVerifier
    fid = finding_id.upper()
    if fid not in state:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    
    target = state[fid].finding
    if not state[fid].analysis:
        enriched = await runner.analyze_single(target)
        state[fid] = enriched
    
    analysis = state[fid].analysis
    context_text = f"Asset: {target.asset}. Ports/Evidence: {json.dumps(target.evidence)}. Severity: {target.severity}."
    analysis_text = f"{analysis.explanation} {analysis.recommended_remediation.permanent_fix}"
    
    verifier = GraniteGuardianVerifier(guardian_model=guardian_model)
    audit_res = await verifier.audit_finding(
        context_text=context_text,
        ai_response_text=analysis_text,
        raw_telemetry=json.dumps(target.evidence)
    )
    return audit_res.model_dump(mode="json")

@app.post("/api/analyze-all", response_model=BatchReport)
async def analyze_all():
    """Batch analyze all findings in the dataset."""
    if not state:
        return runner.compile_report([])
    findings = [item.finding for item in state.values()]
    report = await runner.run_batch(findings)
    for enriched in report.findings:
        state[enriched.finding.id] = enriched
    return report

@app.post("/api/analyze-custom", response_model=EnrichedFinding)
async def analyze_custom(req: CustomFindingRequest):
    """Analyze an ad-hoc custom security finding or payload."""
    import uuid
    custom_id = f"CUSTOM-{uuid.uuid4().hex[:6].upper()}"
    
    evidence_dict = dict(req.evidence)
    if req.description:
        evidence_dict["user_description"] = req.description

    finding = SecurityFinding(
        id=custom_id,
        title=req.title,
        category=req.category,
        severity=req.severity, # type: ignore
        cve_id=req.cve_id,
        cvss_score=req.cvss_score,
        asset=req.asset,
        component=req.component,
        endpoint=req.endpoint,
        discovery_tool="Ad-Hoc Custom Sandbox Input",
        timestamp="2026-09-18T12:00:00Z",
        evidence=evidence_dict
    )
    
    intel_dict, prio_dict = runner.enrich_threat_intel(finding)
    analysis = await runner.engine.analyze_finding(finding)

    # Deterministic priority alignment
    prio_tier = prio_dict.get("priority_tier", "P1 - High Priority Patch")
    if "P0" in prio_tier:
        analysis.suggested_priority = "P0 - Critical"
    elif "P1" in prio_tier:
        analysis.suggested_priority = "P1 - High"
    elif "P2" in prio_tier:
        analysis.suggested_priority = "P2 - Medium"
    else:
        analysis.suggested_priority = "P3 - Low"

    analysis.epss_score = intel_dict.get("epss_score")
    analysis.epss_percentile = intel_dict.get("epss_percentile")
    analysis.cisa_kev_listed = intel_dict.get("cisa_kev_listed", False)
    analysis.ssvc_decision = prio_dict.get("ssvc_decision")
    analysis.composite_risk_score = prio_dict.get("composite_risk_score")
    analysis.remediation_sla_hours = prio_dict.get("remediation_sla_hours")
    analysis.prioritization_rationale = prio_dict.get("decision_rationale")

    enriched = EnrichedFinding(
        finding=finding,
        analysis=analysis,
        threat_intel=intel_dict,
        prioritization=prio_dict
    )
    state[custom_id] = enriched
    return enriched

# Grounding & Schema Endpoints
@app.post("/api/grounding/evaluate", response_model=GroundingEvaluationResult)
async def evaluate_grounding(req: GroundingEvaluationRequest):
    """Perform deterministic security grounding and hallucination evaluation."""
    try:
        res = grounding_evaluator.evaluate_response(
            analysis=req.analysis,
            context=req.context,
            model_name=req.model_name
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Grounding evaluation failed: {str(e)}")

@app.get("/api/schema/security-engine")
async def get_schema_security_engine():
    """Return formal JSON Schema for SecurityContextPayload."""
    return get_security_context_json_schema()

@app.get("/api/schema/grounded-response")
async def get_schema_grounded_response():
    """Return formal JSON Schema for GroundedAIResponse."""
    return get_grounded_response_json_schema()

# Benchmark Endpoints
@app.get("/api/benchmark/models")
async def get_benchmark_models():
    """List available local Ollama models for benchmarking."""
    models = benchmark_runner.discover_ollama_models()
    return {
        "ollama_host": benchmark_runner.ollama_host,
        "models": models,
        "default_model": os.getenv("OLLAMA_MODEL", "hermes3:3b")
    }

@app.post("/api/benchmark/run", response_model=List[ModelBenchmarkResult])
async def run_benchmark(
    models: Optional[List[str]] = Body(None),
    suite: str = Query("all", enum=["all", "hallucination", "adversarial"])
):
    """Run cybersecurity benchmark on specified models or all discovered Ollama models."""
    default_m = os.getenv("OLLAMA_MODEL", "hermes3:3b")
    target_models = models or benchmark_runner.discover_ollama_models() or [default_m]

    results = []
    for model in target_models:
        res = await benchmark_runner.run_benchmark_for_model(model=model, suite_name=suite)
        results.append(res)
    return results

@app.get("/api/report", response_model=BatchReport)
async def get_report():
    """Compile and return current aggregate security report."""
    return runner.compile_report(list(state.values()))

@app.get("/api/export/json")
async def export_json():
    """Download structured JSON batch report."""
    report = runner.compile_report(list(state.values()))
    content = json.dumps(report.model_dump(mode="json"), indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=security_ai_report.json"}
    )

@app.get("/api/export/markdown")
async def export_markdown():
    """Download markdown batch report."""
    report = runner.compile_report(list(state.values()))
    md = runner.export_markdown(report)
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=security_ai_report.md"}
    )

@app.get("/api/export/html")
async def export_html():
    """Download standalone HTML executive dashboard report."""
    report = runner.compile_report(list(state.values()))
    html = runner.export_html(report)
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=security_ai_report.html"}
    )

@app.get("/api/logs")
async def get_logs(limit: int = 100):
    """Retrieve the latest server log lines."""
    if not os.path.exists(LOG_FILE):
        return {"logs": ["No logs recorded yet."]}
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return {"log_file": LOG_FILE, "total_lines": len(lines), "logs": [line.strip() for line in lines[-limit:]]}

# Mount static directory for Frontend Dashboard
if os.path.exists(STATIC_PATH):
    app.mount("/", StaticFiles(directory=STATIC_PATH, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("api.server:app", host=host, port=port, reload=False, app_dir=PROJECT_ROOT)
