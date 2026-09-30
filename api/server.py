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

from fastapi import FastAPI, HTTPException, Body, Response, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models import SecurityFinding, FindingAnalysis, EnrichedFinding, BatchReport
from pipeline.runner import FindingsPipelineRunner
from pipeline.ai_engine import CybersecurityAIEngine

app = FastAPI(
    title="Cybersecurity AI Findings Analysis API",
    description="Automated AI triage, root-cause explanation, and structured remediation engine for security findings",
    version="1.0.0"
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)
    logger.info(f"{request.client.host if request.client else 'client'} - \"{request.method} {request.url.path}\" {response.status_code} ({duration_ms}ms)")
    return response

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_PATH = os.path.join(PROJECT_ROOT, "data", "findings.json")
STATIC_PATH = os.path.join(PROJECT_ROOT, "static")

# Global runner instance
runner = FindingsPipelineRunner(data_path=DATA_PATH)

# In-memory store of enriched findings for interactive updates
state: Dict[str, EnrichedFinding] = {}

def initialize_state():
    findings = runner.load_findings()
    for f in findings:
        if f.id not in state:
            state[f.id] = EnrichedFinding(finding=f, analysis=None)

initialize_state()

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

@app.post("/api/analyze/{finding_id}", response_model=EnrichedFinding)
async def analyze_finding(finding_id: str):
    """Run AI analysis on a specific finding."""
    fid = finding_id.upper()
    if fid not in state:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    
    enriched = await runner.analyze_single(state[fid].finding)
    state[fid] = enriched
    return enriched

@app.post("/api/analyze-all", response_model=BatchReport)
async def analyze_all():
    """Batch analyze all findings in the dataset."""
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
    
    analysis = await runner.engine.analyze_finding(finding)
    enriched = EnrichedFinding(finding=finding, analysis=analysis)
    state[custom_id] = enriched
    return enriched

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
    uvicorn.run("api.server:app", host="127.0.0.1", port=8000, reload=True, app_dir=PROJECT_ROOT)
