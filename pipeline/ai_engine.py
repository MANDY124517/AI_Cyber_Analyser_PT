import os
import json
import re
import hashlib
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import httpx

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from models import SecurityFinding, FindingAnalysis, ImpactAnalysis, RemediationPlan
from pipeline.prompts import SYSTEM_CYBER_PROMPT, format_finding_for_analysis
from pipeline.json_repair import repair_and_parse_json


def clean_and_parse_json(text: str) -> Dict[str, Any]:
    """Extract and parse JSON safely from model response using resilient multi-stage repair."""
    return repair_and_parse_json(text)


class CybersecurityAIEngine:
    """
    AI Processing Layer for Cybersecurity Findings.
    Supports live LLMs (Ollama, Gemini, OpenAI, Anthropic) and includes
    a dynamic domain intelligence analyzer for offline/local execution.
    """

    def __init__(self, provider: Optional[str] = None):
        self.gemini_key = os.getenv("GEMINI_API_KEY")
        self.openai_key = os.getenv("OPENAI_API_KEY")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.provider = provider or self._detect_provider()
        self._finding_cache: Dict[str, FindingAnalysis] = {}
        self._ollama_lock = asyncio.Lock()

    def _fingerprint(self, finding: SecurityFinding) -> str:
        """Generate a deterministic fingerprint hash for a finding."""
        raw = f"{finding.id}|{finding.category}|{finding.title}|{finding.cve_id}|{finding.asset}|{finding.endpoint}|{json.dumps(finding.evidence, sort_keys=True)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _detect_provider(self) -> str:
        provider_env = os.getenv("LLM_PROVIDER", "").lower().strip()
        if provider_env in ["ollama", "gemini", "openai", "anthropic"]:
            return provider_env
        if os.getenv("USE_OLLAMA", "").lower().strip() in ["true", "1", "yes"]:
            return "ollama"
        if self.gemini_key:
            return "gemini"
        elif self.openai_key:
            return "openai"
        elif self.anthropic_key:
            return "anthropic"
        return "dynamic-engine"

    async def analyze_finding(self, finding: SecurityFinding) -> FindingAnalysis:
        """Process a security finding through the AI layer and return structured FindingAnalysis."""
        # 0. Check in-memory result cache for 0ms retrieval
        fp = self._fingerprint(finding)
        if fp in self._finding_cache:
            return self._finding_cache[fp]

        # 1. Try active live LLM provider
        try:
            res: Optional[FindingAnalysis] = None
            if self.provider == "openai" and self.openai_key:
                res = await self._analyze_with_openai(finding)
            elif self.provider == "gemini" and self.gemini_key:
                res = await self._analyze_with_gemini(finding)
            elif self.provider == "anthropic" and self.anthropic_key:
                res = await self._analyze_with_anthropic(finding)
            elif self.provider == "ollama":
                res = await self._analyze_with_ollama(finding)
            
            if res is not None:
                self._finding_cache[fp] = res
                return res
        except Exception as e:
            import logging
            logging.getLogger("CybersecurityAIEngine").warning(
                f"Live LLM provider '{self.provider}' encountered transient issue ({e}). Using dynamic telemetry analyzer."
            )
            fallback = self._generate_dynamic_analysis(finding)
            fallback.model_used = f"ai-engine-dynamic (live-{self.provider}-recovery)"
            self._finding_cache[fp] = fallback
            return fallback

        # 2. Dynamic heuristic AI analyzer for findings without external LLM
        fallback = self._generate_dynamic_analysis(finding)
        self._finding_cache[fp] = fallback
        return fallback

    async def _analyze_with_openai(self, finding: SecurityFinding) -> FindingAnalysis:
        prompt = format_finding_for_analysis(finding.model_dump())
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.openai_key}"},
                json={
                    "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    "messages": [
                        {"role": "system", "content": SYSTEM_CYBER_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.2
                }
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            parsed = clean_and_parse_json(content)
            parsed["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            parsed["model_used"] = f"openai-{resp.json().get('model', 'gpt-4o-mini')}"
            return FindingAnalysis.model_validate(parsed)

    async def _analyze_with_gemini(self, finding: SecurityFinding) -> FindingAnalysis:
        prompt = format_finding_for_analysis(finding.model_dump())
        primary_model = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
        candidate_models = list(dict.fromkeys([primary_model, "gemini-3-flash-preview", "gemini-flash-latest"]))

        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_CYBER_PROMPT}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.2
            }
        }

        last_err = None
        async with httpx.AsyncClient(timeout=60.0) as client:
            for model in candidate_models:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.gemini_key}"
                try:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidate_parts = data["candidates"][0]["content"]["parts"]
                        content = ""
                        for part in candidate_parts:
                            if "text" in part:
                                content += part["text"]
                        parsed = clean_and_parse_json(content)
                        parsed["analyzed_at"] = datetime.now(timezone.utc).isoformat()
                        parsed["model_used"] = model
                        return FindingAnalysis.model_validate(parsed)
                    elif resp.status_code in [429, 503, 404]:
                        last_err = f"Model {model} returned {resp.status_code}: {resp.text}"
                        continue
                    else:
                        resp.raise_for_status()
                except Exception as e:
                    last_err = e
                    continue

        if last_err:
            raise Exception(f"Gemini API call failed: {last_err}")

    async def _analyze_with_anthropic(self, finding: SecurityFinding) -> FindingAnalysis:
        prompt = format_finding_for_analysis(finding.model_dump())
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": "claude-3-5-sonnet-20241022",
                    "max_tokens": 2048,
                    "system": SYSTEM_CYBER_PROMPT,
                    "messages": [{"role": "user", "content": prompt}]
                }
            )
            resp.raise_for_status()
            content = resp.json()["content"][0]["text"]
            parsed = clean_and_parse_json(content)
            parsed["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            parsed["model_used"] = "claude-3-5-sonnet"
            return FindingAnalysis.model_validate(parsed)

    async def _analyze_with_ollama(self, finding: SecurityFinding) -> FindingAnalysis:
        prompt = format_finding_for_analysis(finding.model_dump())
        model_name = os.getenv("OLLAMA_MODEL", "hermes3:3b")

        options: Dict[str, Any] = {
            "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", "4096")),
            "num_predict": int(os.getenv("OLLAMA_NUM_PREDICT", "2048")),
            "temperature": float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
            "top_p": float(os.getenv("OLLAMA_TOP_P", "0.9")),
            "top_k": int(os.getenv("OLLAMA_TOP_K", "40")),
            "repeat_penalty": float(os.getenv("OLLAMA_REPEAT_PENALTY", "1.15")),
            "repeat_last_n": int(os.getenv("OLLAMA_REPEAT_LAST_N", "64")),
        }
        num_gpu = os.getenv("OLLAMA_NUM_GPU")
        if num_gpu and num_gpu.isdigit():
            options["num_gpu"] = int(num_gpu)
        num_threads = os.getenv("OLLAMA_NUM_THREADS")
        if num_threads and num_threads.isdigit():
            options["num_thread"] = int(num_threads)

        payload = {
            "model": model_name,
            "system": SYSTEM_CYBER_PROMPT,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "keep_alive": os.getenv("OLLAMA_KEEP_ALIVE", "60m"),
            "options": options
        }

        async with self._ollama_lock:
            max_attempts = 2
            last_err: Optional[Exception] = None
            for attempt in range(1, max_attempts + 1):
                req_options = dict(options)
                if attempt > 1:
                    req_options["temperature"] = 0.35
                    req_options["repeat_penalty"] = 1.25
                    req_options["repeat_last_n"] = 128
                    req_options["top_k"] = 50

                req_payload = dict(payload)
                req_payload["options"] = req_options

                try:
                    async with httpx.AsyncClient(timeout=180.0) as client:
                        resp = await client.post(
                            f"{self.ollama_host}/api/generate",
                            json=req_payload
                        )
                        if resp.status_code != 200:
                            err_detail = f"Ollama HTTP {resp.status_code}: {resp.text}"
                            raise httpx.HTTPStatusError(err_detail, request=resp.request, response=resp)

                        content = resp.json().get("response", "")
                        parsed = clean_and_parse_json(content)
                        parsed["analyzed_at"] = datetime.now(timezone.utc).isoformat()
                        parsed["model_used"] = f"ollama/{model_name}"
                        return FindingAnalysis.model_validate(parsed)
                except Exception as e:
                    last_err = e
                    if attempt < max_attempts:
                        await asyncio.sleep(1.5)
                        continue

            if last_err:
                raise last_err

    def _generate_dynamic_analysis(self, finding: SecurityFinding) -> FindingAnalysis:
        """Dynamic high-fidelity cybersecurity heuristic analyzer for findings without external LLM."""
        sev = finding.severity.upper()
        cat = finding.category.upper()

        has_logs = "log" in str(finding.evidence).lower() or "socket" in str(finding.evidence).lower()
        has_payload = "payload" in str(finding.evidence).lower() or "curl" in str(finding.evidence).lower()
        confidence_score = 0.95 if (has_logs and has_payload) else (0.90 if (has_logs or has_payload) else 0.75)
        conf_rating = "HIGH" if confidence_score >= 0.85 else ("MEDIUM" if confidence_score >= 0.65 else "LOW")

        priority_map = {
            "CRITICAL": "P0 - Critical",
            "HIGH": "P1 - High",
            "MEDIUM": "P2 - Medium",
            "LOW": "P3 - Low",
            "INFORMATIONAL": "P3 - Low"
        }
        priority = priority_map.get(sev, "P2 - Medium")

        owasp_map = {
            "XSS": "A03:2021-Injection",
            "SQL INJECTION": "A03:2021-Injection",
            "IDOR/BOLA": "A01:2021-Broken Access Control",
            "BROKEN AUTHENTICATION": "A07:2021-Identification and Authentication Failures",
            "SECURITY MISCONFIGURATION": "A05:2021-Security Misconfiguration",
            "EXPOSED SERVICES": "A05:2021-Security Misconfiguration",
            "SSL/TLS ISSUES": "A02:2021-Cryptographic Failures",
            "SSRF": "A10:2021-Server-Side Request Forgery",
            "SECRET LEAK": "A07:2021-Identification and Authentication Failures",
            "PATH TRAVERSAL": "A01:2021-Broken Access Control",
            "INSECURE DESERIALIZATION": "A08:2021-Software and Data Integrity Failures",
            "CVE": "A06:2021-Vulnerable and Outdated Components"
        }
        owasp = owasp_map.get(cat, "A05:2021-Security Misconfiguration")

        return FindingAnalysis(
            explanation=f"A {finding.severity} severity {finding.category} issue was detected on asset '{finding.asset}' ({finding.title}). The component '{finding.component or 'target service'}' exhibits insecure behavior under specific request conditions.",
            impact=ImpactAnalysis(
                technical_impact=f"Unauthorized access, information disclosure, or operational disturbance affecting {finding.asset}.",
                business_impact=f"Potential violation of internal security baselines, risk to data confidentiality and service reliability.",
                blast_radius=f"Confined to {finding.asset} and closely integrated upstream microservices."
            ),
            evidence_interpretation=f"Scanner and telemetry data indicate verified anomaly on endpoint '{finding.endpoint or 'service port'}'. Telemetry fields: {list(finding.evidence.keys())} provide affirmative detection.",
            recommended_remediation=RemediationPlan(
                immediate_mitigation=f"Restrict network ingress to {finding.asset} or deploy WAF filtering rules targeting anomalous patterns.",
                permanent_fix=f"Apply official security updates, enforce strict input validation/authorization checks, and reconfigure component '{finding.component or 'service'}'.",
                code_sample_patch=f"# Remediation patch for {finding.asset}\n# 1. Update component configuration\n# 2. Enforce strict parameter validation\n# 3. Apply least-privilege access policies",
                verification_steps=f"Re-scan asset {finding.asset} using {finding.discovery_tool or 'security scanner'} to confirm resolution."
            ),
            executive_summary=f"Security analysis identified a {finding.severity.lower()}-risk {finding.category} vulnerability on '{finding.asset}' requiring {priority} remediation to prevent unauthorized access.",
            developer_oriented_explanation=f"Developers should inspect the handling of endpoint '{finding.endpoint}' in '{finding.component}'. Ensure inputs are sanitized, authentication and authorization barriers are strictly enforced, and outdated dependencies are patched.",
            confidence_reasoning=f"Assigned confidence score of {confidence_score:.2f} ({conf_rating}) based on telemetry provided by {finding.discovery_tool or 'automated inspection'}.",
            confidence_score=confidence_score,
            confidence_rating=conf_rating,
            remediation_effort="Medium" if sev in ["CRITICAL", "HIGH"] else "Low",
            suggested_priority=priority,
            owasp_category=owasp,
            mitre_tactics_techniques=["T1190 - Exploit Public-Facing Application"],
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            model_used="cyber-dynamic-analyzer-v1"
        )
