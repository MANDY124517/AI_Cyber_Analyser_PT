import os
import json
import re
import hashlib
import asyncio
from typing import Dict, Any, Optional, Union
from datetime import datetime, timezone
import httpx

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from models import SecurityFinding, FindingAnalysis, ImpactAnalysis, RemediationPlan
from pipeline.prompts import (
    SYSTEM_CYBER_PROMPT,
    SECURITY_GROUNDING_POLICY,
    format_finding_for_analysis,
    build_isolated_prompt_payload,
)
from pipeline.json_repair import repair_and_parse_json
from schema.security_engine_schema import SecurityContextPayload
from schema.grounded_response_schema import (
    GroundedAIResponse,
    EpistemicBreakdown,
    StructuredClaim,
    GroundingEvaluationSummary,
)
from schema.normalizer import SecurityEngineNormalizer
from grounding.evaluator import GroundingEvaluator
from grounding.guardian import GraniteGuardianVerifier, GuardianAuditResult


def clean_and_parse_json(text: str) -> Dict[str, Any]:
    """Extract and parse JSON safely from model response using resilient multi-stage repair."""
    return repair_and_parse_json(text)


class CybersecurityAIEngine:
    """
    AI Processing Layer for Cybersecurity Findings.
    Executes live local LLM inference (Ollama) and API backends with strict grounding verification.
    """

    def __init__(self, provider: Optional[str] = None, guardian_model: Optional[str] = None):
        self.gemini_key = os.getenv("GEMINI_API_KEY")
        self.openai_key = os.getenv("OPENAI_API_KEY")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        
        # Normalize localhost -> 127.0.0.1 for Windows network reliability
        raw_host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
        if "localhost" in raw_host:
            raw_host = raw_host.replace("localhost", "127.0.0.1")
        self.ollama_host = raw_host
        
        self.provider = provider or self._detect_provider()
        self._finding_cache: Dict[str, FindingAnalysis] = {}
        self._grounded_cache: Dict[str, GroundedAIResponse] = {}
        self._ollama_lock = asyncio.Lock()
        self.evaluator = GroundingEvaluator()
        self.guardian = GraniteGuardianVerifier(
            ollama_host=self.ollama_host,
            guardian_model=guardian_model
        )

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
        return "ollama"

    async def analyze_finding(self, finding: SecurityFinding, target_model: Optional[str] = None) -> FindingAnalysis:
        """Process a security finding through the AI layer and return structured FindingAnalysis."""
        # 0. Check in-memory result cache for 0ms retrieval
        fp = f"{self._fingerprint(finding)}|{target_model or ''}"
        if fp in self._finding_cache:
            return self._finding_cache[fp]

        # 1. Execute live LLM inference
        res: Optional[FindingAnalysis] = None
        if self.provider == "openai" and self.openai_key:
            res = await self._analyze_with_openai(finding)
        elif self.provider == "gemini" and self.gemini_key:
            res = await self._analyze_with_gemini(finding)
        elif self.provider == "anthropic" and self.anthropic_key:
            res = await self._analyze_with_anthropic(finding)
        else:
            # Default production provider: Local Ollama
            res = await self._analyze_with_ollama(finding, target_model=target_model)
        
        if res is not None:
            self._finding_cache[fp] = res
            return res

        raise RuntimeError(f"Analysis failed to produce result using provider '{self.provider}'")

    async def analyze_grounded(
        self,
        finding: SecurityFinding,
        target_model: Optional[str] = None,
        enable_guardian: Optional[bool] = None
    ) -> GroundedAIResponse:
        """
        Process finding through AI layer, validate against formal schema, and run deterministic grounding evaluation
        alongside IBM Granite Guardian 3 (8B) safety verification.
        Returns a complete GroundedAIResponse.
        """
        fp = f"{self._fingerprint(finding)}|grounded|{target_model or ''}|{enable_guardian}"
        if fp in self._grounded_cache:
            return self._grounded_cache[fp]

        # 1. Run core analysis
        analysis = await self.analyze_finding(finding, target_model=target_model)

        # 2. Normalize finding into formal context payload
        context = SecurityEngineNormalizer.from_security_finding(finding)

        # 3. Perform deterministic grounding evaluation
        eval_result = self.evaluator.evaluate_response(
            analysis=analysis,
            context=context,
            model_name=analysis.model_used
        )

        # 4. Construct Epistemic Breakdown
        epistemic = EpistemicBreakdown(
            verified_facts=eval_result.supported_claims,
            inferences=eval_result.inferences,
            unknowns=eval_result.unknowns,
            recommendations=[
                analysis.recommended_remediation.immediate_mitigation,
                analysis.recommended_remediation.permanent_fix,
                analysis.recommended_remediation.verification_steps
            ]
        )

        # 5. Construct Structured Claims
        structured_claims = []
        for claim in eval_result.supported_claims:
            structured_claims.append(StructuredClaim(
                claim_text=claim,
                epistemic_type="VERIFIED FACT",
                is_grounded=True,
                confidence=1.0
            ))
        for claim in eval_result.unsupported_claims:
            structured_claims.append(StructuredClaim(
                claim_text=claim,
                epistemic_type="ASSUMPTION",
                is_grounded=False,
                confidence=0.3
            ))

        # 6. IBM Granite Guardian 3 Safety & Grounding Audit (Dual-Engine Interceptor)
        guardian_res: Optional[GuardianAuditResult] = None
        should_run_guardian = enable_guardian
        if should_run_guardian is None:
            should_run_guardian = (
                os.getenv("ENABLE_GRANITE_GUARDIAN", "false").lower() in ["true", "1", "yes"]
                or (target_model and "guardian" in target_model.lower())
            )

        if should_run_guardian and self.guardian.is_available():
            try:
                context_summary = (
                    f"Asset: {finding.asset}. "
                    f"Ports: {[p.port for p in context.ports_services]}. "
                    f"Services: {[p.service_name for p in context.ports_services]}. "
                    f"CVEs: {context.cves}. "
                    f"Severity: {finding.severity}."
                )
                response_summary = f"{analysis.explanation} {analysis.recommended_remediation.permanent_fix}"
                raw_payload = json.dumps(finding.evidence)
                guardian_res = await self.guardian.audit_finding(
                    context_text=context_summary,
                    ai_response_text=response_summary,
                    raw_telemetry=raw_payload
                )
                if not guardian_res.groundedness_passed:
                    eval_result.unsupported_claims.append(
                        f"Granite Guardian: Flagged ungrounded claims ({guardian_res.raw_verdict})"
                    )
                if guardian_res.jailbreak_detected:
                    eval_result.prompt_injection_detected = True
                    eval_result.security_policy_violations.append(
                        "Granite Guardian: Prompt injection / jailbreak detected in telemetry"
                    )
            except Exception:
                pass

        eval_summary = GroundingEvaluationSummary(
            grounding_score=eval_result.grounding_score,
            hallucination_score=eval_result.hallucination_score,
            unsupported_claims=eval_result.unsupported_claims,
            supported_claims=eval_result.supported_claims,
            contradictions=eval_result.contradictions,
            security_policy_violations=eval_result.security_policy_violations,
            prompt_injection_detected=eval_result.prompt_injection_detected,
            evaluation_passed=eval_result.evaluation_passed and (guardian_res is None or guardian_res.is_safe),
            guardian_audit=guardian_res
        )

        grounded_response = GroundedAIResponse(
            finding_id=finding.id,
            epistemic_breakdown=epistemic,
            analysis=analysis,
            claims=structured_claims,
            evaluation=eval_summary,
            guardian_audit=guardian_res,
            model_used=analysis.model_used
        )

        self._grounded_cache[fp] = grounded_response
        return grounded_response

    async def _analyze_with_openai(self, finding: SecurityFinding) -> FindingAnalysis:
        prompt_payload = build_isolated_prompt_payload(finding.model_dump())
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.openai_key}"},
                json={
                    "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    "messages": [
                        {"role": "system", "content": prompt_payload["system"]},
                        {"role": "user", "content": prompt_payload["user"]}
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
        prompt_payload = build_isolated_prompt_payload(finding.model_dump())
        primary_model = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
        candidate_models = list(dict.fromkeys([primary_model, "gemini-3-flash-preview", "gemini-flash-latest"]))

        payload = {
            "system_instruction": {"parts": [{"text": prompt_payload["system"]}]},
            "contents": [{"parts": [{"text": prompt_payload["user"]}]}],
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
        prompt_payload = build_isolated_prompt_payload(finding.model_dump())
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
                    "system": prompt_payload["system"],
                    "messages": [{"role": "user", "content": prompt_payload["user"]}]
                }
            )
            resp.raise_for_status()
            content = resp.json()["content"][0]["text"]
            parsed = clean_and_parse_json(content)
            parsed["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            parsed["model_used"] = "claude-3-5-sonnet"
            return FindingAnalysis.model_validate(parsed)

    async def _analyze_with_ollama(self, finding: SecurityFinding, target_model: Optional[str] = None) -> FindingAnalysis:
        prompt_payload = build_isolated_prompt_payload(finding.model_dump())
        model_name = target_model or os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

        options: Dict[str, Any] = {
            "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", "4096")),
            "num_predict": int(os.getenv("OLLAMA_NUM_PREDICT", "3072")),
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
            "system": prompt_payload["system"],
            "prompt": prompt_payload["user"],
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
                    # If prior attempt failed with CUDA/memory crash, fallback to CPU
                    if last_err and any(k in str(last_err).lower() for k in ["cuda", "memory", "terminated", "0xc0000409", "shared object"]):
                        req_options["num_gpu"] = 0

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

                        resp_json = resp.json()
                        if "error" in resp_json:
                            raise RuntimeError(f"Ollama generation error: {resp_json['error']}")

                        content = resp_json.get("response", "")
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
