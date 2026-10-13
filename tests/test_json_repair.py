import pytest
from pipeline.json_repair import repair_and_parse_json


def test_markdown_fence_extraction():
    text = """```json
{
  "explanation": "Test explanation",
  "confidence_score": 0.95
}
```"""
    res = repair_and_parse_json(text)
    assert res["explanation"] == "Test explanation"
    assert res["confidence_score"] == 0.95


def test_trailing_commas_and_newlines():
    text = """{
  "explanation": "Line with unescaped 
 newlines and tabs	",
  "confidence_score": 0.9,
  "mitre_tactics_techniques": ["T1190", "T1059", ],
}"""
    res = repair_and_parse_json(text)
    assert "explanation" in res
    assert res["confidence_score"] == 0.9
    assert res["mitre_tactics_techniques"] == ["T1190", "T1059"]


def test_truncated_json():
    text = """{
  "explanation": "SQL Injection found",
  "impact": {
    "technical_impact": "Unauthorized database read access"
"""
    res = repair_and_parse_json(text)
    assert res["explanation"] == "SQL Injection found"
    assert res["impact"]["technical_impact"] == "Unauthorized database read access"


def test_missing_commas_between_lines():
    text = """{
  "explanation": "BOLA flaw detected"
  "confidence_score": 0.98
  "suggested_priority": "P0 - Critical"
}"""
    res = repair_and_parse_json(text)
    assert res["explanation"] == "BOLA flaw detected"
    assert res["confidence_score"] == 0.98
    assert res["suggested_priority"] == "P0 - Critical"


def test_unescaped_inner_quotes():
    text = """{
  "explanation": "XSS in profile",
  "code_sample_patch": "<img src=x onerror=alert(1)>",
  "suggested_priority": "P1 - High"
}"""
    res = repair_and_parse_json(text)
    assert res["explanation"] == "XSS in profile"
    assert "onerror=alert(1)" in res["code_sample_patch"]


def test_double_escaped_sequences_and_code_leak_isolation():
    from models import FindingAnalysis

    raw_data = {
        "explanation": "The application endpoint processes User-Agent headers without input sanitization.",
        "executive_summary": "java\\nString userAgent = request.getHeader(\\\"User-Agent\\\");\\nif (userAgent != null) { throw new SecurityException(\\\"Invalid\\\"); }",
        "developer_oriented_explanation": "java\\nString userAgent = request.getHeader(\\\"User-Agent\\\");\\nif (userAgent != null) { throw new SecurityException(\\\"Invalid\\\"); }",
        "evidence_interpretation": "WAF log confirms JNDI injection.",
        "recommended_remediation": {
            "immediate_mitigation": "Deploy WAF rule.",
            "permanent_fix": "Upgrade Log4j.",
            "code_sample_patch": None,
            "verification_steps": "Run curl test."
        },
        "impact": {
            "technical_impact": "Remote code execution.",
            "business_impact": "GDPR violation.",
            "blast_radius": "Auth service."
        },
        "confidence_score": 0.98,
        "confidence_rating": "HIGH",
        "suggested_priority": "P0 - Critical",
        "remediation_effort": "Low"
    }

    analysis = FindingAnalysis.model_validate(raw_data)
    # 1. Executive summary should be clean English prose, NOT raw java code
    assert not analysis.executive_summary.startswith("java")
    assert not analysis.executive_summary.startswith("String")
    assert "\\n" not in analysis.executive_summary
    assert '\\"' not in analysis.executive_summary

    # 2. Developer explanation should be clean English prose
    assert not analysis.developer_oriented_explanation.startswith("java")
    assert not analysis.developer_oriented_explanation.startswith("String")

    # 3. Leaked code should be safely isolated into code_sample_patch
    assert analysis.recommended_remediation.code_sample_patch is not None
    assert "request.getHeader" in analysis.recommended_remediation.code_sample_patch
    assert "\\n" not in analysis.recommended_remediation.code_sample_patch

