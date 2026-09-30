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
