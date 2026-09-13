from src.guardrails.input_guardrail import check_injection_hybrid
from src.guardrails.output_guardrail import check_hallucinated_cves_verified, annotate_ungrounded_citations
from src.guardrails.attack_grounding import (
    check_hallucinated_attack_techniques_verified,
    annotate_ungrounded_attack_citations,
)
from src.guardrails.evidence_pack import build_evidence_pack
from src.guardrails.pii_guardrail import redact_report_fields
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv
import os
import json
from datetime import datetime
from src.agent.alert_schema import SecurityAlert

load_dotenv()

MODEL_NAME = "openai/gpt-oss-20b"

llm = ChatGroq(
    api_key=os.getenv("GROQ_API_KEY"),
    model=MODEL_NAME,
    temperature=0.1,
)

SYSTEM_PROMPT = """You are SecureAgent-SOC, an AI assistant for Security Operations Centre analysts.

Your job is to analyse security alerts and produce structured threat reports.

You must respond ONLY with a valid JSON object in exactly this format:
{
    "alert_id": "<the alert ID from the input>",
    "severity_assessment": "<LOW|MEDIUM|HIGH|CRITICAL>",
    "threat_summary": "<2-3 sentence summary of what is happening>",
    "threat_type": "<category of attack>",
    "recommended_action": "<what the analyst should do>",
    "confidence_score": <float between 0.0 and 1.0>,
    "reasoning": "<brief explanation of your analysis>"
}

Do not include any text outside the JSON object. Do not hallucinate CVE numbers, MITRE ATT&CK technique IDs, or threat actor names unless clearly indicated by the alert data."""

def format_alert(alert: SecurityAlert) -> str:
    return f"""
Alert ID: {alert.alert_id}
Timestamp: {alert.timestamp}
Severity: {alert.severity}
Source IP: {alert.source_ip}
Destination IP: {alert.destination_ip}
Event Type: {alert.event_type}
Description: {alert.description}
Protocol: {alert.protocol or 'Unknown'}
Port: {alert.port or 'Unknown'}
Payload Snippet: {alert.payload_snippet or 'None'}
User: {alert.user or 'Unknown'}
Hostname: {alert.hostname or 'Unknown'}
File Hash: {alert.file_hash or 'None'}
"""

def analyse_alert(
    alert: SecurityAlert,
    verify_cves_with_nvd: bool = True,
    input_guardrail_enabled: bool = True,
    cve_guardrail_enabled: bool = True,
    attack_guardrail_enabled: bool = True,
    pii_guardrail_enabled: bool = True,
) -> dict:
    """
    verify_cves_with_nvd: set False to skip the NVD network lookup (e.g. for
    fast local batch runs or when offline) — falls back to grounding-only
    CVE checking with an "UNVERIFIED" classification for any ungrounded CVE.

    input_guardrail_enabled / cve_guardrail_enabled / attack_guardrail_enabled /
    pii_guardrail_enabled: per-stage on/off toggles for the component ablation
    study (all default True, i.e. identical behavior to before these flags
    existed). Disabling a stage skips its check entirely rather than running
    it and discarding the result, so the ablation's cost/latency numbers
    reflect the stage genuinely not running. The report schema is unchanged
    either way — every key a disabled stage would have set is still present,
    just holding its "nothing found" value (empty list / not flagged), so
    disabled-stage reports remain directly comparable to enabled-stage ones
    field-for-field. Pipeline order is unchanged; only whether each stage
    runs is gated.
    """
    alert_text = format_alert(alert)
    evidence_pack = build_evidence_pack(alert)

    if input_guardrail_enabled and check_injection_hybrid(alert_text):
        return {
            "alert_id": alert.alert_id,
            "severity_assessment": "BLOCKED",
            "threat_summary": "Input blocked by guardrail — potential prompt injection detected.",
            "threat_type": "BLOCKED_INPUT",
            "recommended_action": "Manual review required — alert flagged for injection attempt.",
            "confidence_score": 0.0,
            "reasoning": "Alert content matched known prompt injection pattern before reaching LLM.",
            "processed_at": datetime.utcnow().isoformat(),
            "model": MODEL_NAME,
            "agent_version": "guardrail-v0.4",
            "guardrail_blocked": True,
            "hallucinated_cves": [],
            "cve_verifications": [],
            "hallucinated_attack_techniques": [],
            "attack_technique_verifications": [],
            "pii_detections": [],
            "output_guardrail_flagged": False,
            "requires_review": False,
            "evidence_pack": evidence_pack,
        }
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"Analyse this security alert and produce a threat report:\n{alert_text}")
    ]
    
    response = llm.invoke(messages)
    
    try:
        report = json.loads(response.content)
    except json.JSONDecodeError:
        report = {
            "alert_id": alert.alert_id,
            "severity_assessment": "UNKNOWN",
            "threat_summary": response.content,
            "threat_type": "UNKNOWN",
            "recommended_action": "Manual review required",
            "confidence_score": 0.0,
            "reasoning": "Agent failed to produce structured output"
        }
    
    report["processed_at"] = datetime.utcnow().isoformat()
    report["model"] = MODEL_NAME
    report["agent_version"] = "guardrail-v0.4"
    report["guardrail_blocked"] = False

    if cve_guardrail_enabled:
        cve_check = check_hallucinated_cves_verified(report, evidence_pack["text"], verify_with_nvd=verify_cves_with_nvd)
        report = annotate_ungrounded_citations(report, cve_check["verifications"])
        report["hallucinated_cves"] = cve_check["ungrounded_cves"]
        report["cve_verifications"] = cve_check["verifications"]
    else:
        cve_check = {"flagged": False, "requires_review": False}
        report["hallucinated_cves"] = []
        report["cve_verifications"] = []

    if attack_guardrail_enabled:
        attack_check = check_hallucinated_attack_techniques_verified(report, evidence_pack["text"])
        report = annotate_ungrounded_attack_citations(report, attack_check["verifications"])
        report["hallucinated_attack_techniques"] = attack_check["ungrounded_attack_techniques"]
        report["attack_technique_verifications"] = attack_check["verifications"]
    else:
        attack_check = {"flagged": False, "requires_review": False}
        report["hallucinated_attack_techniques"] = []
        report["attack_technique_verifications"] = []

    if pii_guardrail_enabled:
        pii_result = redact_report_fields(report)
        report.update(pii_result["redacted_fields"])
        report["pii_detections"] = pii_result["detections"]
    else:
        pii_result = {"pii_found": False}
        report["pii_detections"] = []

    report["output_guardrail_flagged"] = cve_check["flagged"] or attack_check["flagged"] or pii_result["pii_found"]
    report["requires_review"] = cve_check["requires_review"] or attack_check["requires_review"] or pii_result["pii_found"]
    report["evidence_pack"] = evidence_pack

    return report