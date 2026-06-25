from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv
import os
import json
from datetime import datetime
from src.agent.alert_schema import SecurityAlert

load_dotenv()

llm = ChatGroq(
    api_key=os.getenv("GROQ_API_KEY"),
    model="llama-3.1-8b-instant",
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

Do not include any text outside the JSON object. Do not hallucinate CVE numbers or threat actor names unless clearly indicated by the alert data."""

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
"""

def analyse_alert(alert: SecurityAlert) -> dict:
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"Analyse this security alert and produce a threat report:\n{format_alert(alert)}")
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
    report["model"] = "llama-3.1-8b-instant"
    report["agent_version"] = "baseline-v0.1"
    
    return report