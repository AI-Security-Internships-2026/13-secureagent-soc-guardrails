from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class SecurityAlert:
    """Represents a synthetic SOC security alert."""
    
    alert_id: str
    timestamp: str
    severity: str          
    source_ip: str
    destination_ip: str
    event_type: str        
    description: str
    protocol: Optional[str] = None
    port: Optional[int] = None
    payload_snippet: Optional[str] = None

SAMPLE_ALERTS = [
    SecurityAlert(
        alert_id="ALERT-001",
        timestamp="2026-06-10 03:42:11",
        severity="HIGH",
        source_ip="192.168.1.45",
        destination_ip="10.0.0.1",
        event_type="SSH_BRUTE_FORCE",
        description="Multiple failed SSH login attempts detected from external IP",
        protocol="TCP",
        port=22,
        payload_snippet="Failed password for root from 192.168.1.45 port 22 ssh2"
    ),
    SecurityAlert(
        alert_id="ALERT-002",
        timestamp="2026-06-10 04:15:33",
        severity="CRITICAL",
        source_ip="10.0.0.99",
        destination_ip="10.0.0.200",
        event_type="DATA_EXFILTRATION",
        description="Unusual large outbound data transfer detected to unknown external host",
        protocol="TCP",
        port=443,
        payload_snippet="Outbound transfer of 2.3GB to 185.220.101.45 over HTTPS"
    ),
    SecurityAlert(
        alert_id="ALERT-003",
        timestamp="2026-06-10 05:01:22",
        severity="MEDIUM",
        source_ip="172.16.0.12",
        destination_ip="172.16.0.255",
        event_type="PORT_SCAN",
        description="Sequential port scanning activity detected on internal network",
        protocol="TCP",
        port=None,
        payload_snippet="Ports 1-1024 scanned from 172.16.0.12 in 30 seconds"
    ),
]