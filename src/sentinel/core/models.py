"""Canonical (ECS-inspired) data model for SOC alerts and decisions."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class Severity(StrEnum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"informational": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}[
            self.value
        ]


class Verdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"  # correct detection, legitimate activity
    INCONCLUSIVE = "inconclusive"
    ESCALATE = "escalate"


class ObservableType(StrEnum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"
    EMAIL = "email"
    USERNAME = "username"
    HOSTNAME = "hostname"


class Observable(BaseModel):
    """An IOC / artefact extracted from an alert."""

    model_config = ConfigDict(frozen=True)

    type: ObservableType
    value: str
    role: Literal["source", "destination", "subject", "unknown"] = "unknown"

    def key(self) -> str:
        return f"{self.type}:{self.value.lower()}"


class MitreTechnique(BaseModel):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = ""
    tactic: str = ""


class HostContext(BaseModel):
    hostname: str | None = None
    ip: IPvAnyAddress | None = None
    os: str | None = None
    criticality: Literal["low", "medium", "high", "crown_jewel"] = "medium"


class UserContext(BaseModel):
    username: str | None = None
    department: str | None = None
    is_privileged: bool = False
    is_service_account: bool = False
    mfa_enabled: bool | None = None


class ProcessContext(BaseModel):
    name: str | None = None
    pid: int | None = None
    command_line: str | None = None
    parent_name: str | None = None
    parent_command_line: str | None = None
    hash_sha256: str | None = None


class NetworkContext(BaseModel):
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    bytes_out: int | None = None
    domain: str | None = None
    url: str | None = None


class Alert(BaseModel):
    """Normalised SIEM alert — the heart of the system."""

    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=lambda: f"ALT-{uuid4().hex[:12].upper()}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str  # wazuh, mock-siem, ...
    rule_id: str | None = None
    rule_name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: int = Field(default=50, ge=0, le=100)

    host: HostContext = Field(default_factory=HostContext)
    user: UserContext = Field(default_factory=UserContext)
    process: ProcessContext = Field(default_factory=ProcessContext)
    network: NetworkContext = Field(default_factory=NetworkContext)

    mitre: list[MitreTechnique] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    @field_validator("raw")
    @classmethod
    def _cap_raw_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Never let a giant log blow up the LLM context (cost + attack surface)."""
        if len(json.dumps(v, default=str)) > 20_000:
            return {"_truncated": True, "_keys": list(v)[:50]}
        return v

    def dedup_hash(self) -> str:
        """Fingerprint used to group identical alerts (noise reduction)."""
        parts = [
            self.source,
            self.rule_id or self.rule_name,
            self.host.hostname or "",
            self.user.username or "",
            self.network.destination_ip or "",
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def to_llm_context(self) -> str:
        """Compact, bounded representation — the ONLY way an alert enters a prompt."""
        lines = [
            f"ALERT {self.id} | source={self.source} | severity={self.severity}",
            f"rule: {self.rule_name}",
            f"description: {self.description[:1000]}",
            f"time: {self.timestamp.isoformat()}",
        ]
        if self.host.hostname:
            lines.append(
                f"host: {self.host.hostname} (os={self.host.os}, "
                f"criticality={self.host.criticality})"
            )
        if self.user.username:
            lines.append(
                f"user: {self.user.username} (privileged={self.user.is_privileged}, "
                f"service_account={self.user.is_service_account})"
            )
        if self.process.name:
            lines.append(f"process: {self.process.name} (pid={self.process.pid})")
            if self.process.command_line:
                lines.append(f"  cmdline: {self.process.command_line[:600]}")
            if self.process.parent_name:
                lines.append(f"  parent: {self.process.parent_name}")
        if self.network.destination_ip or self.network.domain or self.network.source_ip:
            lines.append(
                f"network: {self.network.source_ip}:{self.network.source_port} -> "
                f"{self.network.destination_ip}:{self.network.destination_port} "
                f"({self.network.protocol}) domain={self.network.domain}"
            )
        if self.mitre:
            lines.append("mitre: " + ", ".join(f"{t.technique_id} ({t.name})" for t in self.mitre))
        if self.observables:
            lines.append("observables: " + ", ".join(o.key() for o in self.observables[:25]))
        return "\n".join(lines)


class IntelVerdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class IntelResult(BaseModel):
    provider: str
    observable: Observable
    verdict: IntelVerdict = IntelVerdict.UNKNOWN
    score: int = Field(default=0, ge=0, le=100)
    summary: str = ""
    references: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    cached: bool = False


class RiskFactor(BaseModel):
    name: str
    weight: int
    rationale: str


class ActionRisk(StrEnum):
    NONE = "none"  # read-only
    LOW = "low"  # reversible, small impact
    MEDIUM = "medium"  # limited user impact
    HIGH = "high"  # business impact (isolation, disable account)
    CRITICAL = "critical"  # irreversible


class ResponseAction(BaseModel):
    action_type: str  # isolate_host, block_ip, disable_user, ...
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk: ActionRisk = ActionRisk.MEDIUM
    justification: str
    reversible: bool = True
    requires_approval: bool = True
    status: Literal["proposed", "approved", "rejected", "executed", "failed"] = "proposed"


class TriageDecision(BaseModel):
    """Final triage result — what the analyst sees."""

    alert_id: str
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    priority: Literal["P1", "P2", "P3", "P4"] = "P3"
    summary: str
    reasoning: str
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    recommended_actions: list[ResponseAction] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    intel_results: list[IntelResult] = Field(default_factory=list)
    injection_suspected: bool = False
    requires_human_approval: bool = True
    decided_by: Literal["rules", "llm", "hybrid", "human"] = "hybrid"
    model_used: str | None = None
    tokens_used: int = 0
    latency_ms: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
