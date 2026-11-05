"""Scenario-driven SIEM alert simulator (reproducible with a seed)."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from faker import Faker

from sentinel.core.config import settings
from sentinel.core.models import (
    Alert,
    HostContext,
    MitreTechnique,
    NetworkContext,
    ProcessContext,
    Severity,
    UserContext,
)
from sentinel.ingestion.extractors import enrich_observables

INTERNAL_HOSTS = [
    ("WKS-FIN-014", "10.10.20.14", "Windows 11", "medium"),
    ("WKS-RD-102", "10.10.30.102", "Windows 11", "high"),
    ("SRV-DC-01", "10.10.1.5", "Windows Server 2022", "crown_jewel"),
    ("SRV-WEB-03", "10.10.40.3", "Ubuntu 22.04", "high"),
    ("SRV-BKP-01", "10.10.50.1", "Ubuntu 24.04", "high"),
    ("LAP-SALES-77", "10.10.60.77", "Windows 11", "low"),
]


class MockSIEM:
    def __init__(self, scenarios_path: Path | None = None, seed: int | None = None) -> None:
        path = scenarios_path or settings.data_dir / "alerts" / "scenarios.yaml"
        self.scenarios: list[dict[str, Any]] = yaml.safe_load(path.read_text(encoding="utf-8"))[
            "scenarios"
        ]
        self._rng = random.Random(seed)  # noqa: S311 - simulation, not crypto
        self._fake = Faker("fr_FR")
        if seed is not None:
            self._fake.seed_instance(seed)

    def scenario(self, scenario_id: str) -> dict[str, Any]:
        return next(s for s in self.scenarios if s["id"] == scenario_id)

    def generate(self, scenario_id: str | None = None) -> Alert:
        sc = (
            self.scenario(scenario_id)
            if scenario_id
            else self._rng.choices(
                self.scenarios, weights=[s.get("weight", 1) for s in self.scenarios]
            )[0]
        )

        hostname, ip, os_name, crit = self._rng.choice(INTERNAL_HOSTS)
        h = sc.get("host", {})
        u = sc.get("user", {})
        username = u.get("username") or (
            f"{self._fake.first_name()[0].lower()}.{self._fake.last_name().lower()}"
        )

        alert = Alert(
            timestamp=datetime.now(UTC) - timedelta(minutes=self._rng.randint(0, 120)),
            source="mock-siem",
            rule_id=sc["id"],
            rule_name=sc["rule_name"],
            description=sc.get("notes", sc["rule_name"]),
            severity=Severity(sc.get("severity", "medium")),
            confidence=self._rng.randint(55, 95),
            host=HostContext(
                hostname=h.get("hostname", hostname),
                ip=h.get("ip", ip),
                os=h.get("os", os_name),
                criticality=h.get("criticality", crit),
            ),
            user=UserContext(
                username=username,
                department=u.get(
                    "department", self._rng.choice(["IT", "Finance", "R&D", "Sales", "HR"])
                ),
                is_privileged=u.get("is_privileged", self._rng.random() < 0.15),
                is_service_account=u.get("is_service_account", False),
                mfa_enabled=u.get("mfa_enabled", self._rng.random() < 0.8),
            ),
            process=ProcessContext(**sc.get("process", {})),
            network=NetworkContext(**sc.get("network", {})),
            mitre=[MitreTechnique(**m) for m in sc.get("mitre", [])],
            tags=["mock", sc["id"]],
            raw={"scenario_id": sc["id"], "ground_truth": sc.get("ground_truth")},
        )
        return enrich_observables(alert)

    def stream(self, n: int = 20) -> list[Alert]:
        return [self.generate() for _ in range(n)]
