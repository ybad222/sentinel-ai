"""Download MITRE ATT&CK Enterprise (STIX) and flatten it to a small JSON."""

import json
from pathlib import Path

import httpx

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT = Path("data/intel/attack_techniques.json")

bundle = httpx.get(URL, timeout=180, follow_redirects=True).json()
techniques: dict[str, dict] = {}
for obj in bundle["objects"]:
    if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
        continue
    ext = next(
        (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
        None,
    )
    if ext:
        techniques[ext["external_id"]] = {
            "id": ext["external_id"],
            "name": obj.get("name", ""),
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
            "description": obj.get("description", "")[:2000],
            "detection": obj.get("x_mitre_detection", "")[:1500],
            "url": ext.get("url", ""),
        }
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(techniques, ensure_ascii=False), encoding="utf-8")
print(f"{len(techniques)} techniques -> {OUT}")
