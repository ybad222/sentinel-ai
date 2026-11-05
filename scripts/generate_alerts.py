"""Generate a reproducible history of simulated alerts (JSONL)."""

from pathlib import Path

from sentinel.ingestion.mock_siem import MockSIEM

out = Path("data/alerts/generated.jsonl")
alerts = MockSIEM(seed=1337).stream(200)
out.write_text("\n".join(a.model_dump_json() for a in alerts) + "\n", encoding="utf-8")
print(f"{len(alerts)} alerts -> {out}")
print(alerts[0].to_llm_context())
