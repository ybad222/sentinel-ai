from sentinel.core.models import Alert, Severity


def test_raw_is_truncated():
    a = Alert(source="t", rule_name="r", raw={"blob": "x" * 50_000})
    assert a.raw["_truncated"] is True


def test_dedup_hash_is_stable():
    a = Alert(source="t", rule_name="r")
    b = Alert(source="t", rule_name="r")
    assert a.id != b.id and a.dedup_hash() == b.dedup_hash()


def test_severity_score():
    assert Severity.CRITICAL.score == 100
