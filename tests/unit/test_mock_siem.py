from sentinel.ingestion.mock_siem import MockSIEM


def test_same_seed_same_alerts():
    a = MockSIEM(seed=1).stream(5)
    b = MockSIEM(seed=1).stream(5)
    assert [x.rule_id for x in a] == [x.rule_id for x in b]


def test_every_scenario_builds():
    sim = MockSIEM(seed=1)
    for sc in sim.scenarios:
        alert = sim.generate(sc["id"])
        assert alert.raw["ground_truth"] in {"true_positive", "false_positive", "benign_positive"}
