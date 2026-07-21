from detection.rules.rule import Rule


def test_rule_creation():
    rule = Rule(
        action="alert",
        source="windows",
        conditions={
            "event_id": 4625
        },
        message="Failed Login",
        severity="high",
        sid=1001
    )

    assert rule.action == "alert"
    assert rule.source == "windows"
    assert rule.conditions["event_id"] == 4625
    assert rule.threshold is None
    assert rule.message == "Failed Login"
    assert rule.severity == "high"
    assert rule.sid == 1001