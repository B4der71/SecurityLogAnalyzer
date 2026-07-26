from datetime import datetime

from detection.rule import Rule
from detection.rule_engine import RuleEngine


def test_failed_login_rule_generates_alert():

    rule = Rule(
        action="alert",
        source="windows",
        conditions={
            "event_id": 4625
        },
        message="Failed Login",
        severity="high",
        sid=1001,
    )

    engine = RuleEngine([rule])

    log = {
        "event_id": 4625,
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1
    assert alerts[0].sid == 1001
    assert alerts[0].title == "Failed Login"
    assert alerts[0].severity == "high"