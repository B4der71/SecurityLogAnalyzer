from datetime import datetime

from detection.rules.rule import Rule
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

from datetime import datetime

from detection.rules.rule import Rule
from detection.rule_engine import RuleEngine


def test_threshold_rule_generates_alert_after_three_events():

    rule = Rule(
        action="alert",
        source="windows",
        sid=2001,
        message="Brute Force",
        severity="critical",
        conditions={
            "event_id": 4625
        },
        threshold={
            "count": 3,
            "seconds": 60,
            "track": "by_src"
        }
    )

    engine = RuleEngine([rule])

    log = {
        "event_id": 4625,
        "source_ip": "192.168.1.10",
        "timestamp": datetime.utcnow(),
    }

    assert engine.detect(log) == []
    assert engine.detect(log) == []

    alerts = engine.detect(log)

    assert len(alerts) == 1
    assert alerts[0].sid == 2001


from datetime import datetime

from detection.rules.rule import Rule
from detection.rule_engine import RuleEngine


def test_threshold_rule_milestones():

    rule = Rule(
        action="alert",
        source="windows",
        sid=3001,
        message="Brute Force",
        severity="critical",
        conditions={
            "event_id": 4625
        },
        threshold={
            "count": 3,
            "seconds": 60,
            "track": "by_src"
        },
        milestones=[5, 10]
    )

    engine = RuleEngine([rule])

    log = {
        "event_id": 4625,
        "source_ip": "192.168.1.10",
        "timestamp": datetime.utcnow(),
    }

    generated = []

    for _ in range(10):
        generated.extend(engine.detect(log))

    assert len(generated) == 3

    assert generated[0].sid == 3001
    assert generated[1].sid == 3001
    assert generated[2].sid == 3001