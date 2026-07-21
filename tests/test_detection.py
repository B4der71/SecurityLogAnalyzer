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

from detection.rules.parser import RuleParser


def test_rule_parser():
    parser = RuleParser()

    rule_text = """
    alert windows (
        event_id:4625;
        msg:"Failed Login";
        severity:high;
        sid:1001;
    )
    """

    rule = parser.parse(rule_text)

    assert rule.action == "alert"
    assert rule.source == "windows"
    assert rule.conditions["event_id"] == 4625
    assert rule.message == "Failed Login"
    assert rule.severity == "high"
    assert rule.sid == 1001


from detection.rule_loader import RuleLoader


def test_rule_loader():

    loader = RuleLoader()

    rules = loader.load_rules()

    assert len(rules) == 1

    rule = rules[0]

    assert rule.action == "alert"
    assert rule.source == "windows"
    assert rule.conditions["event_id"] == 4625
    assert rule.message == "Failed Login"
    assert rule.severity == "high"
    assert rule.sid == 1001