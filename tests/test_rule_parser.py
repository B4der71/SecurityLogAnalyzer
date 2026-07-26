import pytest

from detection.rules.parser import RuleParser


def test_parse_basic_rule():
    parser = RuleParser()

    rule = parser.parse("""
        alert windows (
            event_id:4625;
            msg:"Failed Login";
            severity:high;
            sid:1001;
        )
    """)

    assert rule.action == "alert"
    assert rule.source == "windows"
    assert rule.conditions["event_id"] == 4625
    assert rule.message == "Failed Login"
    assert rule.severity == "high"
    assert rule.sid == 1001


def test_parse_threshold():
    parser = RuleParser()

    rule = parser.parse("""
        alert windows (
            event_id:4625;
            threshold:3;
            seconds:60;
            track:by_src;
        )
    """)

    assert rule.threshold["count"] == 3
    assert rule.threshold["seconds"] == 60
    assert rule.threshold["track"] == "by_src"


def test_parse_milestones():
    parser = RuleParser()

    rule = parser.parse("""
        alert windows (
            milestones:5,10,20;
        )
    """)

    assert rule.milestones == [5, 10, 20]


def test_invalid_header():
    parser = RuleParser()

    with pytest.raises(ValueError, match="Invalid rule header"):
        parser.parse("""
            windows (
                event_id:4625;
            )
        """)


def test_missing_rule_body():
    parser = RuleParser()

    with pytest.raises(ValueError, match="Rule body not found"):
        parser.parse("""
            alert windows (
        """)


def test_empty_rule():
    parser = RuleParser()

    with pytest.raises(ValueError):
        parser.parse("")


def test_invalid_event_id():
    parser = RuleParser()

    with pytest.raises(ValueError):
        parser.parse("""
            alert windows (
                event_id:abc;
            )
        """)


def test_invalid_sid():
    parser = RuleParser()

    with pytest.raises(ValueError):
        parser.parse("""
            alert windows (
                sid:test;
            )
        """)


def test_invalid_threshold():
    parser = RuleParser()

    with pytest.raises(ValueError):
        parser.parse("""
            alert windows (
                threshold:abc;
            )
        """)


def test_invalid_seconds():
    parser = RuleParser()

    with pytest.raises(ValueError):
        parser.parse("""
            alert windows (
                threshold:3;
                seconds:abc;
            )
        """)


def test_invalid_milestones():
    parser = RuleParser()

    with pytest.raises(ValueError):
        parser.parse("""
            alert windows (
                milestones:5,a,10;
            )
        """)


def test_parse_defaults():
    parser = RuleParser()

    rule = parser.parse("""
        alert windows (
        )
    """)

    assert rule.action == "alert"
    assert rule.source == "windows"
    assert rule.conditions == {}
    assert rule.message == ""
    assert rule.severity == "low"
    assert rule.sid == 0
    assert rule.threshold is None
    assert rule.milestones == []