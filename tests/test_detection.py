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


from detection.rule_engine import RuleEngine
from detection.rule_loader import RuleLoader


def test_rule_engine_creation():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    assert engine.rules == rules

def test_detect_returns_list():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4625
    }

    alerts = engine.detect(log)

    assert isinstance(alerts, list)


def test_detect_matching_rule():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4625
    }

    matches = engine.detect(log)

    assert len(matches) == 1
    assert matches[0].sid == 1001
    assert matches[0].message == "Failed Login"

def test_detect_no_match():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4688
    }

    matches = engine.detect(log)

    assert len(matches) == 0


from detection.detector import Detector
from detection.rule_loader import RuleLoader
from detection.rule_engine import RuleEngine


def test_detector_creation():
    loader = RuleLoader()
    rules = loader.load_rules()

    detector = Detector(rules)

    assert isinstance(detector.rule_engine, RuleEngine)


def test_detector_detect():
    loader = RuleLoader()
    rules = loader.load_rules()

    detector = Detector(rules)

    log = {
        "event_id": 4625
    }

    detections = detector.detect(log)

    assert len(detections) == 1
    assert detections[0].sid == 1001
    assert detections[0].message == "Failed Login"

def test_detector_no_detection():
    loader = RuleLoader()
    rules = loader.load_rules()

    detector = Detector(rules)

    log = {
        "event_id": 9999
    }

    detections = detector.detect(log)

    assert len(detections) == 0