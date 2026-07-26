from datetime import datetime

from detection.detector import Detector
from detection.rules.rule import Rule


def build_rule():
    return Rule(
        action="alert",
        source="windows",
        sid=1001,
        message="Failed Login",
        severity="high",
        conditions={
            "event_id": 4625
        }
    )


def build_log():
    return {
        "event_id": 4625,
        "timestamp": datetime.now(),
    }


def test_detector_returns_alert():
    detector = Detector([build_rule()])

    alerts = detector.detect(build_log())

    assert len(alerts) == 1
    assert alerts[0].sid == 1001


def test_detector_returns_empty_for_non_matching_log():
    detector = Detector([build_rule()])

    log = {
        "event_id": 4624,
        "timestamp": datetime.now(),
    }

    alerts = detector.detect(log)

    assert alerts == []


def test_detector_can_process_multiple_logs():
    detector = Detector([build_rule()])

    log = build_log()

    alerts1 = detector.detect(log)
    alerts2 = detector.detect(log)

    assert len(alerts1) == 1
    assert len(alerts2) == 1


def test_detector_multiple_rules():
    rules = [
        Rule(
            action="alert",
            source="windows",
            sid=1001,
            message="Failed Login",
            severity="high",
            conditions={"event_id": 4625},
        ),
        Rule(
            action="alert",
            source="windows",
            sid=1002,
            message="Another Rule",
            severity="medium",
            conditions={"event_id": 4625},
        ),
    ]

    detector = Detector(rules)

    alerts = detector.detect(build_log())

    assert len(alerts) == 2


def test_detector_returns_list():
    detector = Detector([build_rule()])

    alerts = detector.detect(build_log())

    assert isinstance(alerts, list)


def test_detector_empty_rules():
    detector = Detector([])

    alerts = detector.detect(build_log())

    assert alerts == []


def test_detector_does_not_modify_log():
    detector = Detector([build_rule()])

    log = build_log()
    original = log.copy()

    detector.detect(log)

    assert log == original


def test_account_lockout_generates_alert():

    detector = Detector()

    log = {
        "event_id": 4740,
        "username": "admin",
        "source": "windows",
    }

    alerts = detector.process(log)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.sid == 1003
    assert alert.title == "Account Locked"
    assert alert.severity == "high"