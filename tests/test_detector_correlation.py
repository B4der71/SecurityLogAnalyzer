from datetime import datetime

from detection.detector import Detector
from detection.rules.rule import Rule


def test_bruteforce_success_correlation():

    rules = [
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4625},
            threshold=None,
            milestones=[],
            message="Failed Login",
            severity="high",
            sid=1001,
        ),
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4624},
            threshold=None,
            milestones=[],
            message="Successful Login",
            severity="low",
            sid=1002,
        ),
    ]

    detector = Detector(rules)

    logs = [
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4624,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
    ]

    alerts = []

    for log in logs:
        alerts.extend(detector.detect(log))

    correlation_alerts = [
        alert for alert in alerts
        if alert.detection_method == "correlation"
    ]

    assert len(correlation_alerts) == 1

    assert correlation_alerts[0].title == "Brute Force Success"
    assert correlation_alerts[0].severity == "critical"
    assert correlation_alerts[0].sid == 9001

def test_no_correlation_with_two_failures():

    rules = [
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4625},
            threshold=None,
            milestones=[],
            message="Failed Login",
            severity="high",
            sid=1001,
        ),
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4624},
            threshold=None,
            milestones=[],
            message="Successful Login",
            severity="low",
            sid=1002,
        ),
    ]

    detector = Detector(rules)

    logs = [
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4624,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
    ]

    alerts = []

    for log in logs:
        alerts.extend(detector.detect(log))

    correlation_alerts = [
        alert for alert in alerts
        if alert.detection_method == "correlation"
    ]

    assert len(correlation_alerts) == 0

def test_no_correlation_different_username():

    rules = [
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4625},
            threshold=None,
            milestones=[],
            message="Failed Login",
            severity="high",
            sid=1001,
        ),
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4624},
            threshold=None,
            milestones=[],
            message="Successful Login",
            severity="low",
            sid=1002,
        ),
    ]

    detector = Detector(rules)

    logs = [
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4625,
            "username": "john",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4624,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
    ]

    alerts = []

    for log in logs:
        alerts.extend(detector.detect(log))

    correlation_alerts = [
        alert for alert in alerts
        if alert.detection_method == "correlation"
    ]

    assert len(correlation_alerts) == 0


def test_no_correlation_different_source_ip():

    rules = [
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4625},
            threshold=None,
            milestones=[],
            message="Failed Login",
            severity="high",
            sid=1001,
        ),
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4624},
            threshold=None,
            milestones=[],
            message="Successful Login",
            severity="low",
            sid=1002,
        ),
    ]

    detector = Detector(rules)

    logs = [
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "10.0.0.5",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4625,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
        {
            "event_id": 4624,
            "username": "admin",
            "source_ip": "192.168.1.10",
            "timestamp": datetime.now(),
        },
    ]

    alerts = []

    for log in logs:
        alerts.extend(detector.detect(log))

    correlation_alerts = [
        alert for alert in alerts
        if alert.detection_method == "correlation"
    ]

    assert len(correlation_alerts) == 0

def test_duplicate_success_generates_only_one_correlation():

    rules = [
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4625},
            threshold=None,
            milestones=[],
            message="Failed Login",
            severity="high",
            sid=1001,
        ),
        Rule(
            action="alert",
            source="windows",
            conditions={"event_id": 4624},
            threshold=None,
            milestones=[],
            message="Successful Login",
            severity="low",
            sid=1002,
        ),
    ]

    detector = Detector(rules)

    logs = [
        {"event_id": 4625, "username": "admin", "source_ip": "192.168.1.10", "timestamp": datetime.now()},
        {"event_id": 4625, "username": "admin", "source_ip": "192.168.1.10", "timestamp": datetime.now()},
        {"event_id": 4625, "username": "admin", "source_ip": "192.168.1.10", "timestamp": datetime.now()},
        {"event_id": 4624, "username": "admin", "source_ip": "192.168.1.10", "timestamp": datetime.now()},
        {"event_id": 4624, "username": "admin", "source_ip": "192.168.1.10", "timestamp": datetime.now()},
    ]

    alerts = []

    for log in logs:
        alerts.extend(detector.detect(log))

    correlation_alerts = [
        alert for alert in alerts
        if alert.detection_method == "correlation"
    ]

    assert len(correlation_alerts) == 1










