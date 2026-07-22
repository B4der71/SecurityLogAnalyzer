from datetime import datetime

from detection.detector import Detector


def test_detector_uses_rule_engine():
    detector = Detector([])

    log = {
        "event_id": 4625,
        "source_ip": "192.168.1.20",
        "timestamp": datetime.now()
    }

    result = detector.detect(log)

    assert result == []