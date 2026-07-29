from datetime import datetime, UTC

from detection.rule_engine import RuleEngine
from detection.rules.rule import Rule
from services.alert_service import AlertService
from database.alert_repository import AlertRepository
from database.models import Log


def test_rule_engine_creates_database_alert(db_session):
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    rule = Rule(
        action="alert",
        source="windows",
        sid=4001,
        message="Failed Login",
        severity="high",
        conditions={
            "event_id": 4625
        }
    )

    engine = RuleEngine([rule])

    log = {
        "event_id": 4625,
        "timestamp": datetime.now(UTC),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1

    db_log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(db_log)
    db_session.commit()

    alerts[0].log = db_log

    created = service.create_alert(alerts[0])

    assert created.alert_id is not None
    assert repository.get_by_id(created.alert_id) is not None