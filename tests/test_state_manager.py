from datetime import datetime, timedelta, UTC

from detection.state_manager import StateManager


def test_add_event():
    manager = StateManager()

    event = {
        "timestamp": datetime.now(UTC),
        "event_id": 4625
    }

    manager.add_event("host1", event)

    events = manager.get_events("host1")

    assert len(events) == 1
    assert events[0] == event


def test_get_events_unknown_key():
    manager = StateManager()

    assert manager.get_events("unknown") == []


def test_multiple_keys_are_independent():
    manager = StateManager()

    event1 = {
        "timestamp": datetime.now(UTC),
        "event_id": 4625
    }

    event2 = {
        "timestamp": datetime.now(UTC),
        "event_id": 4624
    }

    manager.add_event("host1", event1)
    manager.add_event("host2", event2)

    assert len(manager.get_events("host1")) == 1
    assert len(manager.get_events("host2")) == 1

    assert manager.get_events("host1")[0]["event_id"] == 4625
    assert manager.get_events("host2")[0]["event_id"] == 4624


def test_count_recent_events():
    manager = StateManager()

    manager.add_event(
        "host1",
        {
            "timestamp": datetime.now(UTC),
            "event_id": 4625
        }
    )

    count = manager.count_recent_events("host1", 60)

    assert count == 1


def test_expired_events_are_removed():
    manager = StateManager()

    manager.add_event(
        "host1",
        {
            "timestamp": datetime.now(UTC) - timedelta(seconds=120),
            "event_id": 4625
        }
    )

    count = manager.count_recent_events("host1", 60)

    assert count == 0
    assert manager.get_events("host1") == []


def test_has_alerted_initially_false():
    manager = StateManager()

    assert manager.has_alerted("host1", 3) is False


def test_mark_alerted():
    manager = StateManager()

    manager.mark_alerted("host1", 3)

    assert manager.has_alerted("host1", 3) is True


def test_multiple_milestones():
    manager = StateManager()

    manager.mark_alerted("host1", 3)
    manager.mark_alerted("host1", 5)
    manager.mark_alerted("host1", 10)

    assert manager.has_alerted("host1", 3)
    assert manager.has_alerted("host1", 5)
    assert manager.has_alerted("host1", 10)


def test_multiple_hosts_have_independent_alerts():
    manager = StateManager()

    manager.mark_alerted("host1", 3)

    assert manager.has_alerted("host1", 3)
    assert not manager.has_alerted("host2", 3)