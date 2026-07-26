from datetime import datetime

from detection.rule_loader import RuleLoader
from detection.rule_engine import RuleEngine
from detection.rules.rule import Rule


def test_failed_login_rule_generates_alert():

    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4625,
        "source_ip": "192.168.1.10",
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1
    assert alerts[0].sid == 1001
    assert alerts[0].title == "Failed Login"
    assert alerts[0].severity == "high"




def test_threshold_rule_generates_alert_after_five_events():

    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4625,
        "source_ip": "192.168.1.10",
        "timestamp": datetime.utcnow(),
    }

    generated = []

    for i in range(5):
        alerts = engine.detect(log)

        print(f"Call {i + 1}:")
        for alert in alerts:
            print(f"  SID={alert.sid}, Title={alert.title}")

        generated.extend(alerts)

    threshold_alerts = [
        alert for alert in generated
        if alert.sid == 2001
    ]

    assert len(threshold_alerts) == 1






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

    for alert in generated:
        print(alert.sid, alert.title)

    assert len(generated) == 3

    assert generated[0].sid == 3001
    assert generated[1].sid == 3001
    assert generated[2].sid == 3001


def test_account_locked_rule_generates_alert():

    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4740,
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1
    assert alerts[0].sid == 1003
    assert alerts[0].title == "Account Locked"
    assert alerts[0].severity == "high"



def test_special_privileges_assigned_rule():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4672,
        "source": "Windows",
        "username": "Administrator",
        "source_ip": "192.168.1.10",
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.sid == 1004
    assert alert.title == "Special Privileges Assigned"
    assert alert.severity == "medium"


def test_user_account_created_rule():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4720,
        "source": "Windows",
        "username": "newuser",
        "source_ip": "192.168.1.20",
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.sid == 1005
    assert alert.title == "User Account Created"
    assert alert.severity == "high"

def test_user_added_to_security_group_rule():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4728,
        "source": "Windows",
        "username": "john",
        "source_ip": "192.168.1.30",
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.sid == 1006
    assert alert.title == "User Added to Security Group"
    assert alert.severity == "high"

def test_user_added_to_local_admins_rule():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4732,
        "source": "Windows",
        "username": "john",
        "source_ip": "192.168.1.40",
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.sid == 1007
    assert alert.title == "User Added to Local Administrators"
    assert alert.severity == "critical"

def test_service_installed_rule():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4697,
        "source": "Windows",
        "username": "SYSTEM",
        "source_ip": "127.0.0.1",
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.sid == 1008
    assert alert.title == "Service Installed"
    assert alert.severity == "high"

def test_new_windows_service_rule():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 7045,
        "source": "Windows",
        "username": "SYSTEM",
        "source_ip": "127.0.0.1",
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.sid == 1009
    assert alert.title == "New Windows Service Installed"
    assert alert.severity == "critical"

def test_powershell_script_rule():
    loader = RuleLoader()
    rules = loader.load_rules()

    engine = RuleEngine(rules)

    log = {
        "event_id": 4104,
        "source": "Windows",
        "username": "Administrator",
        "source_ip": "192.168.1.50",
        "timestamp": datetime.utcnow(),
    }

    alerts = engine.detect(log)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.sid == 1010
    assert alert.title == "PowerShell Script Executed"
    assert alert.severity == "high"







