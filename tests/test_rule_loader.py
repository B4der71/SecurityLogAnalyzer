from pathlib import Path

from detection.rule_loader import RuleLoader


def test_load_single_rule_file():

    loader = RuleLoader()

    file_path = Path("detection/simple_rules/windows.rules")

    rules = loader.load_file(file_path)

    assert len(rules) > 0