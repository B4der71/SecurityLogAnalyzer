from pathlib import Path

from detection.rules.parser import RuleParser


class RuleLoader:
    """
    Loads detection rules from .rules files.
    """

    def __init__(self):
        self.parser = RuleParser()

    def load_rules(self):
        """
        Load all rules from the simple_rules directory.
        """

        rules = []

        rules_directory = Path(__file__).parent / "simple_rules"

        for rule_file in rules_directory.glob("*.rules"):
            rules.extend(self.load_file(rule_file))

        return rules

    def load_file(self, file_path):
        """
        Load all rules from a single .rules file.
        """

        rules = []

        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # Split each rule by the closing parenthesis
        raw_rules = content.split(")")

        for raw_rule in raw_rules:

            raw_rule = raw_rule.strip()

            if not raw_rule:
                continue

            raw_rule += ")"

            rule = self.parser.parse(raw_rule)

            rules.append(rule)

        return rules