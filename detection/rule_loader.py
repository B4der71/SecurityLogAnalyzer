from pathlib import Path

from detection.rules.parser import RuleParser

import logging
from pathlib import Path

class RuleLoader:
    """
    Loads detection rules from .rules files.
    """

    def __init__(self):
        self.parser = RuleParser()
        self.logger = logging.getLogger(__name__)

    def load_rules(self):

        self.logger.info("Loading detection rules...")

        rules = []

        rules_directory = Path(__file__).parent / "simple_rules"

        for rule_file in rules_directory.glob("*.rules"):

            self.logger.info("Loading %s...", rule_file.name)

            try:
                loaded_rules = self.load_file(rule_file)

                self.logger.info(
                    "%s: %d rule(s) loaded.",
                    rule_file.name,
                    len(loaded_rules)
                )

                rules.extend(loaded_rules)

            except Exception as e:
                self.logger.error(
                    "Failed to load '%s': %s",
                    rule_file.name,
                    e
                )

        rules = self._validate_unique_sids(rules)

        self.logger.info(
            "Successfully loaded %d unique rule(s).",
            len(rules)
        )

        return rules


    def _validate_unique_sids(self, rules):
        unique_rules = []
        seen = {}

        for rule in rules:

            if rule.sid in seen:

                first = seen[rule.sid]

                self.logger.warning(
                    "Duplicate SID %d detected. Keeping '%s' and skipping duplicate '%s'.",
                    rule.sid,
                    first.message,
                    rule.message,
                )

                continue

            seen[rule.sid] = rule
            unique_rules.append(rule)

        return unique_rules
    

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

    