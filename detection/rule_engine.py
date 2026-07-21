class RuleEngine:
    """
    Executes detection rules against logs.
    """

    def __init__(self, rules):
        self.rules = rules

    def detect(self, log):
        """
        Detect matching rules for a single log.
        """

        matches = []

        for rule in self.rules:

            if self._matches(rule, log):
                matches.append(rule)

        return matches

    def _matches(self, rule, log):
        """
        Check whether a log satisfies all rule conditions.
        """

        for key, expected_value in rule.conditions.items():

            if key not in log:
                return False

            if log[key] != expected_value:
                return False

        return True