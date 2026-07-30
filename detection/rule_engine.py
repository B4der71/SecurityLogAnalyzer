from detection.state_manager import StateManager
from alerts.alert import Alert
from fnmatch import fnmatch




class RuleEngine:
    """
    Executes detection rules against logs.
    """

    def __init__(self, rules):
        self.rules = rules
        self.state_manager = StateManager()

    def detect(self, log):
        """
        Detect matching rules for a single log.
        """

        matches = []

        for rule in self.rules:

            if not self._matches(rule, log):
                continue

            if rule.threshold:
                result = self._handle_threshold_rule(rule, log)

                if result:
                    matches.append(result)
            else:
                matches.append(
                    self._create_alert(rule, log)
                )

        return matches

    def _get_log_value(self, log, key):
        """
        Return a field value from either a dictionary
        or a Log object.
        """

        if isinstance(log, dict):
            return log.get(key)

        return getattr(log, key, None)

    def _match_value(self, actual_value, expected_value):
        """
        Compare a log value against a rule value.

        Supports:
            - Exact matching
            - Wildcard matching
            - Case-insensitive string matching
        """

        if actual_value is None:
            return False

        # Preserve numeric comparisons
        if isinstance(actual_value, (int, float)) and isinstance(expected_value, (int, float)):
            return actual_value == expected_value

        actual = str(actual_value).casefold()
        expected = str(expected_value).casefold()

        if "*" in expected or "?" in expected:
            return fnmatch(actual, expected)

        return actual == expected

    def _matches(self, rule, log):
        """
        Check whether a log satisfies all rule conditions.
        """

        for key, expected_value in rule.conditions.items():

            actual_value = self._get_log_value(log, key)

            if not self._match_value(actual_value, expected_value):
                return False

        return True
        
    def _handle_threshold_rule(self, rule, log):
        """
        Process threshold-based rules.
        """

        key = self._build_tracking_key(rule, log)

        self.state_manager.add_event(
            key,
            {
                "timestamp": self._get_log_value(log, "timestamp")
            }
        )

        count = self.state_manager.count_recent_events(
            key,
            rule.threshold["seconds"]
        )

        milestone = None

        trigger_points = [rule.threshold["count"]] + rule.milestones

        if count in trigger_points:
            milestone = count

        if milestone is None:
            return None

        if self.state_manager.has_alerted(key, milestone):
            return None

        self.state_manager.mark_alerted(key, milestone)

        return self._create_alert(rule, log)
    
    def _build_tracking_key(self, rule, log):
        """
        Build a unique key used by the StateManager.
        """

        track = rule.threshold["track"]

        if track == "by_src":
            return (
                f"{rule.sid}:"
                f"{self._get_log_value(log, 'source_ip')}"
            )

        raise ValueError(f"Unsupported track type: {track}")
    

    def _create_alert(self, rule, log):
        """
        Create an Alert from a matched rule.
        """

        return Alert(
            sid=rule.sid,
            title=rule.message,
            description=rule.message,
            severity=rule.severity,
            source=rule.source,
            detection_method="rule",
            timestamp=self._get_log_value(log, "timestamp"),
            log=log,
        )