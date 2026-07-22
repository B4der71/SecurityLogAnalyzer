from detection.state_manager import StateManager






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
        
    def _handle_threshold_rule(self, rule, log):
        """
        Process threshold-based rules.
        """

        key = self._build_tracking_key(rule, log)

        self.state_manager.add_event(
            key,
            {
                "timestamp": log["timestamp"]
            }
        )

        count = self.state_manager.count_recent_events(
            key,
            rule.threshold["seconds"]
        )

        milestone = None

        if count == rule.threshold["count"]:
            milestone = rule.threshold["count"]

        elif count == 100:
            milestone = 100

        if milestone is None:
            return None

        if self.state_manager.has_alerted(key, milestone):
            return None

        self.state_manager.mark_alerted(key, milestone)

        return rule 
    
    def _build_tracking_key(self, rule, log):
        """
        Build a unique key used by the StateManager.
        """

        track = rule.threshold["track"]

        if track == "by_src":
            return f"{rule.sid}:{log['source_ip']}"

        raise ValueError(f"Unsupported track type: {track}")