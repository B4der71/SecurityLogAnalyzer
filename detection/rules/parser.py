import re

from detection.rules.rule import Rule


class RuleParser:
    """
    Parses Snort-like rule syntax into Rule objects.
    """

    def parse(self, rule_text: str) -> Rule:
        """
        Parse a single rule.

        Example:

        alert windows (
            event_id:4625;
            msg:"Failed Login";
            severity:high;
            sid:1001;
        )
        """

        rule_text = rule_text.strip()

        # Parse header: alert windows (
        header = re.match(r"(\w+)\s+(\w+)\s*\(", rule_text)
        if not header:
            raise ValueError("Invalid rule header.")

        action = header.group(1)
        source = header.group(2)

        # Extract everything inside (...)
        body = re.search(r"\((.*)\)", rule_text, re.DOTALL)
        if not body:
            raise ValueError("Rule body not found.")

        body = body.group(1)

        conditions = {}
        message = ""
        severity = "low"
        sid = 0
        threshold = {}

        # Read each line
        for line in body.split(";"):
            line = line.strip()

            if not line:
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            key = key.strip()
            value = value.strip().strip('"')

            if key == "event_id":
                conditions["event_id"] = int(value)

            elif key == "msg":
                message = value

            elif key == "severity":
                severity = value

            elif key == "sid":
                sid = int(value)
            
            elif key == "threshold":
                threshold["count"] = int(value)

            elif key == "seconds":
                threshold["seconds"] = int(value)

            elif key == "track":
                threshold["track"] = value

        return Rule(
            action=action,
            source=source,
            conditions=conditions,
            threshold=threshold if threshold else None,
            message=message,
            severity=severity,
            sid=sid,
        )