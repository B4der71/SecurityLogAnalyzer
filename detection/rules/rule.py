from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class Rule:
    """
    Represents a parsed detection rule.
    """

    # Rule information
    action: str                  # alert
    source: str                  # windows, linux, apache, zeek

    # Matching conditions
    conditions: Dict[str, Any] = field(default_factory=dict)

    # Threshold / correlation settings
    threshold: Optional[Dict[str, Any]] = None

    # Alert information
    message: str = ""
    severity: str = "low"
    sid: int = 0