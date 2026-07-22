from collections import defaultdict
from datetime import datetime, timedelta


class StateManager:
    """
    Stores temporary detection state for threshold and correlation rules.
    """

    def __init__(self):
        self.state = defaultdict(list)

    def add_event(self, key, event):
        """
        Store an event under a specific key.
        """
        self.state[key].append(event)

    def get_events(self, key):
        """
        Return all events stored under a key.
        """
        return self.state[key]
    
    def count_recent_events(self, key, seconds):
        """
        Count events that occurred within the last 'seconds' seconds.
        Expired events are removed automatically.
        """

        now = datetime.now()
        cutoff = now - timedelta(seconds=seconds)

        recent_events = []

        for event in self.state[key]:
            if event["timestamp"] >= cutoff:
                recent_events.append(event)

        # Remove expired events
        self.state[key] = recent_events

        return len(recent_events)
    