from backend.models.siem_models import Alert, Event


class DetectionEngine:
    
    def __init__(self, rules):
        self.detection_rules = rules

    def check_for_alerts(self, event: Event) -> list[Alert]:
        """Checks incoming events if they activate a detection rule

        Args:
            event (Event):

        Returns:
            list[Alert]:
        """
        thrown_alerts = []

        if event is None:
            return

        for rule in self.detection_rules:
            alert = rule.detect(event)

            if alert is not None:
                thrown_alerts.append(alert)

        return thrown_alerts

