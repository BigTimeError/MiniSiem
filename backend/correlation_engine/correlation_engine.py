from backend.models.siem_models import Alert, Correlation, Event


class CorrelationEngine:
    
    def __init__(self, rules):
        self.correlation_rules = rules

    def check_for_correlations(self, alerts: list[Alert], event: Event) -> list[Correlation]:
        """Checks incoming events and alerts if they activate a correlation rule

        Args:
            alerts (list[Alert]):
            event (Event):

        Returns:
            list[Correlation]:
        """
        correlations = []

        for rule in self.correlation_rules:
            for alert in alerts:
                correlation = rule.correlate(event, alert)

                if correlation is not None:
                    correlations.append(correlation)

        return correlations

