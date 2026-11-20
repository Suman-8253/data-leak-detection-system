"""
Security service — security events and monitoring business logic.
"""
from database.repositories import SecurityEventRepository


def get_security_events(page=1, per_page=50, event_type=None,
                        severity=None, date_from=None, date_to=None):
    """List security events with pagination and filters."""
    offset = (page - 1) * per_page
    events = SecurityEventRepository.list_events(
        per_page, offset, event_type, severity, date_from, date_to
    )
    total = SecurityEventRepository.count_events(
        event_type, severity, date_from, date_to
    )
    total_pages = max(1, (total + per_page - 1) // per_page)
    return events, total, total_pages


def get_severity_distribution():
    """Get event count by severity."""
    return SecurityEventRepository.severity_distribution()


def get_events_over_time(days=7):
    """Get event counts grouped by day."""
    return SecurityEventRepository.events_over_time(days)


def get_recent_events(limit=10):
    """Get the latest security events."""
    return SecurityEventRepository.recent_events(limit)


def get_event_count(event_type=None, severity=None):
    """Count events with optional filter."""
    return SecurityEventRepository.count_events(event_type=event_type, severity=severity)
