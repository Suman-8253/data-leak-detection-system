"""
Dashboard service — aggregated statistics from real database records.
"""
from database.repositories import (
    UserRepository, RecordRepository,
    SecurityEventRepository, CapabilityRepository, AuditLogRepository
)
from database.connection import check_connection
from security.encryption import is_key_configured


def get_admin_dashboard_stats():
    """
    Get aggregated statistics for the admin dashboard.
    All values come from actual database queries.
    """
    total_users = UserRepository.count_all()
    total_records = RecordRepository.count_all()
    total_events = SecurityEventRepository.count_events()
    blocked_requests = SecurityEventRepository.count_events(
        event_type='sql_injection_attempt'
    )
    failed_logins = SecurityEventRepository.count_events(
        event_type='failed_login'
    )
    unauthorized_access = SecurityEventRepository.count_events(
        event_type='unauthorized_access'
    )
    active_tokens = CapabilityRepository.count_active()
    revoked_tokens = CapabilityRepository.count_revoked()

    severity_dist = SecurityEventRepository.severity_distribution()
    recent_events = SecurityEventRepository.recent_events(5)

    return {
        'total_users': total_users,
        'total_records': total_records,
        'total_events': total_events,
        'blocked_requests': blocked_requests,
        'failed_logins': failed_logins,
        'unauthorized_access': unauthorized_access,
        'active_tokens': active_tokens,
        'revoked_tokens': revoked_tokens,
        'severity_distribution': severity_dist,
        'recent_events': recent_events,
    }


def get_user_dashboard_stats(user_id):
    """Stats visible to a regular user — only their own data."""
    user_records = RecordRepository.count_by_owner(user_id)
    active_tokens = CapabilityRepository.count_active()

    return {
        'user_records': user_records,
        'active_tokens': active_tokens,
    }


def get_system_health():
    """System status checks."""
    db_ok, db_msg = check_connection()
    enc_ok = is_key_configured()

    return {
        'database_connected': db_ok,
        'database_message': db_msg if db_ok else 'Connection failed',
        'encryption_configured': enc_ok,
    }
