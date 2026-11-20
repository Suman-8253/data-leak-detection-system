"""
Audit logger module.
Structured audit logging for sensitive operations.
"""
from database.repositories import AuditLogRepository


def audit_action(actor_id, action, resource_type=None, resource_id=None,
                 outcome='success', correlation_id=None):
    """
    Record an audit log entry.
    Uses parameterized queries internally (via AuditLogRepository).
    """
    return AuditLogRepository.log_action(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        correlation_id=correlation_id,
    )
