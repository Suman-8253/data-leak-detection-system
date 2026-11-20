"""
Injection detection module.
Monitors inputs for SQL injection patterns and logs security events.
This is the DETECTION layer — parameterized queries are the PREVENTION layer.
"""
import uuid
from flask import request
from security.sql_safety import detect_sql_injection_attempt, sanitize_log_detail
from database.repositories import SecurityEventRepository


def check_and_log_injection(input_value, field_name='input', user_id=None):
    """
    Check an input for SQL injection patterns.
    If suspicious, log a security event and return True.
    The caller should still proceed safely because parameterized queries
    prevent actual injection — this is for monitoring only.

    Returns:
        (is_suspicious, correlation_id)
    """
    is_suspicious, matched_pattern = detect_sql_injection_attempt(input_value)

    if is_suspicious:
        correlation_id = uuid.uuid4()
        endpoint = request.path if request else 'unknown'

        # Sanitize the detail — never log raw passwords or full payloads
        safe_detail = sanitize_log_detail(
            f"Suspicious input in '{field_name}': pattern matched [{matched_pattern}]"
        )

        SecurityEventRepository.log_event(
            event_type='sql_injection_attempt',
            severity='high',
            user_id=user_id,
            endpoint=endpoint,
            action_taken='blocked_and_logged',
            sanitized_details=safe_detail,
            correlation_id=correlation_id,
        )

        return True, correlation_id

    return False, None


def log_security_event(event_type, severity, user_id=None,
                       action_taken='logged', details=None):
    """
    General-purpose security event logger.
    """
    endpoint = None
    try:
        endpoint = request.path
    except RuntimeError:
        pass

    correlation_id = uuid.uuid4()
    safe_detail = sanitize_log_detail(details) if details else None

    SecurityEventRepository.log_event(
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        endpoint=endpoint,
        action_taken=action_taken,
        sanitized_details=safe_detail,
        correlation_id=correlation_id,
    )

    return correlation_id
