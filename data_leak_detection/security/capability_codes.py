"""
Capability-code module.
Scoped authorization tokens — generated, hashed, verified, and revocable.
"""
import os
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from database.repositories import CapabilityRepository, AuditLogRepository


# Allowed capability actions
PERMITTED_ACTIONS = [
    'READ_OWN_RECORD',
    'CREATE_RECORD',
    'UPDATE_OWN_RECORD',
    'DELETE_OWN_RECORD',
    'VIEW_SECURITY_LOGS',
    'MANAGE_USERS',
]


def _hash_token(raw_token):
    """SHA-256 hash of a raw capability token."""
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()


def generate_capability(owner_id, permitted_action, resource_scope='*',
                        hours_valid=24):
    """
    Generate a new capability token.

    Returns:
        (raw_token, capability_record) — raw_token is shown ONCE, then discarded.
    """
    if permitted_action not in PERMITTED_ACTIONS:
        raise ValueError(f"Invalid action: {permitted_action}")

    raw_token = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=hours_valid)

    record = CapabilityRepository.create_capability(
        token_hash=token_hash,
        owner_id=owner_id,
        permitted_action=permitted_action,
        resource_scope=resource_scope,
        expires_at=expires_at,
    )

    # Audit the creation
    AuditLogRepository.log_action(
        actor_id=owner_id,
        action='capability_created',
        resource_type='capability_code',
        resource_id=record['id'] if record else None,
        outcome='success',
    )

    return raw_token, record


def verify_capability(raw_token, required_action, resource_id=None):
    """
    Verify a capability token.

    Returns:
        (is_valid, capability_record_or_error_string)
    """
    if not raw_token:
        return False, "No token provided."

    token_hash = _hash_token(raw_token)
    cap = CapabilityRepository.find_by_token_hash(token_hash)

    if not cap:
        return False, "Invalid capability token."

    # Check revocation
    if cap.get('revoked_at') is not None:
        return False, "Token has been revoked."

    # Check expiration
    now = datetime.now(timezone.utc)
    expires = cap['expires_at']
    if expires.tzinfo is None:
        from datetime import timezone as tz
        expires = expires.replace(tzinfo=tz.utc)
    if now > expires:
        return False, "Token has expired."

    # Check action scope
    if cap['permitted_action'] != required_action:
        return False, "Token not authorized for this action."

    # Check resource scope (if specific resource)
    if resource_id and cap.get('resource_scope') not in ('*', str(resource_id)):
        return False, "Token not authorized for this resource."

    return True, cap


def revoke_capability(cap_id, actor_id):
    """Revoke a capability token."""
    CapabilityRepository.revoke(cap_id)
    AuditLogRepository.log_action(
        actor_id=actor_id,
        action='capability_revoked',
        resource_type='capability_code',
        resource_id=cap_id,
        outcome='success',
    )


def list_capabilities(owner_id=None, limit=50, offset=0):
    """List capabilities. If owner_id given, filter by owner."""
    if owner_id:
        return CapabilityRepository.list_by_owner(owner_id, limit, offset)
    return CapabilityRepository.list_all(limit, offset)


def get_permitted_actions():
    """Return the list of valid capability actions."""
    return PERMITTED_ACTIONS
