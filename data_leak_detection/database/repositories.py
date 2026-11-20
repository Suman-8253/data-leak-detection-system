"""
Database repositories — parameterized query data-access layer.
All queries use %s placeholders. NEVER concatenate user input into SQL.
"""
import uuid
from datetime import datetime, timezone
from database.connection import execute_query, get_cursor


# ============================================================
# USER REPOSITORY
# ============================================================

class UserRepository:
    """Data access for the users table."""

    @staticmethod
    def create_user(username, email, password_hash, role='user'):
        """Insert a new user. Returns the new user dict or None."""
        return execute_query(
            """INSERT INTO users (username, normalized_email, password_hash, role)
               VALUES (%s, %s, %s, %s)
               RETURNING id, username, normalized_email, role, account_status, created_at""",
            (username, email.lower().strip(), password_hash, role),
            fetch_one=True
        )

    @staticmethod
    def find_by_username(username):
        """Find a user by username."""
        return execute_query(
            "SELECT * FROM users WHERE username = %s",
            (username,),
            fetch_one=True
        )

    @staticmethod
    def find_by_email(email):
        """Find a user by normalized email."""
        return execute_query(
            "SELECT * FROM users WHERE normalized_email = %s",
            (email.lower().strip(),),
            fetch_one=True
        )

    @staticmethod
    def find_by_id(user_id):
        """Find a user by UUID."""
        return execute_query(
            "SELECT * FROM users WHERE id = %s",
            (str(user_id),),
            fetch_one=True
        )

    @staticmethod
    def update_last_login(user_id):
        """Record the user's most recent login."""
        execute_query(
            "UPDATE users SET last_login = NOW() WHERE id = %s",
            (str(user_id),)
        )

    @staticmethod
    def update_status(user_id, status):
        """Change account status (active / suspended / locked)."""
        execute_query(
            "UPDATE users SET account_status = %s WHERE id = %s",
            (status, str(user_id))
        )

    @staticmethod
    def update_role(user_id, role):
        """Change user role. Caller must verify admin authorization."""
        execute_query(
            "UPDATE users SET role = %s WHERE id = %s",
            (role, str(user_id))
        )

    @staticmethod
    def count_all():
        """Count total users."""
        row = execute_query("SELECT COUNT(*) AS cnt FROM users", fetch_one=True)
        return row['cnt'] if row else 0

    @staticmethod
    def list_all(limit=50, offset=0):
        """List users with pagination."""
        return execute_query(
            """SELECT id, username, normalized_email, role, account_status,
                      created_at, last_login
               FROM users ORDER BY created_at DESC LIMIT %s OFFSET %s""",
            (limit, offset),
            fetch_all=True
        )


# ============================================================
# SECURE RECORDS REPOSITORY
# ============================================================

class RecordRepository:
    """Data access for the secure_records table."""

    @staticmethod
    def create_record(owner_id, title, encrypted_payload, nonce, version=1):
        """Insert an encrypted record."""
        return execute_query(
            """INSERT INTO secure_records
                   (owner_id, title, encrypted_payload, encryption_nonce, encryption_version)
               VALUES (%s, %s, %s, %s, %s)
               RETURNING id, owner_id, title, encryption_version, created_at, updated_at""",
            (str(owner_id), title, encrypted_payload, nonce, version),
            fetch_one=True
        )

    @staticmethod
    def find_by_id(record_id):
        """Get a record by ID."""
        return execute_query(
            "SELECT * FROM secure_records WHERE id = %s",
            (str(record_id),),
            fetch_one=True
        )

    @staticmethod
    def list_by_owner(owner_id, limit=20, offset=0, search=None):
        """List records for a specific owner with optional title search."""
        if search:
            return execute_query(
                """SELECT id, owner_id, title, encryption_version, created_at, updated_at
                   FROM secure_records
                   WHERE owner_id = %s AND title ILIKE %s
                   ORDER BY created_at DESC LIMIT %s OFFSET %s""",
                (str(owner_id), f'%{search}%', limit, offset),
                fetch_all=True
            )
        return execute_query(
            """SELECT id, owner_id, title, encryption_version, created_at, updated_at
               FROM secure_records
               WHERE owner_id = %s
               ORDER BY created_at DESC LIMIT %s OFFSET %s""",
            (str(owner_id), limit, offset),
            fetch_all=True
        )

    @staticmethod
    def count_by_owner(owner_id, search=None):
        """Count records owned by user, optionally filtered by search."""
        if search:
            row = execute_query(
                """SELECT COUNT(*) AS cnt FROM secure_records
                   WHERE owner_id = %s AND title ILIKE %s""",
                (str(owner_id), f'%{search}%'),
                fetch_one=True
            )
        else:
            row = execute_query(
                "SELECT COUNT(*) AS cnt FROM secure_records WHERE owner_id = %s",
                (str(owner_id),),
                fetch_one=True
            )
        return row['cnt'] if row else 0

    @staticmethod
    def update_record(record_id, title, encrypted_payload, nonce, version=1):
        """Update an existing record's encrypted content."""
        return execute_query(
            """UPDATE secure_records
               SET title = %s, encrypted_payload = %s, encryption_nonce = %s,
                   encryption_version = %s, updated_at = NOW()
               WHERE id = %s
               RETURNING id, owner_id, title, encryption_version, created_at, updated_at""",
            (title, encrypted_payload, nonce, version, str(record_id)),
            fetch_one=True
        )

    @staticmethod
    def delete_record(record_id):
        """Delete a record by ID."""
        return execute_query(
            "DELETE FROM secure_records WHERE id = %s",
            (str(record_id),)
        )

    @staticmethod
    def count_all():
        """Count all records."""
        row = execute_query("SELECT COUNT(*) AS cnt FROM secure_records", fetch_one=True)
        return row['cnt'] if row else 0


# ============================================================
# SECURITY EVENTS REPOSITORY
# ============================================================

class SecurityEventRepository:
    """Data access for security_events table."""

    @staticmethod
    def log_event(event_type, severity, user_id=None, endpoint=None,
                  action_taken='logged', sanitized_details=None, correlation_id=None):
        """Insert a security event."""
        return execute_query(
            """INSERT INTO security_events
                   (event_type, severity, user_id, endpoint, action_taken,
                    sanitized_details, correlation_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (event_type, severity,
             str(user_id) if user_id else None,
             endpoint, action_taken, sanitized_details,
             str(correlation_id) if correlation_id else None),
            fetch_one=True
        )

    @staticmethod
    def list_events(limit=50, offset=0, event_type=None, severity=None,
                    date_from=None, date_to=None):
        """List security events with filters and pagination."""
        conditions = []
        params = []

        if event_type:
            conditions.append("event_type = %s")
            params.append(event_type)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if date_from:
            conditions.append("timestamp >= %s")
            params.append(date_from)
        if date_to:
            conditions.append("timestamp <= %s")
            params.append(date_to)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])

        return execute_query(
            f"""SELECT * FROM security_events {where}
                ORDER BY timestamp DESC LIMIT %s OFFSET %s""",
            tuple(params),
            fetch_all=True
        )

    @staticmethod
    def count_events(event_type=None, severity=None, date_from=None, date_to=None):
        """Count events with optional filters."""
        conditions = []
        params = []
        if event_type:
            conditions.append("event_type = %s")
            params.append(event_type)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if date_from:
            conditions.append("timestamp >= %s")
            params.append(date_from)
        if date_to:
            conditions.append("timestamp <= %s")
            params.append(date_to)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        row = execute_query(
            f"SELECT COUNT(*) AS cnt FROM security_events {where}",
            tuple(params),
            fetch_one=True
        )
        return row['cnt'] if row else 0

    @staticmethod
    def severity_distribution():
        """Get event counts grouped by severity."""
        return execute_query(
            """SELECT severity, COUNT(*) AS cnt FROM security_events
               GROUP BY severity ORDER BY severity""",
            fetch_all=True
        )

    @staticmethod
    def events_over_time(days=7):
        """Get event counts per day for the last N days."""
        return execute_query(
            """SELECT DATE(timestamp) AS day, COUNT(*) AS cnt
               FROM security_events
               WHERE timestamp >= NOW() - INTERVAL '%s days'
               GROUP BY DATE(timestamp)
               ORDER BY day""",
            (days,),
            fetch_all=True
        )

    @staticmethod
    def recent_events(limit=10):
        """Get the most recent security events."""
        return execute_query(
            "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT %s",
            (limit,),
            fetch_all=True
        )


# ============================================================
# CAPABILITY CODES REPOSITORY
# ============================================================

class CapabilityRepository:
    """Data access for capability_codes table."""

    @staticmethod
    def create_capability(token_hash, owner_id, permitted_action,
                          resource_scope, expires_at):
        """Insert a new capability code."""
        return execute_query(
            """INSERT INTO capability_codes
                   (token_hash, owner_id, permitted_action, resource_scope, expires_at)
               VALUES (%s, %s, %s, %s, %s)
               RETURNING id, owner_id, permitted_action, resource_scope, expires_at, created_at""",
            (token_hash, str(owner_id), permitted_action, resource_scope, expires_at),
            fetch_one=True
        )

    @staticmethod
    def find_by_token_hash(token_hash):
        """Look up a capability by its hashed token."""
        return execute_query(
            "SELECT * FROM capability_codes WHERE token_hash = %s",
            (token_hash,),
            fetch_one=True
        )

    @staticmethod
    def find_by_id(cap_id):
        """Look up a capability by its ID."""
        return execute_query(
            "SELECT * FROM capability_codes WHERE id = %s",
            (str(cap_id),),
            fetch_one=True
        )

    @staticmethod
    def list_by_owner(owner_id, limit=50, offset=0):
        """List capabilities for a specific owner."""
        return execute_query(
            """SELECT id, owner_id, permitted_action, resource_scope,
                      expires_at, revoked_at, created_at
               FROM capability_codes
               WHERE owner_id = %s
               ORDER BY created_at DESC LIMIT %s OFFSET %s""",
            (str(owner_id), limit, offset),
            fetch_all=True
        )

    @staticmethod
    def list_all(limit=50, offset=0):
        """List all capabilities (admin use)."""
        return execute_query(
            """SELECT cc.id, cc.owner_id, u.username, cc.permitted_action,
                      cc.resource_scope, cc.expires_at, cc.revoked_at, cc.created_at
               FROM capability_codes cc
               LEFT JOIN users u ON cc.owner_id = u.id
               ORDER BY cc.created_at DESC LIMIT %s OFFSET %s""",
            (limit, offset),
            fetch_all=True
        )

    @staticmethod
    def revoke(cap_id):
        """Revoke a capability code."""
        execute_query(
            "UPDATE capability_codes SET revoked_at = NOW() WHERE id = %s",
            (str(cap_id),)
        )

    @staticmethod
    def count_active():
        """Count active (non-revoked, non-expired) capability tokens."""
        row = execute_query(
            """SELECT COUNT(*) AS cnt FROM capability_codes
               WHERE revoked_at IS NULL AND expires_at > NOW()""",
            fetch_one=True
        )
        return row['cnt'] if row else 0

    @staticmethod
    def count_revoked():
        """Count revoked capability tokens."""
        row = execute_query(
            "SELECT COUNT(*) AS cnt FROM capability_codes WHERE revoked_at IS NOT NULL",
            fetch_one=True
        )
        return row['cnt'] if row else 0


# ============================================================
# AUDIT LOGS REPOSITORY
# ============================================================

class AuditLogRepository:
    """Data access for audit_logs table."""

    @staticmethod
    def log_action(actor_id, action, resource_type=None, resource_id=None,
                   outcome='success', correlation_id=None):
        """Insert an audit log entry."""
        return execute_query(
            """INSERT INTO audit_logs
                   (actor_id, action, resource_type, resource_id, outcome, correlation_id)
               VALUES (%s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (str(actor_id) if actor_id else None,
             action, resource_type,
             str(resource_id) if resource_id else None,
             outcome,
             str(correlation_id) if correlation_id else None),
            fetch_one=True
        )

    @staticmethod
    def list_logs(limit=50, offset=0, action=None, outcome=None,
                  date_from=None, date_to=None):
        """List audit logs with filters and pagination."""
        conditions = []
        params = []

        if action:
            conditions.append("al.action = %s")
            params.append(action)
        if outcome:
            conditions.append("al.outcome = %s")
            params.append(outcome)
        if date_from:
            conditions.append("al.timestamp >= %s")
            params.append(date_from)
        if date_to:
            conditions.append("al.timestamp <= %s")
            params.append(date_to)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])

        return execute_query(
            f"""SELECT al.*, u.username AS actor_name
                FROM audit_logs al
                LEFT JOIN users u ON al.actor_id = u.id
                {where}
                ORDER BY al.timestamp DESC LIMIT %s OFFSET %s""",
            tuple(params),
            fetch_all=True
        )

    @staticmethod
    def count_logs(action=None, outcome=None, date_from=None, date_to=None):
        """Count audit logs with optional filters."""
        conditions = []
        params = []
        if action:
            conditions.append("action = %s")
            params.append(action)
        if outcome:
            conditions.append("outcome = %s")
            params.append(outcome)
        if date_from:
            conditions.append("timestamp >= %s")
            params.append(date_from)
        if date_to:
            conditions.append("timestamp <= %s")
            params.append(date_to)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        row = execute_query(
            f"SELECT COUNT(*) AS cnt FROM audit_logs {where}",
            tuple(params),
            fetch_one=True
        )
        return row['cnt'] if row else 0
