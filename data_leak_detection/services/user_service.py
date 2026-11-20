"""
User service — business logic for user registration, login, and management.
"""
from database.repositories import UserRepository
from security.password_security import hash_password, verify_password
from security.input_validation import validate_username, validate_email, validate_password
from security.injection_detection import check_and_log_injection, log_security_event
from security.audit_logger import audit_action


def register_user(username, email, password, confirm_password):
    """
    Register a new user.
    Returns (success, user_or_error_message).
    """
    # Validate input
    ok, err = validate_username(username)
    if not ok:
        return False, err

    ok, err = validate_email(email)
    if not ok:
        return False, err

    ok, err = validate_password(password, confirm_password)
    if not ok:
        return False, err

    # Check for SQL injection patterns (monitoring only)
    check_and_log_injection(username, 'username')
    check_and_log_injection(email, 'email')

    # Check uniqueness
    if UserRepository.find_by_username(username):
        return False, "Username already taken."

    if UserRepository.find_by_email(email):
        return False, "Email already registered."

    # Hash password (Argon2id, never AES)
    pw_hash = hash_password(password)

    # Create user
    user = UserRepository.create_user(username, email, pw_hash, role='user')
    if not user:
        return False, "Registration failed. Please try again."

    audit_action(user['id'], 'user_registered', 'user', user['id'])
    return True, user


def authenticate_user(username, password):
    """
    Authenticate a user.
    Returns (success, user_dict_or_error_message).
    Uses generic error messages to prevent user enumeration.
    """
    # Monitor for injection
    check_and_log_injection(username, 'login_username')

    user = UserRepository.find_by_username(username)
    generic_error = "Invalid username or password."

    if not user:
        return False, generic_error

    if user.get('account_status') != 'active':
        log_security_event(
            'login_locked_account', 'medium',
            user_id=user['id'],
            action_taken='blocked',
            details=f"Login attempt on {user['account_status']} account"
        )
        return False, "Account is not active. Contact an administrator."

    if not verify_password(user['password_hash'], password):
        log_security_event(
            'failed_login', 'medium',
            user_id=user['id'],
            action_taken='denied',
            details="Invalid password"
        )
        return False, generic_error

    # Update last login
    UserRepository.update_last_login(user['id'])
    audit_action(user['id'], 'user_login', 'user', user['id'])
    return True, user


def get_user_by_id(user_id):
    """Get a user by ID."""
    return UserRepository.find_by_id(user_id)


def list_users(limit=50, offset=0):
    """List all users (admin only)."""
    return UserRepository.list_all(limit, offset)


def update_user_status(user_id, status, admin_id):
    """Update user account status. Must be called by an admin."""
    UserRepository.update_status(user_id, status)
    audit_action(admin_id, 'user_status_changed', 'user', user_id,
                 outcome='success')


def update_user_role(user_id, role, admin_id):
    """Update user role. Must be called by an admin."""
    if role not in ('user', 'admin'):
        return False, "Invalid role."
    UserRepository.update_role(user_id, role)
    audit_action(admin_id, 'user_role_changed', 'user', user_id,
                 outcome='success')
    return True, "Role updated."


def count_users():
    """Count all users."""
    return UserRepository.count_all()
