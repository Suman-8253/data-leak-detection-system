"""
Authorization module.
Role-based and ownership-based access control decorators.
"""
from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user


def admin_required(f):
    """Decorator: require the current user to be an admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def active_user_required(f):
    """Decorator: require the current user to have an active account."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.account_status != 'active':
            flash('Your account is not active. Contact an administrator.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def check_record_ownership(record, user_id):
    """Verify that a record belongs to the specified user. Aborts with 403 if not."""
    if str(record.get('owner_id', '')) != str(user_id):
        abort(403)
