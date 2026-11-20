"""
Admin routes — user management, audit logs, security monitoring.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from security.authorization import admin_required
from services.user_service import list_users, update_user_status, update_user_role, count_users
from services.dashboard_service import get_admin_dashboard_stats, get_system_health
from services.security_service import (
    get_security_events, get_severity_distribution,
    get_events_over_time, get_recent_events, get_event_count
)
from database.repositories import AuditLogRepository

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin/users')
@login_required
@admin_required
def user_management():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    users = list_users(per_page, offset)
    total = count_users()
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template('user_management.html',
                           users=users, page=page,
                           total=total, total_pages=total_pages)


@admin_bp.route('/admin/users/<user_id>/status', methods=['POST'])
@login_required
@admin_required
def change_status(user_id):
    new_status = request.form.get('status', '')
    if new_status not in ('active', 'suspended', 'locked'):
        flash('Invalid status.', 'danger')
        return redirect(url_for('admin.user_management'))

    # Prevent admins from locking themselves
    if str(user_id) == str(current_user.id) and new_status != 'active':
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('admin.user_management'))

    update_user_status(user_id, new_status, current_user.id)
    flash(f'User status changed to {new_status}.', 'success')
    return redirect(url_for('admin.user_management'))


@admin_bp.route('/admin/users/<user_id>/role', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    new_role = request.form.get('role', '')

    # Prevent last admin from demoting themselves
    if str(user_id) == str(current_user.id) and new_role != 'admin':
        flash('You cannot remove your own admin role.', 'danger')
        return redirect(url_for('admin.user_management'))

    success, msg = update_user_role(user_id, new_role, current_user.id)
    flash(msg, 'success' if success else 'danger')
    return redirect(url_for('admin.user_management'))


@admin_bp.route('/admin/audit-logs')
@login_required
@admin_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', None)
    outcome_filter = request.args.get('outcome', None)
    per_page = 50
    offset = (page - 1) * per_page

    logs = AuditLogRepository.list_logs(per_page, offset, action_filter, outcome_filter)
    total = AuditLogRepository.count_logs(action_filter, outcome_filter)
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template('audit_logs.html',
                           logs=logs, page=page,
                           total=total, total_pages=total_pages,
                           action_filter=action_filter or '',
                           outcome_filter=outcome_filter or '')


@admin_bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    stats = get_admin_dashboard_stats()
    return render_template('dashboard.html', stats=stats, is_admin=True)


# ---- JSON API endpoints for charts ----

@admin_bp.route('/api/admin/stats')
@login_required
@admin_required
def api_admin_stats():
    stats = get_admin_dashboard_stats()
    # Serialize datetime objects
    for evt in stats.get('recent_events', []):
        if 'timestamp' in evt:
            evt['timestamp'] = str(evt['timestamp'])
    for item in stats.get('severity_distribution', []):
        pass  # already serializable
    return jsonify(stats)


@admin_bp.route('/api/admin/severity-distribution')
@login_required
@admin_required
def api_severity_dist():
    dist = get_severity_distribution()
    return jsonify([dict(row) for row in dist])


@admin_bp.route('/api/admin/events-over-time')
@login_required
@admin_required
def api_events_over_time():
    days = request.args.get('days', 7, type=int)
    data = get_events_over_time(min(days, 90))
    result = [{'day': str(row['day']), 'count': row['cnt']} for row in data]
    return jsonify(result)
