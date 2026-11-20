"""
User routes — user dashboard and settings.
"""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from security.authorization import active_user_required
from services.dashboard_service import get_user_dashboard_stats, get_system_health
from services.record_service import count_user_records
from database.repositories import AuditLogRepository

user_bp = Blueprint('user', __name__)


@user_bp.route('/dashboard')
@login_required
@active_user_required
def dashboard():
    stats = get_user_dashboard_stats(current_user.id)
    return render_template('dashboard.html', stats=stats)


@user_bp.route('/settings')
@login_required
@active_user_required
def settings():
    health = get_system_health()
    return render_template('settings.html', health=health)


@user_bp.route('/api/dashboard-stats')
@login_required
@active_user_required
def api_dashboard_stats():
    """JSON endpoint for dashboard charts."""
    stats = get_user_dashboard_stats(current_user.id)
    return jsonify(stats)
