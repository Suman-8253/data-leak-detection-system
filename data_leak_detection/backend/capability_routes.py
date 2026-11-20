"""
Capability routes — create, view, and revoke capability tokens.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from security.authorization import admin_required
from security.capability_codes import (
    generate_capability, revoke_capability,
    list_capabilities, get_permitted_actions
)
from security.injection_detection import log_security_event

capability_bp = Blueprint('capabilities', __name__)


@capability_bp.route('/capabilities')
@login_required
@admin_required
def management():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    caps = list_capabilities(limit=per_page, offset=offset)
    actions = get_permitted_actions()

    return render_template('capability_management.html',
                           capabilities=caps, actions=actions,
                           page=page)


@capability_bp.route('/capabilities/create', methods=['POST'])
@login_required
@admin_required
def create():
    action = request.form.get('action', '')
    scope = request.form.get('scope', '*')
    hours = request.form.get('hours', 24, type=int)

    if action not in get_permitted_actions():
        flash('Invalid action.', 'danger')
        return redirect(url_for('capabilities.management'))

    try:
        raw_token, record = generate_capability(
            owner_id=current_user.id,
            permitted_action=action,
            resource_scope=scope,
            hours_valid=min(hours, 720)  # max 30 days
        )
        flash(f'Capability token created. Copy it now — it will NOT be shown again: {raw_token}',
              'success')
    except Exception as e:
        flash('Failed to create capability token.', 'danger')

    return redirect(url_for('capabilities.management'))


@capability_bp.route('/capabilities/<cap_id>/revoke', methods=['POST'])
@login_required
@admin_required
def revoke(cap_id):
    try:
        revoke_capability(cap_id, current_user.id)
        flash('Capability token revoked.', 'success')
    except Exception:
        flash('Failed to revoke token.', 'danger')
    return redirect(url_for('capabilities.management'))
