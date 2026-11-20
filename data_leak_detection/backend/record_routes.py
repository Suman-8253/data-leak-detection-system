"""
Record routes — CRUD for encrypted secure records.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from security.authorization import active_user_required
from security.input_validation import validate_search_query
from services.record_service import (
    create_record, get_record, list_records,
    update_record, delete_record
)

record_bp = Blueprint('records', __name__)


@record_bp.route('/records')
@login_required
@active_user_required
def list_view():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)

    ok, sanitized_search, err = validate_search_query(search)
    if not ok:
        flash(err, 'warning')
        sanitized_search = ''

    records, total, total_pages = list_records(
        current_user.id, page=page, search=sanitized_search
    )

    return render_template('secure_records.html',
                           records=records, page=page,
                           total=total, total_pages=total_pages,
                           search=sanitized_search)


@record_bp.route('/records/create', methods=['GET', 'POST'])
@login_required
@active_user_required
def create_view():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '')

        success, result = create_record(current_user.id, title, content)

        if success:
            flash('Record created and encrypted successfully!', 'success')
            return redirect(url_for('records.list_view'))
        else:
            flash(result, 'danger')

    return render_template('record_details.html', mode='create', record=None)


@record_bp.route('/records/<record_id>')
@login_required
@active_user_required
def detail_view(record_id):
    success, result = get_record(record_id, current_user.id)
    if not success:
        flash(result, 'danger')
        return redirect(url_for('records.list_view'))

    return render_template('record_details.html', mode='view', record=result)


@record_bp.route('/records/<record_id>/edit', methods=['GET', 'POST'])
@login_required
@active_user_required
def edit_view(record_id):
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '')

        success, result = update_record(record_id, title, content, current_user.id)
        if success:
            flash('Record updated successfully!', 'success')
            return redirect(url_for('records.detail_view', record_id=record_id))
        else:
            flash(result, 'danger')

    # GET — decrypt and show for editing
    success, result = get_record(record_id, current_user.id)
    if not success:
        flash(result, 'danger')
        return redirect(url_for('records.list_view'))

    return render_template('record_details.html', mode='edit', record=result)


@record_bp.route('/records/<record_id>/delete', methods=['POST'])
@login_required
@active_user_required
def delete_view(record_id):
    success, msg = delete_record(record_id, current_user.id)
    if success:
        flash('Record deleted.', 'success')
    else:
        flash(msg, 'danger')
    return redirect(url_for('records.list_view'))
