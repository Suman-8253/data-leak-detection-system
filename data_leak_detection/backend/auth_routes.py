"""
Authentication routes — register, login, logout.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from security.authentication import User
from security.rate_limiting import limiter
from security.injection_detection import log_security_event
from services.user_service import register_user, authenticate_user

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        success, result = register_user(username, email, password, confirm)

        if success:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(result, 'danger')

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('user.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        success, result = authenticate_user(username, password)

        if success:
            user_obj = User(result)
            login_user(user_obj, remember=False)
            flash(f'Welcome back, {user_obj.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('user.dashboard'))
        else:
            flash(result, 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    log_security_event('user_logout', 'low', current_user.id,
                       action_taken='logged')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
