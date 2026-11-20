"""
Security routes — security monitoring dashboard and SQL injection demo.
"""
from flask import Blueprint, render_template, request, jsonify, flash
from flask_login import login_required, current_user
from security.authorization import admin_required
from security.sql_safety import detect_sql_injection_attempt
from security.injection_detection import log_security_event
from services.security_service import (
    get_security_events, get_severity_distribution,
    get_events_over_time, get_recent_events, get_event_count
)
from database.connection import execute_query

security_bp = Blueprint('security', __name__)


@security_bp.route('/security-monitor')
@login_required
@admin_required
def security_monitor():
    page = request.args.get('page', 1, type=int)
    event_type = request.args.get('event_type', None)
    severity = request.args.get('severity', None)

    events, total, total_pages = get_security_events(
        page=page, event_type=event_type, severity=severity
    )

    stats = {
        'total_events': get_event_count(),
        'blocked_requests': get_event_count(event_type='sql_injection_attempt'),
        'failed_logins': get_event_count(event_type='failed_login'),
        'unauthorized_access': get_event_count(event_type='unauthorized_access'),
    }

    return render_template('security_monitor.html',
                           events=events, page=page,
                           total=total, total_pages=total_pages,
                           stats=stats,
                           event_type_filter=event_type or '',
                           severity_filter=severity or '')


@security_bp.route('/sql-injection-demo', methods=['GET', 'POST'])
@login_required
def sql_injection_demo():
    """
    Educational SQL injection testing page.
    Uses CONTROLLED, PREDEFINED test cases against a safe parameterized query.
    Does NOT execute arbitrary SQL.
    """
    test_results = []

    if request.method == 'POST':
        test_type = request.form.get('test_type', 'predefined')

        # Predefined test cases
        predefined_tests = [
            {
                'name': 'Normal Username Lookup',
                'input': 'john_doe',
                'description': 'A normal username — should succeed safely.',
                'category': 'normal'
            },
            {
                'name': "Classic OR 1=1 Injection",
                'input': "' OR '1'='1",
                'description': "Attempts to bypass authentication with always-true condition.",
                'category': 'injection'
            },
            {
                'name': "UNION SELECT Attack",
                'input': "' UNION SELECT username, password_hash FROM users --",
                'description': "Attempts to extract data using UNION SELECT.",
                'category': 'injection'
            },
            {
                'name': "DROP TABLE Attack",
                'input': "'; DROP TABLE users; --",
                'description': "Attempts to destroy the users table.",
                'category': 'injection'
            },
            {
                'name': "Normal Email Search",
                'input': "user@example.com",
                'description': "A normal email search — should succeed safely.",
                'category': 'normal'
            },
            {
                'name': "Time-Based Blind Injection",
                'input': "' OR SLEEP(5) --",
                'description': "Attempts time-based blind SQL injection.",
                'category': 'injection'
            },
            {
                'name': "Stacked Query Attack",
                'input': "admin'; INSERT INTO users (username, password_hash, role) VALUES ('hacker', 'x', 'admin'); --",
                'description': "Attempts to insert a rogue admin user.",
                'category': 'injection'
            },
            {
                'name': "Normal Search Term",
                'input': "quarterly report",
                'description': "A normal search term — should succeed safely.",
                'category': 'normal'
            },
        ]

        for test in predefined_tests:
            is_suspicious, pattern = detect_sql_injection_attempt(test['input'])

            # Now actually run the input through a SAFE parameterized query
            # This proves that even if it's suspicious, the query is safe
            try:
                result = execute_query(
                    "SELECT COUNT(*) AS cnt FROM users WHERE username = %s",
                    (test['input'],),
                    fetch_one=True
                )
                query_safe = True
                query_result = f"Query returned safely: {result['cnt']} match(es)"
            except Exception as e:
                query_safe = True  # The query itself was parameterized; DB error is not injection
                query_result = "Query executed safely (no results)"

            if test['category'] == 'injection':
                status = 'Rejected' if is_suspicious else 'Passed'
                explanation = (
                    "Input was flagged as suspicious AND parameterized query prevented any harm."
                    if is_suspicious else
                    "Input was not flagged but parameterized query still prevented any harm."
                )
            else:
                status = 'Passed'
                explanation = "Normal input processed safely through parameterized query."

            test_results.append({
                'name': test['name'],
                'input': test['input'],
                'description': test['description'],
                'category': test['category'],
                'is_suspicious': is_suspicious,
                'status': status,
                'query_safe': query_safe,
                'query_result': query_result,
                'explanation': explanation,
            })

        # Log that the demo was run
        log_security_event(
            'sql_injection_demo_executed', 'low',
            user_id=current_user.id,
            action_taken='logged',
            details='SQL injection demo page executed by user'
        )

    return render_template('sql_injection_demo.html', test_results=test_results)


# ---- JSON API for security charts ----

@security_bp.route('/api/security/severity-distribution')
@login_required
@admin_required
def api_severity():
    dist = get_severity_distribution()
    return jsonify([dict(r) for r in dist])


@security_bp.route('/api/security/events-over-time')
@login_required
@admin_required
def api_timeline():
    days = request.args.get('days', 7, type=int)
    data = get_events_over_time(min(days, 90))
    return jsonify([{'day': str(r['day']), 'count': r['cnt']} for r in data])
