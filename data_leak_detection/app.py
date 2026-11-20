"""
Data Leak Detection & SQL Injection Prevention System
Main Flask application entry point.
"""
import os
import sys
from flask import Flask, render_template, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables before anything else
load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import get_config
from security.authentication import login_manager
from security.rate_limiting import init_limiter
from security.encryption import init_encryption
from database.connection import init_pool, close_pool
from database.initialization import initialize_database


def create_app(config_obj=None):
    """Application factory."""
    app = Flask(
        __name__,
        template_folder='frontend/templates',
        static_folder='frontend/static'
    )

    # Load configuration
    if config_obj:
        app.config.from_object(config_obj)
    else:
        cfg = get_config()
        app.config.from_object(cfg)

    app.config['SECRET_KEY'] = app.config.get('SECRET_KEY',
                                               os.environ.get('FLASK_SECRET_KEY', 'dev-key'))
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB

    # CSRF protection
    csrf = CSRFProtect(app)

    # Login manager
    login_manager.init_app(app)

    # Rate limiting
    init_limiter(app)

    # Initialize database pool
    try:
        db_url = app.config.get('DATABASE_URL',
                                os.environ.get('DATABASE_URL'))
        init_pool(db_url)
        # Initialize tables
        initialize_database()
    except Exception as e:
        print(f"[APP] Database initialization warning: {e}")
        print("[APP] The application will start, but database features may not work.")

    # Initialize encryption
    enc_key = app.config.get('ENCRYPTION_KEY',
                              os.environ.get('ENCRYPTION_KEY', ''))
    if enc_key:
        init_encryption(enc_key)
    else:
        print("[APP] WARNING: No encryption key configured.")

    # Register blueprints
    from backend.auth_routes import auth_bp
    from backend.user_routes import user_bp
    from backend.record_routes import record_bp
    from backend.admin_routes import admin_bp
    from backend.security_routes import security_bp
    from backend.capability_routes import capability_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(record_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(capability_bp)

    # Exempt certain API endpoints from CSRF if needed
    # (they're protected by login_required instead)

    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        if app.config.get('FLASK_ENV') == 'production':
            response.headers['Strict-Transport-Security'] = \
                'max-age=31536000; includeSubDomains'
        return response

    # Landing page
    @app.route('/')
    def index():
        return render_template('index.html')

    # Error handlers
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('error.html',
                               error_code=403,
                               error_message='Access Denied',
                               error_detail='You do not have permission to access this resource.'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('error.html',
                               error_code=404,
                               error_message='Page Not Found',
                               error_detail='The page you requested does not exist.'), 404

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template('error.html',
                               error_code=429,
                               error_message='Too Many Requests',
                               error_detail='You have exceeded the rate limit. Please wait and try again.'), 429

    @app.errorhandler(500)
    def server_error(e):
        return render_template('error.html',
                               error_code=500,
                               error_message='Internal Server Error',
                               error_detail='An unexpected error occurred. Please try again later.'), 500

    # Shutdown hook
    @app.teardown_appcontext
    def shutdown_pool(exception=None):
        pass  # Pool is managed at module level

    return app


# Run directly for development
if __name__ == '__main__':
    app = create_app()
    debug = os.environ.get('FLASK_ENV', 'development') != 'production'
    app.run(host='0.0.0.0', port=5000, debug=debug)
