"""
Rate limiting configuration module.
Uses Flask-Limiter to throttle requests and prevent brute-force attacks.
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)


def init_limiter(app):
    """Initialize the rate limiter with the Flask app."""
    storage_uri = app.config.get('RATELIMIT_STORAGE_URI', 'memory://')
    limiter._storage_uri = storage_uri

    if app.config.get('RATELIMIT_ENABLED') is False:
        app.config['RATELIMIT_ENABLED'] = False

    limiter.init_app(app)
