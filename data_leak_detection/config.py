"""
Configuration module for Data Leak Detection System.
Loads settings from environment variables with sensible defaults.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""
    # Flask
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-me')
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development')

    # Database
    DATABASE_URL = os.environ.get(
        'DATABASE_URL',
        'postgresql://postgres:postgres@localhost:5432/data_leak_detection'
    )

    # Encryption
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', '')

    # Session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # Rate limiting
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    RATELIMIT_DEFAULT = "200 per hour"

    # Request limits
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB

    # Admin bootstrap
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', '')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', '')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')

    @property
    def is_production(self):
        return self.FLASK_ENV == 'production'


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    DATABASE_URL = os.environ.get(
        'TEST_DATABASE_URL',
        'postgresql://postgres:postgres@localhost:5432/data_leak_detection_test'
    )
    RATELIMIT_ENABLED = False
    WTF_CSRF_ENABLED = False


config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
}


def get_config():
    env = os.environ.get('FLASK_ENV', 'development')
    return config_by_name.get(env, DevelopmentConfig)()
