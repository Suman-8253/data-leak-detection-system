"""
Authentication module.
Integrates Flask-Login for secure session management.
"""
from flask_login import LoginManager, UserMixin

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'warning'
login_manager.session_protection = 'strong'


class User(UserMixin):
    """Flask-Login User object wrapping a database user row."""

    def __init__(self, user_dict):
        self._data = user_dict

    def get_id(self):
        return str(self._data['id'])

    @property
    def id(self):
        return str(self._data['id'])

    @property
    def username(self):
        return self._data.get('username', '')

    @property
    def email(self):
        return self._data.get('normalized_email', '')

    @property
    def role(self):
        return self._data.get('role', 'user')

    @property
    def account_status(self):
        return self._data.get('account_status', 'active')

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_active(self):
        return self.account_status == 'active'

    @property
    def created_at(self):
        return self._data.get('created_at')

    @property
    def last_login(self):
        return self._data.get('last_login')

    @property
    def password_hash(self):
        return self._data.get('password_hash', '')

    def to_dict(self):
        """Safe dict representation (no password hash)."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'account_status': self.account_status,
            'created_at': str(self.created_at) if self.created_at else None,
            'last_login': str(self.last_login) if self.last_login else None,
        }


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login session restoration."""
    from database.repositories import UserRepository
    user_data = UserRepository.find_by_id(user_id)
    if user_data and user_data.get('account_status') == 'active':
        return User(user_data)
    return None
