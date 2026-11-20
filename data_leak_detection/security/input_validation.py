"""
Input validation module.
Validates and sanitizes user input before any database or business operation.
"""
import re
import html


# Allowed characters for various field types
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

# Maximum field lengths
MAX_USERNAME_LENGTH = 50
MAX_EMAIL_LENGTH = 255
MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_LENGTH = 8
MAX_TITLE_LENGTH = 255
MAX_CONTENT_LENGTH = 10000
MAX_SEARCH_LENGTH = 200


def validate_username(username):
    """Validate username format and length. Returns (is_valid, error_message)."""
    if not username or not isinstance(username, str):
        return False, "Username is required."
    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username must be at most {MAX_USERNAME_LENGTH} characters."
    if not USERNAME_PATTERN.match(username):
        return False, "Username may only contain letters, numbers, and underscores."
    return True, None


def validate_email(email):
    """Validate email format and length. Returns (is_valid, error_message)."""
    if not email or not isinstance(email, str):
        return False, "Email is required."
    email = email.strip().lower()
    if len(email) > MAX_EMAIL_LENGTH:
        return False, f"Email must be at most {MAX_EMAIL_LENGTH} characters."
    if not EMAIL_PATTERN.match(email):
        return False, "Invalid email format."
    return True, None


def validate_password(password, confirm_password=None):
    """Validate password strength. Returns (is_valid, error_message)."""
    if not password or not isinstance(password, str):
        return False, "Password is required."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    if confirm_password is not None and password != confirm_password:
        return False, "Passwords do not match."
    # Check basic complexity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_upper and has_lower and has_digit):
        return False, "Password must include uppercase, lowercase, and a digit."
    return True, None


def validate_uuid(value):
    """Validate UUID format. Returns (is_valid, error_message)."""
    if not value or not isinstance(value, str):
        return False, "Invalid identifier."
    if not UUID_PATTERN.match(value.strip()):
        return False, "Invalid identifier format."
    return True, None


def validate_title(title):
    """Validate record title. Returns (is_valid, error_message)."""
    if not title or not isinstance(title, str):
        return False, "Title is required."
    title = title.strip()
    if len(title) < 1:
        return False, "Title is required."
    if len(title) > MAX_TITLE_LENGTH:
        return False, f"Title must be at most {MAX_TITLE_LENGTH} characters."
    return True, None


def validate_content(content):
    """Validate record content. Returns (is_valid, error_message)."""
    if not content or not isinstance(content, str):
        return False, "Content is required."
    if len(content) > MAX_CONTENT_LENGTH:
        return False, f"Content must be at most {MAX_CONTENT_LENGTH} characters."
    return True, None


def validate_search_query(query):
    """Validate and sanitize search input. Returns (is_valid, sanitized, error)."""
    if not query or not isinstance(query, str):
        return True, '', None  # empty search is OK
    query = query.strip()
    if len(query) > MAX_SEARCH_LENGTH:
        return False, None, f"Search query too long (max {MAX_SEARCH_LENGTH})."
    return True, query, None


def sanitize_for_display(text):
    """HTML-escape text for safe display in templates."""
    if text is None:
        return ''
    return html.escape(str(text))


# Allowlisted column names for sorting
ALLOWED_SORT_COLUMNS = {
    'users': ['username', 'created_at', 'last_login', 'role', 'account_status'],
    'security_events': ['timestamp', 'event_type', 'severity'],
    'audit_logs': ['timestamp', 'action', 'outcome'],
    'secure_records': ['title', 'created_at', 'updated_at'],
}

ALLOWED_SORT_DIRECTIONS = ['ASC', 'DESC']


def validate_sort(table, column, direction='DESC'):
    """
    Validate sort parameters against allowlists.
    Returns (safe_column, safe_direction) or raises ValueError.
    """
    allowed = ALLOWED_SORT_COLUMNS.get(table, [])
    if column not in allowed:
        raise ValueError(f"Invalid sort column: {column}")
    d = direction.upper()
    if d not in ALLOWED_SORT_DIRECTIONS:
        raise ValueError(f"Invalid sort direction: {direction}")
    return column, d
