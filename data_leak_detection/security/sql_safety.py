"""
SQL safety module.
Provides parameterized query helpers and SQL injection detection patterns.
This module does NOT rely on keyword filtering as the primary defense —
parameterized queries are the primary defense. These patterns are used
for security event detection and monitoring.
"""
import re


# Suspicious SQL patterns for DETECTION (not prevention)
# Prevention is handled by parameterized queries
SQL_INJECTION_PATTERNS = [
    re.compile(r"('|\")?\s*(OR|AND)\s+('|\")?\s*\d+\s*=\s*\d+", re.IGNORECASE),
    re.compile(r"(UNION\s+(ALL\s+)?SELECT)", re.IGNORECASE),
    re.compile(r"(;\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\s)", re.IGNORECASE),
    re.compile(r"(--\s|/\*|\*/)", re.IGNORECASE),
    re.compile(r"(EXEC(\s|\()|EXECUTE\s)", re.IGNORECASE),
    re.compile(r"(xp_|sp_)", re.IGNORECASE),
    re.compile(r"('\s*(OR|AND)\s+')", re.IGNORECASE),
    re.compile(r"(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)", re.IGNORECASE),
    re.compile(r"(LOAD_FILE\s*\(|INTO\s+(OUT|DUMP)FILE)", re.IGNORECASE),
    re.compile(r"(information_schema|pg_catalog)", re.IGNORECASE),
]


def detect_sql_injection_attempt(input_string):
    """
    Check if an input string contains patterns commonly associated
    with SQL injection attempts. Returns (is_suspicious, matched_pattern).

    NOTE: This is for DETECTION and MONITORING only.
    The actual prevention is parameterized queries.
    A suspicious match does NOT mean a confirmed attack — it means
    the input warrants logging and review.
    """
    if not input_string or not isinstance(input_string, str):
        return False, None

    for pattern in SQL_INJECTION_PATTERNS:
        match = pattern.search(input_string)
        if match:
            return True, pattern.pattern[:60]

    return False, None


def sanitize_log_detail(detail, max_length=500):
    """
    Truncate and sanitize detail strings for safe logging.
    Never log passwords, keys, or full payloads.
    """
    if detail is None:
        return None
    detail = str(detail)[:max_length]
    # Remove potential credentials
    detail = re.sub(r'(password|secret|key|token)\s*[=:]\s*\S+',
                    r'\1=***REDACTED***', detail, flags=re.IGNORECASE)
    return detail
