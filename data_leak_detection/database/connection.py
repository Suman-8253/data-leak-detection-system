"""
Database connection module.
Provides a thread-safe connection pool to PostgreSQL with parameterized queries.
"""
import os
import psycopg2
import psycopg2.pool
import psycopg2.extras
from contextlib import contextmanager

# Module-level connection pool
_pool = None


def init_pool(database_url=None, min_conn=1, max_conn=10):
    """Initialize the connection pool."""
    global _pool
    url = database_url or os.environ.get(
        'DATABASE_URL',
        'postgresql://postgres:postgres@localhost:5432/data_leak_detection'
    )
    try:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            min_conn, max_conn, url,
            connect_timeout=10,
            options='-c statement_timeout=30000'  # 30s statement timeout
        )
    except psycopg2.OperationalError as e:
        print(f"[DB] Failed to connect to PostgreSQL: {e}")
        _pool = None
        raise


def get_pool():
    """Get the current pool, initializing if needed."""
    global _pool
    if _pool is None:
        init_pool()
    return _pool


def close_pool():
    """Close all connections in the pool."""
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None


@contextmanager
def get_connection():
    """Context manager that provides a database connection from the pool."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        yield conn
    finally:
        pool.putconn(conn)


@contextmanager
def get_cursor(commit=True):
    """
    Context manager for a database cursor.
    Commits on success, rolls back on error.
    Uses RealDictCursor for dictionary-style row access.
    """
    with get_connection() as conn:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()


def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    """
    Execute a parameterized query safely.
    Always uses %s placeholders — NEVER string concatenation.
    """
    with get_cursor() as cur:
        cur.execute(query, params)
        if fetch_one:
            return cur.fetchone()
        if fetch_all:
            return cur.fetchall()
        return cur.rowcount


def execute_query_no_commit(cursor, query, params=None, fetch_one=False, fetch_all=False):
    """Execute a query on an existing cursor without committing (for transactions)."""
    cursor.execute(query, params)
    if fetch_one:
        return cursor.fetchone()
    if fetch_all:
        return cursor.fetchall()
    return cursor.rowcount


def check_connection():
    """Check if the database is reachable. Returns (bool, str)."""
    try:
        with get_cursor() as cur:
            cur.execute("SELECT 1 AS ok")
            row = cur.fetchone()
            if row and row['ok'] == 1:
                return True, "Connected"
    except Exception as e:
        return False, str(e)
    return False, "Unknown error"
