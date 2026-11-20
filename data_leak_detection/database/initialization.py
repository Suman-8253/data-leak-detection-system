"""
Database initialization module.
Creates tables from schema.sql if they don't exist.
"""
import os
from database.connection import get_cursor


def initialize_database():
    """Run schema.sql to create all tables and indexes."""
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r') as f:
        schema_sql = f.read()

    with get_cursor() as cur:
        cur.execute(schema_sql)
    print("[DB] Database schema initialized successfully.")


def drop_all_tables():
    """Drop all application tables (for testing only)."""
    with get_cursor() as cur:
        cur.execute("""
            DROP TABLE IF EXISTS audit_logs CASCADE;
            DROP TABLE IF EXISTS capability_codes CASCADE;
            DROP TABLE IF EXISTS security_events CASCADE;
            DROP TABLE IF EXISTS secure_records CASCADE;
            DROP TABLE IF EXISTS users CASCADE;
        """)
    print("[DB] All tables dropped.")
