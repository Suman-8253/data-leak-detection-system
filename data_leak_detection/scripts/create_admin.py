"""
Create the initial admin user.
Run this after database initialization.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from database.connection import init_pool
from database.initialization import initialize_database
from database.repositories import UserRepository
from security.password_security import hash_password


def create_admin():
    username = os.environ.get('ADMIN_USERNAME', 'admin')
    email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    password = os.environ.get('ADMIN_PASSWORD', '')

    if not password:
        print("ERROR: Set ADMIN_PASSWORD in your .env file first.")
        sys.exit(1)

    # Initialize DB
    init_pool()
    initialize_database()

    # Check if admin already exists
    existing = UserRepository.find_by_username(username)
    if existing:
        print(f"Admin user '{username}' already exists.")
        return

    pw_hash = hash_password(password)
    user = UserRepository.create_user(username, email, pw_hash, role='admin')

    if user:
        print(f"Admin user '{username}' created successfully!")
        print(f"  ID: {user['id']}")
        print(f"  Email: {email}")
        print(f"  Role: admin")
    else:
        print("Failed to create admin user.")


if __name__ == '__main__':
    create_admin()
