"""
Initialize the database schema.
Run this to create all tables and indexes.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from database.connection import init_pool
from database.initialization import initialize_database


if __name__ == '__main__':
    print("Initializing database...")
    init_pool()
    initialize_database()
    print("Done!")
