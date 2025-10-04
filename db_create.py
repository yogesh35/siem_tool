import sqlite3
import os

# Path to the database file
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'system_metrics.db')

def create_database():
    """
    Creates the SQLite database and all required tables for the SIEM system.
    """
    # Connect to SQLite database
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Create metrics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            cpu REAL,
            memory REAL,
            disk REAL,
            network REAL
        )
    ''')

    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            log TEXT
        )
    ''')

    # Create network_requests table for packet analysis
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            type TEXT,
            country TEXT,
            summary TEXT,
            blacklisted TEXT,
            attacks INTEGER,
            reports INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create users table for authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )
    ''')

    # Create indexes for better performance
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_network_requests_timestamp ON network_requests (timestamp)
    ''')

    # Save changes and close connection
    conn.commit()
    conn.close()
    print(f"Database and tables have been successfully created at '{DATABASE_PATH}'.")

if __name__ == '__main__':
    # Ensure directory for database file exists
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    create_database()