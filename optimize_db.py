#!/usr/bin/env python3
"""
Database optimization script to add computed column for faster static/dynamic detection
"""

import psycopg2

DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5432,
    'user': 'postgres',
    'password': 'postgres',
    'database': 'cdn_logs'
}

def optimize():
    """Add is_dynamic column and index for better performance"""
    print("Connecting to database...")
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Check if column exists
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.columns
            WHERE table_name = 'log_entries' AND column_name = 'is_dynamic'
        )
    """)

    column_exists = cursor.fetchone()[0]

    if not column_exists:
        print("Adding is_dynamic column...")
        cursor.execute("""
            ALTER TABLE log_entries
            ADD COLUMN is_dynamic BOOLEAN
        """)
        conn.commit()
        print("Column added.")

    # Update existing rows
    print("Updating is_dynamic values for existing rows...")
    cursor.execute("""
        UPDATE log_entries
        SET is_dynamic = (
            url LIKE '%/api/%' OR
            url LIKE '%/chess/%' OR
            url LIKE '%/homework/%'
        )
        WHERE is_dynamic IS NULL
    """)
    rows_updated = cursor.rowcount
    conn.commit()
    print(f"Updated {rows_updated} rows.")

    # Create index
    print("Creating index on is_dynamic...")
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_log_entries_is_dynamic
        ON log_entries(is_dynamic)
    """)
    conn.commit()
    print("Index created.")

    cursor.close()
    conn.close()

    print("Optimization completed successfully!")

if __name__ == '__main__':
    optimize()
