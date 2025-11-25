#!/usr/bin/env python3
"""
Database migration script to add UNIQUE constraint to log_entries table
"""

import psycopg2

DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5432,
    'user': 'postgres',
    'password': 'postgres',
    'database': 'cdn_logs'
}

def migrate():
    """Drop and recreate log_entries table with UNIQUE constraint"""
    print("Connecting to database...")
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Check if table exists
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'log_entries'
        )
    """)

    table_exists = cursor.fetchone()[0]

    if table_exists:
        print("Table 'log_entries' exists. Dropping it...")
        cursor.execute("DROP TABLE IF EXISTS log_entries CASCADE")
        conn.commit()
        print("Table dropped.")

    # Create new table with UNIQUE constraint and is_dynamic column
    print("Creating log_entries table with UNIQUE constraint and is_dynamic column...")
    cursor.execute("""
        CREATE TABLE log_entries (
            id BIGSERIAL PRIMARY KEY,
            timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
            ip VARCHAR(45) NOT NULL,
            response_time INTEGER NOT NULL,
            method VARCHAR(10) NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            request_size INTEGER NOT NULL,
            response_size BIGINT NOT NULL,
            cache_status VARCHAR(20) NOT NULL,
            user_agent TEXT,
            content_type VARCHAR(100),
            original_ip VARCHAR(45),
            is_dynamic BOOLEAN,
            UNIQUE (timestamp, ip, url, status_code)
        )
    """)

    # Create indexes
    print("Creating indexes...")
    cursor.execute("""
        CREATE INDEX idx_log_entries_ip ON log_entries(ip)
    """)

    cursor.execute("""
        CREATE INDEX idx_log_entries_timestamp ON log_entries(timestamp)
    """)

    cursor.execute("""
        CREATE INDEX idx_log_entries_is_dynamic ON log_entries(is_dynamic)
    """)

    conn.commit()
    cursor.close()
    conn.close()

    print("Migration completed successfully!")
    print("UNIQUE constraint added: (timestamp, ip, url, status_code)")
    print("Columns: request_size (请求字节数), response_size (响应字节数/流量)")
    print("New column added: is_dynamic (for faster static/dynamic filtering)")
    print("Indexes created: ip, timestamp, is_dynamic")

if __name__ == '__main__':
    migrate()
