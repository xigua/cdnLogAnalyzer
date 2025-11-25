#!/usr/bin/env python3
"""
Migration script to add total_response_size column to ip_statistics table
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
    """Add total_response_size column to ip_statistics table"""
    print("Connecting to database...")
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Drop and recreate ip_statistics table with new column
    print("Dropping existing ip_statistics table...")
    cursor.execute("DROP TABLE IF EXISTS ip_statistics CASCADE")
    conn.commit()

    print("Creating ip_statistics table with total_response_size column...")
    cursor.execute("""
        CREATE TABLE ip_statistics (
            ip VARCHAR(45) PRIMARY KEY,
            total_requests INTEGER NOT NULL,
            total_bytes_sent BIGINT NOT NULL,
            total_response_size BIGINT NOT NULL,
            unique_urls INTEGER NOT NULL,
            unique_user_agents INTEGER NOT NULL,
            static_requests INTEGER NOT NULL,
            dynamic_requests INTEGER NOT NULL,
            is_static_only BOOLEAN NOT NULL,
            first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
            last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
            requests_per_minute FLOAT,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()

    print("Migration completed successfully!")
    print("ip_statistics table now has total_response_size column")
    print("You can now re-run analysis to populate the data")

if __name__ == '__main__':
    migrate()
