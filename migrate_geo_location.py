#!/usr/bin/env python3
"""
Migration script to convert geo_location table from individual IPs to C-class subnets
"""

import psycopg2

DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5432,
    'user': 'postgres',
    'password': 'postgres',
    'database': 'cdn_logs'
}

def ip_to_c_class(ip):
    """Convert IP address to C-class subnet (first 3 octets)"""
    parts = ip.split('.')
    if len(parts) >= 3:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return ip

def migrate():
    """Convert geo_location table from individual IPs to C-class subnets"""
    print("Connecting to database...")
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Read all existing geo_location entries
    print("Reading existing geo_location entries...")
    cursor.execute("""
        SELECT ip, country, region, city, isp, organization,
               as_number, as_name, created_at
        FROM geo_location
    """)
    existing_entries = cursor.fetchall()

    print(f"Found {len(existing_entries)} existing entries")

    # Group by C-class, keeping the most recent entry for each
    c_class_map = {}
    for row in existing_entries:
        ip, country, region, city, isp, org, as_number, as_name, created_at = row
        c_class = ip_to_c_class(ip)

        # Combine AS number and name
        as_info = f"{as_number} {as_name}" if as_number and as_name else (as_number or as_name or '')

        # Keep the most recent entry for each C-class
        if c_class not in c_class_map or (created_at and created_at > c_class_map[c_class][7]):
            c_class_map[c_class] = (c_class, country, region, city, isp, org, as_info, created_at)

    print(f"Consolidated to {len(c_class_map)} unique C-class subnets")

    # Drop and recreate geo_location table
    print("Dropping existing geo_location table...")
    cursor.execute("DROP TABLE IF EXISTS geo_location CASCADE")
    conn.commit()

    print("Creating new geo_location table with C-class subnet structure...")
    cursor.execute("""
        CREATE TABLE geo_location (
            c_class_subnet VARCHAR(15) PRIMARY KEY,
            country VARCHAR(100),
            region VARCHAR(100),
            city VARCHAR(100),
            isp VARCHAR(200),
            org VARCHAR(200),
            as_info VARCHAR(200),
            last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    # Insert consolidated C-class entries
    print("Inserting consolidated C-class entries...")
    for c_class_data in c_class_map.values():
        cursor.execute("""
            INSERT INTO geo_location (c_class_subnet, country, region, city, isp, org, as_info, last_updated)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, c_class_data)

    conn.commit()
    cursor.close()
    conn.close()

    print("Migration completed successfully!")
    print(f"geo_location table now contains {len(c_class_map)} C-class subnet entries")
    print("IP lookups will now use C-class subnet matching")

if __name__ == '__main__':
    migrate()
