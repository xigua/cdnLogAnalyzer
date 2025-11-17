#!/usr/bin/env python3
"""
CDN Log Analyzer - Web Application for analyzing CDN access logs
Processes .gz log files and provides interactive visualizations
"""

import os
import gzip
import re
import time
from datetime import datetime
from collections import defaultdict, Counter
from urllib.parse import urlparse
import json
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import statistics
import psycopg2
from psycopg2.extras import execute_batch, RealDictCursor
from psycopg2.pool import SimpleConnectionPool

from flask import Flask, render_template, request, jsonify, Response
from decimal import Decimal

app = Flask(__name__)

# Custom JSON encoder to handle Decimal types from PostgreSQL
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

# Database configuration - supports multiple sites via environment variables
DB_NAME = os.environ.get('CDN_DB_NAME', 'cdn_logs')
APP_PORT = int(os.environ.get('PORT', '8080'))

DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5432,
    'user': 'postgres',
    'password': 'postgres',
    'database': DB_NAME
}

# Connection pool
db_pool = None

def init_db():
    """Initialize database and create tables"""
    global db_pool

    # First connect to default postgres database to create target database
    conn = psycopg2.connect(
        host=DB_CONFIG['host'],
        port=DB_CONFIG['port'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        database='postgres'
    )
    conn.autocommit = True
    cursor = conn.cursor()

    # Check if database exists
    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
    if not cursor.fetchone():
        cursor.execute(f"CREATE DATABASE {DB_NAME}")
        print(f"Database '{DB_NAME}' created successfully")

    cursor.close()
    conn.close()

    # Now connect to target database
    db_pool = SimpleConnectionPool(1, 20, **DB_CONFIG)

    conn = db_pool.getconn()
    cursor = conn.cursor()

    # Create log_entries table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_entries (
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

    # Create index on ip for faster queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_log_entries_ip ON log_entries(ip)
    """)

    # Create index on timestamp for time-based queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp)
    """)

    # Create index on is_dynamic for faster filtering
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_log_entries_is_dynamic ON log_entries(is_dynamic)
    """)

    # Create ip_statistics table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_statistics (
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

    # Create geo_location cache table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS geo_location (
            ip VARCHAR(45) PRIMARY KEY,
            country VARCHAR(100),
            country_code VARCHAR(10),
            region VARCHAR(100),
            city VARCHAR(100),
            latitude FLOAT,
            longitude FLOAT,
            isp VARCHAR(200),
            organization VARCHAR(200),
            as_number VARCHAR(50),
            as_name VARCHAR(200),
            is_mobile BOOLEAN,
            is_proxy BOOLEAN,
            is_hosting BOOLEAN,
            timezone VARCHAR(50),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create analysis results cache table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_cache (
            id SERIAL PRIMARY KEY,
            start_time TIMESTAMP WITH TIME ZONE,
            end_time TIMESTAMP WITH TIME ZONE,
            results JSONB NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create blacklist cache table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist_cache (
            id SERIAL PRIMARY KEY,
            blacklist_data JSONB NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cursor.close()
    db_pool.putconn(conn)

    print("Database tables initialized successfully")

def get_db_connection():
    """Get a connection from the pool with timeout"""
    import threading

    try:
        # Get connection stats before acquiring
        available = len(db_pool._pool)
        in_use = db_pool.maxconn - available
        print(f"[{datetime.now().strftime('%H:%M:%S')}] DB Pool status - Total: {db_pool.maxconn}, Available: {available}, In Use: {in_use}")

        if available == 0:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] WARNING: No connections available! All {db_pool.maxconn} connections are in use. Waiting...")

        # Get connection with timeout using threading
        conn_result = [None]
        error_result = [None]

        def get_conn():
            try:
                conn_result[0] = db_pool.getconn()
            except Exception as e:
                error_result[0] = e

        thread = threading.Thread(target=get_conn)
        thread.daemon = True
        thread.start()
        thread.join(timeout=10)  # 10 second timeout

        if thread.is_alive():
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: Timeout waiting for DB connection after 10 seconds")
            raise Exception("Timeout waiting for database connection - pool may be exhausted")

        if error_result[0]:
            raise error_result[0]

        conn = conn_result[0]
        if not conn:
            raise Exception("Failed to get database connection")

        # Set statement timeout to 5 minutes for all connections
        cursor = conn.cursor()
        cursor.execute("SET statement_timeout = '300000'")  # 5 minutes
        cursor.close()
        conn.commit()
        return conn
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR getting DB connection: {str(e)}")
        raise

def release_db_connection(conn):
    """Release a connection back to the pool"""
    try:
        db_pool.putconn(conn)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] DB connection released. Available: {len(db_pool._pool)}")
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR releasing DB connection: {str(e)}")

@dataclass
class LogEntry:
    timestamp: datetime
    ip: str
    response_time: int
    method: str
    url: str
    status_code: int
    request_size: int  # 请求字节数 (客户端发送)
    response_size: int  # 响应字节数 (CDN返回，即流量)
    cache_status: str
    user_agent: str
    content_type: str
    original_ip: str

class LogAnalyzer:
    def __init__(self):
        self.entries = []
        self.log_pattern = re.compile(
            r'\[([^\]]+)\] '  # timestamp
            r'(\S+) - '  # IP address
            r'(\d+) '  # response time
            r'"([^"]*)" '  # method field (may be "-")
            r'"([^"]+)" '  # method + URL combined
            r'(\d+) '  # status code
            r'(\d+) '  # request size
            r'(\d+) '  # response size
            r'(\S+) '  # cache status
            r'"([^"]*)" '  # user agent
            r'"([^"]*)" '  # content type
            r'(\S+)'  # original IP
        )
        self.progress_callback = None

    # Import time-range analysis methods
    from time_range_analysis import (
        calculate_ip_statistics_for_range,
        _compute_basic_stats_for_range,
        analyze_traffic_by_url_for_range,
        analyze_hourly_traffic_for_range,
        analyze_user_behavior_for_range,
        detect_suspicious_patterns_for_range,
        analyze_performance_for_range,
        analyze_static_vs_dynamic_traffic_for_range
    )

    def parse_log_line(self, line: str) -> Optional[LogEntry]:
        match = self.log_pattern.match(line.strip())
        if not match:
            return None

        timestamp_str = match.group(1)
        timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')

        # Group 5 contains "METHOD URL", need to split
        method_url = match.group(5)
        parts = method_url.split(' ', 1)
        method = parts[0] if len(parts) > 0 else ''
        url = parts[1] if len(parts) > 1 else method_url

        return LogEntry(
            timestamp=timestamp,
            ip=match.group(2),
            response_time=int(match.group(3)),
            method=method,
            url=url,
            status_code=int(match.group(6)),
            request_size=int(match.group(7)),  # 请求字节数
            response_size=int(match.group(8)),  # 响应字节数 (流量)
            cache_status=match.group(9),
            user_agent=match.group(10),
            content_type=match.group(11),
            original_ip=match.group(12)
        )

    def insert_entries_to_db(self, entries_batch):
        """Insert a batch of log entries into the database, skipping duplicates"""
        if not entries_batch:
            return

        batch_size = len(entries_batch)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Getting DB connection for batch of {batch_size} entries...")

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] DB connection acquired")
            cursor = conn.cursor()

            # Prepare data for batch insert
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Preparing insert data...")
            insert_data = [
                (
                    entry.timestamp,
                    entry.ip,
                    entry.response_time,
                    entry.method,
                    entry.url,
                    entry.status_code,
                    entry.request_size,
                    entry.response_size,
                    entry.cache_status,
                    entry.user_agent,
                    entry.content_type,
                    entry.original_ip,
                    # Pre-calculate is_dynamic to avoid scanning in aggregation
                    ('/api/' in entry.url or '/chess/' in entry.url or '/homework/' in entry.url)
                )
                for entry in entries_batch
            ]

            # Batch insert with ON CONFLICT DO NOTHING to skip duplicates
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Executing batch insert...")
            execute_batch(cursor, """
                INSERT INTO log_entries (
                    timestamp, ip, response_time, method, url, status_code,
                    request_size, response_size, cache_status, user_agent,
                    content_type, original_ip, is_dynamic
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (timestamp, ip, url, status_code) DO NOTHING
            """, insert_data, page_size=500)

            print(f"[{datetime.now().strftime('%H:%M:%S')}] Committing transaction...")
            conn.commit()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Transaction committed successfully")

        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR in insert_entries_to_db: {str(e)}")
            if conn:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Rolling back transaction...")
                conn.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if conn:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Releasing DB connection")
                release_db_connection(conn)

    def calculate_and_store_ip_statistics(self):
        """Calculate IP statistics from database and store in ip_statistics table"""
        print("Starting IP statistics calculation...")
        start_time = time.time()

        conn = get_db_connection()
        # Set statement timeout to 30 minutes for large datasets
        conn.set_session(autocommit=False)
        cursor = conn.cursor()

        try:
            # Set statement timeout to 30 minutes
            cursor.execute("SET statement_timeout = '1800000'")  # 30 minutes

            # First, get total log count
            cursor.execute("SELECT COUNT(*) FROM log_entries")
            total_logs = cursor.fetchone()[0]
            print(f"Total logs in database: {total_logs:,}")

            # Clear existing IP statistics
            print("Truncating ip_statistics table...")
            cursor.execute("TRUNCATE TABLE ip_statistics")
            conn.commit()

            # Calculate IP statistics using optimized SQL aggregation with pre-computed is_dynamic
            print("Calculating IP statistics (this may take several minutes for large datasets)...")
            print("Please wait... This query is processing millions of records grouped by IP address.")
            cursor.execute("""
                INSERT INTO ip_statistics (
                    ip, total_requests, total_bytes_sent, total_response_size, unique_urls, unique_user_agents,
                    static_requests, dynamic_requests, is_static_only,
                    first_seen, last_seen, requests_per_minute
                )
                SELECT
                    ip,
                    COUNT(*) as total_requests,
                    SUM(response_size) as total_bytes_sent,
                    SUM(response_size) as total_response_size,
                    COUNT(DISTINCT url) as unique_urls,
                    COUNT(DISTINCT user_agent) as unique_user_agents,
                    SUM(CASE WHEN is_dynamic = FALSE THEN 1 ELSE 0 END) as static_requests,
                    SUM(CASE WHEN is_dynamic = TRUE THEN 1 ELSE 0 END) as dynamic_requests,
                    BOOL_AND(COALESCE(is_dynamic, FALSE) = FALSE) as is_static_only,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    CASE
                        WHEN EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) / 60 > 0
                        THEN COUNT(*)::float / (EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) / 60)
                        ELSE 0
                    END as requests_per_minute
                FROM log_entries
                GROUP BY ip
            """)

            conn.commit()

            # Get count of unique IPs processed
            cursor.execute("SELECT COUNT(*) FROM ip_statistics")
            ip_count = cursor.fetchone()[0]

            elapsed = time.time() - start_time
            print(f"IP statistics calculation completed in {elapsed:.2f} seconds")
            print(f"Processed {ip_count:,} unique IP addresses from {total_logs:,} log entries")

        except Exception as e:
            print(f"Error calculating IP statistics: {e}")
            conn.rollback()
            raise
        finally:
            cursor.close()
            release_db_connection(conn)

    def process_directory(self, directory_path: str, progress_callback=None) -> Dict[str, Any]:
        """Process all .gz files in directory and return analysis results"""
        self.entries = []
        self.progress_callback = progress_callback

        gz_files = [f for f in os.listdir(directory_path) if f.endswith('.gz')]
        gz_files.sort()

        total_files = len(gz_files)
        start_time = time.time()

        if self.progress_callback:
            self.progress_callback({
                'progress': 0.0,
                'message': f'Found {total_files} .gz files to process',
                'current_file_index': 0,
                'total_files': total_files,
                'current_file': '',
                'estimated_remaining_seconds': 0
            })

        for i, filename in enumerate(gz_files):
            filepath = os.path.join(directory_path, filename)

            if self.progress_callback:
                self.progress_callback({
                    'progress': i / total_files,
                    'message': f'Processing file {i + 1} of {total_files}',
                    'current_file_index': i + 1,
                    'total_files': total_files,
                    'current_file': filename,
                    'estimated_remaining_seconds': self._calculate_remaining_time(i, total_files, start_time)
                })

            with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                for line in f:
                    entry = self.parse_log_line(line)
                    if entry:
                        self.entries.append(entry)
                    line_count += 1

                    # Update progress within file every 1000 lines
                    if line_count % 1000 == 0 and self.progress_callback:
                        file_progress = i / total_files + (0.5 / total_files)  # Approximate mid-file progress
                        self.progress_callback({
                            'progress': file_progress,
                            'message': f'Processing file {i + 1} of {total_files} ({line_count:,} lines processed)',
                            'current_file_index': i + 1,
                            'total_files': total_files,
                            'current_file': filename,
                            'estimated_remaining_seconds': self._calculate_remaining_time(i, total_files, start_time)
                        })

        if self.progress_callback:
            self.progress_callback({
                'progress': 1.0,
                'message': 'Generating analysis results...',
                'current_file_index': total_files,
                'total_files': total_files,
                'current_file': '',
                'estimated_remaining_seconds': 0
            })

        return self.generate_analysis()

    def _calculate_remaining_time(self, current_index: int, total_files: int, start_time: float) -> int:
        """Calculate estimated remaining time based on current progress"""
        if current_index == 0:
            return 0

        elapsed_time = time.time() - start_time
        files_per_second = current_index / elapsed_time
        remaining_files = total_files - current_index

        if files_per_second > 0:
            return int(remaining_files / files_per_second)
        return 0

    def process_directory_with_sse(self, directory_path: str, sse_generator) -> Dict[str, Any]:
        """Process directory with Server-Sent Events progress updates"""
        self.entries = []

        gz_files = [f for f in os.listdir(directory_path) if f.endswith('.gz')]
        gz_files.sort()

        total_files = len(gz_files)
        start_time = time.time()

        # Send initial progress
        initial_data = {
            'progress': 0.0,
            'message': f'Found {total_files} .gz files to process',
            'current_file_index': 0,
            'total_files': total_files,
            'current_file': '',
            'estimated_remaining_seconds': 0
        }
        sse_generator.send(f"data: {json.dumps(initial_data)}\n\n")

        for i, filename in enumerate(gz_files):
            filepath = os.path.join(directory_path, filename)

            # Send file start progress
            progress_data = {
                'progress': i / total_files,
                'message': f'Processing file {i + 1} of {total_files}',
                'current_file_index': i + 1,
                'total_files': total_files,
                'current_file': filename,
                'estimated_remaining_seconds': self._calculate_remaining_time(i, total_files, start_time)
            }
            sse_generator.send(f"data: {json.dumps(progress_data)}\n\n")

            with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                for line in f:
                    entry = self.parse_log_line(line)
                    if entry:
                        self.entries.append(entry)
                    line_count += 1

                    # Send progress every 1000 lines
                    if line_count % 1000 == 0:
                        file_progress = i / total_files + (0.5 / total_files)
                        progress_data = {
                            'progress': file_progress,
                            'message': f'Processing file {i + 1} of {total_files} ({line_count:,} lines processed)',
                            'current_file_index': i + 1,
                            'total_files': total_files,
                            'current_file': filename,
                            'estimated_remaining_seconds': self._calculate_remaining_time(i, total_files, start_time)
                        }
                        sse_generator.send(f"data: {json.dumps(progress_data)}\n\n")

        # Send final progress before analysis
        final_progress = {
            'progress': 1.0,
            'message': 'Generating analysis results...',
            'current_file_index': total_files,
            'total_files': total_files,
            'current_file': '',
            'estimated_remaining_seconds': 0
        }
        sse_generator.send(f"data: {json.dumps(final_progress)}\n\n")

        return self.generate_analysis()

    def generate_analysis(self, progress_callback=None) -> Dict[str, Any]:
        """Generate comprehensive analysis of log entries with progress tracking"""
        if not self.entries:
            return {}

        analysis_steps = [
            ("Computing basic statistics", self._compute_basic_stats),
            ("Analyzing traffic by IP", self.analyze_traffic_by_ip),
            ("Analyzing traffic by URL", self.analyze_traffic_by_url),
            ("Analyzing hourly traffic patterns", self.analyze_hourly_traffic),
            ("Analyzing user behavior", self.analyze_user_behavior),
            ("Detecting suspicious patterns", self.detect_suspicious_patterns),
            ("Computing performance statistics", self.analyze_performance)
        ]

        results = {}
        total_steps = len(analysis_steps)

        for i, (step_name, step_func) in enumerate(analysis_steps):
            if progress_callback:
                progress_callback({
                    'progress': 1.0 + (i / total_steps) * 0.2,  # Analysis is 20% of total progress after file processing
                    'message': step_name,
                    'current_file_index': None,
                    'total_files': None,
                    'current_file': '',
                    'estimated_remaining_seconds': max(0, (total_steps - i) * 2)  # Estimate 2 seconds per step
                })

            if step_name == "Computing basic statistics":
                basic_stats = step_func()
                results['basic_stats'] = basic_stats
            elif step_name == "Analyzing traffic by IP":
                results['traffic_by_ip'] = step_func()
            elif step_name == "Analyzing traffic by URL":
                results['traffic_by_url'] = step_func()
            elif step_name == "Analyzing hourly traffic patterns":
                results['hourly_traffic'] = step_func()
            elif step_name == "Analyzing user behavior":
                results['user_behavior'] = step_func()
            elif step_name == "Detecting suspicious patterns":
                results['suspicious_patterns'] = step_func()
            elif step_name == "Computing performance statistics":
                results['performance_stats'] = step_func()

        return results

    def generate_analysis_with_progress(self, progress_callback, total_files_processed):
        """Generator that yields progress updates and final results"""
        if not self.entries:
            yield {}
            return

        analysis_steps = [
            ("Computing basic statistics", self._compute_basic_stats),
            ("Analyzing traffic by IP", self.analyze_traffic_by_ip),
            ("Analyzing traffic by URL", self.analyze_traffic_by_url),
            ("Analyzing hourly traffic patterns", self.analyze_hourly_traffic),
            ("Analyzing user behavior", self.analyze_user_behavior),
            ("Detecting suspicious patterns", self.detect_suspicious_patterns),
            ("Computing performance statistics", self.analyze_performance)
        ]

        results = {}
        total_steps = len(analysis_steps)

        for i, (step_name, step_func) in enumerate(analysis_steps):
            # Send progress update (keep total progress between 0.85 and 1.0 for analysis phase)
            analysis_progress = 0.85 + (i / total_steps) * 0.15
            progress_data = {
                'progress': min(analysis_progress, 1.0),  # Ensure never exceeds 1.0
                'message': step_name,
                'current_file_index': total_files_processed,  # Keep file count consistent
                'total_files': total_files_processed,
                'current_file': f'Analysis step {i+1}/{total_steps}',
                'estimated_remaining_seconds': max(0, (total_steps - i) * 1)
            }
            yield progress_callback(progress_data)

            # Execute the analysis step
            if step_name == "Computing basic statistics":
                basic_stats = step_func()
                results['basic_stats'] = basic_stats
            elif step_name == "Analyzing traffic by IP":
                results['traffic_by_ip'] = step_func()
            elif step_name == "Analyzing traffic by URL":
                results['traffic_by_url'] = step_func()
            elif step_name == "Analyzing hourly traffic patterns":
                results['hourly_traffic'] = step_func()
            elif step_name == "Analyzing user behavior":
                results['user_behavior'] = step_func()
            elif step_name == "Detecting suspicious patterns":
                results['suspicious_patterns'] = step_func()
            elif step_name == "Computing performance statistics":
                results['performance_stats'] = step_func()

        yield results

    def _run_analysis_with_progress(self, progress_callback, total_files_processed):
        """Run analysis with progress updates for SSE"""
        if not self.entries:
            return {}

        analysis_steps = [
            ("Computing basic statistics", self._compute_basic_stats),
            ("Analyzing traffic by IP", self.analyze_traffic_by_ip),
            ("Analyzing traffic by URL", self.analyze_traffic_by_url),
            ("Analyzing hourly traffic patterns", self.analyze_hourly_traffic),
            ("Analyzing user behavior", self.analyze_user_behavior),
            ("Detecting suspicious patterns", self.detect_suspicious_patterns),
            ("Computing performance statistics", self.analyze_performance)
        ]

        results = {}
        total_steps = len(analysis_steps)

        for i, (step_name, step_func) in enumerate(analysis_steps):
            # Send progress update
            analysis_progress = 0.85 + (i / total_steps) * 0.15
            progress_data = {
                'progress': min(analysis_progress, 1.0),
                'message': step_name,
                'current_file_index': total_files_processed,
                'total_files': total_files_processed,
                'current_file': f'Step {i+1}/{total_steps}',
                'estimated_remaining_seconds': max(0, (total_steps - i) * 1)
            }

            # Execute the analysis step
            if step_name == "Computing basic statistics":
                basic_stats = step_func()
                results['basic_stats'] = basic_stats
            elif step_name == "Analyzing traffic by IP":
                results['traffic_by_ip'] = step_func()
            elif step_name == "Analyzing traffic by URL":
                results['traffic_by_url'] = step_func()
            elif step_name == "Analyzing hourly traffic patterns":
                results['hourly_traffic'] = step_func()
            elif step_name == "Analyzing user behavior":
                results['user_behavior'] = step_func()
            elif step_name == "Detecting suspicious patterns":
                results['suspicious_patterns'] = step_func()
            elif step_name == "Computing performance statistics":
                results['performance_stats'] = step_func()

        return results

    def _run_analysis_with_progress_sse(self, progress_callback, total_files_processed):
        """Run analysis with progress updates specifically for SSE streaming"""
        if not self.entries:
            return {}

        analysis_steps = [
            ("Computing basic statistics", self._compute_basic_stats),
            ("Analyzing traffic by IP", self.analyze_traffic_by_ip),
            ("Analyzing traffic by URL", self.analyze_traffic_by_url),
            ("Analyzing hourly traffic patterns", self.analyze_hourly_traffic),
            ("Analyzing user behavior", self.analyze_user_behavior),
            ("Detecting suspicious patterns", self.detect_suspicious_patterns),
            ("Computing performance statistics", self.analyze_performance)
        ]

        results = {}
        total_steps = len(analysis_steps)

        for i, (step_name, step_func) in enumerate(analysis_steps):
            # Send progress update directly through the generator
            analysis_progress = 0.85 + (i / total_steps) * 0.15
            progress_data = {
                'progress': min(analysis_progress, 1.0),
                'message': step_name,
                'current_file_index': total_files_processed,
                'total_files': total_files_processed,
                'current_file': f'Step {i+1}/{total_steps}',
                'estimated_remaining_seconds': max(0, (total_steps - i) * 1)
            }

            # Send progress update through SSE
            yield progress_callback(progress_data)

            # Execute the analysis step
            if step_name == "Computing basic statistics":
                basic_stats = step_func()
                results['basic_stats'] = basic_stats
            elif step_name == "Analyzing traffic by IP":
                results['traffic_by_ip'] = step_func()
            elif step_name == "Analyzing traffic by URL":
                results['traffic_by_url'] = step_func()
            elif step_name == "Analyzing hourly traffic patterns":
                results['hourly_traffic'] = step_func()
            elif step_name == "Analyzing user behavior":
                results['user_behavior'] = step_func()
            elif step_name == "Detecting suspicious patterns":
                results['suspicious_patterns'] = step_func()
            elif step_name == "Computing performance statistics":
                results['performance_stats'] = step_func()

        return results

    def _compute_basic_stats(self) -> Dict[str, Any]:
        """Compute basic statistics from database"""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                COUNT(*) as total_requests,
                COUNT(DISTINCT ip) as unique_ips,
                MIN(timestamp) as start_time,
                MAX(timestamp) as end_time
            FROM log_entries
        """)

        row = cursor.fetchone()
        cursor.close()
        release_db_connection(conn)

        return {
            'total_requests': row[0] if row[0] else 0,
            'unique_ips': row[1] if row[1] else 0,
            'time_range': {
                'start': row[2].isoformat() if row[2] else '',
                'end': row[3].isoformat() if row[3] else ''
            }
        }

    def analyze_traffic_by_ip(self) -> List[Dict]:
        """Analyze traffic consumption by IP address - from database"""
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT
                ip,
                total_requests as requests,
                total_bytes_sent as bytes_sent,
                unique_urls,
                unique_user_agents as unique_user_agents,
                EXTRACT(EPOCH FROM (last_seen - first_seen)) / 60 as duration_minutes,
                requests_per_minute
            FROM ip_statistics
            ORDER BY total_bytes_sent DESC
            LIMIT 50
        """)

        results = cursor.fetchall()
        cursor.close()
        release_db_connection(conn)

        return [dict(row) for row in results]

    def analyze_traffic_by_url(self) -> List[Dict]:
        """Analyze traffic consumption by URL"""
        url_stats = defaultdict(lambda: {
            'requests': 0,
            'bytes_sent': 0,  # 保留字段名以保持向后兼容
            'unique_ips': set(),
            'avg_response_time': []
        })

        for entry in self.entries:
            stats = url_stats[entry.url]
            stats['requests'] += 1
            stats['bytes_sent'] += entry.response_size  # 使用response_size
            stats['unique_ips'].add(entry.ip)
            stats['avg_response_time'].append(entry.response_time)

        result = []
        for url, stats in url_stats.items():
            parsed_url = urlparse(url)
            result.append({
                'url': url,
                'path': parsed_url.path,
                'requests': stats['requests'],
                'bytes_sent': stats['bytes_sent'],
                'unique_ips': len(stats['unique_ips']),
                'avg_response_time': statistics.mean(stats['avg_response_time'])
            })

        return sorted(result, key=lambda x: x['bytes_sent'], reverse=True)[:50]

    def analyze_hourly_traffic(self) -> Dict[str, Any]:
        """Analyze traffic patterns by hour"""
        hourly_requests = defaultdict(int)
        hourly_bytes = defaultdict(int)
        hourly_unique_ips = defaultdict(set)

        for entry in self.entries:
            hour = entry.timestamp.hour
            hourly_requests[hour] += 1
            hourly_bytes[hour] += entry.response_size  # 使用response_size
            hourly_unique_ips[hour].add(entry.ip)

        hourly_data = []
        for hour in range(24):
            hourly_data.append({
                'hour': hour,
                'requests': hourly_requests[hour],
                'bytes_sent': hourly_bytes[hour],
                'unique_ips': len(hourly_unique_ips[hour])
            })

        return {
            'hourly_data': hourly_data,
            'peak_hour': max(hourly_requests.items(), key=lambda x: x[1])[0] if hourly_requests else 0
        }

    def analyze_user_behavior(self) -> Dict[str, Any]:
        """Analyze user behavior patterns"""
        user_sessions = defaultdict(lambda: {
            'requests': [],
            'urls': set(),
            'user_agents': set()
        })

        for entry in self.entries:
            session = user_sessions[entry.ip]
            session['requests'].append({
                'timestamp': entry.timestamp,
                'url': entry.url,
                'status_code': entry.status_code
            })
            session['urls'].add(entry.url)
            session['user_agents'].add(entry.user_agent)

        # Analyze session patterns
        bounce_rate_data = []
        session_duration_data = []

        for ip, session in user_sessions.items():
            requests = sorted(session['requests'], key=lambda x: x['timestamp'])

            # Calculate session duration
            if len(requests) > 1:
                duration = (requests[-1]['timestamp'] - requests[0]['timestamp']).total_seconds()
                session_duration_data.append(duration)

            # Check for bounce (single page visit)
            is_bounce = len(session['urls']) == 1
            bounce_rate_data.append(is_bounce)

        bounce_rate = sum(bounce_rate_data) / len(bounce_rate_data) * 100 if bounce_rate_data else 0
        avg_session_duration = statistics.mean(session_duration_data) if session_duration_data else 0

        return {
            'bounce_rate': bounce_rate,
            'avg_session_duration_seconds': avg_session_duration,
            'total_sessions': len(user_sessions),
            'single_request_sessions': sum(bounce_rate_data)
        }

    def analyze_static_vs_dynamic_traffic(self) -> Dict[str, Any]:
        """Analyze IPs that only access static content vs those accessing dynamic APIs - from database"""
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Get total traffic
        cursor.execute("SELECT SUM(response_size) as total FROM log_entries")
        result = cursor.fetchone()
        total_traffic = result['total'] if result and result['total'] else 0

        # Get static-only IPs
        cursor.execute("""
            SELECT
                ip,
                total_requests,
                static_requests,
                dynamic_requests,
                total_bytes_sent as total_bytes,
                unique_urls,
                unique_user_agents,
                (static_requests::float / total_requests * 100) as static_percentage
            FROM ip_statistics
            WHERE is_static_only = TRUE
            ORDER BY total_bytes_sent DESC
            LIMIT 20
        """)
        static_only_ips = [dict(row) for row in cursor.fetchall()]

        # Add bot indicators to static-only IPs
        for ip_data in static_only_ips:
            ip_data['bot_indicators'] = ['Only static assets', 'No API requests']
            ip_data['bot_score'] = 2

        # Get mixed IPs
        cursor.execute("""
            SELECT
                ip,
                total_requests,
                static_requests,
                dynamic_requests,
                total_bytes_sent as total_bytes,
                unique_urls,
                unique_user_agents,
                (static_requests::float / total_requests * 100) as static_percentage
            FROM ip_statistics
            WHERE is_static_only = FALSE AND static_requests > 0 AND dynamic_requests > 0
            ORDER BY total_bytes_sent DESC
            LIMIT 10
        """)
        mixed_ips = [dict(row) for row in cursor.fetchall()]

        # Get dynamic-only IPs
        cursor.execute("""
            SELECT
                ip,
                total_requests,
                static_requests,
                dynamic_requests,
                total_bytes_sent as total_bytes,
                unique_urls,
                unique_user_agents,
                0.0 as static_percentage
            FROM ip_statistics
            WHERE static_requests = 0 AND dynamic_requests > 0
            ORDER BY total_bytes_sent DESC
            LIMIT 10
        """)
        dynamic_only_ips = [dict(row) for row in cursor.fetchall()]

        # Get counts and traffic totals
        cursor.execute("""
            SELECT
                COUNT(CASE WHEN is_static_only = TRUE THEN 1 END) as static_only_count,
                SUM(CASE WHEN is_static_only = TRUE THEN total_bytes_sent ELSE 0 END) as static_only_traffic,
                COUNT(CASE WHEN static_requests > 0 AND dynamic_requests > 0 THEN 1 END) as mixed_count,
                SUM(CASE WHEN static_requests > 0 AND dynamic_requests > 0 THEN total_bytes_sent ELSE 0 END) as mixed_traffic,
                COUNT(CASE WHEN static_requests = 0 AND dynamic_requests > 0 THEN 1 END) as dynamic_only_count,
                SUM(CASE WHEN static_requests = 0 AND dynamic_requests > 0 THEN total_bytes_sent ELSE 0 END) as dynamic_only_traffic,
                COUNT(*) as total_unique_ips
            FROM ip_statistics
        """)
        counts = cursor.fetchone()

        cursor.close()
        release_db_connection(conn)

        return {
            'static_only_ips': {
                'count': counts['static_only_count'] or 0,
                'percentage': ((counts['static_only_count'] or 0) / (counts['total_unique_ips'] or 1) * 100),
                'traffic_bytes': counts['static_only_traffic'] or 0,
                'traffic_percentage': ((counts['static_only_traffic'] or 0) / max(total_traffic, 1) * 100),
                'top_ips': static_only_ips
            },
            'mixed_ips': {
                'count': counts['mixed_count'] or 0,
                'percentage': ((counts['mixed_count'] or 0) / (counts['total_unique_ips'] or 1) * 100),
                'traffic_bytes': counts['mixed_traffic'] or 0,
                'traffic_percentage': ((counts['mixed_traffic'] or 0) / max(total_traffic, 1) * 100),
                'top_ips': mixed_ips
            },
            'dynamic_only_ips': {
                'count': counts['dynamic_only_count'] or 0,
                'percentage': ((counts['dynamic_only_count'] or 0) / (counts['total_unique_ips'] or 1) * 100),
                'traffic_bytes': counts['dynamic_only_traffic'] or 0,
                'traffic_percentage': ((counts['dynamic_only_traffic'] or 0) / max(total_traffic, 1) * 100),
                'top_ips': dynamic_only_ips
            },
            'total_unique_ips': counts['total_unique_ips'] or 0,
            'total_traffic_bytes': total_traffic
        }

    def detect_suspicious_patterns(self) -> Dict[str, Any]:
        """Detect suspicious or unusual patterns - optimized version"""
        # Group entries by IP first (single pass)
        ip_entries = {}
        for entry in self.entries:
            if entry.ip not in ip_entries:
                ip_entries[entry.ip] = []
            ip_entries[entry.ip].append(entry)

        suspicious_ips = []
        high_frequency_ips = []

        for ip, entries in ip_entries.items():
            num_requests = len(entries)

            # Skip IPs with very few requests to save processing time
            if num_requests < 5:
                continue

            # Sort entries by timestamp for this IP
            entries.sort(key=lambda x: x.timestamp)

            # Calculate timespan
            timespan_seconds = (entries[-1].timestamp - entries[0].timestamp).total_seconds()
            timespan_minutes = timespan_seconds / 60 if timespan_seconds > 0 else 1

            requests_per_minute = num_requests / timespan_minutes
            unique_urls = len({e.url for e in entries})

            # High frequency detection
            if requests_per_minute > 10:
                high_frequency_ips.append({
                    'ip': ip,
                    'requests': num_requests,
                    'requests_per_minute': requests_per_minute,
                    'unique_urls': unique_urls
                })

            # Bot behavior detection (only for high-request IPs to save time)
            if num_requests > 20:
                intervals = []
                for i in range(1, len(entries)):
                    interval = (entries[i].timestamp - entries[i-1].timestamp).total_seconds()
                    intervals.append(interval)

                if intervals:
                    avg_interval = statistics.mean(intervals)
                    interval_variance = statistics.variance(intervals) if len(intervals) > 1 else 0

                    # Regular interval requests (potential bot)
                    if avg_interval < 60 and interval_variance < 100:
                        suspicious_ips.append({
                            'ip': ip,
                            'requests': num_requests,
                            'avg_interval_seconds': avg_interval,
                            'reason': 'Regular interval requests (potential bot)'
                        })

        return {
            'suspicious_ips': suspicious_ips[:20],
            'high_frequency_ips': sorted(high_frequency_ips, key=lambda x: x['requests_per_minute'], reverse=True)[:20]
        }

    def analyze_performance(self) -> Dict[str, Any]:
        """Analyze performance metrics"""
        response_times = [entry.response_time for entry in self.entries]
        status_codes = Counter(entry.status_code for entry in self.entries)
        cache_status = Counter(entry.cache_status for entry in self.entries)

        return {
            'avg_response_time': statistics.mean(response_times) if response_times else 0,
            'median_response_time': statistics.median(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
            'status_codes': dict(status_codes),
            'cache_hit_ratio': cache_status.get('HIT', 0) / max(1, sum(cache_status.values())) * 100,
            'cache_status_distribution': dict(cache_status)
        }

analyzer = LogAnalyzer()
# Global storage for log entries to persist between requests
global_log_entries = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_logs():
    directory_path = request.json.get('directory_path')

    if not directory_path or not os.path.exists(directory_path):
        return jsonify({'error': 'Invalid directory path'}), 400

    try:
        results = analyzer.process_directory(directory_path)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze/progress')
def analyze_logs_with_progress():
    directory_path = request.args.get('directory_path')

    if not directory_path or not os.path.exists(directory_path):
        return Response(
            f"data: {json.dumps({'status': 'error', 'message': 'Invalid directory path'})}\n\n",
            mimetype='text/event-stream'
        )

    def generate():
        import sys
        global db_pool  # Declare global at the top of function

        # Send initial message
        initial_msg = f"data: {json.dumps({'status': 'started', 'message': 'Starting analysis...'})}\n\n"
        yield initial_msg
        sys.stdout.flush()  # Force flush stdout

        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting log analysis for directory: {directory_path}")

            # Check connection pool health
            available = len(db_pool._pool)
            in_use = db_pool.maxconn - available
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Initial DB Pool status - Available: {available}, In Use: {in_use}")

            # If too many connections are in use, warn and try to clean up
            if in_use > 15:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] WARNING: {in_use} connections in use! This may indicate connection leaks from previous requests.")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Attempting to close idle connections...")
                # Close all idle connections in the pool
                try:
                    while db_pool._pool:
                        conn = db_pool._pool.pop()
                        try:
                            conn.close()
                        except:
                            pass
                    # Reinitialize pool
                    db_pool.closeall()
                    db_pool = SimpleConnectionPool(1, 20, **DB_CONFIG)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] DB pool reinitialized")
                except Exception as pool_error:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Error reinitializing pool: {pool_error}")

            # Create analyzer instance for this request
            analyzer_instance = LogAnalyzer()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Analyzer instance created successfully")

            # Define progress callback that yields progress updates
            def progress_callback(data):
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Progress update: {data.get('message', 'unknown')}")
                sys.stdout.flush()  # Force flush after each progress update
                return f"data: {json.dumps(data)}\n\n"

            # Process directory with real-time progress updates
            print(f"Scanning directory for .gz files: {directory_path}")
            gz_files = [f for f in os.listdir(directory_path) if f.endswith('.gz')]
            gz_files.sort()
            total_files = len(gz_files)
            print(f"Found {total_files} .gz files to process")
            start_time = time.time()
            analyzer_instance.entries = []

            # Send initial progress (but don't wait for response)
            try:
                initial_data = {
                    'progress': 0.0,
                    'message': f'Found {total_files} .gz files to process',
                    'current_file_index': 0,
                    'total_files': total_files,
                    'current_file': '',
                    'estimated_remaining_seconds': 0
                }
                yield progress_callback(initial_data)
                sys.stdout.flush()
            except GeneratorExit:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Client disconnected early")
                return

            # Process each file and commit individually
            total_lines_processed = 0

            for i, filename in enumerate(gz_files):
                filepath = os.path.join(directory_path, filename)

                # Send file start progress (file processing takes 70% of total progress)
                file_progress = (i / total_files) * 0.7 if total_files > 0 else 0
                progress_data = {
                    'progress': file_progress,
                    'message': f'Processing file {i + 1} of {total_files}',
                    'current_file_index': i + 1,
                    'total_files': total_files,
                    'current_file': filename,
                    'estimated_remaining_seconds': analyzer_instance._calculate_remaining_time(i, total_files, start_time)
                }
                yield progress_callback(progress_data)

                # Buffer for this file only
                file_entries = []

                print(f"[{datetime.now().strftime('%H:%M:%S')}] Opening gzip file: {filename}")
                with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                    line_count = 0
                    last_log_time = time.time()

                    for line in f:
                        # Debug: Print heartbeat every 5 seconds even if no progress update
                        current_time = time.time()
                        if current_time - last_log_time > 5:
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Still reading {filename}, line {line_count}")
                            last_log_time = current_time

                        try:
                            entry = analyzer_instance.parse_log_line(line)
                            if entry:
                                file_entries.append(entry)
                        except Exception as parse_error:
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR parsing line {line_count} in {filename}: {str(parse_error)[:100]}")
                            # Continue processing other lines

                        line_count += 1
                        total_lines_processed += 1

                        # Send progress every 20000 lines (reduced frequency to avoid blocking)
                        # Also skip progress updates for first 20000 lines to avoid early blocking
                        if line_count % 20000 == 0 and line_count >= 20000:
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Reached {line_count} lines in {filename}, preparing progress update...")
                            file_progress = ((i + 0.5) / total_files) * 0.7 if total_files > 0 else 0.35
                            progress_data = {
                                'progress': min(file_progress, 0.7),
                                'message': f'Processing file {i + 1} of {total_files} ({line_count:,} lines in current file)',
                                'current_file_index': i + 1,
                                'total_files': total_files,
                                'current_file': filename,
                                'estimated_remaining_seconds': analyzer_instance._calculate_remaining_time(i, total_files, start_time)
                            }
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Yielding progress update...")

                            # Yield and force flush
                            msg = progress_callback(progress_data)
                            yield msg
                            sys.stdout.flush()  # Force flush stdout

                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Progress update yielded successfully, continuing...")

                print(f"[{datetime.now().strftime('%H:%M:%S')}] Finished reading {filename}, total lines: {line_count}")

                # Insert all entries from this file
                if file_entries:
                    try:
                        progress_data = {
                            'progress': ((i + 0.9) / total_files) * 0.7,
                            'message': f'Inserting {len(file_entries)} entries from {filename}...',
                            'current_file_index': i + 1,
                            'total_files': total_files,
                            'current_file': filename,
                            'estimated_remaining_seconds': analyzer_instance._calculate_remaining_time(i, total_files, start_time)
                        }
                        yield progress_callback(progress_data)

                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting DB insert for {len(file_entries)} entries from file {filename}")
                        insert_start = time.time()
                        analyzer_instance.insert_entries_to_db(file_entries)
                        insert_duration = time.time() - insert_start
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] File {filename} inserted successfully ({len(file_entries)} entries in {insert_duration:.2f}s)")

                        # Clear file entries to free memory
                        file_entries.clear()

                    except Exception as file_error:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR inserting entries from file {filename}: {str(file_error)}")
                        import traceback
                        print(traceback.format_exc())
                        raise

            # Send IP statistics calculation progress
            ip_stats_progress = {
                'progress': 0.7,
                'message': 'Calculating IP statistics...',
                'current_file_index': total_files,
                'total_files': total_files,
                'current_file': '',
                'estimated_remaining_seconds': 10
            }
            yield progress_callback(ip_stats_progress)

            # Calculate and store IP statistics
            try:
                print("Starting IP statistics calculation...")
                analyzer_instance.calculate_and_store_ip_statistics()
                print("IP statistics calculated successfully")
            except Exception as stats_error:
                print(f"ERROR calculating IP statistics: {str(stats_error)}")
                import traceback
                print(traceback.format_exc())
                raise

            # Send completion message - skip full analysis for large datasets during load
            print("Log loading completed. Skipping full analysis for performance.")
            print(f"Total lines processed: {total_lines_processed:,}")
            completion_data = {
                'status': 'completed',
                'progress': 1.0,
                'message': f'Log loading complete! Processed {total_lines_processed:,} lines from {total_files} files.',
                'results': None
            }
            yield f"data: {json.dumps(completion_data)}\n\n"
            return

            # Send analysis phase progress
            analysis_data = {
                'progress': 0.85,  # Start analysis phase at 85%
                'message': 'Generating analysis results...',
                'current_file_index': total_files,
                'total_files': total_files,
                'current_file': '',
                'estimated_remaining_seconds': 5  # Estimate 5 seconds for analysis
            }
            yield progress_callback(analysis_data)

            # Run analysis with progress tracking (step by step)
            analysis_steps = [
                ("Computing basic statistics", analyzer_instance._compute_basic_stats),
                ("Analyzing traffic by IP", analyzer_instance.analyze_traffic_by_ip),
                ("Analyzing traffic by URL", analyzer_instance.analyze_traffic_by_url),
                ("Analyzing hourly traffic patterns", analyzer_instance.analyze_hourly_traffic),
                ("Analyzing user behavior", analyzer_instance.analyze_user_behavior),
                ("Analyzing static vs dynamic traffic patterns", analyzer_instance.analyze_static_vs_dynamic_traffic),
                ("Detecting suspicious patterns", analyzer_instance.detect_suspicious_patterns),
                ("Computing performance statistics", analyzer_instance.analyze_performance)
            ]

            results = {}
            total_steps = len(analysis_steps)

            for i, (step_name, step_func) in enumerate(analysis_steps):
                # Send progress update
                analysis_progress = 0.85 + (i / total_steps) * 0.15
                progress_data = {
                    'progress': min(analysis_progress, 1.0),
                    'message': step_name,
                    'current_file_index': total_files,
                    'total_files': total_files,
                    'current_file': f'Step {i+1}/{total_steps}',
                    'estimated_remaining_seconds': max(0, (total_steps - i) * 1)
                }
                yield progress_callback(progress_data)

                # Execute analysis step
                if step_name == "Computing basic statistics":
                    results['basic_stats'] = step_func()
                elif step_name == "Analyzing traffic by IP":
                    results['traffic_by_ip'] = step_func()
                elif step_name == "Analyzing traffic by URL":
                    results['traffic_by_url'] = step_func()
                elif step_name == "Analyzing hourly traffic patterns":
                    results['hourly_traffic'] = step_func()
                elif step_name == "Analyzing user behavior":
                    results['user_behavior'] = step_func()
                elif step_name == "Analyzing static vs dynamic traffic patterns":
                    results['static_vs_dynamic_analysis'] = step_func()
                elif step_name == "Detecting suspicious patterns":
                    results['suspicious_patterns'] = step_func()
                elif step_name == "Computing performance statistics":
                    results['performance_stats'] = step_func()

            # Send completion message
            completion_data = {
                'status': 'completed',
                'progress': 1.0,
                'message': 'Analysis complete!',
                'results': results
            }
            yield f"data: {json.dumps(completion_data)}\n\n"

        except Exception as e:
            import traceback
            error_traceback = traceback.format_exc()
            print(f"ERROR in analyze_logs_with_progress: {str(e)}")
            print(f"Traceback:\n{error_traceback}")
            error_data = {
                'status': 'error',
                'message': f'Error: {str(e)}',
                'traceback': error_traceback
            }
            yield f"data: {json.dumps(error_data)}\n\n"

    response = Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # Disable nginx buffering
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type'
        }
    )
    # Disable werkzeug response buffering
    response.implicit_sequence_conversion = False
    return response

@app.route('/api/db-stats', methods=['GET'])
def get_db_stats():
    """Get database statistics (total logs and time range)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                COUNT(*) as total_logs,
                MIN(timestamp) as start_time,
                MAX(timestamp) as end_time
            FROM log_entries
        """)

        row = cursor.fetchone()
        cursor.close()
        release_db_connection(conn)

        return jsonify({
            'total_logs': row[0] if row[0] else 0,
            'start_time': row[1].isoformat() if row[1] else None,
            'end_time': row[2].isoformat() if row[2] else None
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis-cache', methods=['GET'])
def get_analysis_cache():
    """Get cached analysis results"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT id, start_time, end_time, results, created_at
            FROM analysis_cache
            ORDER BY created_at DESC
            LIMIT 1
        """)

        cache = cursor.fetchone()
        cursor.close()
        release_db_connection(conn)

        if cache:
            return jsonify({
                'has_cache': True,
                'cache_id': cache['id'],
                'start_time': cache['start_time'].isoformat() if cache['start_time'] else None,
                'end_time': cache['end_time'].isoformat() if cache['end_time'] else None,
                'results': cache['results'],
                'created_at': cache['created_at'].isoformat()
            })
        else:
            return jsonify({'has_cache': False})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis-cache', methods=['DELETE'])
def delete_analysis_cache():
    """Delete cached analysis results"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("TRUNCATE TABLE analysis_cache")
        conn.commit()
        cursor.close()
        release_db_connection(conn)

        return jsonify({'status': 'success'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blacklist-cache', methods=['GET'])
def get_blacklist_cache():
    """Get cached blacklist"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT id, blacklist_data, created_at
            FROM blacklist_cache
            ORDER BY created_at DESC
            LIMIT 1
        """)

        cache = cursor.fetchone()
        cursor.close()
        release_db_connection(conn)

        if cache:
            return jsonify({
                'has_cache': True,
                'blacklist_data': cache['blacklist_data'],
                'created_at': cache['created_at'].isoformat()
            })
        else:
            return jsonify({'has_cache': False})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-range', methods=['POST'])
def analyze_time_range():
    """Analyze logs within a specific time range with SSE progress"""
    import traceback

    data = request.json
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    force_refresh = data.get('force_refresh', False)

    print(f"\n=== Analyze Range Request ===")
    print(f"Start time: {start_time}")
    print(f"End time: {end_time}")
    print(f"Force refresh: {force_refresh}")
    print(f"db_pool status: {db_pool}")

    if not start_time or not end_time:
        return jsonify({'error': 'start_time and end_time are required'}), 400

    def generate():
        try:
            yield f"data: {json.dumps({'status': 'started', 'progress': 0, 'message': 'Starting analysis...'}, cls=DecimalEncoder)}\n\n"

            print("Creating LogAnalyzer instance...")
            analyzer_instance = LogAnalyzer()

            # Recalculate IP statistics for the time range
            yield f"data: {json.dumps({'progress': 0.1, 'message': 'Calculating IP statistics for time range...'}, cls=DecimalEncoder)}\n\n"
            print("Calculating IP statistics for range...")
            analyzer_instance.calculate_ip_statistics_for_range(start_time, end_time)

            # Run analysis - note: analyze_traffic_by_ip() reads from ip_statistics which was just recalculated for the range
            results = {}
            total_steps = 8
            current_step = 0

            current_step += 1
            yield f"data: {json.dumps({'progress': 0.2 + (current_step / total_steps) * 0.7, 'message': 'Computing basic statistics...'}, cls=DecimalEncoder)}\n\n"
            print("Computing basic stats...")
            results['basic_stats'] = analyzer_instance._compute_basic_stats_for_range(start_time, end_time)

            current_step += 1
            yield f"data: {json.dumps({'progress': 0.2 + (current_step / total_steps) * 0.7, 'message': 'Analyzing traffic by IP...'}, cls=DecimalEncoder)}\n\n"
            print("Analyzing traffic by IP...")
            results['traffic_by_ip'] = analyzer_instance.analyze_traffic_by_ip()

            current_step += 1
            yield f"data: {json.dumps({'progress': 0.2 + (current_step / total_steps) * 0.7, 'message': 'Analyzing traffic by URL...'}, cls=DecimalEncoder)}\n\n"
            print("Analyzing traffic by URL...")
            results['traffic_by_url'] = analyzer_instance.analyze_traffic_by_url_for_range(start_time, end_time)

            current_step += 1
            yield f"data: {json.dumps({'progress': 0.2 + (current_step / total_steps) * 0.7, 'message': 'Analyzing hourly traffic patterns...'}, cls=DecimalEncoder)}\n\n"
            print("Analyzing hourly traffic...")
            results['hourly_traffic'] = analyzer_instance.analyze_hourly_traffic_for_range(start_time, end_time)

            current_step += 1
            yield f"data: {json.dumps({'progress': 0.2 + (current_step / total_steps) * 0.7, 'message': 'Analyzing user behavior...'}, cls=DecimalEncoder)}\n\n"
            print("Analyzing user behavior...")
            results['user_behavior'] = analyzer_instance.analyze_user_behavior_for_range(start_time, end_time)

            current_step += 1
            yield f"data: {json.dumps({'progress': 0.2 + (current_step / total_steps) * 0.7, 'message': 'Analyzing static vs dynamic traffic...'}, cls=DecimalEncoder)}\n\n"
            print("Analyzing static vs dynamic...")
            results['static_vs_dynamic_analysis'] = analyzer_instance.analyze_static_vs_dynamic_traffic_for_range()

            current_step += 1
            yield f"data: {json.dumps({'progress': 0.2 + (current_step / total_steps) * 0.7, 'message': 'Detecting suspicious patterns...'}, cls=DecimalEncoder)}\n\n"
            print("Detecting suspicious patterns...")
            results['suspicious_patterns'] = analyzer_instance.detect_suspicious_patterns_for_range(start_time, end_time)

            current_step += 1
            yield f"data: {json.dumps({'progress': 0.2 + (current_step / total_steps) * 0.7, 'message': 'Analyzing performance metrics...'}, cls=DecimalEncoder)}\n\n"
            print("Analyzing performance...")
            results['performance_stats'] = analyzer_instance.analyze_performance_for_range(start_time, end_time)

            print("Analysis complete!")

            # Save results to cache
            yield f"data: {json.dumps({'progress': 0.95, 'message': 'Saving results to cache...'}, cls=DecimalEncoder)}\n\n"
            try:
                cache_conn = get_db_connection()
                cache_cursor = cache_conn.cursor()

                # Clear old cache
                cache_cursor.execute("TRUNCATE TABLE analysis_cache")

                # Save new cache
                cache_cursor.execute("""
                    INSERT INTO analysis_cache (start_time, end_time, results)
                    VALUES (%s, %s, %s)
                """, (start_time if start_time else None, end_time if end_time else None, json.dumps(results, cls=DecimalEncoder)))

                cache_conn.commit()
                cache_cursor.close()
                release_db_connection(cache_conn)
                print("Results saved to cache")
            except Exception as cache_error:
                print(f"Warning: Failed to save cache: {cache_error}")
                # Make sure to release connection on error
                if 'cache_conn' in locals() and cache_conn:
                    try:
                        if 'cache_cursor' in locals() and cache_cursor:
                            cache_cursor.close()
                        release_db_connection(cache_conn)
                    except:
                        pass

            yield f"data: {json.dumps({'status': 'completed', 'progress': 1.0, 'message': 'Analysis complete!', 'results': results, 'time_range': {'start': start_time, 'end': end_time}}, cls=DecimalEncoder)}\n\n"

        except Exception as e:
            print(f"\n!!! ERROR in analyze_time_range !!!")
            print(f"Error type: {type(e).__name__}")
            print(f"Error message: {str(e)}")
            print(f"Full traceback:")
            traceback.print_exc()
            print(f"db_pool at error: {db_pool}")
            yield f"data: {json.dumps({'status': 'error', 'message': str(e)}, cls=DecimalEncoder)}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type'
        }
    )

@app.route('/api/ip-details', methods=['POST'])
def get_ip_details():
    """Get detailed request history for a specific IP from database"""
    ip = request.json.get('ip')

    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Get all log entries for this IP
        cursor.execute("""
            SELECT
                timestamp,
                method,
                url,
                status_code,
                response_time,
                response_size,
                user_agent,
                cache_status
            FROM log_entries
            WHERE ip = %s
            ORDER BY timestamp ASC
        """, (ip,))

        entries = cursor.fetchall()

        # Calculate total traffic
        cursor.execute("""
            SELECT SUM(response_size) as total_bytes
            FROM log_entries
            WHERE ip = %s
        """, (ip,))

        total_bytes = cursor.fetchone()['total_bytes'] or 0

        cursor.close()
        release_db_connection(conn)

        # Convert to JSON-serializable format
        ip_entries = []
        for entry in entries:
            ip_entries.append({
                'timestamp': entry['timestamp'].isoformat(),
                'method': entry['method'],
                'url': entry['url'],
                'status_code': entry['status_code'],
                'response_time': entry['response_time'],
                'response_size': entry['response_size'],
                'user_agent': entry['user_agent'],
                'cache_status': entry['cache_status']
            })

        return jsonify({
            'ip': ip,
            'requests': ip_entries,
            'count': len(ip_entries),
            'total_traffic_bytes': total_bytes,
            'total_traffic_mb': round(total_bytes / 1024 / 1024, 2)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip-geolocation', methods=['POST'])
def get_ip_geolocation():
    """Get IP geolocation with database caching"""
    ip = request.json.get('ip')

    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Check if we have cached geolocation data
        cursor.execute("""
            SELECT * FROM geo_location WHERE ip = %s
        """, (ip,))

        cached_data = cursor.fetchone()

        if cached_data:
            # Return cached data
            cursor.close()
            release_db_connection(conn)

            return jsonify({
                'ip': ip,
                'country': cached_data['country'],
                'country_code': cached_data['country_code'],
                'region': cached_data['region'],
                'city': cached_data['city'],
                'latitude': cached_data['latitude'],
                'longitude': cached_data['longitude'],
                'isp': cached_data['isp'],
                'organization': cached_data['organization'],
                'as_number': cached_data['as_number'],
                'as_name': cached_data['as_name'],
                'is_mobile': cached_data['is_mobile'],
                'is_proxy': cached_data['is_proxy'],
                'is_hosting': cached_data['is_hosting'],
                'timezone': cached_data['timezone'],
                'cached': True
            })

        # No cache, fetch from API
        import urllib.request

        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting"

        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())

            if data.get('status') == 'success':
                # Cache the result
                cursor.execute("""
                    INSERT INTO geo_location (
                        ip, country, country_code, region, city, latitude, longitude,
                        isp, organization, as_number, as_name, is_mobile, is_proxy, is_hosting, timezone
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (ip) DO UPDATE SET
                        country = EXCLUDED.country,
                        country_code = EXCLUDED.country_code,
                        region = EXCLUDED.region,
                        city = EXCLUDED.city,
                        latitude = EXCLUDED.latitude,
                        longitude = EXCLUDED.longitude,
                        isp = EXCLUDED.isp,
                        organization = EXCLUDED.organization,
                        as_number = EXCLUDED.as_number,
                        as_name = EXCLUDED.as_name,
                        is_mobile = EXCLUDED.is_mobile,
                        is_proxy = EXCLUDED.is_proxy,
                        is_hosting = EXCLUDED.is_hosting,
                        timezone = EXCLUDED.timezone
                """, (
                    ip,
                    data.get('country', 'Unknown'),
                    data.get('countryCode', 'Unknown'),
                    data.get('regionName', 'Unknown'),
                    data.get('city', 'Unknown'),
                    data.get('lat', 0),
                    data.get('lon', 0),
                    data.get('isp', 'Unknown'),
                    data.get('org', 'Unknown'),
                    data.get('as', 'Unknown'),
                    data.get('asname', 'Unknown'),
                    data.get('mobile', False),
                    data.get('proxy', False),
                    data.get('hosting', False),
                    data.get('timezone', 'Unknown')
                ))
                conn.commit()
                cursor.close()
                release_db_connection(conn)

                return jsonify({
                    'ip': ip,
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'latitude': data.get('lat', 0),
                    'longitude': data.get('lon', 0),
                    'isp': data.get('isp', 'Unknown'),
                    'organization': data.get('org', 'Unknown'),
                    'as_number': data.get('as', 'Unknown'),
                    'as_name': data.get('asname', 'Unknown'),
                    'is_mobile': data.get('mobile', False),
                    'is_proxy': data.get('proxy', False),
                    'is_hosting': data.get('hosting', False),
                    'timezone': data.get('timezone', 'Unknown'),
                    'cached': False
                })
            else:
                cursor.close()
                release_db_connection(conn)
                return jsonify({'error': data.get('message', 'Failed to get location data')}), 400

    except Exception as e:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            release_db_connection(conn)
        return jsonify({'error': f'Failed to get geolocation: {str(e)}'}), 500

@app.before_request
def ensure_db_initialized():
    """Ensure database is initialized before handling any request"""
    global db_pool
    if db_pool is None:
        init_db()

def is_subnet_safe_to_block(subnet, all_ip_behaviors):
    """
    Check if it's safe to block an entire C-class subnet (/24).
    Safe = NO IP in the subnet (xxx.xxx.xxx.0-255) has accessed dynamic content.

    Args:
        subnet: String like "192.168.1" (first 3 octets)
        all_ip_behaviors: Dict of all IP behaviors including dynamic_requests count

    Returns:
        bool: True if safe to block entire subnet, False otherwise
    """
    # Check all IPs in our behavior data for this subnet
    for ip_str, behavior in all_ip_behaviors.items():
        # Check if this IP belongs to the subnet
        ip_parts = ip_str.split('.')
        if len(ip_parts) == 4:
            ip_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"

            if ip_subnet == subnet:
                # This IP is in our target subnet
                has_dynamic = behavior.get('dynamic_requests', 0) > 0

                if has_dynamic:
                    # Found an IP in this subnet that accesses dynamic content
                    # NOT safe to block entire subnet
                    return False

    # No IPs in this subnet access dynamic content - safe to block
    return True

@app.route('/api/static-only-ips', methods=['GET'])
def get_static_only_ips():
    """Get all static-only IP addresses for blacklisting from database"""
    try:
        # Get min_traffic_mb from query parameter
        min_traffic_mb = int(request.args.get('min_traffic_mb', 0))
        min_traffic_bytes = min_traffic_mb * 1024 * 1024

        print(f"Generating blacklist with min_traffic_mb = {min_traffic_mb} MB ({min_traffic_bytes} bytes)")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Get all static-only IPs with traffic filter, including traffic info
        cursor.execute("""
            SELECT ip, total_response_size
            FROM ip_statistics
            WHERE is_static_only = TRUE AND total_response_size >= %s
            ORDER BY total_response_size DESC
        """, (min_traffic_bytes,))

        ip_traffic_data = [(row[0], row[1]) for row in cursor.fetchall()]
        static_only_ips = [row[0] for row in ip_traffic_data]
        ip_traffic_map = {row[0]: row[1] for row in ip_traffic_data}

        # Get all IP behaviors for safety check
        cursor.execute("""
            SELECT ip, dynamic_requests
            FROM ip_statistics
        """)

        ip_behaviors = {row[0]: {'dynamic_requests': row[1]} for row in cursor.fetchall()}

        # Get mixed traffic IPs (both static and dynamic content access)
        cursor.execute("""
            SELECT ip, total_response_size
            FROM ip_statistics
            WHERE static_requests > 0 AND dynamic_requests > 0 AND total_response_size >= %s
            ORDER BY total_response_size DESC
        """, (min_traffic_bytes,))

        mixed_traffic_data = [(row[0], row[1]) for row in cursor.fetchall()]
        mixed_traffic_ips = [row[0] for row in mixed_traffic_data]
        mixed_traffic_map = {row[0]: row[1] for row in mixed_traffic_data}

        # Get dynamic-only IPs (only dynamic content access)
        cursor.execute("""
            SELECT ip, total_response_size
            FROM ip_statistics
            WHERE static_requests = 0 AND dynamic_requests > 0 AND total_response_size >= %s
            ORDER BY total_response_size DESC
        """, (min_traffic_bytes,))

        dynamic_only_data = [(row[0], row[1]) for row in cursor.fetchall()]
        dynamic_only_ips = [row[0] for row in dynamic_only_data]
        dynamic_only_map = {row[0]: row[1] for row in dynamic_only_data}

        cursor.close()
        release_db_connection(conn)

        # Group IPs by C-class subnet (first 3 octets)
        subnet_groups = {}
        for ip in static_only_ips:
            parts = ip.split('.')
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
                if subnet not in subnet_groups:
                    subnet_groups[subnet] = []
                subnet_groups[subnet].append(ip)

        # Separate CIDR blocks and individual IPs
        cidr_blocks = []  # Will store tuples: (cidr, total_traffic, ip_count)
        individual_ips = []

        for subnet, ips in subnet_groups.items():
            if len(ips) >= 2:
                # Safety check: ensure no IP in this subnet has accessed dynamic content
                subnet_is_safe = is_subnet_safe_to_block(subnet, ip_behaviors)

                if subnet_is_safe:
                    # Calculate total traffic for this C-class subnet
                    subnet_total_traffic = sum(ip_traffic_map.get(ip, 0) for ip in ips)
                    # Use CIDR notation for 2+ IPs in same C-class
                    cidr_blocks.append((f"{subnet}.0/24", subnet_total_traffic, len(ips)))
                else:
                    # Not safe to block entire subnet, add individual static-only IPs
                    individual_ips.extend(ips)
            else:
                # Add individual IPs
                individual_ips.extend(ips)

        # Sort CIDR blocks by network address
        cidr_blocks.sort(key=lambda x: tuple(int(part) for part in x[0].replace('.0/24', '').split('.')))

        # Sort individual IPs by traffic (descending)
        individual_ips.sort(key=lambda ip: ip_traffic_map.get(ip, 0), reverse=True)

        # Build final blacklist with traffic comments
        blacklist_entries = []

        # Add CIDR blocks first
        if cidr_blocks:
            blacklist_entries.append("# === C-Class Subnets (CIDR /24 blocks) ===")
            blacklist_entries.append("# Format: CIDR_Block    Traffic(MB)    IP_Count")
            for cidr, total_traffic, ip_count in cidr_blocks:
                traffic_mb = total_traffic / (1024 * 1024)
                # Format: "116.16.0.0/24    1234.56 MB    15 IPs"
                blacklist_entries.append(f"{cidr:<20} {traffic_mb:>10.2f} MB    {ip_count:>3} IPs")
            blacklist_entries.append("")

        # Add individual IPs with traffic tier comments
        if individual_ips:
            blacklist_entries.append("# === Individual IPs (sorted by traffic, highest first) ===")
            blacklist_entries.append("# Format: IP_Address    Traffic(MB)    IP_Count")

            current_tier_mb = None
            for ip in individual_ips:
                traffic_bytes = ip_traffic_map.get(ip, 0)
                traffic_mb = traffic_bytes / (1024 * 1024)

                # Determine tier based on traffic
                if traffic_mb >= 100:
                    # For >= 100MB: use 100MB intervals
                    tier_mb = (int(traffic_mb) // 100) * 100
                else:
                    # For < 100MB: use 10MB intervals (90, 80, 70, ..., 0)
                    tier_mb = (int(traffic_mb) // 10) * 10

                # Add comment when entering a new traffic tier
                if tier_mb != current_tier_mb:
                    if current_tier_mb is not None:
                        blacklist_entries.append("")  # Add blank line between tiers
                    blacklist_entries.append(f"# Traffic >= {tier_mb} MB")
                    current_tier_mb = tier_mb

                # Format: "222.216.37.7         1234.56 MB      1 IPs"
                blacklist_entries.append(f"{ip:<20} {traffic_mb:>10.2f} MB    {1:>3} IPs")

        # Add Section 3: Mixed traffic IPs (both static and dynamic content)
        if mixed_traffic_ips:
            blacklist_entries.append("")
            blacklist_entries.append("")
            blacklist_entries.append("# ============================================")
            blacklist_entries.append("# === Mixed Traffic IPs (Static + Dynamic) ===")
            blacklist_entries.append("# ============================================")
            blacklist_entries.append("# These IPs access both static and dynamic content")
            blacklist_entries.append("# Sorted by total traffic (highest first)")
            blacklist_entries.append("# Format: IP_Address    Traffic(MB)")
            blacklist_entries.append("")

            current_tier_mb = None
            for ip in mixed_traffic_ips:
                traffic_bytes = mixed_traffic_map.get(ip, 0)
                traffic_mb = traffic_bytes / (1024 * 1024)

                # Determine tier based on traffic
                if traffic_mb >= 100:
                    tier_mb = (int(traffic_mb) // 100) * 100
                else:
                    tier_mb = (int(traffic_mb) // 10) * 10

                # Add comment when entering a new traffic tier
                if tier_mb != current_tier_mb:
                    if current_tier_mb is not None:
                        blacklist_entries.append("")
                    blacklist_entries.append(f"# Traffic >= {tier_mb} MB")
                    current_tier_mb = tier_mb

                # Format: "222.216.37.7         1234.56 MB"
                blacklist_entries.append(f"# {ip:<20} {traffic_mb:>10.2f} MB")

        # Add Section 4: Dynamic-only traffic IPs
        if dynamic_only_ips:
            blacklist_entries.append("")
            blacklist_entries.append("")
            blacklist_entries.append("# ============================================")
            blacklist_entries.append("# === Dynamic-Only Traffic IPs ===")
            blacklist_entries.append("# ============================================")
            blacklist_entries.append("# These IPs only access dynamic content (APIs, etc.)")
            blacklist_entries.append("# Sorted by total traffic (highest first)")
            blacklist_entries.append("# Format: IP_Address    Traffic(MB)")
            blacklist_entries.append("")

            current_tier_mb = None
            for ip in dynamic_only_ips:
                traffic_bytes = dynamic_only_map.get(ip, 0)
                traffic_mb = traffic_bytes / (1024 * 1024)

                # Determine tier based on traffic
                if traffic_mb >= 100:
                    tier_mb = (int(traffic_mb) // 100) * 100
                else:
                    tier_mb = (int(traffic_mb) // 10) * 10

                # Add comment when entering a new traffic tier
                if tier_mb != current_tier_mb:
                    if current_tier_mb is not None:
                        blacklist_entries.append("")
                    blacklist_entries.append(f"# Traffic >= {tier_mb} MB")
                    current_tier_mb = tier_mb

                # Format: "222.216.37.7         1234.56 MB"
                blacklist_entries.append(f"# {ip:<20} {traffic_mb:>10.2f} MB")

        # Count only actual IPs/CIDR blocks (exclude comments and blank lines)
        actual_entries = [e for e in blacklist_entries if e and not e.startswith('#')]

        result_data = {
            'static_only_ips': blacklist_entries,
            'count': len(actual_entries),
            'cidr_count': len(cidr_blocks),
            'original_count': len(static_only_ips),
            'min_traffic_mb': min_traffic_mb
        }

        return jsonify(result_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deep-analysis', methods=['GET'])
def deep_analysis():
    """Deep analysis of C-class subnets to understand why some aren't converted to /24"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Get all IPs and their behavior (static_only or mixed)
        cursor.execute("""
            SELECT
                ip,
                is_static_only,
                static_requests,
                dynamic_requests,
                total_requests
            FROM ip_statistics
            ORDER BY ip
        """)

        all_ips = cursor.fetchall()
        cursor.close()
        release_db_connection(conn)

        # Group by C-class subnet
        subnet_analysis = {}

        for ip_data in all_ips:
            ip = ip_data['ip']
            parts = ip.split('.')
            if len(parts) != 4:
                continue

            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"

            if subnet not in subnet_analysis:
                subnet_analysis[subnet] = {
                    'subnet': subnet,
                    'static_only_ips': [],
                    'mixed_ips': []
                }

            if ip_data['is_static_only']:
                subnet_analysis[subnet]['static_only_ips'].append(ip)
            else:
                subnet_analysis[subnet]['mixed_ips'].append(ip)

        # Filter: only show subnets that have >= 4 static-only IPs AND have at least 1 mixed IP
        # (These are subnets that could potentially be /24 but aren't because some IPs access dynamic content)
        result = []
        for subnet, data in subnet_analysis.items():
            static_count = len(data['static_only_ips'])
            mixed_count = len(data['mixed_ips'])

            # Only include if:
            # 1. Has 4+ static-only IPs (meets threshold for /24 conversion)
            # 2. Has at least 1 mixed IP (reason why it's NOT converted to /24)
            if static_count >= 4 and mixed_count > 0:
                result.append({
                    'subnet': subnet,
                    'static_only_count': static_count,
                    'static_only_ips': sorted(data['static_only_ips'], key=lambda x: tuple(int(p) for p in x.split('.'))),
                    'mixed_ips': sorted(data['mixed_ips'], key=lambda x: tuple(int(p) for p in x.split('.'))),
                    'mixed_count': mixed_count
                })

        # Sort by static_only_count descending (show most problematic subnets first)
        result.sort(key=lambda x: x['static_only_count'], reverse=True)

        return jsonify({
            'subnets': result,
            'total_subnets': len(result)
        })

    except Exception as e:
        import traceback
        print(f"Error in deep analysis: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip-range-analysis', methods=['GET'])
def ip_range_analysis():
    """
    Advanced IP range analysis: identify suspicious C-class subnets where most IPs
    are static-only but a few (<3) access dynamic content. Also aggregate into
    larger subnets (/20, /21, B-class) if most C-class subnets in those ranges
    are predominantly static.
    """
    try:
        # Get min_traffic_mb from query parameter
        min_traffic_mb = int(request.args.get('min_traffic_mb', 0))
        min_traffic_bytes = min_traffic_mb * 1024 * 1024

        print(f"IP Range Analysis with min_traffic_mb = {min_traffic_mb} MB ({min_traffic_bytes} bytes)")

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Get all IPs with their behavior and traffic
        cursor.execute("""
            SELECT
                ip,
                is_static_only,
                static_requests,
                dynamic_requests,
                total_requests,
                total_response_size
            FROM ip_statistics
            WHERE total_response_size >= %s
            ORDER BY ip
        """, (min_traffic_bytes,))

        all_ips = cursor.fetchall()
        cursor.close()
        release_db_connection(conn)

        # Group by C-class subnet
        c_class_analysis = {}

        for ip_data in all_ips:
            ip = ip_data['ip']
            parts = ip.split('.')
            if len(parts) != 4:
                continue

            c_class = f"{parts[0]}.{parts[1]}.{parts[2]}"

            if c_class not in c_class_analysis:
                c_class_analysis[c_class] = {
                    'c_class': c_class,
                    'static_only_ips': [],
                    'dynamic_ips': [],
                    'total_traffic': 0
                }

            c_class_analysis[c_class]['total_traffic'] += ip_data['total_response_size']

            if ip_data['is_static_only']:
                c_class_analysis[c_class]['static_only_ips'].append({
                    'ip': ip,
                    'traffic': ip_data['total_response_size']
                })
            else:
                c_class_analysis[c_class]['dynamic_ips'].append({
                    'ip': ip,
                    'traffic': ip_data['total_response_size']
                })

        # Identify suspicious C-class subnets (mostly static, few dynamic)
        suspicious_c_classes = []
        individual_ips = []

        for c_class, data in c_class_analysis.items():
            static_count = len(data['static_only_ips'])
            dynamic_count = len(data['dynamic_ips'])
            total_count = static_count + dynamic_count

            # Criteria for suspicious C-class:
            # 1. Has at least 2 IPs total
            # 2. Dynamic IPs < 3
            # 3. Static IPs >= Dynamic IPs (majority are static)
            if total_count >= 2 and dynamic_count <= 5 and static_count >= dynamic_count:
                ratio = dynamic_count / static_count if static_count > 0 else 0
                suspicious_c_classes.append({
                    'c_class': c_class,
                    'static_count': static_count,
                    'dynamic_count': dynamic_count,
                    'total_count': total_count,
                    'ratio': ratio,
                    'total_traffic': data['total_traffic']
                })
            else:
                # Add individual IPs from this C-class
                for ip_info in data['static_only_ips']:
                    individual_ips.append(ip_info)
                for ip_info in data['dynamic_ips']:
                    individual_ips.append(ip_info)

        # Now aggregate suspicious C-classes into larger subnets
        # Strategy: Start from largest subnet (/20) and work down to smallest (/24)
        # This ensures we use the most compact representation possible

        # Create a map of suspicious C-classes for quick lookup
        suspicious_c_class_map = {c['c_class']: c for c in suspicious_c_classes}
        processed_c_classes = set()
        aggregated_subnets = []

        # Helper function to calculate subnet aggregation
        def try_aggregate_subnet(first_octet, second_octet, third_octet_base, subnet_size, cidr_prefix):
            """
            Try to aggregate a subnet if ALL C-classes in the range are suspicious.
            subnet_size: number of /24 subnets in this range
            cidr_prefix: the CIDR notation (e.g., 20, 21, 22, 23)

            IMPORTANT: Only aggregate if EVERY C-class in the range exists in suspicious_c_class_map.
            This ensures no "holes" in the subnet (e.g., don't create /23 if only one /24 exists).
            """
            c_classes_in_range = []
            expected_c_classes = []

            for offset in range(subnet_size):
                third_octet = third_octet_base + offset
                if third_octet > 255:
                    break
                c_class = f"{first_octet}.{second_octet}.{third_octet}"
                expected_c_classes.append(c_class)

                if c_class in suspicious_c_class_map and c_class not in processed_c_classes:
                    c_classes_in_range.append(c_class)

            # Only aggregate if ALL expected C-classes are present (100% coverage required)
            # This prevents creating a /23 when only one /24 exists
            if len(c_classes_in_range) == len(expected_c_classes) and len(c_classes_in_range) > 0:
                # Calculate aggregated statistics
                total_traffic = sum(suspicious_c_class_map[c]['total_traffic'] for c in c_classes_in_range)
                total_static = sum(suspicious_c_class_map[c]['static_count'] for c in c_classes_in_range)
                total_dynamic = sum(suspicious_c_class_map[c]['dynamic_count'] for c in c_classes_in_range)
                total_ips = total_static + total_dynamic
                ratio = total_dynamic / total_static if total_static > 0 else 0

                aggregated_subnets.append({
                    'subnet': f"{first_octet}.{second_octet}.{third_octet_base}.0/{cidr_prefix}",
                    'static_count': total_static,
                    'dynamic_count': total_dynamic,
                    'total_count': total_ips,
                    'ratio': ratio,
                    'total_traffic': total_traffic,
                    'c_class_count': len(c_classes_in_range)
                })

                # Mark these C-classes as processed
                for c_class in c_classes_in_range:
                    processed_c_classes.add(c_class)

                return True
            return False

        # Group suspicious C-classes by first two octets (B-class)
        grouped_by_b_class = set()
        for c_class in suspicious_c_class_map.keys():
            parts = c_class.split('.')
            b_class = f"{parts[0]}.{parts[1]}"
            grouped_by_b_class.add(b_class)

        # Process each B-class range
        for b_class in grouped_by_b_class:
            parts = b_class.split('.')
            first_octet = parts[0]
            second_octet = parts[1]

            # Try to aggregate in order: /20, /21, /22, /23
            # /20: covers 16 C-classes (0-15, 16-31, 32-47, ...)
            for base in range(0, 256, 16):
                try_aggregate_subnet(first_octet, second_octet, base, 16, 20)

            # /21: covers 8 C-classes (0-7, 8-15, 16-23, ...)
            for base in range(0, 256, 8):
                try_aggregate_subnet(first_octet, second_octet, base, 8, 21)

            # /22: covers 4 C-classes (0-3, 4-7, 8-11, ...)
            for base in range(0, 256, 4):
                try_aggregate_subnet(first_octet, second_octet, base, 4, 22)

            # /23: covers 2 C-classes (0-1, 2-3, 4-5, ...)
            for base in range(0, 256, 2):
                try_aggregate_subnet(first_octet, second_octet, base, 2, 23)

        # Add remaining suspicious C-classes that weren't aggregated
        c_class_entries = []
        for c_data in suspicious_c_classes:
            if c_data['c_class'] not in processed_c_classes:
                c_class_entries.append({
                    'subnet': f"{c_data['c_class']}.0/24",
                    'static_count': c_data['static_count'],
                    'dynamic_count': c_data['dynamic_count'],
                    'total_count': c_data['total_count'],
                    'ratio': c_data['ratio'],
                    'total_traffic': c_data['total_traffic'],
                    'c_class_count': 1
                })

        # Combine aggregated and C-class entries, sort by IP address (not traffic)
        all_subnet_entries = aggregated_subnets + c_class_entries

        # Sort by IP address numerically
        def subnet_sort_key(entry):
            # Extract IP from subnet (e.g., "116.16.0.0/24" -> [116, 16, 0, 0])
            subnet_str = entry['subnet'].split('/')[0]  # Remove CIDR mask
            parts = subnet_str.split('.')
            return tuple(int(p) for p in parts)

        all_subnet_entries.sort(key=subnet_sort_key)

        # Sort individual IPs by traffic (highest first)
        individual_ips.sort(key=lambda x: x['traffic'], reverse=True)

        # Format output
        output_lines = []

        # Section 1: Suspicious subnets
        if all_subnet_entries:
            output_lines.append("# === Suspicious IP Ranges (mostly static, few dynamic) ===")
            output_lines.append("# Format: Subnet    Traffic(MB)    Total_IPs    Static_IPs    Dynamic_IPs    Ratio    C-Classes")

            for entry in all_subnet_entries:
                traffic_mb = entry['total_traffic'] / (1024 * 1024)
                subnet_str = entry['subnet']
                output_lines.append(
                    f"{subnet_str:<20} {traffic_mb:>10.2f} MB    "
                    f"{entry['total_count']:>4} IPs    "
                    f"{entry['static_count']:>4} static    "
                    f"{entry['dynamic_count']:>4} dynamic    "
                    f"{entry['ratio']:>6.3f}    "
                    f"{entry['c_class_count']:>2} C-classes"
                )
            output_lines.append("")

        # Section 2: Individual IPs
        if individual_ips:
            output_lines.append("# === Individual IPs (not in suspicious ranges) ===")
            output_lines.append("# Format: IP_Address    Traffic(MB)")

            current_tier_mb = None
            for ip_info in individual_ips:
                traffic_mb = ip_info['traffic'] / (1024 * 1024)

                # Add tier markers
                if traffic_mb >= 100:
                    tier_mb = (int(traffic_mb) // 100) * 100
                else:
                    tier_mb = (int(traffic_mb) // 10) * 10

                if tier_mb != current_tier_mb:
                    if current_tier_mb is not None:
                        output_lines.append("")
                    output_lines.append(f"# Traffic >= {tier_mb} MB")
                    current_tier_mb = tier_mb

                output_lines.append(f"{ip_info['ip']:<20} {traffic_mb:>10.2f} MB")

        return jsonify({
            'analysis_lines': output_lines,
            'suspicious_subnet_count': len(all_subnet_entries),
            'individual_ip_count': len(individual_ips),
            'total_entries': len(all_subnet_entries) + len(individual_ips),
            'min_traffic_mb': min_traffic_mb
        })

    except Exception as e:
        import traceback
        print(f"Error in IP range analysis: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip-logs/<ip>', methods=['GET'])
def get_ip_logs(ip):
    """Get all log entries for a specific IP address"""
    try:
        limit = request.args.get('limit', 100, type=int)  # Default to 100 logs

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Get total count
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM log_entries
            WHERE ip = %s
        """, (ip,))
        total_count = cursor.fetchone()['total']

        # Get log entries (most recent first)
        cursor.execute("""
            SELECT
                timestamp,
                method,
                url,
                status_code,
                response_time,
                response_size,
                is_dynamic,
                cache_status,
                user_agent
            FROM log_entries
            WHERE ip = %s
            ORDER BY timestamp DESC
            LIMIT %s
        """, (ip, limit))

        logs = cursor.fetchall()
        cursor.close()
        release_db_connection(conn)

        return jsonify({
            'ip': ip,
            'total_requests': total_count,
            'logs': [dict(log) for log in logs]
        })

    except Exception as e:
        import traceback
        print(f"Error getting IP logs: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip-statistics', methods=['GET'])
def get_ip_statistics():
    """Get IP statistics by prefix"""
    try:
        prefix = request.args.get('prefix', '')
        if not prefix:
            return jsonify({'error': 'Prefix parameter is required'}), 400

        dynamic_only = request.args.get('dynamic_only', 'false').lower() == 'true'

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Build WHERE clause based on filters
        where_conditions = ["ip LIKE %s"]
        params = [f"{prefix}%"]

        if dynamic_only:
            where_conditions.append("dynamic_requests > 0")

        where_clause = " AND ".join(where_conditions)

        # Query with LIKE pattern, excluding requests_per_minute and updated_at
        query = f"""
            SELECT
                ip,
                total_requests,
                total_bytes_sent,
                total_response_size,
                unique_urls,
                unique_user_agents,
                static_requests,
                dynamic_requests,
                is_static_only,
                first_seen,
                last_seen
            FROM ip_statistics
            WHERE {where_clause}
            ORDER BY total_response_size DESC
            LIMIT 5000
        """

        cursor.execute(query, params)

        statistics = cursor.fetchall()
        cursor.close()
        release_db_connection(conn)

        return jsonify({
            'prefix': prefix,
            'dynamic_only': dynamic_only,
            'count': len(statistics),
            'statistics': [dict(stat) for stat in statistics]
        })

    except Exception as e:
        import traceback
        print(f"Error getting IP statistics: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/geo-location-by-ip', methods=['GET'])
def get_geo_location_by_ip():
    """Get geo location for an IP address using C-class subnet lookup"""
    ip = request.args.get('ip', '')

    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    # Convert IP to C-class subnet
    parts = ip.split('.')
    if len(parts) < 3:
        return jsonify({'error': 'Invalid IP address format'}), 400

    c_class = f"{parts[0]}.{parts[1]}.{parts[2]}"

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Check if C-class subnet exists in geo_location table
        cursor.execute("""
            SELECT c_class_subnet, country, region, city, isp, org, as_info, last_updated
            FROM geo_location
            WHERE c_class_subnet = %s
        """, (c_class,))

        result = cursor.fetchone()

        if result:
            return jsonify({
                'ip': ip,
                'c_class_subnet': result['c_class_subnet'],
                'country': result['country'],
                'region': result['region'],
                'city': result['city'],
                'isp': result['isp'],
                'org': result['org'],
                'as_info': result['as_info'],
                'last_updated': result['last_updated'].isoformat() if result['last_updated'] else None,
                'cached': True
            })
        else:
            # Not found in database, fetch from external API
            import urllib.request

            try:
                url = f'http://ip-api.com/json/{ip}'
                with urllib.request.urlopen(url, timeout=5) as response:
                    data = json.loads(response.read().decode())

                    if data.get('status') == 'fail':
                        return jsonify({'error': data.get('message', 'Failed to fetch geo location')}), 500

                    # Combine AS info
                    as_info = f"{data.get('as', '')} {data.get('asname', '')}".strip()

                    # Insert into geo_location table with C-class subnet
                    cursor.execute("""
                        INSERT INTO geo_location (c_class_subnet, country, region, city, isp, org, as_info)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (c_class_subnet) DO UPDATE SET
                            country = EXCLUDED.country,
                            region = EXCLUDED.region,
                            city = EXCLUDED.city,
                            isp = EXCLUDED.isp,
                            org = EXCLUDED.org,
                            as_info = EXCLUDED.as_info,
                            last_updated = CURRENT_TIMESTAMP
                    """, (
                        c_class,
                        data.get('country', ''),
                        data.get('regionName', ''),
                        data.get('city', ''),
                        data.get('isp', ''),
                        data.get('org', ''),
                        as_info
                    ))
                    conn.commit()

                    return jsonify({
                        'ip': ip,
                        'c_class_subnet': c_class,
                        'country': data.get('country', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'isp': data.get('isp', ''),
                        'org': data.get('org', ''),
                        'as_info': as_info,
                        'cached': False
                    })
            except Exception as e:
                return jsonify({'error': f'External API request failed: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        release_db_connection(conn)

if __name__ == '__main__':
    # Initialize database
    init_db()
    print(f"Starting CDN Log Analyzer...")
    print(f"Database: {DB_NAME}")
    print(f"Server: http://0.0.0.0:{APP_PORT}")
    app.run(debug=True, host='0.0.0.0', port=APP_PORT)