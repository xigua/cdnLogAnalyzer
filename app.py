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

# Database configuration
DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5432,
    'user': 'postgres',
    'password': 'postgres',
    'database': 'cdn_logs'
}

# Connection pool
db_pool = None

def init_db():
    """Initialize database and create tables"""
    global db_pool

    # First connect to default postgres database to create cdn_logs database
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
    cursor.execute("SELECT 1 FROM pg_database WHERE datname = 'cdn_logs'")
    if not cursor.fetchone():
        cursor.execute("CREATE DATABASE cdn_logs")
        print("Database 'cdn_logs' created successfully")

    cursor.close()
    conn.close()

    # Now connect to cdn_logs database
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

    conn.commit()
    cursor.close()
    db_pool.putconn(conn)

    print("Database tables initialized successfully")

def get_db_connection():
    """Get a connection from the pool"""
    return db_pool.getconn()

def release_db_connection(conn):
    """Release a connection back to the pool"""
    db_pool.putconn(conn)

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
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] '
            r'(\d+\.\d+\.\d+\.\d+) - '
            r'(\d+) "-" "([A-Z]+) ([^"]+)" '
            r'(\d+) (\d+) (\d+) (\w+) '
            r'"([^"]*)" "([^"]*)" (\d+\.\d+\.\d+\.\d+)'
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

        return LogEntry(
            timestamp=timestamp,
            ip=match.group(2),
            response_time=int(match.group(3)),
            method=match.group(4),
            url=match.group(5),
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

        conn = get_db_connection()
        cursor = conn.cursor()

        # Prepare data for batch insert
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
        execute_batch(cursor, """
            INSERT INTO log_entries (
                timestamp, ip, response_time, method, url, status_code,
                request_size, response_size, cache_status, user_agent,
                content_type, original_ip, is_dynamic
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (timestamp, ip, url, status_code) DO NOTHING
        """, insert_data, page_size=500)

        conn.commit()
        cursor.close()
        release_db_connection(conn)

    def calculate_and_store_ip_statistics(self):
        """Calculate IP statistics from database and store in ip_statistics table"""
        print("Starting IP statistics calculation...")
        start_time = time.time()

        conn = get_db_connection()
        # Set statement timeout to 10 minutes
        conn.set_session(autocommit=False)
        cursor = conn.cursor()

        try:
            # Set statement timeout
            cursor.execute("SET statement_timeout = '600000'")  # 10 minutes

            # Clear existing IP statistics
            print("Truncating ip_statistics table...")
            cursor.execute("TRUNCATE TABLE ip_statistics")
            conn.commit()

            # Calculate IP statistics using optimized SQL aggregation with pre-computed is_dynamic
            print("Calculating IP statistics (this may take a few minutes for large datasets)...")
            cursor.execute("""
                INSERT INTO ip_statistics (
                    ip, total_requests, total_bytes_sent, unique_urls, unique_user_agents,
                    static_requests, dynamic_requests, is_static_only,
                    first_seen, last_seen, requests_per_minute
                )
                SELECT
                    ip,
                    COUNT(*) as total_requests,
                    SUM(response_size) as total_bytes_sent,
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
            elapsed = time.time() - start_time
            print(f"IP statistics calculation completed in {elapsed:.2f} seconds")

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
        cursor.execute("SELECT SUM(response_size) FROM log_entries")
        total_traffic = cursor.fetchone()[0] or 0

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
        # Send initial message
        yield f"data: {json.dumps({'status': 'started', 'message': 'Starting analysis...'})}\n\n"

        try:
            # Create analyzer instance for this request
            analyzer_instance = LogAnalyzer()

            # Define progress callback that yields progress updates
            def progress_callback(data):
                return f"data: {json.dumps(data)}\n\n"

            # Process directory with real-time progress updates
            gz_files = [f for f in os.listdir(directory_path) if f.endswith('.gz')]
            gz_files.sort()
            total_files = len(gz_files)
            start_time = time.time()
            analyzer_instance.entries = []

            # Send initial progress
            initial_data = {
                'progress': 0.0,
                'message': f'Found {total_files} .gz files to process',
                'current_file_index': 0,
                'total_files': total_files,
                'current_file': '',
                'estimated_remaining_seconds': 0
            }
            yield progress_callback(initial_data)

            # Batch processing buffer
            batch_buffer = []
            batch_size = 5000  # Increased batch size to reduce DB commits
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

                with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                    line_count = 0
                    for line in f:
                        entry = analyzer_instance.parse_log_line(line)
                        if entry:
                            batch_buffer.append(entry)
                        line_count += 1
                        total_lines_processed += 1

                        # Insert batch when buffer is full
                        if len(batch_buffer) >= batch_size:
                            # Send DB insert progress
                            progress_data = {
                                'progress': min(((i + 0.5) / total_files) * 0.7, 0.7),
                                'message': f'Inserting {len(batch_buffer)} entries to database...',
                                'current_file_index': i + 1,
                                'total_files': total_files,
                                'current_file': filename,
                                'estimated_remaining_seconds': analyzer_instance._calculate_remaining_time(i, total_files, start_time)
                            }
                            yield progress_callback(progress_data)

                            analyzer_instance.insert_entries_to_db(batch_buffer)
                            batch_buffer = []

                        # Send progress every 5000 lines
                        if line_count % 5000 == 0:
                            # Mid-file progress: current file + 50% progress within current file
                            file_progress = ((i + 0.5) / total_files) * 0.7 if total_files > 0 else 0.35
                            progress_data = {
                                'progress': min(file_progress, 0.7),  # Cap at 70% for file processing
                                'message': f'Processing file {i + 1} of {total_files} ({total_lines_processed:,} total lines)',
                                'current_file_index': i + 1,
                                'total_files': total_files,
                                'current_file': filename,
                                'estimated_remaining_seconds': analyzer_instance._calculate_remaining_time(i, total_files, start_time)
                            }
                            yield progress_callback(progress_data)

            # Insert remaining entries
            if batch_buffer:
                progress_data = {
                    'progress': 0.7,
                    'message': f'Inserting final {len(batch_buffer)} entries to database...',
                    'current_file_index': total_files,
                    'total_files': total_files,
                    'current_file': '',
                    'estimated_remaining_seconds': 5
                }
                yield progress_callback(progress_data)
                analyzer_instance.insert_entries_to_db(batch_buffer)
                batch_buffer = []

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
            analyzer_instance.calculate_and_store_ip_statistics()

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
            error_data = {
                'status': 'error',
                'message': f'Error: {str(e)}'
            }
            yield f"data: {json.dumps(error_data)}\n\n"

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

@app.route('/api/analyze-range', methods=['POST'])
def analyze_time_range():
    """Analyze logs within a specific time range with SSE progress"""
    import traceback

    data = request.json
    start_time = data.get('start_time')
    end_time = data.get('end_time')

    print(f"\n=== Analyze Range Request ===")
    print(f"Start time: {start_time}")
    print(f"End time: {end_time}")
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
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get all static-only IPs
        cursor.execute("""
            SELECT ip
            FROM ip_statistics
            WHERE is_static_only = TRUE
        """)

        static_only_ips = [row[0] for row in cursor.fetchall()]

        # Get all IP behaviors for safety check
        cursor.execute("""
            SELECT ip, dynamic_requests
            FROM ip_statistics
        """)

        ip_behaviors = {row[0]: {'dynamic_requests': row[1]} for row in cursor.fetchall()}

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

        # Convert to blacklist format with safety checks
        blacklist_entries = []
        for subnet, ips in subnet_groups.items():
            if len(ips) >= 4:
                # Safety check: ensure no IP in this subnet has accessed dynamic content
                subnet_is_safe = is_subnet_safe_to_block(subnet, ip_behaviors)

                if subnet_is_safe:
                    # Use CIDR notation for 4+ IPs in same C-class
                    blacklist_entries.append(f"{subnet}.0/24")
                else:
                    # Not safe to block entire subnet, add individual static-only IPs
                    blacklist_entries.extend(ips)
            else:
                # Add individual IPs
                blacklist_entries.extend(ips)

        # Sort entries (CIDR blocks first, then individual IPs)
        def sort_key(entry):
            if '/24' in entry:
                # CIDR block - sort by network address
                network = entry.replace('.0/24', '')
                return (0, tuple(int(part) for part in network.split('.')))
            else:
                # Individual IP
                return (1, tuple(int(part) for part in entry.split('.')))

        blacklist_entries.sort(key=sort_key)

        return jsonify({
            'static_only_ips': blacklist_entries,
            'count': len(blacklist_entries),
            'original_count': len(static_only_ips)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    print("Starting CDN Log Analyzer...")
    app.run(debug=True, host='0.0.0.0', port=8080)