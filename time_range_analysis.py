"""Time-range specific analysis methods for LogAnalyzer"""

from psycopg2.extras import RealDictCursor
from typing import Dict, Any, List
import time

# Global reference to connection functions - will be set when methods are imported
_get_db_connection = None
_release_db_connection = None

def _ensure_db_functions(self):
    """Ensure database connection functions are available"""
    global _get_db_connection, _release_db_connection
    if _get_db_connection is None:
        import inspect
        main_module = inspect.getmodule(self.__class__)
        _get_db_connection = main_module.get_db_connection
        _release_db_connection = main_module.release_db_connection

def calculate_ip_statistics_for_range(self, start_time: str, end_time: str):
    """Calculate IP statistics for a specific time range"""
    _ensure_db_functions(self)
    
    print(f"Calculating IP statistics for range: {start_time} to {end_time}")
    start = time.time()

    conn = _get_db_connection()
    conn.set_session(autocommit=False)
    cursor = conn.cursor()

    try:
        cursor.execute("SET statement_timeout = '600000'")
        cursor.execute("TRUNCATE TABLE ip_statistics")
        conn.commit()

        cursor.execute("""
            INSERT INTO ip_statistics (
                ip, total_requests, total_bytes_sent, unique_urls, unique_user_agents,
                static_requests, dynamic_requests, is_static_only,
                first_seen, last_seen, requests_per_minute
            )
            SELECT
                ip,
                COUNT(*) as total_requests,
                SUM(bytes_sent) as total_bytes_sent,
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
            WHERE timestamp >= %s AND timestamp <= %s
            GROUP BY ip
        """, (start_time, end_time))

        conn.commit()
        elapsed = time.time() - start
        print(f"IP statistics for range calculated in {elapsed:.2f} seconds")

    except Exception as e:
        print(f"Error calculating IP statistics for range: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        _release_db_connection(conn)

def _compute_basic_stats_for_range(self, start_time: str, end_time: str) -> Dict[str, Any]:
    """Compute basic statistics for a time range"""
    _ensure_db_functions(self)

    conn = _get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            COUNT(*) as total_requests,
            COUNT(DISTINCT ip) as unique_ips,
            MIN(timestamp) as start_time,
            MAX(timestamp) as end_time
        FROM log_entries
        WHERE timestamp >= %s AND timestamp <= %s
    """, (start_time, end_time))

    row = cursor.fetchone()
    cursor.close()
    _release_db_connection(conn)

    return {
        'total_requests': row[0] if row[0] else 0,
        'unique_ips': row[1] if row[1] else 0,
        'time_range': {
            'start': row[2].isoformat() if row[2] else '',
            'end': row[3].isoformat() if row[3] else ''
        }
    }

def analyze_traffic_by_url_for_range(self, start_time: str, end_time: str) -> List[Dict]:
    """Analyze traffic by URL for a time range"""
    _ensure_db_functions(self)
    from urllib.parse import urlparse

    conn = _get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("""
        SELECT
            url,
            COUNT(*) as requests,
            SUM(bytes_sent) as bytes_sent,
            COUNT(DISTINCT ip) as unique_ips,
            AVG(response_time) as avg_response_time
        FROM log_entries
        WHERE timestamp >= %s AND timestamp <= %s
        GROUP BY url
        ORDER BY SUM(bytes_sent) DESC
        LIMIT 50
    """, (start_time, end_time))

    results = cursor.fetchall()
    cursor.close()
    _release_db_connection(conn)

    return [
        {
            **dict(row),
            'path': urlparse(row['url']).path
        }
        for row in results
    ]

def analyze_hourly_traffic_for_range(self, start_time: str, end_time: str) -> Dict[str, Any]:
    """Analyze hourly traffic patterns for a time range"""
    _ensure_db_functions(self)

    conn = _get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("""
        SELECT
            EXTRACT(HOUR FROM timestamp) as hour,
            COUNT(*) as requests,
            SUM(bytes_sent) as bytes_sent,
            COUNT(DISTINCT ip) as unique_ips
        FROM log_entries
        WHERE timestamp >= %s AND timestamp <= %s
        GROUP BY EXTRACT(HOUR FROM timestamp)
        ORDER BY hour
    """, (start_time, end_time))

    hourly_data_dict = {int(row['hour']): dict(row) for row in cursor.fetchall()}

    # Fill in missing hours with zeros
    hourly_data = []
    for hour in range(24):
        if hour in hourly_data_dict:
            hourly_data.append(hourly_data_dict[hour])
        else:
            hourly_data.append({
                'hour': hour,
                'requests': 0,
                'bytes_sent': 0,
                'unique_ips': 0
            })

    cursor.close()
    _release_db_connection(conn)

    peak_hour = max(hourly_data, key=lambda x: x['requests'])['hour'] if hourly_data else 0

    return {
        'hourly_data': hourly_data,
        'peak_hour': peak_hour
    }

def analyze_user_behavior_for_range(self, start_time: str, end_time: str) -> Dict[str, Any]:
    """Analyze user behavior for a time range"""
    _ensure_db_functions(self)
    from collections import defaultdict
    import statistics

    conn = _get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("""
        SELECT ip, url, timestamp
        FROM log_entries
        WHERE timestamp >= %s AND timestamp <= %s
        ORDER BY ip, timestamp
    """, (start_time, end_time))

    user_sessions = defaultdict(lambda: {'urls': set(), 'timestamps': []})

    for row in cursor.fetchall():
        user_sessions[row['ip']]['urls'].add(row['url'])
        user_sessions[row['ip']]['timestamps'].append(row['timestamp'])

    cursor.close()
    _release_db_connection(conn)

    bounce_count = sum(1 for session in user_sessions.values() if len(session['urls']) == 1)

    session_durations = []
    for session in user_sessions.values():
        if len(session['timestamps']) > 1:
            duration = (max(session['timestamps']) - min(session['timestamps'])).total_seconds()
            session_durations.append(duration)

    return {
        'bounce_rate': (bounce_count / len(user_sessions) * 100) if user_sessions else 0,
        'avg_session_duration_seconds': statistics.mean(session_durations) if session_durations else 0,
        'total_sessions': len(user_sessions),
        'single_request_sessions': bounce_count
    }

def detect_suspicious_patterns_for_range(self, start_time: str, end_time: str) -> Dict[str, Any]:
    """Detect suspicious patterns for a time range"""
    _ensure_db_functions(self)

    conn = _get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # High frequency IPs
    cursor.execute("""
        SELECT
            ip,
            COUNT(*) as requests,
            COUNT(DISTINCT url) as unique_urls,
            EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) / 60 as duration_minutes
        FROM log_entries
        WHERE timestamp >= %s AND timestamp <= %s
        GROUP BY ip
        HAVING COUNT(*) > 100 AND EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) / 60 > 0
        ORDER BY (COUNT(*) / (EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) / 60)) DESC
        LIMIT 20
    """, (start_time, end_time))

    high_frequency_ips = []
    for row in cursor.fetchall():
        rpm = row['requests'] / row['duration_minutes'] if row['duration_minutes'] > 0 else 0
        high_frequency_ips.append({
            'ip': row['ip'],
            'requests': row['requests'],
            'requests_per_minute': rpm,
            'unique_urls': row['unique_urls']
        })

    cursor.close()
    _release_db_connection(conn)

    return {
        'suspicious_ips': [],
        'high_frequency_ips': high_frequency_ips
    }

def analyze_performance_for_range(self, start_time: str, end_time: str) -> Dict[str, Any]:
    """Analyze performance metrics for a time range"""
    _ensure_db_functions(self)

    conn = _get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("""
        SELECT
            AVG(response_time) as avg_response_time,
            PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY response_time) as median_response_time,
            MAX(response_time) as max_response_time
        FROM log_entries
        WHERE timestamp >= %s AND timestamp <= %s
    """, (start_time, end_time))

    perf_row = cursor.fetchone()

    cursor.execute("""
        SELECT status_code, COUNT(*) as count
        FROM log_entries
        WHERE timestamp >= %s AND timestamp <= %s
        GROUP BY status_code
    """, (start_time, end_time))

    status_codes = {row['status_code']: row['count'] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT cache_status, COUNT(*) as count
        FROM log_entries
        WHERE timestamp >= %s AND timestamp <= %s
        GROUP BY cache_status
    """, (start_time, end_time))

    cache_status = {row['cache_status']: row['count'] for row in cursor.fetchall()}
    total_cache = sum(cache_status.values())

    cursor.close()
    _release_db_connection(conn)

    return {
        'avg_response_time': float(perf_row['avg_response_time']) if perf_row['avg_response_time'] else 0,
        'median_response_time': float(perf_row['median_response_time']) if perf_row['median_response_time'] else 0,
        'max_response_time': perf_row['max_response_time'] if perf_row['max_response_time'] else 0,
        'status_codes': status_codes,
        'cache_hit_ratio': (cache_status.get('HIT', 0) / total_cache * 100) if total_cache > 0 else 0,
        'cache_status_distribution': cache_status
    }

def analyze_static_vs_dynamic_traffic_for_range(self) -> Dict[str, Any]:
    """Analyze IPs that only access static content vs those accessing dynamic APIs - from ip_statistics table (already filtered for range)"""
    _ensure_db_functions(self)

    conn = _get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # Get total traffic from ip_statistics (already filtered by time range)
    cursor.execute("SELECT SUM(total_bytes_sent) as total FROM ip_statistics")
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
    _release_db_connection(conn)

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
