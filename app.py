#!/usr/bin/env python3
"""
CDN Log Analyzer - Web Application for analyzing CDN access logs
Processes .gz log files and provides interactive visualizations
"""

import os
import gzip
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from urllib.parse import urlparse
import json
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import statistics

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@dataclass
class LogEntry:
    timestamp: datetime
    ip: str
    response_time: int
    method: str
    url: str
    status_code: int
    response_size: int
    bytes_sent: int
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
            response_size=int(match.group(7)),
            bytes_sent=int(match.group(8)),
            cache_status=match.group(9),
            user_agent=match.group(10),
            content_type=match.group(11),
            original_ip=match.group(12)
        )

    def process_directory(self, directory_path: str) -> Dict[str, Any]:
        """Process all .gz files in directory and return analysis results"""
        self.entries = []

        gz_files = [f for f in os.listdir(directory_path) if f.endswith('.gz')]
        gz_files.sort()

        for filename in gz_files:
            filepath = os.path.join(directory_path, filename)
            with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self.parse_log_line(line)
                    if entry:
                        self.entries.append(entry)

        return self.generate_analysis()

    def generate_analysis(self) -> Dict[str, Any]:
        """Generate comprehensive analysis of log entries"""
        if not self.entries:
            return {}

        # Basic statistics
        total_requests = len(self.entries)
        unique_ips = len(set(entry.ip for entry in self.entries))

        # Traffic analysis
        traffic_by_ip = self.analyze_traffic_by_ip()
        traffic_by_url = self.analyze_traffic_by_url()
        hourly_traffic = self.analyze_hourly_traffic()

        # Behavioral patterns
        user_behavior = self.analyze_user_behavior()
        suspicious_patterns = self.detect_suspicious_patterns()

        # Performance analysis
        performance_stats = self.analyze_performance()

        return {
            'basic_stats': {
                'total_requests': total_requests,
                'unique_ips': unique_ips,
                'time_range': {
                    'start': min(entry.timestamp for entry in self.entries).isoformat(),
                    'end': max(entry.timestamp for entry in self.entries).isoformat()
                }
            },
            'traffic_by_ip': traffic_by_ip,
            'traffic_by_url': traffic_by_url,
            'hourly_traffic': hourly_traffic,
            'user_behavior': user_behavior,
            'suspicious_patterns': suspicious_patterns,
            'performance_stats': performance_stats
        }

    def analyze_traffic_by_ip(self) -> List[Dict]:
        """Analyze traffic consumption by IP address"""
        ip_stats = defaultdict(lambda: {
            'requests': 0,
            'bytes_sent': 0,
            'unique_urls': set(),
            'user_agents': set(),
            'first_seen': None,
            'last_seen': None
        })

        for entry in self.entries:
            stats = ip_stats[entry.ip]
            stats['requests'] += 1
            stats['bytes_sent'] += entry.bytes_sent
            stats['unique_urls'].add(entry.url)
            stats['user_agents'].add(entry.user_agent)

            if stats['first_seen'] is None or entry.timestamp < stats['first_seen']:
                stats['first_seen'] = entry.timestamp
            if stats['last_seen'] is None or entry.timestamp > stats['last_seen']:
                stats['last_seen'] = entry.timestamp

        # Convert to list and sort by bytes sent
        result = []
        for ip, stats in ip_stats.items():
            result.append({
                'ip': ip,
                'requests': stats['requests'],
                'bytes_sent': stats['bytes_sent'],
                'unique_urls': len(stats['unique_urls']),
                'unique_user_agents': len(stats['user_agents']),
                'duration_minutes': (stats['last_seen'] - stats['first_seen']).total_seconds() / 60,
                'requests_per_minute': stats['requests'] / max(1, (stats['last_seen'] - stats['first_seen']).total_seconds() / 60)
            })

        return sorted(result, key=lambda x: x['bytes_sent'], reverse=True)[:50]

    def analyze_traffic_by_url(self) -> List[Dict]:
        """Analyze traffic consumption by URL"""
        url_stats = defaultdict(lambda: {
            'requests': 0,
            'bytes_sent': 0,
            'unique_ips': set(),
            'avg_response_time': []
        })

        for entry in self.entries:
            stats = url_stats[entry.url]
            stats['requests'] += 1
            stats['bytes_sent'] += entry.bytes_sent
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
            hourly_bytes[hour] += entry.bytes_sent
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

    def detect_suspicious_patterns(self) -> Dict[str, Any]:
        """Detect suspicious or unusual patterns"""
        suspicious_ips = []
        high_frequency_ips = []

        # Analyze request patterns by IP
        ip_patterns = defaultdict(lambda: {
            'requests': 0,
            'timespan_minutes': 0,
            'unique_urls': set(),
            'status_codes': [],
            'regular_intervals': []
        })

        for entry in self.entries:
            pattern = ip_patterns[entry.ip]
            pattern['requests'] += 1
            pattern['unique_urls'].add(entry.url)
            pattern['status_codes'].append(entry.status_code)

        # Calculate time patterns
        for ip in ip_patterns:
            ip_entries = [e for e in self.entries if e.ip == ip]
            if len(ip_entries) > 1:
                ip_entries.sort(key=lambda x: x.timestamp)
                timespan = (ip_entries[-1].timestamp - ip_entries[0].timestamp).total_seconds() / 60
                ip_patterns[ip]['timespan_minutes'] = timespan

                # Check for regular intervals (potential bot behavior)
                intervals = []
                for i in range(1, len(ip_entries)):
                    interval = (ip_entries[i].timestamp - ip_entries[i-1].timestamp).total_seconds()
                    intervals.append(interval)

                if intervals:
                    avg_interval = statistics.mean(intervals)
                    interval_variance = statistics.variance(intervals) if len(intervals) > 1 else 0
                    ip_patterns[ip]['avg_interval'] = avg_interval
                    ip_patterns[ip]['interval_variance'] = interval_variance

        # Identify suspicious patterns
        for ip, pattern in ip_patterns.items():
            requests_per_minute = pattern['requests'] / max(1, pattern['timespan_minutes'])

            # High frequency requests
            if requests_per_minute > 10:
                high_frequency_ips.append({
                    'ip': ip,
                    'requests': pattern['requests'],
                    'requests_per_minute': requests_per_minute,
                    'unique_urls': len(pattern['unique_urls'])
                })

            # Regular interval requests (potential bot)
            if ('avg_interval' in pattern and pattern['avg_interval'] < 60 and
                pattern['interval_variance'] < 100 and pattern['requests'] > 20):
                suspicious_ips.append({
                    'ip': ip,
                    'requests': pattern['requests'],
                    'avg_interval_seconds': pattern['avg_interval'],
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)