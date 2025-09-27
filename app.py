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

from flask import Flask, render_template, request, jsonify, Response

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
        self.progress_callback = None

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
        """Compute basic statistics efficiently"""
        total_requests = len(self.entries)

        # Use set comprehension for unique IPs (more efficient than generator)
        unique_ips = len({entry.ip for entry in self.entries})

        # Get time range efficiently
        timestamps = [entry.timestamp for entry in self.entries]

        return {
            'total_requests': total_requests,
            'unique_ips': unique_ips,
            'time_range': {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat()
            }
        }

    def analyze_traffic_by_ip(self) -> List[Dict]:
        """Analyze traffic consumption by IP address - optimized version"""
        ip_stats = {}

        for entry in self.entries:
            ip = entry.ip
            if ip not in ip_stats:
                ip_stats[ip] = {
                    'requests': 0,
                    'bytes_sent': 0,
                    'unique_urls': set(),
                    'user_agents': set(),
                    'timestamps': []
                }

            stats = ip_stats[ip]
            stats['requests'] += 1
            stats['bytes_sent'] += entry.bytes_sent
            stats['unique_urls'].add(entry.url)
            stats['user_agents'].add(entry.user_agent)
            stats['timestamps'].append(entry.timestamp)

        # Convert to list and calculate derived metrics
        result = []
        for ip, stats in ip_stats.items():
            timestamps = stats['timestamps']
            if len(timestamps) > 1:
                duration_seconds = (max(timestamps) - min(timestamps)).total_seconds()
                duration_minutes = duration_seconds / 60
                requests_per_minute = stats['requests'] / max(1, duration_minutes)
            else:
                duration_minutes = 0
                requests_per_minute = 0

            result.append({
                'ip': ip,
                'requests': stats['requests'],
                'bytes_sent': stats['bytes_sent'],
                'unique_urls': len(stats['unique_urls']),
                'unique_user_agents': len(stats['user_agents']),
                'duration_minutes': duration_minutes,
                'requests_per_minute': requests_per_minute
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

            for i, filename in enumerate(gz_files):
                filepath = os.path.join(directory_path, filename)

                # Send file start progress (file processing takes 85% of total progress)
                file_progress = (i / total_files) * 0.85 if total_files > 0 else 0
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
                            analyzer_instance.entries.append(entry)
                        line_count += 1

                        # Send progress every 1000 lines
                        if line_count % 1000 == 0:
                            # Mid-file progress: current file + 50% progress within current file
                            file_progress = ((i + 0.5) / total_files) * 0.85 if total_files > 0 else 0.425
                            progress_data = {
                                'progress': min(file_progress, 0.85),  # Cap at 85% for file processing
                                'message': f'Processing file {i + 1} of {total_files} ({line_count:,} lines processed)',
                                'current_file_index': i + 1,
                                'total_files': total_files,
                                'current_file': filename,
                                'estimated_remaining_seconds': analyzer_instance._calculate_remaining_time(i, total_files, start_time)
                            }
                            yield progress_callback(progress_data)

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

            # Store entries globally for IP details lookup
            global global_log_entries
            global_log_entries = analyzer_instance.entries.copy()

            # Run analysis with progress tracking (step by step)
            analysis_steps = [
                ("Computing basic statistics", analyzer_instance._compute_basic_stats),
                ("Analyzing traffic by IP", analyzer_instance.analyze_traffic_by_ip),
                ("Analyzing traffic by URL", analyzer_instance.analyze_traffic_by_url),
                ("Analyzing hourly traffic patterns", analyzer_instance.analyze_hourly_traffic),
                ("Analyzing user behavior", analyzer_instance.analyze_user_behavior),
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

@app.route('/api/ip-details', methods=['POST'])
def get_ip_details():
    ip = request.json.get('ip')

    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    try:
        global global_log_entries

        if not global_log_entries:
            return jsonify({'error': 'No log data available. Please run analysis first.'}), 400

        # Filter entries for the specified IP and sort by timestamp
        ip_entries = [
            {
                'timestamp': entry.timestamp.isoformat(),
                'method': entry.method,
                'url': entry.url,
                'status_code': entry.status_code,
                'response_time': entry.response_time,
                'bytes_sent': entry.bytes_sent,
                'user_agent': entry.user_agent,
                'cache_status': entry.cache_status
            }
            for entry in global_log_entries
            if entry.ip == ip
        ]

        # Sort by timestamp (ascending - oldest first)
        ip_entries.sort(key=lambda x: x['timestamp'])

        return jsonify({
            'ip': ip,
            'requests': ip_entries,
            'count': len(ip_entries)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)