# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CDN Log Analyzer is a Flask web application that analyzes CDN access logs from gzipped files and provides interactive visualizations of traffic patterns, suspicious behavior, and performance metrics.

## Commands

### Running the Application
```bash
python3 app.py
```
The app runs on `http://0.0.0.0:8080` by default.

### Installing Dependencies
```bash
pip install -r requirements.txt
```

## Architecture

### Core Components

**LogAnalyzer Class** (`app.py:38-765`)
- Main analysis engine that processes `.gz` log files
- Log format: Custom CDN format with timestamp, IP, response time, HTTP method/URL, status codes, bytes sent, cache status, user agent, content type, and original IP
- Regex pattern at `app.py:41-47` defines the log parsing structure

**Log Processing Pipeline**
1. `process_directory()` - Reads all `.gz` files from a directory
2. `parse_log_line()` - Parses individual log lines into `LogEntry` dataclass
3. `generate_analysis()` - Runs multiple analysis steps in sequence

**Analysis Functions**
- `analyze_traffic_by_ip()` - Traffic consumption by IP (top 50 by bytes_sent)
- `analyze_traffic_by_url()` - Traffic consumption by URL (top 50)
- `analyze_hourly_traffic()` - 24-hour traffic patterns
- `analyze_user_behavior()` - Bounce rate, session duration
- `analyze_static_vs_dynamic_traffic()` - Categorizes IPs by content access patterns
  - Dynamic content includes: `/api/`, `/chess/`, `/homework/` (see `app.py:609-613`)
- `detect_suspicious_patterns()` - Bot detection via request intervals and high-frequency patterns
- `analyze_performance()` - Response times, cache hit ratios, status codes

### API Endpoints

**`/api/analyze/progress` (GET)** - Main analysis endpoint with Server-Sent Events (SSE) for real-time progress tracking
- Progress phases: File processing (0-85%), Analysis (85-100%)
- Stores results in global `global_log_entries` for subsequent queries

**`/api/ip-details` (POST)** - Returns detailed request history for a specific IP
- Requires prior analysis to populate `global_log_entries`

**`/api/ip-geolocation` (POST)** - Fetches geolocation data using ip-api.com

**`/api/static-only-ips` (GET)** - Generates blacklist of IPs that only access static content
- Automatically converts to CIDR `/24` notation when 4+ IPs from same subnet are static-only
- Safety check via `is_subnet_safe_to_block()` ensures no dynamic-accessing IPs are blocked

### Frontend
- Single-page application in `templates/index.html`
- Uses Chart.js for visualizations and Tailwind CSS for styling
- Connects to SSE endpoint for real-time progress updates

## Important Implementation Details

### Static vs Dynamic Content Classification
The application distinguishes between static and dynamic content to identify bot traffic:
- **Dynamic**: URLs containing `/api/`, `/chess/`, `/homework/` (app.py:609-613)
- **Static**: Everything else (CSS, JS, images, etc.)

IPs accessing only static content are flagged as potential bots.

### Subnet Blocking Logic
When generating blacklists (`/api/static-only-ips`):
1. Groups static-only IPs by Class C subnet (first 3 octets)
2. If 4+ IPs from same subnet AND all IPs in that subnet are static-only → use `/24` CIDR notation
3. Otherwise, list individual IPs
4. Safety function: `is_subnet_safe_to_block()` (app.py:1039-1068)

### Progress Tracking
The analyzer uses SSE to stream progress:
- Updates every 1000 log lines during file processing
- Provides estimated remaining time based on processing speed
- Tracks current file, file count, and analysis step

### Global State
`global_log_entries` (app.py:768) stores all parsed log entries in memory after analysis to support detail queries. This means:
- Memory usage scales with log file size
- IP details and blacklist generation require prior analysis
- Data persists only for the current server instance
