# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CDN Log Analyzer is a Flask web application that analyzes CDN access logs from gzipped files and provides interactive visualizations of traffic patterns, suspicious behavior, and performance metrics.

## Commands

### Prerequisites
Ensure PostgreSQL is running on `127.0.0.1:5432` with:
- Username: `postgres`
- Password: `postgres`

Databases will be created automatically on first run:
- Default: `cdn_logs`
- For other sites, specify via `CDN_DB_NAME` environment variable

### Installing Dependencies
```bash
pip3 install -r requirements.txt
```

### Running the Application

**Single Site (Default)**
```bash
python3 app.py
```
The app runs on `http://0.0.0.0:8080` by default with database `cdn_logs`. Database tables are initialized automatically on startup.

**Multiple Sites (Different Databases)**

To analyze logs from different sites simultaneously, run multiple instances with different databases and ports:

```bash
# Site A (default)
python3 app.py

# Site B (in a new terminal)
CDN_DB_NAME=cdn_logs_2 PORT=8081 python3 app.py

# Site C (in another terminal)
CDN_DB_NAME=cdn_logs_3 PORT=8082 python3 app.py
```

**Environment Variables:**
- `CDN_DB_NAME` - Database name (default: `cdn_logs`)
- `PORT` - Web server port (default: `8080`)

Each instance will:
- Create and use its own database
- Run on its own port
- Maintain separate log data and statistics

Access the instances at:
- Site A: `http://localhost:8080`
- Site B: `http://localhost:8081`
- Site C: `http://localhost:8082`

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

### Database Architecture

**PostgreSQL Database: `cdn_logs` (configurable via `CDN_DB_NAME`)**

Two main tables:

1. **`log_entries`** - Stores all individual CDN log entries
   - Indexed on `ip` and `timestamp` for fast queries
   - Contains: timestamp, IP, response_time, method, URL, status codes, bytes_sent, cache_status, user_agent, etc.

2. **`ip_statistics`** - Pre-aggregated IP statistics for faster analysis
   - Primary key: `ip`
   - Calculated fields: total_requests, total_bytes_sent, unique_urls, unique_user_agents
   - Static vs dynamic classification: `static_requests`, `dynamic_requests`, `is_static_only`
   - Time tracking: `first_seen`, `last_seen`, `requests_per_minute`
   - Updated via `calculate_and_store_ip_statistics()` after log import

**Log Processing Flow:**
1. Parse `.gz` files line by line
2. Batch insert to `log_entries` (1000 records at a time)
3. Calculate and store IP statistics in `ip_statistics` table
4. Run analysis queries against database tables

**Benefits:**
- Handles large datasets (7+ days of logs) without memory issues
- Persistent storage - data survives server restarts
- Fast queries via indexes and pre-aggregated statistics
- IP details fetched on-demand from database

**API Endpoints Using Database:**
- `/api/db-stats` - Returns total logs count and time range
- `/api/ip-details` - Queries log_entries for specific IP
- `/api/static-only-ips` - Reads from ip_statistics table
- All analysis functions read from database instead of memory
