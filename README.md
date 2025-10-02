# CDN Log Analyzer

A powerful web-based tool for analyzing CDN access logs with real-time processing and interactive visualizations.

## Features

### 📊 Comprehensive Traffic Analysis

**Traffic by IP Address**
- Identify top bandwidth consumers
- Track requests per IP with traffic consumption metrics
- Calculate requests per minute and session duration
- View unique URLs and user agents per IP

**Traffic by URL**
- Analyze most accessed resources
- Monitor bandwidth usage per URL
- Track unique visitors per endpoint
- Measure average response times

### 🕐 Temporal Analysis

**Hourly Traffic Patterns**
- 24-hour traffic distribution
- Peak hour identification
- Hourly bandwidth consumption
- Unique visitor tracking by hour

### 🤖 Bot Detection & Security

**Static vs Dynamic Traffic Analysis**
- Automatically categorize IPs by access patterns
- Identify IPs accessing only static content (potential bots)
- Separate legitimate users from scrapers/crawlers
- Traffic percentage breakdown by category

**Suspicious Pattern Detection**
- High-frequency request detection
- Regular interval request patterns (bot behavior)
- Requests per minute analysis
- Automated threat scoring

**IP Blacklist Generation**
- Export static-only IPs for blocking
- Smart CIDR /24 subnet grouping
- Safety checks to prevent blocking legitimate users
- Ready-to-use blacklist format

### 🔍 Deep IP Investigation

**Detailed IP Analysis**
- Complete request history per IP
- Timestamp-sorted request logs
- Total traffic consumption tracking
- User agent and cache status details

**IP Geolocation**
- Country, region, and city lookup
- ISP and organization information
- Proxy/hosting/mobile detection
- AS number and name identification

### 📈 Performance Metrics

**Response Time Analysis**
- Average, median, and maximum response times
- Performance distribution tracking
- Identify slow endpoints

**Cache Performance**
- Cache hit ratio calculation
- HIT/MISS/BYPASS distribution
- Cache effectiveness monitoring

**HTTP Status Codes**
- Status code distribution
- Error rate tracking
- Success vs failure analysis

### 👥 User Behavior Analytics

**Session Analysis**
- Bounce rate calculation
- Average session duration
- Single-page visit tracking
- User engagement metrics

### ⚡ Real-Time Processing

**Live Progress Tracking**
- File-by-file processing updates
- Estimated time remaining
- Current file and line count display
- Progress bar with percentage completion
- Elapsed time tracking

## Screenshots

### Main Dashboard
<!-- Screenshot: Main dashboard showing the directory input and analyze button -->

### Analysis Progress
<!-- Screenshot: Real-time progress tracking with file count and estimated time -->

### Traffic Overview
<!-- Screenshot: Basic statistics cards showing total requests, unique IPs, bounce rate, and avg response time -->

### Traffic by IP
<!-- Screenshot: Table showing top IPs by bandwidth consumption -->

### Traffic by URL
<!-- Screenshot: Chart/table showing most accessed URLs -->

### Hourly Traffic Patterns
<!-- Screenshot: Chart showing 24-hour traffic distribution -->

### Bot Detection Results
<!-- Screenshot: Static vs Dynamic traffic analysis with percentage breakdown -->

### Suspicious IP Detection
<!-- Screenshot: Table of high-frequency and suspicious IPs -->

### IP Details Modal
<!-- Screenshot: Detailed view of a single IP's request history -->

### Geolocation Results
<!-- Screenshot: IP geolocation information with country, ISP, and threat indicators -->

### Blacklist Export
<!-- Screenshot: Generated blacklist with CIDR notation -->

## Installation

### Requirements
- Python 3.7+
- Flask 2.3.3

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd cdnLogAnalyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python3 app.py
```

4. Open your browser and navigate to:
```
http://localhost:8080
```

## Usage

### Analyzing Log Files

1. **Prepare Your Logs**
   - Ensure your CDN logs are in `.gz` format
   - Place all log files in a single directory

2. **Start Analysis**
   - Enter the directory path containing your `.gz` log files
   - Click "Analyze Logs"
   - Watch real-time progress as files are processed

3. **Explore Results**
   - View comprehensive statistics and visualizations
   - Click on IPs to see detailed request history
   - Export blacklists for bot mitigation
   - Use geolocation data for threat analysis

### Log Format

The analyzer expects CDN logs in the following format:
```
[DD/MMM/YYYY:HH:MM:SS +ZZZZ] IP - RESPONSE_TIME "-" "METHOD URL" STATUS_CODE BYTES_SENT RESPONSE_SIZE CACHE_STATUS "USER_AGENT" "CONTENT_TYPE" ORIGINAL_IP
```

Example:
```
[01/Jan/2024:12:00:00 +0000] 192.168.1.1 - 150 "-" "GET /static/image.jpg" 200 1024 2048 HIT "Mozilla/5.0..." "image/jpeg" 10.0.0.1
```

## Use Cases

### 🛡️ Security & Bot Mitigation
- Identify and block malicious scrapers
- Detect DDoS patterns
- Generate IP blacklists automatically
- Monitor suspicious access patterns

### 💰 Bandwidth Optimization
- Find bandwidth-heavy IPs and URLs
- Identify opportunities for caching improvements
- Analyze cache hit ratios
- Optimize resource delivery

### 📊 Traffic Analytics
- Understand user behavior patterns
- Identify peak traffic hours
- Track bounce rates and engagement
- Monitor geographic distribution

### 🔧 Performance Monitoring
- Track response time trends
- Identify slow endpoints
- Monitor cache effectiveness
- Analyze error rates

## Technical Details

### Architecture
- **Backend**: Flask web framework
- **Frontend**: HTML, TailwindCSS, Chart.js
- **Processing**: Server-Sent Events (SSE) for real-time updates
- **Analysis**: In-memory processing with efficient algorithms

### Performance
- Processes large `.gz` files efficiently
- Real-time progress tracking
- Optimized regex parsing
- Memory-efficient streaming

### Smart Features
- **Subnet Detection**: Automatically groups IPs into /24 CIDR blocks when safe
- **Safety Checks**: Prevents blocking legitimate users when generating blacklists
- **Dynamic vs Static Classification**: Intelligent URL categorization
- **Bot Scoring**: Multi-factor bot detection algorithm

## Configuration

### Customizing Dynamic Content Detection

Edit `app.py` lines 609-613 to define what counts as dynamic content:
```python
is_dynamic = (
    '/api/' in entry.url or
    '/chess/' in entry.url or
    '/homework/' in entry.url
)
```

Add your own dynamic URL patterns to improve bot detection accuracy.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

[Your License Here]

## Support

For issues, questions, or suggestions, please open an issue on the repository.
