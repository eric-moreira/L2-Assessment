import re
from datetime import datetime, timedelta

def parse_log_line(log_line):
    # Fixed regex: original pattern was too rigid for real-world Nginx logs
    pattern = r'(\d+\.\d+\.\d+\.\d+)\s-\s(\w+)\s\[(.*?)\]\s"([^"]+)"\s"([^"]+)"\s(\d+)\s(\d+)\s(\d+)'
    match = re.match(pattern, log_line)
    if match:
        ip, action, timestamp_str, domain, request, status, bytes_sent, unknown = match.groups()
        try:
            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            return None  # Skip lines with bad timestamp format
        return {
            'timestamp': timestamp,
            'status': int(status),
            'ip': ip
        }
    else:
        return None

def is_error_status(status):
    return 400 <= status <= 599

def monitor_logs(log_file):
    with open(log_file, 'r') as f:
        lines = f.readlines()

    window_size_minutes = 5
    error_threshold_percentage = 10.0
    window_start_time = None
    window_end_time = None
    window_requests = 0
    window_errors = 0

    for line in lines:
        log_data = parse_log_line(line.strip())
        if log_data is None:
            continue

        timestamp = log_data['timestamp']
        status = log_data['status']

        if window_start_time is None:
            window_start_time = timestamp
            window_end_time = window_start_time + timedelta(minutes=window_size_minutes)

        # If current log timestamp exceeds the current window
        if timestamp > window_end_time:
            if window_requests > 0:
                error_rate = (window_errors / window_requests) * 100
                if error_rate > error_threshold_percentage:
                    print(f"ALERT: Error rate {error_rate:.2f}% exceeded threshold in window starting at {window_start_time}")
            # Move window forward
            window_start_time = timestamp
            window_end_time = window_start_time + timedelta(minutes=window_size_minutes)
            window_requests = 0
            window_errors = 0

        window_requests += 1
        if is_error_status(status):
            window_errors += 1

    # Final window check for any remaining unprocessed logs
    if window_requests > 0:
        error_rate = (window_errors / window_requests) * 100
        if error_rate > error_threshold_percentage:
            print(f"ALERT: Error rate {error_rate:.2f}% exceeded threshold in window starting at {window_start_time}")

# Example usage:
monitor_logs('nginx_access.log')

