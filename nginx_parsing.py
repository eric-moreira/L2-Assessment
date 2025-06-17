import re
import pandas as pd
from pathlib import Path # For handling file paths robustly

def parse_log_line(log_line: str) -> dict | None:
    """
    Parses a single log line using a regular expression and returns a dictionary
    with extracted and converted data.

    Args:
        log_line (str): A single string representing a log entry.

    Returns:
        dict | None: A dictionary containing parsed log data if successful,
                     otherwise None.
    """
    # Regex to capture fields from the log line.
    # Named groups (?P<name>...) are used for easy extraction.
    import re
import pandas as pd
from pathlib import Path

log_pattern = re.compile(
    r'^(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+'
    r'(?P<cache_status>[A-Z-]+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<requested_host>[^"]+)"\s+'
    r'"(?P<method_uri_protocol>[^"]+)"\s+'
    r'(?P<http_status>\d{3})\s+'
    r'(?P<response_size>\d+)\s+'
    r'(?P<transferred_size>\d+)\s+'
    r'"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"\s+'
    r'"(?P<x_forwarded_for>[^"]*)"\s+'
    r'"(?P<backend_host_port>[^"]+)"\s+'
    r'cc="(?P<country_code>[^"]+)"\s+'
    r'rt=(?P<response_time>[\d\.]+)\s+'
    r'uct="(?P<upstream_connect_time>[\d\.]+)"\s+'
    r'uht="(?P<upstream_header_time>[\d\.]+)"\s+'
    r'urt="(?P<upstream_response_time>[\d\.]+)"\s+'
    r'ucs="(?P<upstream_status>\d{3})"'
    r'(?:\s+.*)?$'
)

def parse_log_line(line: str) -> dict | None:
    match = log_pattern.match(line)
    if not match:
        print(f"Warning: Regex didn't match for line: {line.strip()}")
        return None

    data = match.groupdict()

    # Split HTTP method, URI, and Protocol
    try:
        method, uri, protocol = data['method_uri_protocol'].split(' ', 2)
        data['http_method'] = method
        data['requested_uri'] = uri
        data['http_protocol'] = protocol
    except ValueError:
        print(f"Warning: Could not split method_uri_protocol for line: {line.strip()}")
        return None
    del data['method_uri_protocol']

    # Convert numeric types
    for field in ['http_status', 'response_size', 'transferred_size', 'upstream_status']:
        try:
            data[field] = int(data[field])
        except ValueError:
            print(f"Warning: Cannot convert {field} to int for line: {line.strip()}")
            return None

    for field in ['response_time', 'upstream_connect_time', 'upstream_header_time', 'upstream_response_time']:
        try:
            data[field] = float(data[field])
        except ValueError:
            print(f"Warning: Cannot convert {field} to float for line: {line.strip()}")
            return None

    # Handle nullables
    for field in ['referrer', 'user_agent', 'x_forwarded_for']:
        if data[field] == '-':
            data[field] = None

    try:
        data['timestamp'] = pd.to_datetime(
            data['timestamp'],
            format='%d/%b/%Y:%H:%M:%S %z',
            errors='raise'  # <-- Aqui é engenharia: Se der problema, quero que exploda MESMO!
        )
    except Exception as e:
        print(f"[CRITICAL] Failed to parse timestamps in the log batch. Reason: {e}")
        # Opcional: dump sample of bad lines
        print(data['timestamp'].head(5))
        raise  # Let the program crash - better fail fast than process garbage

    return data


def create_dataframe_from_logs(log_file_path: Path) -> pd.DataFrame:
    parsed_logs = []
    if not log_file_path.exists():
        print(f"Error: Log file not found at {log_file_path}")
        return pd.DataFrame()

    with log_file_path.open('r') as f:
        for line_num, line in enumerate(f, 1):
            parsed_data = parse_log_line(line.strip())
            if parsed_data:
                parsed_logs.append(parsed_data)
    return pd.DataFrame(parsed_logs)

def top_ips_by_request_count(df: pd.DataFrame, num_results: int) -> pd.Series:
    top_ips = df['client_ip'].value_counts().head(num_results)
    #print(top_ips)
    return top_ips

def percentage_4xx_5xx(df: pd.DataFrame) -> float:
    total_requests = len(df)
    if total_requests == 0:
        print("Warning: empty DataFrame.")
        return 0.0

    error_mask = df['http_status'].between(400, 599)
    error_count = error_mask.sum()
    percentage = (error_count / total_requests) * 100

    print(f"HTTP 4xx/5xx: {error_count} from {total_requests} ({percentage:.2f}%)")
    return percentage

def average_response_size_for_get(df: pd.DataFrame) -> float:
    get_requests = df[df['http_method'] == 'GET']
    if get_requests.empty:
        print("Warning: No GET request found.")
        return 0.0

    average_size = get_requests['response_size'].mean()
    print(f"Average: {average_size:.2f} bytes")
    return average_size

def potential_threats_analysis(df: pd.DataFrame):
    top_ips = top_ips_by_request_count(df, 5)
    
    for ip in top_ips.index:
        ip_df = df[df['client_ip'] == ip]

        top_urls = ip_df['requested_uri'].value_counts().head(5)
        
        unique_url_count = ip_df['requested_uri'].nunique()
        if unique_url_count > 10:
            print(f"Potential fuzz attack URLs accessed by {ip}: {unique_url_count}")

        error_count = ip_df[ip_df['http_status'].between(400, 599)].shape[0]
        total_requests = ip_df.shape[0]
        error_rate = (error_count / total_requests) * 100 if total_requests > 0 else 0

        for url, value in top_urls.items():
            if re.search(r'(login|admin)', url, re.IGNORECASE) and value > 100 and error_rate > 50:
                print(f"\nSensitive attempts from {ip}:")
                print(top_urls.to_dict())
                print(f"Error rate for {ip}: {error_rate:.2f}%")
                print("")
            else:
                continue

def detect_rate_limited_ips(df: pd.DataFrame, status_code: int = 429):
    if 'http_status' not in df.columns or 'client_ip' not in df.columns:
        print("[ERROR] DataFrame missing required columns ('http_status' and 'client_ip').")
        return pd.DataFrame()

    rate_limited = df[df['http_status'] == status_code]

    ip_429_counts = rate_limited['client_ip'].value_counts().reset_index()
    ip_429_counts.columns = ['client_ip', '429_count']

    print(f"\n[INFO] Total unique IPs flagged with HTTP status {status_code}: {len(ip_429_counts)}")
    flagged_ips = ip_429_counts['client_ip'].tolist()
    print(f"Flagged IPs: ")
    for ip in flagged_ips:
        print(ip)
    return ip_429_counts


# End of Definitions/Functions



if __name__ == "__main__":
    # Define the log file path using pathlib.Path
    log_file_path = Path('./nginx_access.log')

    # Create the DataFrame from the log file
    df = create_dataframe_from_logs(log_file_path)

    # Display the first few rows of the DataFrame and its information
    print("DataFrame created successfully!")
    print(df.head())

    # --- Examples of Statistical Analysis (after DataFrame creation) ---

    print("\n--- Statistical Analysis ---")
    print("")

    print("---- Top 5 IPS requests ----")
    potential_threats = top_ips_by_request_count(df, 5)
    print(f"{potential_threats}")


    print("---- % of 4xx/5xx errors ----")
    percentage_4xx_5xx(df)
    print("")

    print("---- Avg Response Size for GET method ----")
    average_response_size_for_get(df)
    print("")

    print("")
    print("---- Evaluating Potential Threats ----")
    potential_threats_analysis(df)

    print("---- Rate Limit Analysis ----")
    detect_rate_limited_ips(df)
 

