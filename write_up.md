# Diff Summary - Log Parser Fixes (python_monitor.py)

## What I changed:

### 1. Regex was too strict → Made it more flexible

The original regex only worked for domains like `xxx.yyy.zzz` (exactly three words separated by dots) and was picky about spaces.  
I rewrote it to use `"([^"]+)"` to capture anything inside quotes and cleaned up the spacing rules.

---

### 2. Added error handling for bad timestamps

Before, if a log line had a bad timestamp (wrong format or corrupted), the whole script would crash.  
Now I wrapped the `datetime.strptime()` in a `try/except` and just skip lines that fail to parse.

---

### 3. Status code was a string → Now it's an int

Originally, the status code (HTTP) was being stored as a string.  
That broke numeric comparisons later (like `if status >= 400`).  
Now I explicitly cast it to `int(status)` during parsing.

---

## Why I did this:

Because the script was way too fragile for real-world NGINX logs.  
Any slightly malformed line would kill the whole thing.

---

## Next steps (maybe):

- Add logging to track which lines are being skipped due to bad timestamps (for future debugging).
- Build a few tests with intentionally broken log lines.

---

```
diff --git a/python_monitor.py b/python_monitor.py
index ab7dd40..d26dd67 100644
--- a/python_monitor.py
+++ b/python_monitor.py
@@ -1,30 +1,35 @@
 import re
-from datetime import datetime
+from datetime import datetime, timedelta
 
 def parse_log_line(log_line):
-    pattern = r'(\d+\.\d+\.\d+\.\d+) - (\w+) \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] "(\w+\.\w+\.\w+)" "(\w+ /.+ HTTP/\d\.\d)" (\d+) (\d+) (\d+)'
+    # Fixed regex: original pattern was too rigid for real-world Nginx logs
+    pattern = r'(\d+\.\d+\.\d+\.\d+)\s-\s(\w+)\s\[(.*?)\]\s"([^"]+)"\s"([^"]+)"\s(\d+)\s(\d+)\s(\d+)'
     match = re.match(pattern, log_line)
     if match:
         ip, action, timestamp_str, domain, request, status, bytes_sent, unknown = match.groups()
-        timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
+        try:
+            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
+        except ValueError:
+            return None  # Skip lines with bad timestamp format
         return {
             'timestamp': timestamp,
-            'status': status,
+            'status': int(status),
             'ip': ip
         }
```

```
(.venv) ericmoreira@Mac-Lykos L2-assessment % python3 python_monitor.py 
ALERT: Error rate 100.00% exceeded threshold in window starting at 2025-05-17 00:41:58+08:00
ALERT: Error rate 100.00% exceeded threshold in window starting at 2025-05-17 09:38:27+08:00
ALERT: Error rate 50.00% exceeded threshold in window starting at 2025-05-17 09:51:47+08:00
ALERT: Error rate 45.26% exceeded threshold in window starting at 2025-05-17 23:31:00+08:00
ALERT: Error rate 45.00% exceeded threshold in window starting at 2025-05-17 23:42:23+08:00
ALERT: Error rate 47.33% exceeded threshold in window starting at 2025-05-17 23:59:49+08:00
```

# Sqlite Analysis:

## Find the hour of the day with the highest average response time.

sqlite> .mode column
sqlite> .headers on
sqlite> SELECT 
   ...>     strftime('%H', timestamp) AS hour,
   ...>     ROUND(AVG(response_time_ms), 2) AS avg_response_time_ms
   ...> FROM request_logs
   ...> GROUP BY hour
   ...> ORDER BY avg_response_time_ms DESC
   ...> LIMIT 1;
hour  avg_response_time_ms
----  --------------------
22    905.18

## Identify any IPs that sent more than 350 requests with a 429 status code (rate-limited).

sqlite> SELECT 
   ...>     ip_address AS IP,
   ...>     COUNT(*) AS Total_429_Requests
   ...> FROM request_logs
   ...> WHERE status_code = 429
   ...> GROUP BY IP
   ...> HAVING Total_429_Requests > 350
   ...> ORDER BY Total_429_Requests DESC;

IP               Total_429_Requests
---------------  ------------------
122.157.29.219   363               
119.103.226.136  358


## Calculate the total bytes sent for requests where response time > 500ms.


sqlite> SELECT 
   ...>     SUM(bytes_sent) AS Total_Bytes_Sent_Over_500ms
   ...> FROM request_logs
   ...> WHERE response_time_ms > 500;
Total_Bytes_Sent_Over_500ms
---------------------------
10719865


# CDN Suggestions

CDN is not my """thing""", but after some research and considering my reports on the previous tasks I believe this could be relevant:

To reduce backend load and improve CDN performance, the customer should implement stricter rate limiting at the CDN edge for sensitive endpoints like `/login`, combined with a CAPTCHA or challenge-response mechanism for high-frequency IPs. Additionally, caching static assets more aggressively (like CSS and JS files) would help reduce response time spikes during peak hours.

