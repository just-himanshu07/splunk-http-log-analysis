#Splunk Basics – HTTP Log Analysis

## 🎯 Objective

In this project, we analyze HTTP logs using Splunk Enterprise to investigate web traffic and identify potentially suspicious activity.

The objectives are to:

- Analyze HTTP traffic and identify the most active source IP addresses.
- Detect HTTP server errors (5xx).
- Identify User-Agent strings associated with scripting tools.
- Investigate unusually large HTTP responses.
- Review suspicious URI access patterns.
- Practice SPL queries used in SOC investigations.

## 🖥️ Lab Setup

- **SIEM Tool:** Splunk Enterprise 9.3.0
- **Data Source:** JSON-formatted Zeek-style HTTP logs
- **Index:** `http_logs`
- **Source Type:** `_json`

### 📥 Download HTTP Log File

[Download HTTP Logs (JSON)](https://raw.githubusercontent.com/0xrajneesh/30-Days-SOC-Challenge-Beginner/refs/heads/main/http_logs.json)

## ⚙️ Steps to Upload HTTP Logs into Splunk

1. Open Splunk Web.
2. Navigate to **Settings → Add Data → Upload**.
3. Upload the downloaded HTTP JSON file.
4. Select the `_json` source type.
5. Choose the `http_logs` index or create it if necessary.
6. Finish the upload and verify that events are searchable.

## 🔍 Investigation Tasks

### Task 1: Identify the Top 10 Source IP Addresses

**Objective:** Find the source IP addresses generating the highest volume of HTTP traffic.

```spl
index=http_logs sourcetype="_json"
| stats count by id.orig_h
| sort -count
| head 10
```

**Investigation:** Identify the most active sources and determine whether their traffic volume warrants further analysis.

### Task 2: Count HTTP Server Errors (5xx)

**Objective:** Identify the number of server-error events.

```spl
index=http_logs sourcetype="_json" status_code>=500 status_code<600
| stats count as server_errors
```

**Investigation:** Review the frequency of server errors and check whether they cluster around particular endpoints or time periods.

### Task 3: Investigate Suspicious User-Agent Strings

**Objective:** Identify events matching selected User-Agent strings associated with tools or scripted requests.

```spl
index=http_logs sourcetype="_json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count by user_agent
| sort -count
```

**Investigation:** Review matching requests and determine whether they indicate legitimate automation, security testing, or potentially suspicious activity.

### Task 4: Identify Large HTTP Responses

**Objective:** Find HTTP responses with body lengths greater than 500,000 bytes.

```spl
index=http_logs sourcetype="_json" resp_body_len>500000
| table ts id.orig_h id.resp_h uri resp_body_len status_code
| sort -resp_body_len
```

**Investigation:** Examine the requested URI, source and destination IPs, response size, and status code.

### Task 5: Investigate Frequently Requested URIs

**Objective:** Identify the most frequently requested web resources.

```spl
index=http_logs sourcetype="_json"
| stats count by uri
| sort -count
| head 20
```

**Investigation:** Review frequently accessed URIs and identify unusual paths that may require additional investigation.

## 📊 Key Findings

Based on the Splunk analysis performed in this lab:

- **3,000 HTTP events** were analyzed.
- **285 server-error events** were identified.
- **323 events** had response body lengths greater than 500,000 bytes.
- **296 events** matched the selected User-Agent patterns.
- Source IP and URI analysis helped prioritize traffic for further investigation.

These results are specific to the dataset and search conditions used. Suspicious patterns require validation before being classified as malicious.


## 🛡️ Skills Demonstrated

- Splunk Enterprise and SPL
- HTTP log analysis
- Source IP investigation
- HTTP status-code analysis
- User-Agent investigation
- Web traffic triage
- Evidence-based security analysis

## 🚀 Future Improvements

- Create a Splunk dashboard for HTTP traffic analysis.
- Configure alerts for unusual increases in server errors.
- Investigate repeated requests to sensitive or unusual URIs.
- Correlate source IPs with request volume, response codes, and timestamps.
- Add validated findings to an incident investigation report.

## ✅ Conclusion

This project demonstrates how Splunk can be used to analyze HTTP logs, identify unusual traffic patterns, and prioritize events for further investigation. It provides hands-on experience with SIEM searches and the initial triage workflow used by SOC Analysts.

**Disclaimer:** HTTP errors, large responses, and suspicious User-Agent strings are investigation leads, not proof of a successful attack or compromised system.
