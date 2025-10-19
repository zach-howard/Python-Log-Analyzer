# Basic Log Analyzer (Python)

## Project Overview

This is a simple command-line utility for parsing web server access logs. Built purely with **Python's standard library**, the tool rapidly analyzes log files to identify patterns often associated with security threats.

The analyzer focuses on two key indicators:
1.  **Volume Analysis:** Identifying the top source IP addresses by request count (useful for detecting DoS/DDoS or aggressive scanning).
2.  **Anomaly Detection:** Tallying counts of suspicious HTTP status codes (e.g., 401, 403, 404, 500) which often indicate unauthorized access attempts or exploit vulnerability checks.

## Skills Demonstrated

| Skill Area | Python Implementation |
| :--- | :--- |
| **Log Analysis** | Opens, reads, and processes unstructured text data (simulated access logs). |
| **Data Aggregation** | Uses the `collections.Counter` module for efficient tallying of IPs and status codes. |
| **Regular Expressions (RegEx)** | Employs the `re` module to reliably extract specific data (`IP Address` and `Status Code`) from complex log lines. |
| **Anomaly Detection** | Filters and reports on specific error codes (`403 Forbidden`, `404 Not Found`, etc.) to flag potential attacks. |
| **Environment Management** | Uses `venv` and a proper `.gitignore` for isolated, clean project dependencies. |

## Usage and Setup

### 1. Prerequisites

* Python 3.x installed on your system.

### 2. Setup (Recommended)

Clone the repository and set up a virtual environment (venv) for isolation:

```bash
# Clone the project
git clone [YOUR_GITHUB_REPOSITORY_URL]
cd basic_log_analyzer

# Create and activate the virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1  # Use this command for Windows PowerShell
# OR: source venv/bin/activate (for macOS/Linux)
