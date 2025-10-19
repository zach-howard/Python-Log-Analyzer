import sys
from collections import Counter
import re

# Regex pattern to extract IP address (Group 1) and HTTP Status Code (Group 2).
# This pattern matches the standard combined log format (IP - - [time] "method path protocol" status size).
LOG_PATTERN = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"\s+(\d{3})\s+\d+$')
SUSPICIOUS_STATUS_CODES = ['401', '403', '404', '407', '500']

def get_status_description(code):
    """Provides context for common suspicious HTTP status codes."""
    descriptions = {
        '401': 'Unauthorized',
        '403': 'Forbidden',
        '404': 'Not Found',
        '407': 'Proxy Auth Req',
        '500': 'Internal Server Error'
    }
    return descriptions.get(code, "Unknown")

def analyze_log(log_filepath):
    """Analyzes the log file to count IPs and suspicious status codes."""
    
    ip_counts = Counter()
    status_counts = Counter()
    
    print("-" * 50)
    print(f"Analyzing log file: {log_filepath}")
    
    try:
        # Open the file for reading ('r'). 'with open' ensures the file is closed automatically.
        with open(log_filepath, 'r') as f:
            for line in f:
                # Search the current line for the IP and Status Code
                match = LOG_PATTERN.search(line)
                
                if match:
                    # Group 1 is the IP Address, Group 2 is the Status Code
                    ip_address = match.group(1)
                    status_code = match.group(2)
                    
                    # Tally the counts
                    ip_counts[ip_address] += 1
                    status_counts[status_code] += 1
        
        # --- Reporting Section ---
        
        # 1. Report Top IPs (Volume Analysis)
        print("\nTOP 5 MOST ACTIVE IP ADDRESSES (Potential Scanners/Attackers):")
        print("-------------------------------------------------------------")
        for ip, count in ip_counts.most_common(5):
            print(f"IP: {ip:<16} Count: {count}")
            
        # 2. Report Suspicious Status Codes (Anomaly Detection)
        print("\nSUSPICIOUS HTTP STATUS CODE COUNTS (Security Indicators):")
        print("----------------------------------------------------------")
        suspicious_found = False
        
        for code in SUSPICIOUS_STATUS_CODES:
            count = status_counts.get(code, 0)
            if count > 0:
                print(f"Code {code} ({get_status_description(code)}): {count} hits")
                suspicious_found = True
                
        if not suspicious_found:
            print("No suspicious status codes were found.")
            
        print("-" * 50)

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def main():
    # Check for correct number of arguments: the script name + the log file path
    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <log_file_path>")
        print("Example: python log_analyzer.py access.log")
        sys.exit(1) 

    log_filepath = sys.argv[1]
    analyze_log(log_filepath)

if __name__ == "__main__":
    main()