# Network Port Scanner - Phase 1 Project

**Course:** 605346 - Information & Network Security Programming  
**University:** University of Petra  
**Student Names:** [Memas Shekhani ,Shahed Hamadin ,Lama Hamdan]

---

## Description

A multithreaded TCP port scanner that scans target hosts for open ports. Uses ThreadPoolExecutor for concurrent scanning and thread-safe logging.

---

## Requirements

- Python 3.6 or higher
- No additional libraries needed (all are standard)

---

## How to Run

```bash
python scanner.py <TARGET> <PORTS> [OPTIONS]

Arguments:

Argument    Description	                Example
target	   IP address or domain name	scanme.nmap.org
ports	   Port or range to scan	    80, 20-100, 22,80,443


Options:

Option	          Description	                  Default
-t,--threads	Number of concurrent threads	    100
-to,--timeout	Connection timeout in seconds	    1.0


Examples:
# Scan single port
python scanner.py scanme.nmap.org 80

# Scan port range
python scanner.py scanme.nmap.org 20-100

# Scan specific ports
python scanner.py scanme.nmap.org 22,80,443

# Scan with custom threads and timeout
python scanner.py scanme.nmap.org 1-500 -t 200 -to 0.5


Output
The scanner generates a timestamped log file: scan_YYYYMMDD_HHMMSS.txt

Example output:
 Port 80: OPEN
 Port 22: OPEN
 Port 23: CLOSED

 Design Decisions
ThreadPoolExecutor: Used for efficient concurrent scanning 
Lock (threading.Lock): Ensures thread-safe file writing, preventing race conditions
connect_ex(): Returns error codes instead of throwing exceptions 
Timestamped files: Each scan creates a unique file using datetime module


Thread Safety Explanation
Multiple threads writing to the same file simultaneously could cause corrupted output. The threading.Lock ensures only one thread writes at a time:

with file_lock:
    with open(filename, 'a') as f:
        f.write(log_line)


Test Results
Tested on scanme.nmap.org:

Scan Type	  Ports	   Time	    Open Ports
Single port	   80	   0.33s	   80
Range	     20-100	    1.0s	 22, 80


References
Python socket documentation
Week 1: File System & Multithreading slides
Week 2 & 3: Socket Programming slides