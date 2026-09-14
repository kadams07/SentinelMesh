# SentinelMesh

SentinelMesh is a Python-based cybersecurity application designed to detect suspicious login activity from authentication log files.

The application analyzes login events, counts failed login attempts, identifies suspicious IP addresses, calculates a security risk level, and generates a security report. To protect privacy, IP addresses are converted into SHA-256 hash identifiers before they are displayed in the report.

## Key Features

- Authentication log file analysis
- Detection of repeated failed login attempts
- Suspicious IP address identification
- Privacy-preserving SHA-256 IP hashing
- Risk-level calculation
- Automated security report generation
- Terminal-based user interaction
- File reading, writing, and appending
- Colored security alerts using Colorama

## Technologies Used

- Python 3
- os
- hashlib
- datetime
- colorama

## How It Works

1. The application creates or reads an authentication log file.
2. It counts successful and failed login attempts.
3. It groups failed attempts according to IP address.
4. IP addresses with three or more failed attempts are marked as suspicious.
5. The application calculates a risk level.
6. The original IP address is converted into a SHA-256 hash.
7. A security report is generated automatically.

## Installation

```bash
python -m pip install colorama
```

## Run the Application

```bash
python main.py
```

## Example Detection

```text
Failed attempts: 3
Risk level: HIGH
Risk score: 40
```

## Ethical Use

SentinelMesh is an educational defensive cybersecurity project. It should only be used with log files that belong to you or that you are authorized to analyze.
