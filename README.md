# review_that_code

**Comprehensive source code vulnerability scanner with OWASP Top 10 2021 compliance and CVSSv3.1 scoring**

## Overview

`review_that_code` is a vulnerability scanner that analyses source code for security weaknesses across all programming languages and application types. It identifies vulnerabilities based on OWASP Top 10 2021 standards, provides detailed contextual explanations for each finding, and generates comprehensive security assessment reports with CVSSv3.1 scoring suitable for penetration testing and security audits.

## Security Checks

The scanner detects vulnerabilities including:
- **Hardcoded credentials and API keys** - Identifies exposed secrets in source code
- **SQL injection vulnerabilities** - Detects unsafe database query construction
- **Cross-site scripting (XSS)** - Finds unsafe HTML output and DOM manipulation
- **Command injection** - Identifies unsafe system command execution
- **Path traversal attacks** - Detects unsafe file path construction
- **Cryptographic failures** - Finds weak encryption and insecure implementations
- **Authentication bypasses** - Identifies weak authentication mechanisms
- **Security misconfigurations** - Detects debug modes and exposed information
- **Input validation issues** - Finds missing or inadequate input sanitization
- **Session management flaws** - Identifies insecure session handling

...and more based on OWASP Top 10 2021, CWE Top 25, and SANS Top 25 standards.

## Installation

### Option 1: Install Dependencies Manually
```bash
pip install python-magic
```

### Option 2: Install from Requirements File
```bash
pip install -r requirements.txt
```

## Usage

### Scan a Single File
```bash
python3 review_that_code_v2.py /path/to/file.py
```

### Scan a Directory (Recursive)
```bash
python3 review_that_code_v2.py /path/to/project/
```

### Scan with Verbose Output
```bash
python3 review_that_code_v2.py /path/to/project/ --verbose
```

### Custom Output File
```bash
python3 review_that_code_v2.py /path/to/project/ --output my_report.txt
```

### View Help
```bash
python3 review_that_code_v2.py --help
```

## Output

Generates a detailed security assessment report with:
- Executive summary with vulnerability counts and severity breakdown
- CVSSv3.1 scores and severity classifications (Critical, High, Medium, Low)
- Detailed findings grouped by OWASP categories
- File locations, line numbers, and vulnerable code context
- Contextual explanations of why each finding is a security risk
- Remediation recommendations

## Supported Languages

Supports 20+ programming languages including Python, JavaScript, Java, C/C++, C#, PHP, Ruby, Go, Rust, Swift, HTML, SQL, Shell scripts, and more.
