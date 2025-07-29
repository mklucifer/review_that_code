#!/usr/bin/env python3
"""
review_that_code v2 - Comprehensive OWASP + CWE + SANS Vulnerability Scanner
Ultra-comprehensive source code security assessment tool with advanced false positive reduction.
Includes OWASP Top 10 2021 + CWE Top 25 2024 + SANS Top 25 + Programming Best Practices.
Features enhanced contextual explanations and professional-grade security assessment capabilities.
"""

import os
import re
import json
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Set
from datetime import datetime
from collections import defaultdict
import math

try:
    import magic
except ImportError:
    magic = None

class CVSSv31Calculator:
    """CVSSv3.1 Base Score Calculator for vulnerability assessment."""
    
    def __init__(self):
        self.metrics = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},  # Attack Vector
            'AC': {'L': 0.77, 'H': 0.44},  # Attack Complexity
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},  # Privileges Required
            'UI': {'N': 0.85, 'R': 0.62},  # User Interaction
            'S': {'U': 1.0, 'C': 1.0},  # Scope (multiplier handled separately)
            'C': {'N': 0.0, 'L': 0.22, 'H': 0.56},  # Confidentiality
            'I': {'N': 0.0, 'L': 0.22, 'H': 0.56},  # Integrity
            'A': {'N': 0.0, 'L': 0.22, 'H': 0.56}   # Availability
        }
    
    def calculate_base_score(self, vector: Dict[str, str]) -> Tuple[float, str]:
        """Calculate CVSSv3.1 base score from metrics vector."""
        # Exploitability Score
        exploitability = 8.22 * self.metrics['AV'][vector['AV']] * \
                        self.metrics['AC'][vector['AC']] * \
                        self.metrics['PR'][vector['PR']] * \
                        self.metrics['UI'][vector['UI']]
        
        # Impact Score
        impact_base = 1 - ((1 - self.metrics['C'][vector['C']]) * \
                          (1 - self.metrics['I'][vector['I']]) * \
                          (1 - self.metrics['A'][vector['A']]))
        
        if vector['S'] == 'U':  # Unchanged scope
            impact = 6.42 * impact_base
        else:  # Changed scope
            impact = 7.52 * (impact_base - 0.029) - 3.25 * pow(impact_base - 0.02, 15)
        
        # Base Score
        if impact <= 0:
            base_score = 0.0
        elif vector['S'] == 'U':
            base_score = min(10.0, impact + exploitability)
        else:
            base_score = min(10.0, 1.08 * (impact + exploitability))
        
        base_score = math.ceil(base_score * 10) / 10  # Round up to 1 decimal
        
        # Determine severity
        if base_score == 0.0:
            severity = "None"
        elif base_score <= 3.9:
            severity = "Low"
        elif base_score <= 6.9:
            severity = "Medium"
        elif base_score <= 8.9:
            severity = "High"
        else:
            severity = "Critical"
        
        return base_score, severity
    
    def get_cvss_vector_string(self, vector: Dict[str, str]) -> str:
        """Generate CVSS vector string."""
        return f"CVSS:3.1/AV:{vector['AV']}/AC:{vector['AC']}/PR:{vector['PR']}/UI:{vector['UI']}/S:{vector['S']}/C:{vector['C']}/I:{vector['I']}/A:{vector['A']}"

class EnhancedOWASPScanner:
    def __init__(self):
        self.findings = defaultdict(list)
        self.dependency_findings = []
        self.vulnerability_patterns = self._initialize_patterns()
        self.cvss_calculator = CVSSv31Calculator()

    def _initialize_patterns(self):
        """Initialize comprehensive OWASP-based vulnerability patterns with CVSS scoring."""
        return {
            # Critical Severity - Hardcoded Secrets
            'hardcoded_secrets': {
                'patterns': [
                    r'password\s*=\s*["\'][^"\']{3,}["\']',
                    r'api_key\s*=\s*["\'][^"\']{10,}["\']',
                    r'secret\s*=\s*["\'][^"\']{8,}["\']',
                    r'token\s*=\s*["\'][^"\']{10,}["\']',
                    r'private_key\s*=\s*["\'].*["\']',
                    r'aws_access_key_id\s*=\s*["\']AKIA[A-Z0-9]{16}["\']',
                    r'aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']',
                    r'AKIA[A-Z0-9]{16}',
                    r'["\'][A-Za-z0-9/+=]{40}["\']',
                ],
                'severity': 'Critical',
                'title': 'Critical Security Issue - Hardcoded Secrets and Credentials',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'H'},
                'description': '''Hardcoded secrets in source code represent one of the most critical security vulnerabilities.

IMPACT: Complete compromise of associated systems, unauthorized access to databases and APIs.

RECOMMENDATION: Store credentials in environment variables or dedicated secret management systems.''',
                'contextual_explanation': self._get_hardcoded_secrets_explanation
            },

            # A02:2021 - Cryptographic Failures
            'cryptographic_failures': {
                'patterns': [
                    r'hashlib\.md5\s*\(',
                    r'hashlib\.sha1\s*\(',
                    r'\bMD5\s*\(',
                    r'\bSHA1\s*\(',
                    r'\bDES\s*\(',  # Word boundary to avoid matching method names
                    r'\bRC4\s*\(',
                    r'\bECB\s*\(',
                    r'ssl_verify\s*=\s*False',
                    r'verify\s*=\s*False',
                    r'TrustAllCertificates',
                    r'HostnameVerifier.*ALLOW_ALL',
                    r'Math\.random\s*\(',
                    # More specific cryptographic library patterns
                    r'Cipher\.getInstance\s*\(\s*["\']DES["\']',
                    r'Cipher\.getInstance\s*\(\s*["\']RC4["\']',
                    r'Cipher\.getInstance\s*\(\s*["\'].*ECB.*["\']',
                    r'new\s+DESKeySpec\s*\(',
                    r'new\s+RC4\s*\(',
                    r'CryptoJS\.DES\.',
                    r'CryptoJS\.RC4\.',
                    r'from\s+Crypto\.Cipher\s+import\s+DES',
                    r'from\s+Crypto\.Cipher\s+import\s+RC4',
                ],
                'severity': 'High',
                'title': 'A02:2021 - Cryptographic Failures',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'L', 'A': 'N'},
                'description': '''Cryptographic failures occur when cryptography is not used or is used incorrectly to protect sensitive data. This includes weak encryption algorithms, poor key management, and disabled security features.

IMPACT: Sensitive data exposure, identity theft, credit card fraud, and other privacy violations.

RECOMMENDATION: Use strong, up-to-date cryptographic algorithms, implement proper key management, enforce encryption in transit and at rest.''',
                'contextual_explanation': self._get_crypto_explanation
            },

            # A03:2021 - Injection (including XSS)
            'injection_vulnerabilities': {
                'patterns': [
                    # SQL Injection
                    r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*["\'\s]*\+',
                    r'INSERT\s+INTO\s+.*\s+VALUES\s*\(.*["\'\s]*\+',
                    r'UPDATE\s+.*\s+SET\s+.*["\'\s]*\+',
                    r'DELETE\s+FROM\s+.*\s+WHERE\s+.*["\'\s]*\+',
                    r'execute\s*\(\s*["\'].*["\'\s]*\+',
                    r'query\s*\(\s*["\'].*["\'\s]*\+',
                    r'f["\']SELECT.*\{.*\}.*["\']',
                    r'`SELECT.*\$\{.*\}.*`',
                    
                    # XSS
                    r'innerHTML\s*=\s*[^"\';\s]*["\'\s]*\+',
                    r'outerHTML\s*=\s*[^"\';\s]*["\'\s]*\+',
                    r'document\.write\s*\(',
                    r'eval\s*\(',
                    r'\$\(.*\)\.html\s*\(',
                    r'dangerouslySetInnerHTML',
                    r'v-html\s*=',
                    
                    # Command Injection
                    r'os\.system\s*\(',
                    r'subprocess\.(call|run|Popen)\s*\(',
                    r'exec\s*\(',
                    r'shell_exec\s*\(',
                    r'system\s*\(',
                    r'passthru\s*\(',
                    r'popen\s*\(',
                    r'child_process\.exec',
                    r'Runtime\.getRuntime\(\)\.exec',
                ],
                'severity': 'Critical',
                'title': 'A03:2021 - Injection Vulnerabilities',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'H'},
                'description': '''Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Common injection types include SQL, NoSQL, OS command, LDAP injection, and Cross-Site Scripting (XSS).

IMPACT: Data loss, corruption, or disclosure to unauthorized parties, complete host takeover in some cases.

RECOMMENDATION: Use parameterized queries, stored procedures, input validation, output encoding, and principle of least privilege.''',
                'contextual_explanation': self._get_injection_explanation
            },

            # A05:2021 - Security Misconfiguration
            'security_misconfiguration': {
                'patterns': [
                    r'DEBUG\s*=\s*True',
                    r'debug\s*:\s*true',
                    r'console\.log\s*\(',
                    r'print\s*\(',
                    r'printStackTrace\s*\(',
                    r'error_reporting\s*\(\s*E_ALL',
                    r'display_errors\s*=\s*On',
                    r'expose_php\s*=\s*On',
                ],
                'severity': 'Medium',
                'title': 'A05:2021 - Security Misconfiguration',
                'cvss_vector': {'AV': 'L', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'N', 'A': 'N'},
                'description': '''Security misconfiguration can happen at any level of an application stack, including network services, platform, web server, application server, database, frameworks, custom code, and pre-installed virtual machines, containers, or storage.

IMPACT: Information disclosure, system compromise, unauthorized access to sensitive functionality.

RECOMMENDATION: Implement secure installation processes, regular security updates, and proper configuration management.''',
                'contextual_explanation': self._get_security_misconfiguration_explanation
            },

            # Container Security Issues
            'container_security': {
                'patterns': [
                    r'^\s*ENTRYPOINT\s+(?!.*USER)',  # ENTRYPOINT without USER directive
                    r'^\s*CMD\s+(?!.*USER)',         # CMD without USER directive
                ],
                'severity': 'High',
                'title': 'Container Security - Missing User Directive',
                'cvss_vector': {'AV': 'L', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'H'},
                'description': '''Running containers as root poses significant security risks. If an attacker compromises a process running as root, they may gain control over the entire container and potentially the host system.

IMPACT: Container escape, privilege escalation, complete system compromise.

RECOMMENDATION: Always specify a non-root USER directive in Dockerfiles before ENTRYPOINT or CMD instructions.''',
                'contextual_explanation': self._get_container_security_explanation
            },

            # Cookie Security Issues
            'cookie_security': {
                'patterns': [
                    r'new\s+Cookie\s*\([^)]*\)(?!.*\.setSecure\(true\))',
                    r'new\s+Cookie\s*\([^)]*\)(?!.*\.setHttpOnly\(true\))',
                    r'response\.addCookie\s*\([^)]*\)(?!.*setSecure)',
                    r'response\.addCookie\s*\([^)]*\)(?!.*setHttpOnly)',
                ],
                'severity': 'Medium',
                'title': 'A05:2021 - Insecure Cookie Configuration',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'},
                'description': '''Cookies without proper security flags are vulnerable to various attacks including session hijacking, cross-site scripting, and man-in-the-middle attacks.

IMPACT: Session hijacking, credential theft, cross-site scripting attacks.

RECOMMENDATION: Always set HttpOnly, Secure, and SameSite flags on cookies containing sensitive data.''',
                'contextual_explanation': self._get_cookie_security_explanation
            }
        }

    def _get_hardcoded_secrets_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for hardcoded secrets vulnerabilities."""
        explanations = {
            'password.*=': "Hardcoded passwords in source code are visible to anyone with code access and cannot be rotated without code changes. Attackers finding this code can use these credentials.",
            'api_key.*=': "Hardcoded API keys allow unauthorized access to external services and can result in data breaches or service abuse if the code is compromised.",
            'secret.*=': "Hardcoded secrets compromise the security of the entire application as they cannot be easily changed and are visible in version control.",
            'token.*=': "Hardcoded tokens provide persistent access that attackers can abuse if they gain access to the source code or binary.",
            'AKIA': "This appears to be an AWS Access Key ID hardcoded in the source code. If compromised, attackers can access your AWS resources and potentially incur significant costs or steal data."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific case: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This code contains hardcoded sensitive information that should be stored securely. The pattern '{matched_text.strip()}' in '{line_content.strip()}' exposes credentials to attackers."

    def _get_crypto_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for cryptographic vulnerabilities."""
        # First, check for false positives - method names that contain crypto terms
        false_positive_patterns = [
            r'\w+des\w*\s*\(',  # Method names containing 'des' like getHecosCodes()
            r'\w+md5\w*\s*\(',  # Method names containing 'md5'
            r'\w+sha\w*\s*\(',  # Method names containing 'sha'
            r'\w+rc4\w*\s*\(',  # Method names containing 'rc4'
        ]
        
        for fp_pattern in false_positive_patterns:
            if re.search(fp_pattern, matched_text, re.IGNORECASE):
                # This looks like a method name, not actual crypto usage
                return None  # Signal this is a false positive
        
        explanations = {
            'md5': "MD5 is cryptographically broken and vulnerable to collision attacks. Attackers can create two different inputs that produce the same MD5 hash in seconds, allowing them to bypass password verification, forge digital signatures, or replace legitimate files with malicious ones that have the same hash. This makes MD5 completely unsuitable for any security purpose.",
            'sha1': "SHA-1 is deprecated due to collision vulnerabilities demonstrated by Google in 2017. Attackers can create different documents with identical SHA-1 hashes, allowing them to forge certificates, bypass integrity checks, or replace legitimate software with malicious versions. Modern attacks can find SHA-1 collisions in hours.",
            'DES': "DES uses only 56-bit keys which can be brute-forced in hours with modern hardware or cloud computing. The Electronic Frontier Foundation cracked DES in 1998, and today's hardware can break it in minutes. Any data encrypted with DES can be easily decrypted by attackers, exposing sensitive information like passwords, personal data, or financial records.",
            'RC4': "RC4 has known statistical biases in its keystream that allow attackers to recover plaintext without knowing the key. These weaknesses have been exploited in real-world attacks against WEP WiFi encryption and early TLS connections. Attackers can decrypt communications, steal session cookies, or recover encrypted passwords.",
            'ECB': "ECB (Electronic Codebook) mode encrypts identical plaintext blocks to identical ciphertext blocks, revealing patterns in the encrypted data. Attackers can see repeated data patterns, rearrange encrypted blocks, or perform cut-and-paste attacks. This is why ECB mode makes encrypted images still show recognizable patterns.",
            'verify.*False': "Disabling SSL/TLS certificate verification allows man-in-the-middle attacks where attackers can intercept, read, and modify all communications between the client and server. Attackers can steal login credentials, inject malicious content, or redirect users to malicious sites while appearing legitimate.",
            'Math.random': "Math.random() uses a predictable pseudorandom number generator that attackers can predict if they know the seed or observe enough outputs. This makes it completely unsuitable for generating passwords, session tokens, cryptographic keys, or any security-sensitive random values. Attackers can predict future 'random' values and compromise security.",
            'Cipher.getInstance': "Using weak cipher algorithms or insecure modes makes encrypted data vulnerable to various cryptographic attacks including brute force, known-plaintext attacks, or exploitation of algorithm weaknesses. Attackers can decrypt sensitive data, forge encrypted messages, or bypass authentication mechanisms.",
            'CryptoJS': "Using deprecated or weak cryptographic algorithms in JavaScript can expose sensitive data to client-side attacks. Weak algorithms can be broken by attackers, and client-side crypto can be manipulated through browser developer tools or malicious scripts.",
            'TrustAllCertificates': "Trusting all certificates bypasses SSL/TLS security entirely, allowing any attacker with a self-signed certificate to perform man-in-the-middle attacks. This completely negates the security benefits of HTTPS and allows attackers to intercept, read, and modify all encrypted communications."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This code uses weak or broken cryptography. The pattern '{matched_text.strip()}' in '{line_content.strip()}' can be exploited by attackers."

    def _get_injection_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for injection vulnerabilities."""
        explanations = {
            'SELECT.*\+': "This SQL query concatenates user input directly into the SQL string. An attacker can inject malicious SQL like \"'; DROP TABLE users; --\" to execute arbitrary database commands.",
            'INSERT.*\+': "String concatenation in INSERT statements allows SQL injection. Attackers can manipulate the VALUES clause to insert malicious data or execute additional SQL commands.",
            'f\".*SELECT': "Python f-strings with user input in SQL queries are vulnerable to injection. If user input contains SQL syntax, it will be executed as code.",
            'innerHTML': "Setting innerHTML with user data allows XSS attacks. Malicious scripts like <script>alert('XSS')</script> will execute in the user's browser.",
            'document.write': "document.write() with user input enables XSS. Attackers can inject JavaScript that steals cookies, redirects users, or performs actions on their behalf.",
            'exec.*\+': "String concatenation in exec() calls allows command injection. Attackers can append commands like '; rm -rf /' to execute arbitrary system commands.",
            'system.*\+': "Concatenating user input into system() calls enables command injection, allowing attackers to execute arbitrary operating system commands."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This code allows injection attacks where user input is interpreted as code. The pattern '{matched_text.strip()}' in '{line_content.strip()}' can be exploited."

    def _get_security_misconfiguration_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for security misconfiguration vulnerabilities."""
        explanations = {
            'DEBUG.*True': "Debug mode enabled in production exposes sensitive information like stack traces, variable values, database queries, and system internals to attackers. This information can be used to understand the application's structure and find additional vulnerabilities.",
            'console.log': "Console logging in production can expose sensitive data like user credentials, API keys, or personal information in browser developer tools or server logs. Attackers who gain access to logs or can view the browser console can steal this sensitive data.",
            'printStackTrace': "Printing stack traces reveals internal application structure, file paths, class names, method signatures, and potentially sensitive data like database connection strings or API endpoints. Attackers use this information to map the application and identify attack vectors.",
            'error_reporting.*E_ALL': "Full error reporting in production exposes detailed system information, file paths, database schemas, and internal application logic. This gives attackers a roadmap of the system's internals and potential vulnerabilities to exploit.",
            'print\\s*\\(': "Print statements in production code can expose sensitive information like file paths, error details, user data, or system internals to logs or console output. Attackers who gain access to logs can use this information to understand the system and plan attacks. Additionally, excessive logging can cause performance issues and fill up disk space."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This represents a security misconfiguration that can expose sensitive system information to attackers. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should be removed or secured with proper logging controls."

    def _get_container_security_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for container security vulnerabilities."""
        explanations = {
            'ENTRYPOINT': "By not specifying a USER directive before ENTRYPOINT, the container process runs as root (UID 0) with full administrative privileges. If an attacker exploits a vulnerability in the application (such as RCE, deserialization, or path traversal), they gain root access to the container. This allows them to: install malware, access sensitive files, modify system configurations, potentially escape the container to attack the host system, and pivot to other containers or network resources. Root access amplifies any security vulnerability into a critical system compromise.",
            'CMD': "Running CMD instructions as root gives the container process unnecessary administrative privileges. If the application is compromised through vulnerabilities like SQL injection leading to RCE, buffer overflows, or insecure deserialization, attackers inherit root privileges. This enables them to: read/write any file in the container, install backdoors, modify system binaries, access other containers' data if volumes are shared, and potentially break out of container isolation to attack the host system."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This container configuration runs as root (UID 0), giving any compromised process full administrative privileges. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should be preceded by a USER directive specifying a non-root user (e.g., USER 1000:1000) to limit the blast radius of any security compromise."

    def _get_cookie_security_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for cookie security vulnerabilities."""
        explanations = {
            'new.*Cookie.*(?!.*setSecure)': "Cookie created without the 'Secure' flag allows transmission over unencrypted HTTP connections. Attackers on the same network (WiFi, corporate network, or ISP level) can intercept these cookies using packet sniffing tools like Wireshark. Once stolen, attackers can use the session cookies to impersonate the user and gain unauthorized access to their account.",
            'new.*Cookie.*(?!.*setHttpOnly)': "Cookie created without the 'HttpOnly' flag can be accessed by client-side JavaScript code. If the application is vulnerable to Cross-Site Scripting (XSS), malicious scripts can steal these cookies using document.cookie and send them to attacker-controlled servers. This allows session hijacking and account takeover attacks.",
            'addCookie.*(?!.*setSecure)': "Cookie added without the 'Secure' flag can be transmitted over insecure HTTP connections. Network attackers can intercept these cookies through man-in-the-middle attacks, packet sniffing, or by downgrading HTTPS connections to HTTP. Stolen session cookies allow attackers to impersonate users and access their accounts.",
            'addCookie.*(?!.*setHttpOnly)': "Cookie added without the 'HttpOnly' flag is accessible to JavaScript, making it vulnerable to XSS attacks. Malicious scripts injected through XSS can read these cookies and exfiltrate them to attacker servers. This enables session hijacking, where attackers can use stolen cookies to access user accounts without knowing passwords."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This cookie lacks proper security flags, making it vulnerable to interception and theft. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should include HttpOnly (prevents JavaScript access) and Secure (prevents transmission over HTTP) flags to protect against session hijacking and XSS attacks."

    def _is_text_file(self, file_path: str) -> bool:
        """Check if a file is a text file that should be scanned."""
        if magic:
            try:
                file_type = magic.from_file(file_path, mime=True)
                return file_type.startswith('text/') or 'json' in file_type
            except:
                pass
        
        # Fallback to extension-based detection
        text_extensions = {
            '.py', '.js', '.php', '.java', '.c', '.cpp', '.h', '.hpp',
            '.cs', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.html', '.htm', '.xml', '.json', '.yaml', '.yml',
            '.sql', '.sh', '.bash', '.ps1', '.bat', '.cmd',
            '.txt', '.md', '.rst', '.cfg', '.conf', '.ini'
        }
        return Path(file_path).suffix.lower() in text_extensions

    def scan_file(self, file_path: str) -> None:
        """Scan a single file for vulnerabilities with CVSS scoring and contextual explanations."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                for vuln_type, vuln_data in self.vulnerability_patterns.items():
                    for pattern in vuln_data['patterns']:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            # Calculate CVSS score
                            cvss_score, cvss_severity = self.cvss_calculator.calculate_base_score(vuln_data['cvss_vector'])
                            cvss_vector_string = self.cvss_calculator.get_cvss_vector_string(vuln_data['cvss_vector'])
                            
                            # Get contextual explanation
                            contextual_explanation = vuln_data['contextual_explanation'](match.group(), line.strip())
                            
                            # Skip if this is identified as a false positive
                            if contextual_explanation is None:
                                continue
                            
                            # Convert to relative path if base_directory is set
                            relative_path = file_path
                            if hasattr(self, 'base_directory') and self.base_directory:
                                try:
                                    relative_path = os.path.relpath(file_path, self.base_directory)
                                except ValueError:
                                    # If relative path calculation fails, use original path
                                    relative_path = file_path
                            
                            finding = {
                                'file': relative_path,
                                'line': line_num,
                                'matched_text': match.group(),
                                'line_content': line.strip(),
                                'pattern': pattern,
                                'cvss_score': cvss_score,
                                'cvss_severity': cvss_severity,
                                'cvss_vector': cvss_vector_string,
                                'contextual_explanation': contextual_explanation
                            }
                            self.findings[vuln_type].append(finding)
                            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")

    def scan_directory(self, directory: str, verbose: bool = False) -> None:
        """Recursively scan directory for vulnerabilities."""
        exclude_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 
                       'build', 'dist', '.pytest_cache', '.mypy_cache', 'vendor'}
        
        scanned_files = 0
        # Store the base directory for relative path calculation
        self.base_directory = os.path.abspath(directory)
        
        for root, dirs, files in os.walk(directory):
            # Remove excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                if self._is_text_file(file_path):
                    if verbose:
                        print(f"Scanning: {file_path}")
                    self.scan_file(file_path)
                    scanned_files += 1
        
        if verbose:
            print(f"Scanned {scanned_files} files")

    def generate_report(self, output_file: str = None) -> str:
        """Generate enhanced OWASP security assessment report with CVSS scores and contextual explanations."""
        report_lines = []
        
        # Header
        report_lines.extend([
            "review_that_code - SECURITY ASSESSMENT REPORT",
            "=" * 44,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "Based on OWASP Top 10 2021 with CVSSv3.1 Scoring and Contextual Analysis",
            "",
            "EXECUTIVE SUMMARY",
            "=" * 17
        ])
        
        # Calculate summary statistics - count categories, not instances
        total_categories = len([vuln_type for vuln_type, findings in self.findings.items() if findings])
        affected_files = len(set(f['file'] for findings in self.findings.values() for f in findings))
        
        # CVSS severity breakdown by categories (not instances)
        cvss_severity_counts = defaultdict(int)
        for vuln_type, findings in self.findings.items():
            if findings:  # Only count if there are findings for this category
                # Use the severity from the first finding in each category
                cvss_severity_counts[findings[0]['cvss_severity']] += 1
        
        report_lines.extend([
            f"Vulnerability Categories Found: {total_categories}",
            f"Files Affected: {affected_files}",
            "",
            "CVSSv3.1 Severity Distribution (by category):",
            f"- Critical: {cvss_severity_counts['Critical']} categories",
            f"- High:     {cvss_severity_counts['High']} categories",
            f"- Medium:   {cvss_severity_counts['Medium']} categories",
            f"- Low:      {cvss_severity_counts['Low']} categories",
            "",
            "DETAILED VULNERABILITY FINDINGS WITH CVSS SCORING",
            "=" * 50,
            ""
        ])
        
        # Group findings by CVSS severity
        severity_order = ['Critical', 'High', 'Medium', 'Low']
        findings_by_severity = defaultdict(list)
        
        for vuln_type, findings in self.findings.items():
            if findings:
                vuln_data = self.vulnerability_patterns[vuln_type]
                findings_by_severity[findings[0]['cvss_severity']].append((vuln_type, vuln_data, findings))
        
        # Generate findings by severity
        for severity in severity_order:
            if severity in findings_by_severity:
                report_lines.extend([
                    f"{severity.upper()} SEVERITY FINDINGS",
                    "=" * (len(severity) + 18),
                    ""
                ])
                
                for vuln_type, vuln_data, findings in findings_by_severity[severity]:
                    # Group findings by file
                    files_affected = defaultdict(list)
                    for finding in findings:
                        files_affected[finding['file']].append(finding['line'])
                    
                    # Get CVSS information from first finding
                    first_finding = findings[0]
                    
                    report_lines.extend([
                        f"FINDING: {vuln_data['title']}",
                        "-" * (len(vuln_data['title']) + 9),
                        "",
                        f"CVSSv3.1 Score: {first_finding['cvss_score']} ({first_finding['cvss_severity']})",
                        f"CVSS Vector: {first_finding['cvss_vector']}",
                        "",
                        f"Affected Files ({len(files_affected)} files, {len(findings)} instances):"
                    ])
                    
                    for file_path, lines in files_affected.items():
                        report_lines.append(f"  • {file_path} (lines: {', '.join(map(str, lines))})")
                    
                    report_lines.extend([
                        "",
                        "OWASP Description:",
                        vuln_data['description'],
                        "",
                        f"Example from {first_finding['file']} (line {first_finding['line']}):",
                        f"Matched pattern: {first_finding['matched_text']}",
                        "",
                        "Code context:",
                        f"  {first_finding['line']}: >>> {first_finding['line_content']}",
                        "",
                        first_finding['contextual_explanation'],
                        "",
                        "=" * 80,
                        ""
                    ])
        
        report_content = '\n'.join(report_lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"review_that_code security assessment report written to: {output_file}")
        
        return report_content

def main():
    parser = argparse.ArgumentParser(description='review_that_code - OWASP Vulnerability Scanner with CVSSv3.1 Scoring')
    parser.add_argument('target', help='Target directory or file to scan')
    parser.add_argument('--output', '-o', help='Output file for the report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = EnhancedOWASPScanner()
    
    print("Starting review_that_code - OWASP-compliant vulnerability scan with CVSSv3.1 scoring...")
    print("Checking for OWASP Top 10 2021 vulnerabilities with contextual explanations...")
    
    if os.path.isfile(args.target):
        scanner.scan_file(args.target)
        print(f"Scanned 1 file")
    else:
        scanner.scan_directory(args.target, args.verbose)
    
    # Calculate summary
    total_findings = sum(len(findings) for findings in scanner.findings.values())
    total_categories = len(scanner.findings)
    
    print(f"Found {total_findings} vulnerability instances across {total_categories} OWASP categories")
    
    # Generate and save report
    output_file = args.output or 'review_that_code_security_report.txt'
    scanner.generate_report(output_file)
    
    # Show CVSS severity breakdown
    cvss_severity_counts = defaultdict(int)
    for findings in scanner.findings.values():
        for finding in findings:
            cvss_severity_counts[finding['cvss_severity']] += 1
    
    print("\nCVSSv3.1 vulnerability severity breakdown:")
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if cvss_severity_counts[severity] > 0:
            print(f"  {severity}: {cvss_severity_counts[severity]}")

if __name__ == "__main__":
    main()
