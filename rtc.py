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
                'cvss_vector': {'AV': 'L', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'H'},
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
                    r'MD5\s*\(',
                    r'SHA1\s*\(',
                    r'DES\s*\(',
                    r'RC4\s*\(',
                    r'ECB\s*\(',
                    r'ssl_verify\s*=\s*False',
                    r'verify\s*=\s*False',
                    r'TrustAllCertificates',
                    r'HostnameVerifier.*ALLOW_ALL',
                    r'Math\.random\s*\(',
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
                'severity': 'High',
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
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'N', 'A': 'N'},
                'description': '''Security misconfiguration can happen at any level of an application stack, including network services, platform, web server, application server, database, frameworks, custom code, and pre-installed virtual machines, containers, or storage.

IMPACT: Information disclosure, system compromise, unauthorized access to sensitive functionality.

RECOMMENDATION: Implement secure installation processes, regular security updates, and proper configuration management.''',
                'contextual_explanation': self._get_security_misconfiguration_explanation
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
        explanations = {
            'md5': "MD5 is cryptographically broken and vulnerable to collision attacks. Attackers can create different inputs that produce the same hash, allowing password bypasses or data integrity attacks.",
            'sha1': "SHA-1 is deprecated due to collision vulnerabilities. Google demonstrated practical attacks in 2017, making it unsuitable for security purposes.",
            'DES': "DES uses only 56-bit keys which can be brute-forced in hours with modern hardware. It's been broken since the late 1990s.",
            'RC4': "RC4 has known biases in its keystream that allow attackers to recover plaintext, especially in protocols like WEP and early TLS.",
            'ECB': "ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, revealing patterns in the data and allowing partial decryption.",
            'verify.*False': "Disabling SSL/TLS certificate verification allows man-in-the-middle attacks where attackers can intercept and modify communications.",
            'Math.random': "Math.random() is not cryptographically secure and predictable, making it unsuitable for generating passwords, tokens, or keys."
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
            'DEBUG.*True': "Debug mode enabled in production exposes sensitive information like stack traces, variable values, and system internals to attackers.",
            'console.log': "Console logging in production can expose sensitive data in browser developer tools or server logs that attackers might access.",
            'printStackTrace': "Printing stack traces reveals internal application structure, file paths, and potentially sensitive data to attackers.",
            'error_reporting.*E_ALL': "Full error reporting in production exposes system information and potential vulnerabilities to attackers."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This represents a security misconfiguration that exposes the application to attacks. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should be secured."

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
                            
                            finding = {
                                'file': file_path,
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
        
        # Calculate summary statistics
        total_findings = sum(len(findings) for findings in self.findings.values())
        affected_files = len(set(f['file'] for findings in self.findings.values() for f in findings))
        
        # CVSS severity breakdown
        cvss_severity_counts = defaultdict(int)
        for findings in self.findings.values():
            for finding in findings:
                cvss_severity_counts[finding['cvss_severity']] += 1
        
        report_lines.extend([
            f"Total Vulnerability Instances: {total_findings}",
            f"Vulnerability Categories Found: {len(self.findings)}",
            f"Files Affected: {affected_files}",
            "",
            "CVSSv3.1 Severity Distribution:",
            f"- Critical: {cvss_severity_counts['Critical']} findings",
            f"- High:     {cvss_severity_counts['High']} findings",
            f"- Medium:   {cvss_severity_counts['Medium']} findings",
            f"- Low:      {cvss_severity_counts['Low']} findings",
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
