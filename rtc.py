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
import urllib.request
import urllib.parse
import urllib.error
import time
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
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
            severity = "Informational"
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

class DependencyVulnerabilityChecker:
    """Automated dependency vulnerability checker using OSV API."""
    
    def __init__(self):
        self.osv_api_url = "https://api.osv.dev/v1/query"
        self.cache = {}  # Simple cache to avoid repeated API calls
        self.rate_limit_delay = 0.1  # 100ms delay between API calls
        
    def _make_osv_request(self, package_name: str, version: str, ecosystem: str) -> Optional[Dict]:
        """Make request to OSV API for vulnerability data."""
        cache_key = f"{ecosystem}:{package_name}:{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Prepare request data
        request_data = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            },
            "version": version
        }
        
        try:
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            # Make API request
            data = json.dumps(request_data).encode('utf-8')
            req = urllib.request.Request(
                self.osv_api_url,
                data=data,
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                self.cache[cache_key] = result
                return result
                
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, Exception) as e:
            print(f"Warning: Failed to check {package_name} for vulnerabilities: {e}")
            return None
    
    def _map_ecosystem(self, dep_type: str) -> str:
        """Map dependency type to OSV ecosystem identifier."""
        ecosystem_map = {
            'npm': 'npm',
            'python': 'PyPI',
            'maven': 'Maven',
            'gradle': 'Maven',  # Gradle uses Maven ecosystem
            'ruby': 'RubyGems',
            'php': 'Packagist',
            'go': 'Go',
            'rust': 'crates.io'
        }
        return ecosystem_map.get(dep_type, dep_type)
    
    def _extract_cvss_score(self, vulnerability: Dict) -> Tuple[float, str]:
        """Extract CVSS score and severity from vulnerability data."""
        # Try to find CVSS score in various locations
        cvss_score = 0.0
        severity = "Unknown"
        
        # Check database_specific field
        if 'database_specific' in vulnerability:
            db_specific = vulnerability['database_specific']
            if 'cvss' in db_specific:
                cvss_data = db_specific['cvss']
                if isinstance(cvss_data, dict) and 'score' in cvss_data:
                    cvss_score = float(cvss_data['score'])
                elif isinstance(cvss_data, (int, float)):
                    cvss_score = float(cvss_data)
        
        # Check severity field
        if 'severity' in vulnerability:
            severity_data = vulnerability['severity']
            if isinstance(severity_data, list) and severity_data:
                severity_info = severity_data[0]
                if 'score' in severity_info:
                    score_value = severity_info['score']
                    # Handle both numeric scores and CVSS vector strings
                    if isinstance(score_value, (int, float)):
                        cvss_score = float(score_value)
                    elif isinstance(score_value, str):
                        # Try to extract score from CVSS vector or use default
                        if score_value.startswith('CVSS:'):
                            # Default score based on severity type
                            cvss_score = 5.0  # Medium severity default
                        else:
                            try:
                                cvss_score = float(score_value)
                            except ValueError:
                                cvss_score = 5.0
                if 'type' in severity_info and severity_info['type'] == 'CVSS_V3':
                    severity = self._cvss_to_severity(cvss_score)
        
        # Fallback: estimate severity from score
        if severity == "Unknown" and cvss_score > 0:
            severity = self._cvss_to_severity(cvss_score)
        elif severity == "Unknown":
            severity = "Medium"  # Default for unknown vulnerabilities
            cvss_score = 5.0
        
        return cvss_score, severity
    
    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    def check_dependency_vulnerabilities(self, dependencies: List[Dict]) -> List[Dict]:
        """Check all dependencies for vulnerabilities using OSV API."""
        vulnerability_findings = []
        
        print("\n🔍 Checking dependencies for known vulnerabilities...")
        
        for i, dep in enumerate(dependencies):
            # Progress indicator
            progress = (i + 1) / len(dependencies) * 100
            print(f"\rProgress: {progress:.1f}% ({i + 1}/{len(dependencies)}) - Checking {dep['name']}", end='', flush=True)
            
            ecosystem = self._map_ecosystem(dep['type'])
            package_name = dep['name']
            version = dep['version']
            
            # Clean version string (remove operators like >=, ==, etc.)
            clean_version = re.sub(r'^[><=!]+', '', version).strip()
            if not clean_version or clean_version in ['*', 'latest']:
                continue
            
            # Query OSV API
            result = self._make_osv_request(package_name, clean_version, ecosystem)
            
            if result and 'vulns' in result and result['vulns']:
                for vuln in result['vulns']:
                    cvss_score, severity = self._extract_cvss_score(vuln)
                    
                    vulnerability_findings.append({
                        'dependency': dep,
                        'vulnerability_id': vuln.get('id', 'Unknown'),
                        'summary': vuln.get('summary', 'No summary available'),
                        'details': vuln.get('details', 'No details available'),
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'published': vuln.get('published', 'Unknown'),
                        'modified': vuln.get('modified', 'Unknown'),
                        'aliases': vuln.get('aliases', []),
                        'references': [ref.get('url', '') for ref in vuln.get('references', [])]
                    })
        
        print(f"\n✅ Vulnerability check complete! Found {len(vulnerability_findings)} vulnerabilities.")
        return vulnerability_findings

class EnhancedOWASPScanner:
    def __init__(self):
        self.findings = defaultdict(list)
        self.dependency_findings = []
        self.dependency_vulnerabilities = []  # List of dependency vulnerabilities found
        self.extracted_dependencies = []  # List of found dependencies for manual review
        self.vulnerability_patterns = self._initialize_patterns()
        self.cvss_calculator = CVSSv31Calculator()
        self.dependency_checker = DependencyVulnerabilityChecker()

    def _initialize_patterns(self):
        """Initialize comprehensive OWASP-based vulnerability patterns with CVSS scoring."""
        return {
            # Critical Severity - Hardcoded Secrets
            'hardcoded_secrets': {
                'patterns': [
                    # High-confidence patterns for real secrets
                    r'(?:password|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',  # Passwords 8+ chars
                    r'(?:api_key|apikey|api-key)\s*[=:]\s*["\'][A-Za-z0-9]{16,}["\']',  # API keys
                    r'(?:secret_key|secretkey|secret-key)\s*[=:]\s*["\'][A-Za-z0-9/+=]{16,}["\']',  # Secret keys
                    r'(?:access_token|accesstoken|bearer_token)\s*[=:]\s*["\'][A-Za-z0-9._-]{20,}["\']',  # Tokens
                    r'private_key\s*[=:]\s*["\']-----BEGIN.*PRIVATE KEY-----.*["\']',  # Private keys
                    # AWS specific patterns
                    r'aws_access_key_id\s*[=:]\s*["\']AKIA[A-Z0-9]{16}["\']',
                    r'aws_secret_access_key\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']',
                    r'AKIA[A-Z0-9]{16}(?![A-Za-z0-9])',  # AWS access key standalone
                    # Generic secret patterns with prefixes
                    r'["\'](?:sk_|pk_|key_|secret_)[A-Za-z0-9/+=]{20,}["\']',
                    # Database connection strings
                    r'(?:db_password|database_password)\s*[=:]\s*["\'][^"\']{6,}["\']',
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
                    # SQL Injection - String concatenation (dangerous)
                    r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*["\'\'s]*\+',
                    r'INSERT\s+INTO\s+.*\s+VALUES\s*\(.*["\'\'s]*\+',
                    r'UPDATE\s+.*\s+SET\s+.*["\'\'s]*\+',
                    r'DELETE\s+FROM\s+.*\s+WHERE\s+.*["\'\'s]*\+',
                    # Dynamic query building with string concatenation
                    r'execute\s*\([^)]*["\'].*\+.*["\'][^)]*\)',  # execute with string concat
                    r'query\s*\([^)]*["\'].*\+.*["\'][^)]*\)',  # query with string concat
                    r'f["\']SELECT.*\{.*\}.*["\']',
                    r'`SELECT.*\$\{.*\}.*`',
                    
                    # XSS - Focus on user-controlled input with string concatenation
                    r'innerHTML\s*=\s*[^"\'\';\'s]*["\'\';\'s]*\+',
                    r'outerHTML\s*=\s*[^"\'\';\'s]*["\'\';\'s]*\+',
                    r'document\.write\s*\([^)]*[a-zA-Z_]\w*[^)]*\+',  # document.write with variables and concat
                    r'eval\s*\([^)]*[a-zA-Z_]\w*[^)]*\)',  # eval with variables
                    r'\$\(.*\)\.html\s*\(',
                    r'dangerouslySetInnerHTML',
                    r'v-html\s*=',
                    
                    # Command Injection - Focus on string concatenation with user input
                    r'os\.system\s*\([^)]*["\'].*\+.*["\'][^)]*\)',  # system with string concat
                    r'subprocess\.(call|run|Popen)\s*\([^)]*["\'].*\+.*["\'][^)]*\)',  # subprocess with string concat
                    r'exec\s*\([^)]*["\'].*\+.*["\'][^)]*\)',  # exec with string concat
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
                    # Only flag console.log that exposes sensitive data
                    r'console\.log\s*\([^)]*(?:password|key|token|secret|credential)[^)]*\)',
                    r'console\.log\s*\([^)]*(?:database|db_|connection)[^)]*\)',
                    r'console\.log\s*\([^)]*(?:error|exception|stack)[^)]*\)',
                    r'console\.log\s*\([^)]*(?:user|email|phone)[^)]*\)',
                    # Only flag prints that expose sensitive data
                    r'print\s*\([^)]*(?:password|key|token|secret|credential)[^)]*\)',
                    r'print\s*\([^)]*(?:database|db_|connection)[^)]*\)',
                    r'print\s*\([^)]*(?:error|exception|traceback)[^)]*\)',
                    r'print\s*\([^)]*(?:debug|DEBUG)[^)]*\)',
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
            },

            # Buffer Overflow and Memory Safety Issues (C/C++)
            'buffer_overflow': {
                'patterns': [
                    # Unsafe string functions
                    r'\bgets\s*\(',
                    r'\bstrcpy\s*\(',
                    r'\bstrcat\s*\(',
                    r'\bsprintf\s*\(',
                    r'\bvsprintf\s*\(',
                    r'\bstrcpyA\s*\(',
                    r'\bstrcpyW\s*\(',
                    r'\bStrCpy\s*\(',
                    r'\bStrCat\s*\(',
                    r'\bwcscat\s*\(',
                    r'\bwcscpy\s*\(',
                    # Unsafe scanf variants
                    r'\bscanf\s*\([^,]*%s',
                    r'\bfscanf\s*\([^,]*%s',
                    r'\bsscanf\s*\([^,]*%s',
                    # Unsafe memory operations
                    r'\bmemcpy\s*\([^,]*,\s*[^,]*,\s*strlen\s*\(',
                    r'\balloca\s*\(',
                    # Buffer with fixed size and unsafe input
                    r'char\s+\w+\[\d+\];[^}]*gets\s*\(',
                    r'char\s+\w+\[\d+\];[^}]*scanf\s*\([^,]*%s',
                ],
                'severity': 'Critical',
                'title': 'A06:2021 - Buffer Overflow and Memory Safety',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'},
                'description': '''Buffer overflow vulnerabilities occur when programs write data beyond the allocated buffer boundaries, potentially overwriting adjacent memory. This is one of the most dangerous vulnerability classes in C/C++.

IMPACT: Arbitrary code execution, system compromise, denial of service, data corruption.

RECOMMENDATION: Use safe string functions (strncpy, strncat, snprintf), bounds checking, and modern C++ containers.''',
                'contextual_explanation': self._get_buffer_overflow_explanation
            },

            # Format String Vulnerabilities
            'format_string': {
                'patterns': [
                    r'printf\s*\(\s*[a-zA-Z_]\w*\s*\)',  # printf(user_input) - variable as format
                    r'printf\s*\(\s*[a-zA-Z_]\w*\s*,',  # printf(var, ...) - variable as format with args
                    r'fprintf\s*\([^,]*,\s*[a-zA-Z_]\w*\s*\)',  # fprintf(file, user_input)
                    r'fprintf\s*\([^,]*,\s*[a-zA-Z_]\w*\s*,',  # fprintf(file, var, ...)
                    r'sprintf\s*\([^,]*,\s*[a-zA-Z_]\w*\s*\)',  # sprintf(buf, user_input)
                    r'sprintf\s*\([^,]*,\s*[a-zA-Z_]\w*\s*,',  # sprintf(buf, var, ...)
                    r'snprintf\s*\([^,]*,\s*[^,]*,\s*[a-zA-Z_]\w*\s*\)',  # snprintf with user format
                    r'snprintf\s*\([^,]*,\s*[^,]*,\s*[a-zA-Z_]\w*\s*,',  # snprintf with user format and args
                    r'syslog\s*\([^,]*,\s*[a-zA-Z_]\w*\s*\)',
                    r'err\s*\([^,]*,\s*[a-zA-Z_]\w*\s*\)',
                    r'warn\s*\([a-zA-Z_]\w*\s*\)',
                ],
                'severity': 'High',
                'title': 'A03:2021 - Format String Vulnerabilities',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'},
                'description': '''Format string vulnerabilities occur when user-controlled data is used as a format string in printf-family functions without proper validation.

IMPACT: Information disclosure, arbitrary memory writes, code execution.

RECOMMENDATION: Always use format strings as literals, validate user input, use safe alternatives.''',
                'contextual_explanation': self._get_format_string_explanation
            },

            # Memory Management Issues
            'memory_management': {
                'patterns': [
                    # Double free
                    r'free\s*\([^;]*\);[^}]*free\s*\(',
                    # Use after free patterns
                    r'free\s*\([^;]*\);[^}]*\*\s*\w+',
                    # Memory leak patterns
                    r'malloc\s*\([^;]*\);(?![^}]*free\s*\()',
                    r'calloc\s*\([^;]*\);(?![^}]*free\s*\()',
                    r'realloc\s*\([^;]*\);(?![^}]*free\s*\()',
                    # Null pointer dereference
                    r'\*\s*\w+\s*;[^}]*if\s*\(\s*\w+\s*==\s*NULL\s*\)',
                    # Uninitialized pointer
                    r'\*\s*\w+;(?![^}]*\w+\s*=)',
                ],
                'severity': 'High',
                'title': 'A06:2021 - Memory Management Vulnerabilities',
                'cvss_vector': {'AV': 'L', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'},
                'description': '''Memory management vulnerabilities include double-free, use-after-free, memory leaks, and null pointer dereferences that can lead to crashes or exploitation.

IMPACT: Denial of service, information disclosure, potential code execution.

RECOMMENDATION: Use smart pointers in C++, validate pointers before use, implement proper error handling.''',
                'contextual_explanation': self._get_memory_management_explanation
            },

            # Integer Overflow/Underflow
            'integer_overflow': {
                'patterns': [
                    # Unchecked arithmetic that could overflow
                    r'\w+\s*\+\s*\w+\s*\*',  # multiplication in addition
                    r'malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)',  # malloc with multiplication
                    r'calloc\s*\(\s*\w+\s*\*\s*\w+',  # calloc with potential overflow
                    r'for\s*\([^;]*;\s*\w+\s*<\s*\w+\s*\+\s*\w+',  # loop bounds
                    # Size calculations without bounds checking
                    r'sizeof\s*\([^)]*\)\s*\*\s*\w+',
                ],
                'severity': 'Medium',
                'title': 'A04:2021 - Integer Overflow Vulnerabilities',
                'cvss_vector': {'AV': 'L', 'AC': 'H', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'L'},
                'description': '''Integer overflow vulnerabilities occur when arithmetic operations exceed the maximum value that can be stored in an integer type.

IMPACT: Buffer overflows, memory corruption, unexpected program behavior.

RECOMMENDATION: Use safe integer libraries, validate arithmetic operations, check for overflow conditions.''',
                'contextual_explanation': self._get_integer_overflow_explanation
            },

            # Race Conditions and TOCTOU
            'race_conditions': {
                'patterns': [
                    # Time-of-check-time-of-use patterns
                    r'access\s*\([^)]*\)\s*;[^}]*open\s*\(',
                    r'stat\s*\([^)]*\)\s*;[^}]*open\s*\(',
                    r'if\s*\([^}]*access\s*\([^}]*open\s*\(',
                    # File operations without proper locking
                    r'fopen\s*\([^)]*,\s*["\']w["\']\)',
                    r'open\s*\([^,]*,\s*O_CREAT',
                    # Temporary file creation
                    r'tmpnam\s*\(',
                    r'tempnam\s*\(',
                    r'mktemp\s*\(',
                ],
                'severity': 'Medium',
                'title': 'A04:2021 - Race Conditions and TOCTOU',
                'cvss_vector': {'AV': 'L', 'AC': 'H', 'PR': 'L', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'L'},
                'description': '''Race condition vulnerabilities occur when the security of code depends on the timing of events. Time-of-check-time-of-use (TOCTOU) vulnerabilities are a common subclass where file system checks are bypassed.

IMPACT: Privilege escalation, unauthorized file access, data corruption.

RECOMMENDATION: Use atomic operations, proper file locking, avoid TOCTOU patterns, use secure temporary file functions.''',
                'contextual_explanation': self._get_race_condition_explanation
            },

            # Path Traversal and File System Issues
            'path_traversal': {
                'patterns': [
                    # Directory traversal patterns
                    r'fopen\s*\([^)]*\.\./[^)]*\)',
                    r'open\s*\([^)]*\.\./[^)]*\)',
                    r'include\s*\([^)]*\.\./[^)]*\)',
                    r'require\s*\([^)]*\.\./[^)]*\)',
                    # Focus on actual path traversal and suspicious operations
                    r'fopen\s*\([^)]*(?:argv|input|param|user)[^)]*,',  # fopen with user input variables
                    r'open\s*\([^)]*(?:argv|input|param|user)[^)]*,',   # open with user input variables
                    # Unsafe path operations with user input
                    r'chdir\s*\([^)]*(?:argv|input|param|user)[^)]*\)',
                    r'unlink\s*\([^)]*(?:argv|input|param|user)[^)]*\)',
                    r'remove\s*\([^)]*(?:argv|input|param|user)[^)]*\)',
                ],
                'severity': 'High',
                'title': 'A01:2021 - Path Traversal and File System Access',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'L'},
                'description': '''Path traversal vulnerabilities allow attackers to access files and directories outside the intended directory through directory traversal sequences like ../.

IMPACT: Unauthorized file access, information disclosure, file manipulation, system compromise.

RECOMMENDATION: Validate and sanitize file paths, use whitelists, implement proper access controls, avoid user-controlled file paths.''',
                'contextual_explanation': self._get_path_traversal_explanation
            },

            # Unsafe System Calls and Privilege Issues
            'unsafe_system_calls': {
                'patterns': [
                    # Dangerous system calls
                    r'setuid\s*\(\s*0\s*\)',
                    r'seteuid\s*\(\s*0\s*\)',
                    r'setgid\s*\(\s*0\s*\)',
                    r'setegid\s*\(\s*0\s*\)',
                    # Signal handling issues
                    r'signal\s*\(\s*SIGCHLD\s*,\s*SIG_IGN\s*\)',
                    r'signal\s*\([^)]*,\s*SIG_DFL\s*\)',
                    # Unsafe environment usage
                    r'getenv\s*\([^)]*\)(?![^}]*NULL)',
                    r'putenv\s*\([a-zA-Z_]\w*\)',
                    # Process creation without validation
                    r'execve\s*\([a-zA-Z_]\w*',
                    r'execl\s*\([a-zA-Z_]\w*',
                ],
                'severity': 'High',
                'title': 'A05:2021 - Unsafe System Calls and Privilege Management',
                'cvss_vector': {'AV': 'L', 'AC': 'L', 'PR': 'L', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'H'},
                'description': '''Unsafe system calls and improper privilege management can lead to privilege escalation and system compromise.

IMPACT: Privilege escalation, system compromise, unauthorized access, denial of service.

RECOMMENDATION: Follow principle of least privilege, validate system call parameters, use secure alternatives, implement proper error handling.''',
                'contextual_explanation': self._get_unsafe_system_calls_explanation
            },

            # Cryptographic Implementation Issues
            'crypto_implementation': {
                'patterns': [
                    # Weak random number generation
                    r'rand\s*\(\s*\)',
                    r'srand\s*\(\s*time\s*\(',
                    r'random\s*\(\s*\)',
                    # Custom crypto implementations
                    r'for\s*\([^}]*\^\s*[^}]*\+\+',  # XOR loops
                    r'\w+\s*\^=\s*\w+',  # XOR operations
                    r'\w+\[\w+\]\s*\^=\s*\w+',  # Array XOR operations
                    r'\^\s*0x[0-9A-Fa-f]+',  # XOR with hex constants
                    # Hardcoded crypto keys/IVs
                    r'char\s+\w*key\w*\[\]\s*=\s*["\'][^"\']["\']',
                    r'unsigned char\s+\w*iv\w*\[\]\s*=',
                    # Insecure key storage
                    r'memset\s*\([^,]*key[^,]*,\s*0',
                ],
                'severity': 'High',
                'title': 'A02:2021 - Cryptographic Implementation Failures',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'L', 'A': 'N'},
                'description': '''Poor cryptographic implementations including weak random number generation, custom crypto, and insecure key management.

IMPACT: Data exposure, cryptographic bypass, predictable encryption, key recovery.

RECOMMENDATION: Use cryptographically secure random number generators, established crypto libraries, proper key management, secure key erasure.''',
                'contextual_explanation': self._get_crypto_implementation_explanation
            },

            # Dependencies are now extracted and listed for manual review
            # No longer treated as vulnerability findings to avoid false positives

            # Debug Code - Informational Findings (CVSS 0.0)
            'debug_code_informational': {
                'patterns': [
                    # Debug statements and flags
                    r'console\.log\s*\(',
                    r'System\.out\.println\s*\(',
                    r'print\s*\(',
                    r'printf\s*\(',
                    r'fprintf\s*\(.*stderr',
                    r'DEBUG\s*=\s*[Tt]rue',
                    r'debug\s*=\s*[Tt]rue',
                    r'VERBOSE\s*=\s*[Tt]rue',
                    r'verbose\s*=\s*[Tt]rue',
                    # Debug comments
                    r'//\s*(?:DEBUG|TODO|FIXME|HACK|XXX)',
                    r'/\*\s*(?:DEBUG|TODO|FIXME|HACK|XXX)',
                    r'#\s*(?:DEBUG|TODO|FIXME|HACK|XXX)',
                    # Debug libraries and imports
                    r'import\s+(?:pdb|ipdb|debugpy|pydevd)',
                    r'from\s+(?:pdb|ipdb|debugpy|pydevd)',
                    r'require\s*\(["\']debug["\']\)',
                    r'import\s+["\']debug["\']',
                    # Debugging breakpoints
                    r'debugger;',
                    r'pdb\.set_trace\(\)',
                    r'ipdb\.set_trace\(\)',
                    r'breakpoint\(\)',
                    # Test/development markers
                    r'//\s*(?:TEMP|TEMPORARY|REMOVE|DELETE)',
                    r'/\*\s*(?:TEMP|TEMPORARY|REMOVE|DELETE)',
                    r'#\s*(?:TEMP|TEMPORARY|REMOVE|DELETE)'
                ],
                'severity': 'Informational',
                'title': 'Informational - Debug Code and Development Artifacts',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'N', 'I': 'N', 'A': 'N'},
                'description': '''Debug code and development artifacts found in source code. While not direct security vulnerabilities, these may indicate incomplete development processes or potential information disclosure.

IMPACT: Potential information disclosure, performance impact, unprofessional appearance.

RECOMMENDATION: Remove debug statements before production deployment, use proper logging frameworks, implement build processes to strip debug code.''',
                'contextual_explanation': self._get_debug_code_explanation
            },
            
            # Dependency Vulnerability Patterns (dynamically added)
            'dependency_vulnerability_critical': {
                'patterns': [],  # No regex patterns - populated dynamically
                'severity': 'Critical',
                'title': 'Critical Dependency Vulnerabilities',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'},
                'description': 'Critical security vulnerabilities found in project dependencies.',
                'contextual_explanation': None  # Handled dynamically
            },
            'dependency_vulnerability_high': {
                'patterns': [],
                'severity': 'High',
                'title': 'High Severity Dependency Vulnerabilities',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'N'},
                'description': 'High severity security vulnerabilities found in project dependencies.',
                'contextual_explanation': None
            },
            'dependency_vulnerability_medium': {
                'patterns': [],
                'severity': 'Medium',
                'title': 'Medium Severity Dependency Vulnerabilities',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'},
                'description': 'Medium severity security vulnerabilities found in project dependencies.',
                'contextual_explanation': None
            },
            'dependency_vulnerability_low': {
                'patterns': [],
                'severity': 'Low',
                'title': 'Low Severity Dependency Vulnerabilities',
                'cvss_vector': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'N', 'A': 'N'},
                'description': 'Low severity security vulnerabilities found in project dependencies.',
                'contextual_explanation': None
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
        # Check for false positives - MongoDB parameterized queries
        if self._is_mongodb_parameterized_query(line_content):
            return None  # Skip this as it's a false positive
        
        # Check for Spring Data JPA parameterized queries
        if self._is_spring_parameterized_query(line_content):
            return None  # Skip this as it's a false positive
            
        explanations = {
            r'SELECT.*\+': "This SQL query concatenates user input directly into the SQL string. An attacker can inject malicious SQL like \"'; DROP TABLE users; --\" to execute arbitrary database commands.",
            r'INSERT.*\+': "String concatenation in INSERT statements allows SQL injection. Attackers can manipulate the VALUES clause to insert malicious data or execute additional SQL commands.",
            r'f".*SELECT': "Python f-strings with user input in SQL queries are vulnerable to injection. If user input contains SQL syntax, it will be executed as code.",
            'innerHTML': "Setting innerHTML with user data allows XSS attacks. Malicious scripts like <script>alert('XSS')</script> will execute in the user's browser.",
            'document.write': "document.write() with user input enables XSS. Attackers can inject JavaScript that steals cookies, redirects users, or performs actions on their behalf.",
            r'exec.*\+': "String concatenation in exec() calls allows command injection. Attackers can append commands like '; rm -rf /' to execute arbitrary system commands.",
            r'system.*\+': "Concatenating user input into system() calls enables command injection, allowing attackers to execute arbitrary operating system commands."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This code allows injection attacks where user input is interpreted as code. The pattern '{matched_text.strip()}' in '{line_content.strip()}' can be exploited."

    def _get_security_misconfiguration_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for security misconfiguration vulnerabilities with production/development context."""
        # Check for false positives - printStackTrace in development/debug contexts
        if self._is_development_printStackTrace(line_content):
            return None  # Skip this as it's a false positive
            
        explanations = {
            'DEBUG.*True': {
                'production': "Debug mode enabled in production exposes sensitive information like stack traces, variable values, database queries, and system internals to attackers. This information can be used to understand the application's structure and find additional vulnerabilities.",
                'dev_mitigation': "If this is development/testing code, ensure debug mode is disabled in production deployments through environment variables or build configurations.",
                'dev_severity': 'Low',
                'dev_finding': True
            },
            r'console\.log\s*\([^)]*(?:password|key|token|secret|credential)': {
                'production': "Console logging of sensitive data like passwords, keys, tokens, or credentials exposes this information in browser developer tools or server logs. Attackers who gain access to logs or can view the browser console can steal these credentials for unauthorized access.",
                'dev_mitigation': "If this is development/debugging code, ensure sensitive data logging is removed before production deployment and use proper logging frameworks with log level controls.",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            r'console\.log\s*\([^)]*(?:database|db_|connection)': {
                'production': "Console logging of database connection details exposes sensitive system information including connection strings, database names, or credentials. This information helps attackers understand the system architecture and potentially access databases.",
                'dev_mitigation': "If this is development/debugging code, ensure database connection details are removed before production and use environment variables for configuration.",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            r'console\.log\s*\([^)]*(?:error|exception|stack)': {
                'production': "Console logging of error details, exceptions, or stack traces can expose internal application structure, file paths, and system internals. This information helps attackers map the application and identify potential attack vectors.",
                'dev_mitigation': "If this is development/debugging code, replace with proper error logging that doesn't expose internal details to end users.",
                'dev_severity': 'Low',
                'dev_finding': True
            },
            r'console\.log\s*\([^)]*(?:user|email|phone)': {
                'production': "Console logging of user data like emails, phone numbers, or personal information violates privacy and can expose sensitive user data to anyone with access to browser developer tools or logs.",
                'dev_mitigation': "If this is development/debugging code, ensure user data logging is removed before production and comply with privacy regulations (GDPR, CCPA).",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            'printStackTrace': {
                'production': "Printing stack traces reveals internal application structure, file paths, class names, method signatures, and potentially sensitive data like database connection strings or API endpoints. Attackers use this information to map the application and identify attack vectors.",
                'dev_mitigation': "If this is development/debugging code, replace with proper logging (logger.error()) that can be controlled via log levels and doesn't expose stack traces to end users.",
                'dev_severity': 'Low',
                'dev_finding': True
            },
            'error_reporting.*E_ALL': {
                'production': "Full error reporting in production exposes detailed system information, file paths, database schemas, and internal application logic. This gives attackers a roadmap of the system's internals and potential vulnerabilities to exploit.",
                'dev_mitigation': "If this is development configuration, ensure error reporting is set to minimal levels in production (E_ERROR only).",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            'print\\s*\\([^)]*(?:password|key|token|secret|credential)': {
                'production': "Print statements containing sensitive data like passwords, keys, tokens, or credentials expose this information to logs, console output, or error streams. Attackers who gain access to logs can steal these credentials for unauthorized access.",
                'dev_mitigation': "If this is development/debugging code, ensure sensitive data printing is removed before production deployment.",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            'print\\s*\\([^)]*(?:database|db_|connection)': {
                'production': "Print statements containing database connection details expose sensitive system information including connection strings, database names, or credentials. This information helps attackers understand the system architecture and potentially access databases.",
                'dev_mitigation': "If this is development/debugging code, ensure database connection details are removed before production.",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            'print\\s*\\([^)]*(?:error|exception|traceback)': {
                'production': "Print statements containing error details, exceptions, or tracebacks can expose internal application structure, file paths, and system internals. This information helps attackers map the application and identify potential attack vectors.",
                'dev_mitigation': "If this is development/debugging code, replace with proper logging that doesn't expose internal details.",
                'dev_severity': 'Low',
                'dev_finding': True
            },
            'print\\s*\\([^)]*(?:debug|DEBUG)': {
                'production': "Print statements containing debug information in production code can expose sensitive system details, internal logic, and debugging data that should not be visible to users or logged in production environments.",
                'dev_mitigation': "If this is development/debugging code, ensure debug prints are removed or controlled via debug flags before production.",
                'dev_severity': 'Low',
                'dev_finding': True
            }
        }
        
        for pattern, explanation_data in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                production_explanation = explanation_data['production']
                dev_mitigation = explanation_data['dev_mitigation']
                dev_severity = explanation_data['dev_severity']
                dev_finding = explanation_data['dev_finding']
                
                result = f"WHY THIS IS VULNERABLE (PRODUCTION CONTEXT): {production_explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}\n\n"
                result += f"DEVELOPMENT/DEBUG MITIGATION: {dev_mitigation}\n"
                
                if dev_finding:
                    result += f"IF IN DEVELOPMENT CONTEXT: Still a finding - Severity would be {dev_severity} (reduced from current severity)"
                else:
                    result += "IF IN DEVELOPMENT CONTEXT: Not a security finding - acceptable for development/debugging purposes"
                
                return result
        
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
        """Provide contextual explanation for cookie security vulnerabilities with production/development context."""
        # Check for false positives - cookie security flags might be set elsewhere
        if self._has_cookie_security_context(line_content):
            return None  # Skip this as security flags might be set elsewhere
            
        explanations = {
            'new.*Cookie.*(?!.*setSecure)': {
                'production': "Cookie created without the 'Secure' flag allows transmission over unencrypted HTTP connections. Attackers on the same network (WiFi, corporate network, or ISP level) can intercept these cookies using packet sniffing tools like Wireshark. Once stolen, attackers can use the session cookies to impersonate the user and gain unauthorized access to their account.",
                'dev_mitigation': "If this is development/testing code running on HTTP, ensure the Secure flag is added before production deployment on HTTPS. Use conditional logic to set Secure flag only in production environments.",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            'new.*Cookie.*(?!.*setHttpOnly)': {
                'production': "Cookie created without the 'HttpOnly' flag can be accessed by client-side JavaScript code. If the application is vulnerable to Cross-Site Scripting (XSS), malicious scripts can steal these cookies using document.cookie and send them to attacker-controlled servers. This allows session hijacking and account takeover attacks.",
                'dev_mitigation': "If this is development/testing code, ensure HttpOnly flag is added before production. This is critical for session cookies regardless of environment.",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            'addCookie.*(?!.*setSecure)': {
                'production': "Cookie added without the 'Secure' flag can be transmitted over insecure HTTP connections. Network attackers can intercept these cookies through man-in-the-middle attacks, packet sniffing, or by downgrading HTTPS connections to HTTP. Stolen session cookies allow attackers to impersonate users and access their accounts.",
                'dev_mitigation': "If this is development/testing code on HTTP, ensure Secure flag is conditionally set for production HTTPS deployments. Consider using environment-based configuration.",
                'dev_severity': 'Medium',
                'dev_finding': True
            },
            'addCookie.*(?!.*setHttpOnly)': {
                'production': "Cookie added without the 'HttpOnly' flag is accessible to JavaScript, making it vulnerable to XSS attacks. Malicious scripts injected through XSS can read these cookies and exfiltrate them to attacker servers. This enables session hijacking, where attackers can use stolen cookies to access user accounts without knowing passwords.",
                'dev_mitigation': "If this is development/testing code, ensure HttpOnly flag is added before production. This protection is essential for session cookies in all environments.",
                'dev_severity': 'Medium',
                'dev_finding': True
            }
        }
        
        for pattern, explanation_data in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                production_explanation = explanation_data['production']
                dev_mitigation = explanation_data['dev_mitigation']
                dev_severity = explanation_data['dev_severity']
                dev_finding = explanation_data['dev_finding']
                
                result = f"WHY THIS IS VULNERABLE (PRODUCTION CONTEXT): {production_explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}\n\n"
                result += f"DEVELOPMENT/DEBUG MITIGATION: {dev_mitigation}\n"
                
                if dev_finding:
                    result += f"IF IN DEVELOPMENT CONTEXT: Still a finding - Severity would be {dev_severity} (same as current severity for cookie security)"
                else:
                    result += "IF IN DEVELOPMENT CONTEXT: Not a security finding - acceptable for development/debugging purposes"
                
                return result
        
        return f"WHY THIS IS VULNERABLE: This cookie lacks proper security flags, making it vulnerable to interception and theft. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should include HttpOnly (prevents JavaScript access) and Secure (prevents transmission over HTTP) flags to protect against session hijacking and XSS attacks."

    def _get_buffer_overflow_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for buffer overflow vulnerabilities."""
        explanations = {
            'gets\\s*\\(': "The gets() function is extremely dangerous as it reads input without bounds checking. Attackers can send more data than the buffer can hold, overwriting adjacent memory including return addresses, function pointers, and other critical data. This can lead to arbitrary code execution, allowing attackers to run malicious code with the same privileges as the vulnerable program.",
            'strcpy\\s*\\(': "strcpy() copies strings without checking destination buffer size. If the source string is longer than the destination buffer, it will overflow and overwrite adjacent memory. Attackers can craft input to overwrite return addresses or function pointers, leading to code execution vulnerabilities.",
            'strcat\\s*\\(': "strcat() concatenates strings without bounds checking. If the combined length exceeds the destination buffer size, memory corruption occurs. This can overwrite critical program data and enable code execution attacks.",
            'sprintf\\s*\\(': "sprintf() formats strings without bounds checking. Long format strings or large values can overflow the destination buffer, corrupting memory and potentially allowing code execution.",
            'scanf.*%s': "Using %s in scanf() without width specifiers allows unlimited input, causing buffer overflows. Attackers can send long strings to overflow buffers and corrupt memory.",
            'alloca\\s*\\(': "alloca() allocates memory on the stack without bounds checking. Large allocations can cause stack overflow, and the memory isn't automatically freed, potentially causing stack corruption."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: This function can cause buffer overflow by writing beyond allocated memory boundaries. The pattern '{matched_text.strip()}' in '{line_content.strip()}' lacks proper bounds checking and can be exploited to corrupt memory and execute arbitrary code."

    def _get_format_string_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for format string vulnerabilities."""
        explanations = {
            'printf\\s*\\(\\s*[a-zA-Z_]': "Using user-controlled data as a format string in printf() allows attackers to read from and write to arbitrary memory locations. Attackers can use format specifiers like %x to leak memory contents or %n to write values to memory addresses, leading to information disclosure or code execution.",
            'sprintf\\s*\\([^,]*,\\s*[a-zA-Z_]': "User-controlled format strings in sprintf() enable memory read/write attacks. Attackers can use %x specifiers to dump stack/heap contents or %n to write arbitrary values to memory, potentially overwriting function pointers or return addresses.",
            'fprintf\\s*\\([^,]*,\\s*[a-zA-Z_]': "Format string vulnerabilities in fprintf() allow attackers to control program execution by reading sensitive memory or writing to arbitrary locations. This can lead to information leakage or code execution.",
            'syslog\\s*\\([^,]*,\\s*[a-zA-Z_]': "User-controlled format strings in syslog() can expose sensitive system information or allow memory corruption attacks through format string exploitation."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: User-controlled format strings allow attackers to read from and write to arbitrary memory locations. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should use a literal format string instead of user input."

    def _get_memory_management_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for memory management vulnerabilities."""
        explanations = {
            'free\\s*\\([^;]*\\);[^}]*free': "Double-free vulnerabilities occur when free() is called twice on the same memory pointer. This corrupts the heap metadata and can lead to arbitrary code execution. Attackers can exploit this by controlling heap layout to overwrite function pointers or other critical data.",
            'free\\s*\\([^;]*\\);[^}]*\\*\\s*\\w+': "Use-after-free vulnerabilities happen when memory is accessed after being freed. The freed memory may be reallocated and contain attacker-controlled data, leading to information disclosure or code execution when the stale pointer is dereferenced.",
            'malloc\\s*\\([^;]*\\);(?![^}]*free)': "Memory leaks occur when dynamically allocated memory is not freed. While not directly exploitable, memory leaks can lead to denial of service by exhausting available memory, causing the application to crash or become unresponsive.",
            '\\*\\s*\\w+\\s*;[^}]*if\\s*\\(\\s*\\w+\\s*==\\s*NULL': "Null pointer dereference after use indicates a time-of-check-time-of-use (TOCTOU) vulnerability. The pointer is used before being checked for NULL, which can cause crashes or potentially exploitable conditions."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: Improper memory management can lead to crashes, information disclosure, or code execution. The pattern '{matched_text.strip()}' in '{line_content.strip()}' indicates unsafe memory handling that should be reviewed and fixed."

    def _get_integer_overflow_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for integer overflow vulnerabilities."""
        explanations = {
            'malloc\\s*\\(\\s*\\w+\\s*\\*\\s*\\w+': "Integer overflow in malloc() size calculation can result in allocating less memory than expected. If the multiplication overflows, a small buffer is allocated but the program assumes it's larger, leading to heap buffer overflows when writing data.",
            '\\w+\\s*\\+\\s*\\w+\\s*\\*': "Arithmetic operations without overflow checking can wrap around to small values. This can cause buffer overflows if the result is used for memory allocation or array indexing.",
            'for\\s*\\([^;]*;\\s*\\w+\\s*<\\s*\\w+\\s*\\+': "Loop bounds calculated with addition can overflow, causing infinite loops or buffer overflows if the overflow results in a smaller boundary value than expected."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: Integer overflow can cause unexpected behavior including buffer overflows and infinite loops. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should include overflow checking to prevent exploitation."

    def _get_race_condition_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for race condition vulnerabilities."""
        explanations = {
            'access\\s*\\([^)]*\\)\\s*;[^}]*open': "Time-of-check-time-of-use (TOCTOU) vulnerability where file permissions are checked with access() but then the file is opened later. Between these calls, an attacker can replace the file with a symlink to a sensitive file, bypassing the permission check.",
            'stat\\s*\\([^)]*\\)\\s*;[^}]*open': "TOCTOU race condition where file attributes are checked with stat() before opening. An attacker can replace the file between the check and use, potentially accessing unauthorized files.",
            'tmpnam\\s*\\(': "tmpnam() creates predictable temporary file names that attackers can guess. This allows symlink attacks where attackers create files with the predicted names, leading to unauthorized file access or data corruption.",
            'mktemp\\s*\\(': "mktemp() creates temporary files with predictable names and has inherent race conditions. Attackers can predict the filename and create malicious files, leading to security vulnerabilities."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: Race condition vulnerabilities occur when security depends on timing. The pattern '{matched_text.strip()}' in '{line_content.strip()}' creates a window where attackers can manipulate the system state between operations."

    def _get_path_traversal_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for path traversal vulnerabilities."""
        explanations = {
            'fopen\\s*\\([^)]*\\.\\./': "Directory traversal vulnerability using '../' sequences allows attackers to access files outside the intended directory. Attackers can read sensitive system files, configuration files, or other application data by navigating up the directory tree.",
            'fopen\\s*\\(\\s*[a-zA-Z_]\\w*\\s*,': "User-controlled file path in fopen() allows attackers to specify arbitrary files to open. Without proper validation, attackers can read sensitive files, overwrite critical system files, or access unauthorized data.",
            'unlink\\s*\\([a-zA-Z_]\\w*\\)': "User-controlled file deletion allows attackers to delete arbitrary files on the system. This can lead to denial of service, data loss, or system compromise by removing critical system files.",
            'chdir\\s*\\([a-zA-Z_]\\w*\\)': "User-controlled directory changes can allow attackers to manipulate the application's working directory, potentially affecting subsequent file operations and leading to unauthorized file access."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: Path traversal vulnerabilities allow access to files outside intended directories. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should validate and sanitize file paths to prevent unauthorized access."

    def _get_unsafe_system_calls_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for unsafe system call vulnerabilities."""
        explanations = {
            'setuid\\s*\\(\\s*0\\s*\\)': "Setting UID to 0 (root) grants the process full administrative privileges. If the application is compromised, attackers gain complete system control. This violates the principle of least privilege and creates unnecessary security risks.",
            'getenv\\s*\\([^)]*\\)(?![^}]*NULL)': "Using environment variables without NULL checking can cause crashes if the variable doesn't exist. Additionally, environment variables can be controlled by attackers in some contexts, leading to injection attacks or unexpected behavior.",
            'execve\\s*\\([a-zA-Z_]\\w*': "Executing programs with user-controlled paths allows command injection attacks. Attackers can specify malicious executables or use path traversal to execute unintended programs with the application's privileges.",
            'signal\\s*\\(\\s*SIGCHLD\\s*,\\s*SIG_IGN\\s*\\)': "Ignoring SIGCHLD signals can lead to zombie processes that consume system resources. This can cause denial of service by exhausting process table entries."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: Unsafe system calls can lead to privilege escalation and system compromise. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should be reviewed for security implications and proper error handling."

    def _get_crypto_implementation_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for cryptographic implementation vulnerabilities."""
        explanations = {
            'rand\\s*\\(\\s*\\)': "The rand() function produces predictable pseudo-random numbers that are not cryptographically secure. Attackers can predict the sequence, making it unsuitable for generating keys, tokens, or other security-critical random values.",
            'srand\\s*\\(\\s*time\\s*\\(': "Seeding random number generator with time() creates predictable sequences since time values are easily guessable. This makes generated keys, tokens, or nonces vulnerable to prediction attacks.",
            '\\w+\\s*\\^=\\s*\\w+': "Simple XOR operations for encryption are easily breakable, especially with known plaintext attacks. XOR encryption without proper key management and randomization provides minimal security and can be easily reversed.",
            'char\\s+\\w*key\\w*\\[\\]\\s*=': "Hardcoded cryptographic keys in source code are visible to anyone with code access and cannot be rotated without code changes. This violates fundamental cryptographic principles and makes the encryption easily breakable."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return f"WHY THIS IS VULNERABLE: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}"
        
        return f"WHY THIS IS VULNERABLE: Poor cryptographic implementation can lead to data exposure and security bypass. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should use established cryptographic libraries and secure practices."

    def _get_outdated_dependencies_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for outdated dependency vulnerabilities with production/development context."""
        explanations = {
            r'"(?:lodash|moment|jquery|express|request|handlebars|marked|serialize-javascript)"': {
                'production': "JavaScript/Node.js dependency with known security vulnerabilities. Outdated versions may contain unpatched security flaws that attackers can exploit for remote code execution, cross-site scripting, or data theft.",
                'dev_mitigation': "If this is development code, ensure dependencies are updated to latest secure versions before production deployment. Use npm audit or yarn audit to identify vulnerabilities.",
                'dev_severity': 'High',
                'dev_finding': True
            },
            r'(?:django|flask|requests|urllib3|pillow|pyyaml|jinja2|cryptography)': {
                'production': "Python dependency with potential security vulnerabilities. Outdated versions may contain known security flaws including injection vulnerabilities, deserialization attacks, or cryptographic weaknesses.",
                'dev_mitigation': "If this is development code, update to latest secure versions and use tools like safety or pip-audit to scan for known vulnerabilities before production.",
                'dev_severity': 'High',
                'dev_finding': True
            },
            r'<artifactId>(?:struts|spring-core|log4j|jackson|commons|xerces)</artifactId>': {
                'production': "Java dependency with known security vulnerabilities. Components like Log4j, Struts, and Jackson have had critical vulnerabilities including remote code execution flaws that can completely compromise applications.",
                'dev_mitigation': "If this is development code, ensure all Java dependencies are updated to latest secure versions and use OWASP Dependency Check before production deployment.",
                'dev_severity': 'Critical',
                'dev_finding': True
            },
            r'gem\s+["\'](?:rails|devise|nokogiri|ffi|loofah)["\']': {
                'production': "Ruby gem with potential security vulnerabilities. Outdated gems may contain security flaws including XML external entity (XXE) attacks, SQL injection, or authentication bypass vulnerabilities.",
                'dev_mitigation': "If this is development code, update gems to latest secure versions and use bundle audit to identify vulnerabilities before production.",
                'dev_severity': 'High',
                'dev_finding': True
            },
            r'<version>[^<]*(?:SNAPSHOT|RELEASE|LATEST)[^<]*</version>': {
                'production': "Dynamic version references (SNAPSHOT, LATEST, RELEASE) in dependencies can introduce unpredictable security vulnerabilities as they may pull in untested or vulnerable versions without explicit control.",
                'dev_mitigation': "If this is development code, pin to specific secure versions before production to ensure reproducible and secure builds.",
                'dev_severity': 'Medium',
                'dev_finding': True
            }
        }
        
        for pattern, explanation_data in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                production_explanation = explanation_data['production']
                dev_mitigation = explanation_data['dev_mitigation']
                dev_severity = explanation_data['dev_severity']
                dev_finding = explanation_data['dev_finding']
                
                result = f"WHY THIS IS VULNERABLE (PRODUCTION CONTEXT): {production_explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}\n\n"
                result += f"DEVELOPMENT/DEBUG MITIGATION: {dev_mitigation}\n"
                
                if dev_finding:
                    result += f"IF IN DEVELOPMENT CONTEXT: Still a finding - Severity would be {dev_severity} (dependency vulnerabilities are critical regardless of environment)"
                else:
                    result += "IF IN DEVELOPMENT CONTEXT: Not a security finding - acceptable for development/debugging purposes"
                
                return result
        
        return f"WHY THIS IS VULNERABLE: This dependency may contain known security vulnerabilities. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should be updated to the latest secure version and regularly monitored for security advisories."

    def _get_debug_code_explanation(self, matched_text: str, line_content: str) -> str:
        """Provide contextual explanation for debug code informational findings."""
        explanations = {
            r'console\.log\s*\(': "Console logging statements found in source code. While not a direct security vulnerability, these may expose sensitive information in browser developer tools or server logs if not properly controlled.",
            r'System\.out\.println\s*\(': "Debug print statements found in Java code. These may expose internal application state or sensitive data to logs and should be removed or replaced with proper logging frameworks.",
            r'print\s*\(': "Print statements found in source code. These may expose sensitive information to console output or logs and should be replaced with proper logging mechanisms.",
            r'DEBUG\s*=\s*[Tt]rue': "Debug flag enabled in source code. This may expose additional information or functionality that should not be available in production environments.",
            r'//\s*(?:DEBUG|TODO|FIXME|HACK|XXX)': "Development comments found indicating incomplete or temporary code. These suggest areas that may need attention before production deployment.",
            r'import\s+(?:pdb|ipdb|debugpy|pydevd)': "Debug library imports found in Python code. These debugging tools should not be included in production code as they may allow unauthorized access to application internals.",
            r'debugger;': "JavaScript debugger statement found. This will cause browsers to break into the debugger and should be removed from production code.",
            r'pdb\.set_trace\(\)': "Python debugger breakpoint found. This will halt execution and drop into an interactive debugger, which should not occur in production.",
            r'//\s*(?:TEMP|TEMPORARY|REMOVE|DELETE)': "Temporary code markers found indicating code that was intended to be removed. This suggests incomplete development or testing artifacts."
        }
        
        for pattern, explanation in explanations.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                result = f"INFORMATIONAL FINDING: {explanation} In this specific code: '{matched_text.strip()}' - {line_content.strip()}\n\n"
                result += "RECOMMENDATION: Review and remove debug code before production deployment. Use proper logging frameworks with configurable log levels instead of debug prints.\n"
                result += "DEVELOPMENT CONTEXT: This is normal in development but should be cleaned up for production releases."
                return result
        
        return f"INFORMATIONAL FINDING: Debug or development artifact found in source code. The pattern '{matched_text.strip()}' in '{line_content.strip()}' should be reviewed and potentially removed before production deployment."

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
    
    def _is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file that should have different scanning rules."""
        file_path_lower = file_path.lower()
        test_indicators = [
            '/test/', '/tests/', '\\test\\', '\\tests\\',
            'test.', 'tests.', '_test.', '_tests.',
            'spec.', '_spec.', '.spec.', '.test.',
            'testcase', 'unittest', 'integrationtest'
        ]
        return any(indicator in file_path_lower for indicator in test_indicators)
    
    def _is_c_cpp_file(self, file_path: str) -> bool:
        """Check if a file is a C/C++ file that should have memory management checks."""
        c_cpp_extensions = {'.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'}
        return Path(file_path).suffix.lower() in c_cpp_extensions
    
    def _is_mongodb_parameterized_query(self, line_content: str) -> bool:
        """Check if this is a safe MongoDB parameterized query."""
        # MongoDB queries with parameter placeholders like ?0, ?1, ?2, etc.
        mongodb_patterns = [
            r'@Query\s*\(\s*["\'].*\?\d+.*["\']\s*\)',  # @Query with ?0, ?1 parameters
            r'\{[^}]*\?\d+[^}]*\}',  # MongoDB query with ?0, ?1 parameters
            r'Query\s*\(\s*["\'].*\?\d+.*["\']\s*\)'  # Query annotation with parameters
        ]
        return any(re.search(pattern, line_content, re.IGNORECASE) for pattern in mongodb_patterns)
    
    def _is_spring_parameterized_query(self, line_content: str) -> bool:
        """Check if this is a safe Spring Data parameterized query."""
        # Spring Data JPA parameterized queries
        spring_patterns = [
            r'@Query\s*\(\s*["\'].*:\w+.*["\']\s*\)',  # @Query with :parameter
            r'@Query\s*\(\s*["\'].*\?\d+.*["\']\s*\)',  # @Query with ?1, ?2 parameters
            r'createQuery\s*\([^)]*:\w+',  # createQuery with named parameters
            r'createNativeQuery\s*\([^)]*\?\d+'  # createNativeQuery with positional parameters
        ]
        return any(re.search(pattern, line_content, re.IGNORECASE) for pattern in spring_patterns)
    
    def _is_development_printStackTrace(self, line_content: str) -> bool:
        """Check if printStackTrace is in a development/debug context."""
        # Check for development/debug context indicators
        development_indicators = [
            r'if\s*\(.*debug.*\)',  # if (debug) context
            r'if\s*\(.*DEBUG.*\)',  # if (DEBUG) context
            r'catch\s*\([^)]*\)\s*\{[^}]*printStackTrace',  # Simple catch block with only printStackTrace
            r'//.*debug',  # Debug comment
            r'//.*test',   # Test comment
            r'/\*.*debug.*\*/',  # Debug block comment
            r'System\.out\.println.*printStackTrace',  # Debug print with printStackTrace
            r'logger\.debug.*printStackTrace'  # Debug logging with printStackTrace
        ]
        
        # If it's in a simple catch block with only printStackTrace, it's likely debug code
        if re.search(r'catch\s*\([^)]*\)\s*\{\s*[^}]*printStackTrace\s*\(\s*\)\s*;\s*\}', line_content, re.IGNORECASE):
            return True
            
        return any(re.search(pattern, line_content, re.IGNORECASE) for pattern in development_indicators)
    
    def _has_cookie_security_context(self, line_content: str) -> bool:
        """Check if cookie security flags might be set elsewhere in the context."""
        # Check for indicators that security flags are handled elsewhere
        security_context_indicators = [
            r'Cookie.*cookie\s*=.*new.*Cookie',  # Cookie variable assignment
            r'cookie\.setSecure\s*\(',  # Security flag being set
            r'cookie\.setHttpOnly\s*\(',  # HttpOnly flag being set
            r'@CookieValue',  # Spring annotation handling
            r'CookieBuilder',  # Cookie builder pattern
            r'withSecure\s*\(',  # Builder pattern with security
            r'httpOnly\s*\(',  # Builder pattern with httpOnly
            r'secure\s*\(',  # Builder pattern with secure
            r'SessionCookieConfig',  # Session cookie configuration
            r'CookieSecure',  # Security configuration
        ]
        
        return any(re.search(pattern, line_content, re.IGNORECASE) for pattern in security_context_indicators)

    def _extract_dependencies_from_file(self, file_path: str) -> None:
        """Extract dependencies from various dependency files for manual review."""
        file_name = os.path.basename(file_path).lower()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Extract dependencies based on file type
            if file_name == 'package.json':
                self._extract_npm_dependencies(file_path, content)
            elif file_name in ['requirements.txt', 'requirements-dev.txt', 'requirements-test.txt']:
                self._extract_python_dependencies(file_path, content)
            elif file_name == 'pom.xml':
                self._extract_maven_dependencies(file_path, content)
            elif file_name == 'gemfile':
                self._extract_ruby_dependencies(file_path, content)
            elif file_name == 'composer.json':
                self._extract_composer_dependencies(file_path, content)
            elif file_name == 'go.mod':
                self._extract_go_dependencies(file_path, content)
            elif file_name == 'cargo.toml':
                self._extract_rust_dependencies(file_path, content)
            elif file_name.endswith('.gradle') or file_name == 'build.gradle':
                self._extract_gradle_dependencies(file_path, content)
                
        except Exception as e:
            # Silently skip files that can't be read
            pass
    
    def _extract_npm_dependencies(self, file_path: str, content: str) -> None:
        """Extract dependencies from package.json."""
        import json
        try:
            data = json.loads(content)
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        self.extracted_dependencies.append({
                            'file': file_path,
                            'type': 'npm',
                            'name': name,
                            'version': version,
                            'category': dep_type
                        })
        except:
            pass
    
    def _extract_python_dependencies(self, file_path: str, content: str) -> None:
        """Extract dependencies from requirements.txt files."""
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Parse requirements.txt format: package==version or package>=version
                match = re.match(r'^([a-zA-Z0-9_-]+)([><=!]+)([0-9.]+)', line)
                if match:
                    name, operator, version = match.groups()
                    self.extracted_dependencies.append({
                        'file': file_path,
                        'type': 'python',
                        'name': name,
                        'version': f'{operator}{version}',
                        'category': 'dependency'
                    })
    
    def _extract_maven_dependencies(self, file_path: str, content: str) -> None:
        """Extract dependencies from pom.xml."""
        # Simple regex-based extraction for Maven dependencies
        dependency_pattern = r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>'
        matches = re.findall(dependency_pattern, content, re.DOTALL)
        for group_id, artifact_id, version in matches:
            self.extracted_dependencies.append({
                'file': file_path,
                'type': 'maven',
                'name': f'{group_id.strip()}:{artifact_id.strip()}',
                'version': version.strip(),
                'category': 'dependency'
            })
    
    def _extract_ruby_dependencies(self, file_path: str, content: str) -> None:
        """Extract dependencies from Gemfile."""
        gem_pattern = r'gem\s+["\']([^"\+]+)["\'](?:\s*,\s*["\']([^"\+]+)["\'])?'
        matches = re.findall(gem_pattern, content)
        for name, version in matches:
            self.extracted_dependencies.append({
                'file': file_path,
                'type': 'ruby',
                'name': name,
                'version': version if version else 'latest',
                'category': 'dependency'
            })
    
    def _extract_composer_dependencies(self, file_path: str, content: str) -> None:
        """Extract dependencies from composer.json."""
        import json
        try:
            data = json.loads(content)
            for dep_type in ['require', 'require-dev']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        if not name.startswith('php'):  # Skip PHP version requirements
                            self.extracted_dependencies.append({
                                'file': file_path,
                                'type': 'composer',
                                'name': name,
                                'version': version,
                                'category': dep_type
                            })
        except:
            pass
    
    def _extract_go_dependencies(self, file_path: str, content: str) -> None:
        """Extract dependencies from go.mod."""
        require_pattern = r'require\s+([^\s]+)\s+([^\s]+)'
        matches = re.findall(require_pattern, content)
        for name, version in matches:
            self.extracted_dependencies.append({
                'file': file_path,
                'type': 'go',
                'name': name,
                'version': version,
                'category': 'dependency'
            })
    
    def _extract_rust_dependencies(self, file_path: str, content: str) -> None:
        """Extract dependencies from Cargo.toml."""
        # Simple pattern for [dependencies] section
        in_dependencies = False
        for line in content.split('\n'):
            line = line.strip()
            if line == '[dependencies]':
                in_dependencies = True
                continue
            elif line.startswith('[') and line.endswith(']'):
                in_dependencies = False
                continue
            
            if in_dependencies and '=' in line:
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line)
                if match:
                    name, version = match.groups()
                    self.extracted_dependencies.append({
                        'file': file_path,
                        'type': 'rust',
                        'name': name,
                        'version': version,
                        'category': 'dependency'
                    })
    
    def _extract_gradle_dependencies(self, file_path: str, content: str) -> None:
        """Extract dependencies from build.gradle."""
        gradle_pattern = r'(?:implementation|compile|api|testImplementation)\s+["\']([^:]+):([^:]+):([^"\+]+)["\']'
        matches = re.findall(gradle_pattern, content)
        for group, artifact, version in matches:
            self.extracted_dependencies.append({
                'file': file_path,
                'type': 'gradle',
                'name': f'{group}:{artifact}',
                'version': version,
                'category': 'dependency'
            })

    def scan_file(self, file_path: str) -> None:
        """Scan a single file for vulnerabilities with CVSS scoring and contextual explanations."""
        # Check file type for language-specific rules
        is_test_file = self._is_test_file(file_path)
        is_c_cpp_file = self._is_c_cpp_file(file_path)
        
        # Extract dependencies if this is a dependency file
        self._extract_dependencies_from_file(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                for vuln_type, vuln_data in self.vulnerability_patterns.items():
                    # Skip hardcoded secrets detection in test files
                    if is_test_file and vuln_type == 'hardcoded_secrets':
                        continue
                    
                    # Skip C/C++ memory management patterns for non-C/C++ files
                    c_cpp_patterns = {'buffer_overflow', 'memory_management', 'integer_overflow', 'race_conditions', 'path_traversal_c', 'unsafe_system_calls', 'crypto_implementation'}
                    if not is_c_cpp_file and vuln_type in c_cpp_patterns:
                        continue
                        
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
        """Recursively scan directory for vulnerabilities with progress tracking."""
        exclude_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 
                       'build', 'dist', '.pytest_cache', '.mypy_cache', 'vendor'}
        
        # Store the base directory for relative path calculation
        self.base_directory = os.path.abspath(directory)
        
        # Show starting message
        print(f"Starting scan on {self.base_directory}")
        
        # First pass: count total files to scan
        total_files = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                file_path = os.path.join(root, file)
                if self._is_text_file(file_path):
                    total_files += 1
        
        if total_files == 0:
            print("No files to scan found.")
            return
            
        # Second pass: scan files with progress
        scanned_files = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                if self._is_text_file(file_path):
                    scanned_files += 1
                    progress = (scanned_files / total_files) * 100
                    
                    # Show progress bar
                    bar_length = 50
                    filled_length = int(bar_length * scanned_files // total_files)
                    bar = '█' * filled_length + '-' * (bar_length - filled_length)
                    print(f'\rProgress: |{bar}| {progress:.1f}% ({scanned_files}/{total_files})', end='', flush=True)
                    
                    if verbose:
                        print(f"\nScanning: {file_path}")
                    
                    self.scan_file(file_path)
        
        print(f"\nScan complete! Processed {scanned_files} files.")

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
                        f"  {first_finding['line']}: >>> {first_finding.get('line_content', first_finding['matched_text'])}",
                        "",
                        first_finding['contextual_explanation'],
                        "",
                        "=" * 80,
                        ""
                    ])
        
        # Dependencies are now only shown if vulnerabilities are found (integrated into findings)
        
        report_content = '\n'.join(report_lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
        
        return report_content
    
    def check_dependency_vulnerabilities(self):
        """Check extracted dependencies for known vulnerabilities."""
        if not self.extracted_dependencies:
            return
        
        # Run vulnerability check
        self.dependency_vulnerabilities = self.dependency_checker.check_dependency_vulnerabilities(
            self.extracted_dependencies
        )
        
        # Convert dependency vulnerabilities to findings format for integration
        if self.dependency_vulnerabilities:
            for vuln in self.dependency_vulnerabilities:
                dep = vuln['dependency']
                
                # Get relative file path for better readability
                file_path = os.path.relpath(dep['file'], self.base_directory) if hasattr(self, 'base_directory') else dep['file']
                
                finding = {
                    'file': dep['file'],
                    'line': 1,  # Dependencies don't have specific line numbers
                    'matched_text': f"Vulnerable dependency: {dep['name']} v{dep['version']} in {file_path} (CVE: {vuln['vulnerability_id']})",
                    'cvss_score': vuln['cvss_score'],
                    'cvss_severity': vuln['severity'],
                    'cvss_vector': f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Network-based dependency vuln
                    'contextual_explanation': self._get_dependency_vulnerability_explanation(vuln)
                }
                
                # Add to findings under a new category
                vuln_category = f"dependency_vulnerability_{vuln['severity'].lower()}"
                if vuln_category not in self.findings:
                    self.findings[vuln_category] = []
                self.findings[vuln_category].append(finding)
    
    def _get_dependency_vulnerability_explanation(self, vuln: Dict) -> str:
        """Generate detailed explanation for dependency vulnerability."""
        dep = vuln['dependency']
        
        # Get relative file path for better readability
        file_path = os.path.relpath(dep['file'], self.base_directory) if hasattr(self, 'base_directory') else dep['file']
        
        explanation = f"""VULNERABLE DEPENDENCY DETECTED

🔍 EVIDENCE:
Dependency: {dep['name']} version {dep['version']}
Found in: {file_path}
Category: {dep.get('category', 'dependency')}

🚨 VULNERABILITY DETAILS:
Vulnerability ID: {vuln['vulnerability_id']}
CVSS Score: {vuln['cvss_score']} ({vuln['severity']})

SUMMARY:
{vuln['summary']}

DETAILS:
{vuln['details'][:500]}{'...' if len(vuln['details']) > 500 else ''}

⚠️ SECURITY IMPACT:
This vulnerable dependency poses a security risk because:
- It contains a known security flaw that attackers can exploit
- The vulnerability could lead to system compromise, data breaches, or service disruption
- Attackers actively scan for applications using known vulnerable dependencies
- The risk exists regardless of whether the vulnerable code path is actively used

🛠️ IMMEDIATE ACTION REQUIRED:
1. Update {dep['name']} to the latest secure version (check for versions > {dep['version']})
2. Review the vulnerability details and assess impact on your application
3. Test the updated dependency thoroughly before deploying
4. Consider implementing automated dependency scanning in your CI/CD pipeline
5. Regularly audit and update all project dependencies

📅 TIMELINE:
Published: {vuln['published']}
Last Modified: {vuln['modified']}
"""
        
        if vuln['aliases']:
            explanation += f"\nALIASES: {', '.join(vuln['aliases'])}"
        
        if vuln['references']:
            explanation += f"\nREFERENCES:\n"
            for ref in vuln['references'][:3]:  # Limit to first 3 references
                explanation += f"- {ref}\n"
        
        explanation += "\nDEVELOPMENT/DEBUG MITIGATION: Even in development, vulnerable dependencies should be updated as they can be exploited in development environments and may be deployed to production.\n"
        explanation += f"IF IN DEVELOPMENT CONTEXT: Still a finding - Severity would be {vuln['severity']} (same as current severity for dependency vulnerabilities)"
        
        return explanation
    
    def display_findings_by_severity(self):
        """Display findings grouped by severity with summary counts."""
        if not any(self.findings.values()):
            print("\n✅ No security vulnerabilities found!")
            return
        
        # Group findings by severity
        severity_groups = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Informational': []}
        
        for vuln_type, findings in self.findings.items():
            if findings:
                vuln_data = self.vulnerability_patterns[vuln_type]
                severity = vuln_data['severity']
                severity_groups[severity].append((vuln_type, vuln_data, findings))
        
        print("\n" + "="*60)
        print("SECURITY FINDINGS BY SEVERITY")
        print("="*60)
        
        # Display findings by severity
        total_findings = 0
        severity_counts = {}
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            if severity_groups[severity]:
                if severity == 'Informational':
                    print(f"\n📋 {severity.upper()} FINDINGS")
                else:
                    print(f"\n🚨 {severity.upper()} SEVERITY")
                print("-" * 40)
                
                severity_count = 0
                for vuln_type, vuln_data, findings in severity_groups[severity]:
                    finding_count = len(findings)
                    severity_count += finding_count
                    
                    print(f"\n• {vuln_data['title']}")
                    print(f"  Instances: {finding_count}")
                    
                    # Show affected files (up to 5)
                    files_affected = list(set(f['file'] for f in findings))
                    if len(files_affected) <= 5:
                        for file_path in files_affected:
                            lines = [str(f['line']) for f in findings if f['file'] == file_path]
                            print(f"    - {file_path} (lines: {', '.join(lines)})")
                    else:
                        print(f"    - {len(files_affected)} files affected")
                
                severity_counts[severity] = severity_count
                total_findings += severity_count
        
        # Summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Total findings: {total_findings}")
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            if severity in severity_counts:
                print(f"{severity}: {severity_counts[severity]}")
        
        print(f"\n📄 Detailed report saved to: review_that_code_security_report.txt")

    def display_extracted_dependencies(self):
        """Display extracted dependencies for manual review."""
        if not self.extracted_dependencies:
            return
        
        print("\n" + "="*60)
        print("📦 DEPENDENCIES FOUND (FOR MANUAL REVIEW)")
        print("="*60)
        
        # Group dependencies by type
        deps_by_type = {}
        for dep in self.extracted_dependencies:
            dep_type = dep['type']
            if dep_type not in deps_by_type:
                deps_by_type[dep_type] = []
            deps_by_type[dep_type].append(dep)
        
        total_deps = len(self.extracted_dependencies)
        print(f"Total dependencies found: {total_deps}\n")
        
        for dep_type, deps in sorted(deps_by_type.items()):
            print(f"🔧 {dep_type.upper()} DEPENDENCIES ({len(deps)} found)")
            print("-" * 40)
            
            # Group by file for cleaner display
            files_with_deps = {}
            for dep in deps:
                file_path = os.path.relpath(dep['file'], self.base_directory) if hasattr(self, 'base_directory') else dep['file']
                if file_path not in files_with_deps:
                    files_with_deps[file_path] = []
                files_with_deps[file_path].append(dep)
            
            for file_path, file_deps in sorted(files_with_deps.items()):
                print(f"  📁 {file_path}:")
                for dep in file_deps:
                    category = f" ({dep['category']})" if dep['category'] != 'dependency' else ""
                    print(f"    • {dep['name']} - {dep['version']}{category}")
                print()
        
        print("💡 Review these dependencies for known vulnerabilities using:")
        print("   • npm audit (Node.js)")
        print("   • pip-audit or safety (Python)")
        print("   • OWASP Dependency Check (Java/Maven)")
        print("   • bundle audit (Ruby)")
        print("   • composer audit (PHP)")
        print("   • go list -m all && go mod tidy (Go)")
        print("   • cargo audit (Rust)")

def main():
    parser = argparse.ArgumentParser(description='review_that_code - OWASP Vulnerability Scanner with CVSSv3.1 Scoring')
    parser.add_argument('target', help='Target directory or file to scan')
    parser.add_argument('--output', '-o', help='Output file for the report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = EnhancedOWASPScanner()
    
    # Scan files
    if os.path.isfile(args.target):
        print(f"Starting scan on {os.path.abspath(args.target)}")
        scanner.scan_file(args.target)
        print("Scan complete! Processed 1 file.")
    else:
        scanner.scan_directory(args.target, args.verbose)
    
    # Check dependencies for vulnerabilities
    scanner.check_dependency_vulnerabilities()
    
    # Display findings grouped by severity
    scanner.display_findings_by_severity()
    
    # Generate and save report
    output_file = args.output or 'review_that_code_security_report.txt'
    scanner.generate_report(output_file)

if __name__ == "__main__":
    main()
