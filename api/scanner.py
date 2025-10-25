# api/scanner.py - Vercel Serverless Function
from http.server import BaseHTTPRequestHandler
import json
import sys
import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime, UTC
import re

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.parsed_url = urlparse(target_url)
        self.base_domain = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def scan(self):
        """Perform comprehensive vulnerability scan"""
        # Execute all scan modules
        self.check_https()
        self.check_security_headers()
        self.check_exposed_paths()
        self.check_information_disclosure()
        self.check_cookies()
        self.check_ssl_tls()
        self.check_cors_misconfiguration()
        self.check_content_security_policy()
        self.check_common_vulnerabilities()
        self.check_server_configuration()
        self.check_http_methods()
        self.check_open_redirects()
        self.check_subdomain_takeover()
        self.check_email_disclosure()
        
        return {
            'targetUrl': self.target_url,
            'scanTime': datetime.now(UTC).isoformat(),
            'vulnerabilitiesFound': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'scanStatus': 'completed',
            'summary': self._generate_summary()
        }
    
    def add_vulnerability(self, vuln_type, severity, title, description, 
                         affected_url, recommendation, attack_scenarios, 
                         cvss_score=None, cwe_id=None):
        """Add vulnerability with full details"""
        self.vulnerabilities.append({
            'type': vuln_type,
            'severity': severity,
            'title': title,
            'description': description,
            'affectedUrl': affected_url,
            'recommendation': recommendation,
            'attackScenarios': attack_scenarios,
            'cvssScore': cvss_score,
            'cweId': cwe_id,
            'timestamp': datetime.now(UTC).isoformat()
        })
    
    # ==================== SCAN MODULES ====================
    
    def check_https(self):
        """Check HTTPS implementation"""
        if not self.target_url.startswith('https://'):
            self.add_vulnerability(
                vuln_type='INSECURE_PROTOCOL',
                severity='HIGH',
                title='Website Not Using HTTPS',
                description='The website is accessible over unencrypted HTTP protocol, allowing attackers to intercept and modify traffic.',
                affected_url=self.target_url,
                recommendation='Implement SSL/TLS certificate and redirect all HTTP traffic to HTTPS. Use Let\'s Encrypt for free certificates.',
                attack_scenarios=[
                    'Man-in-the-Middle (MITM) Attack: Intercept communication between user and server',
                    'Session Hijacking: Steal session cookies transmitted in plain text',
                    'Credential Theft: Capture usernames and passwords during login',
                    'Data Modification: Alter requests/responses in transit',
                    'WiFi Eavesdropping: Monitor all traffic on public networks'
                ],
                cvss_score=7.4,
                cwe_id='CWE-319'
            )
    
    def check_security_headers(self):
        """Check for missing security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            # X-Content-Type-Options
            if 'X-Content-Type-Options' not in headers:
                self.add_vulnerability(
                    vuln_type='MISSING_SECURITY_HEADER',
                    severity='MEDIUM',
                    title='Missing X-Content-Type-Options Header',
                    description='Browser can interpret files as different MIME type than declared, enabling XSS attacks.',
                    affected_url=self.target_url,
                    recommendation='Add header: X-Content-Type-Options: nosniff',
                    attack_scenarios=[
                        'MIME Sniffing Attack: Upload malicious file as image, browser executes as script',
                        'XSS via File Upload: Bypass upload restrictions using MIME confusion',
                        'Drive-by Download: Force browser to execute malicious content'
                    ],
                    cvss_score=5.3,
                    cwe_id='CWE-693'
                )
            
            # X-Frame-Options
            if 'X-Frame-Options' not in headers:
                self.add_vulnerability(
                    vuln_type='MISSING_SECURITY_HEADER',
                    severity='HIGH',
                    title='Missing X-Frame-Options Header',
                    description='Website can be embedded in iframe, enabling clickjacking attacks.',
                    affected_url=self.target_url,
                    recommendation='Add header: X-Frame-Options: DENY or SAMEORIGIN',
                    attack_scenarios=[
                        'Clickjacking: Overlay invisible iframe to trick users into clicking malicious content',
                        'UI Redressing: Make users perform unintended actions (transfer money, change settings)',
                        'Like-jacking: Trick users into liking/sharing content on social media',
                        'Cursorjacking: Change cursor position to manipulate clicks'
                    ],
                    cvss_score=6.5,
                    cwe_id='CWE-1021'
                )
            
            # Strict-Transport-Security
            if self.target_url.startswith('https://') and 'Strict-Transport-Security' not in headers:
                self.add_vulnerability(
                    vuln_type='MISSING_SECURITY_HEADER',
                    severity='HIGH',
                    title='Missing HSTS Header',
                    description='No HTTP Strict Transport Security, allowing SSL stripping attacks.',
                    affected_url=self.target_url,
                    recommendation='Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                    attack_scenarios=[
                        'SSL Stripping: Downgrade HTTPS to HTTP to intercept traffic',
                        'Cookie Hijacking: Steal session cookies over downgraded connection',
                        'First-Visit Attack: Compromise user on first HTTP connection before HTTPS',
                        'Subdomain Takeover: Attack insecure subdomains without HSTS'
                    ],
                    cvss_score=7.4,
                    cwe_id='CWE-523'
                )
            
            # Content-Security-Policy
            if 'Content-Security-Policy' not in headers:
                self.add_vulnerability(
                    vuln_type='MISSING_SECURITY_HEADER',
                    severity='MEDIUM',
                    title='Missing Content Security Policy',
                    description='No CSP header to prevent XSS and data injection attacks.',
                    affected_url=self.target_url,
                    recommendation='Add CSP header with strict policy: Content-Security-Policy: default-src \'self\'; script-src \'self\'',
                    attack_scenarios=[
                        'Cross-Site Scripting (XSS): Inject malicious JavaScript code',
                        'Data Exfiltration: Load external scripts to steal sensitive data',
                        'Cryptojacking: Inject cryptocurrency mining scripts',
                        'Malicious Redirects: Load external resources to phishing sites'
                    ],
                    cvss_score=6.1,
                    cwe_id='CWE-79'
                )
            
            # X-XSS-Protection
            if 'X-XSS-Protection' not in headers:
                self.add_vulnerability(
                    vuln_type='MISSING_SECURITY_HEADER',
                    severity='LOW',
                    title='Missing X-XSS-Protection Header',
                    description='Browser XSS filter not enabled, reducing XSS attack protection.',
                    affected_url=self.target_url,
                    recommendation='Add header: X-XSS-Protection: 1; mode=block',
                    attack_scenarios=[
                        'Reflected XSS: Inject scripts via URL parameters',
                        'DOM-based XSS: Manipulate client-side JavaScript execution'
                    ],
                    cvss_score=5.3,
                    cwe_id='CWE-79'
                )
            
            # Referrer-Policy
            if 'Referrer-Policy' not in headers:
                self.add_vulnerability(
                    vuln_type='MISSING_SECURITY_HEADER',
                    severity='LOW',
                    title='Missing Referrer-Policy Header',
                    description='Referrer information may leak sensitive data to external sites.',
                    affected_url=self.target_url,
                    recommendation='Add header: Referrer-Policy: no-referrer or strict-origin-when-cross-origin',
                    attack_scenarios=[
                        'Information Leakage: Expose sensitive URLs to third-party sites',
                        'Session Token Exposure: Leak tokens in URL to external domains',
                        'User Tracking: Allow cross-site user behavior tracking'
                    ],
                    cvss_score=3.7,
                    cwe_id='CWE-200'
                )
            
            # Permissions-Policy
            if 'Permissions-Policy' not in headers and 'Feature-Policy' not in headers:
                self.add_vulnerability(
                    vuln_type='MISSING_SECURITY_HEADER',
                    severity='LOW',
                    title='Missing Permissions-Policy Header',
                    description='No policy to control browser features and APIs.',
                    affected_url=self.target_url,
                    recommendation='Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()',
                    attack_scenarios=[
                        'Unauthorized Feature Access: Third-party scripts access camera/microphone',
                        'Privacy Violation: Malicious scripts access user location',
                        'Resource Abuse: Unauthorized use of browser features'
                    ],
                    cvss_score=4.3,
                    cwe_id='CWE-250'
                )
                
        except Exception as e:
            pass
    
    def check_exposed_paths(self):
        """Check for exposed sensitive paths"""
        sensitive_paths = {
            '/.git/config': {
                'title': 'Git Repository Exposed',
                'description': 'Git configuration file accessible, exposing source code and credentials.',
                'attack_scenarios': [
                    'Source Code Disclosure: Download entire git repository with git-dumper',
                    'Credential Theft: Extract database credentials and API keys from config files',
                    'Algorithm Analysis: Study code to find logic vulnerabilities',
                    'Backdoor Discovery: Find hidden admin endpoints and debug functions',
                    'Commit History Access: Read sensitive data from old commits'
                ]
            },
            '/.git/HEAD': {
                'title': 'Git HEAD File Exposed',
                'description': 'Git HEAD file accessible, indicating repository exposure.',
                'attack_scenarios': [
                    'Repository Cloning: Clone entire git repository',
                    'Branch Discovery: Identify development branches',
                    'Version History: Access all code versions'
                ]
            },
            '/.env': {
                'title': 'Environment File Exposed',
                'description': 'Environment configuration file exposed with sensitive credentials.',
                'attack_scenarios': [
                    'Database Access: Get database credentials for direct access',
                    'API Key Theft: Steal third-party API keys (AWS, Stripe, Twilio)',
                    'JWT Secret Exposure: Forge authentication tokens',
                    'Email Server Compromise: Access SMTP credentials',
                    'Payment Gateway Access: Steal payment API keys'
                ]
            },
            '/.env.production': {
                'title': 'Production Environment File Exposed',
                'description': 'Production environment configuration accessible.',
                'attack_scenarios': [
                    'Production Credentials: Access production database',
                    'Live API Keys: Steal production API keys',
                    'Infrastructure Access: Gain access to production servers'
                ]
            },
            '/admin': {
                'title': 'Admin Panel Accessible',
                'description': 'Administrative interface publicly accessible without proper protection.',
                'attack_scenarios': [
                    'Brute Force Attack: Attempt to guess admin credentials',
                    'Default Credentials: Try common admin/admin combinations',
                    'Privilege Escalation: Access admin functions if logged in',
                    'Configuration Manipulation: Change critical system settings',
                    'User Data Access: View and modify user information'
                ]
            },
            '/phpinfo.php': {
                'title': 'PHP Info Page Exposed',
                'description': 'PHP configuration details exposed, revealing system information.',
                'attack_scenarios': [
                    'System Reconnaissance: Learn server configuration and versions',
                    'Path Disclosure: Discover file system paths for targeted attacks',
                    'Extension Analysis: Identify installed PHP extensions for exploits',
                    'Security Setting Discovery: Find disabled security functions',
                    'Database Info Leakage: Expose database configuration details'
                ]
            },
            '/wp-admin': {
                'title': 'WordPress Admin Accessible',
                'description': 'WordPress admin login exposed to public.',
                'attack_scenarios': [
                    'Brute Force: Automated password guessing attacks',
                    'XML-RPC Exploitation: Amplify brute force attempts',
                    'Plugin Vulnerabilities: Exploit known WordPress plugin flaws',
                    'User Enumeration: Discover valid usernames for targeted attacks',
                    'Version Detection: Identify WordPress version for known exploits'
                ]
            },
            '/backup': {
                'title': 'Backup Directory Exposed',
                'description': 'Backup files publicly accessible.',
                'attack_scenarios': [
                    'Data Breach: Download database backups with user data',
                    'Source Code Access: Obtain complete application code',
                    'Credential Discovery: Find hardcoded passwords in backups',
                    'Historical Data Access: Access old but sensitive information'
                ]
            },
            '/backup.zip': {
                'title': 'Backup Archive Exposed',
                'description': 'Compressed backup file publicly accessible.',
                'attack_scenarios': [
                    'Complete Site Download: Access entire website backup',
                    'Database Dump Access: Download database exports',
                    'Configuration Files: Access server configuration'
                ]
            },
            '/.htaccess': {
                'title': 'Apache Config Exposed',
                'description': 'Apache configuration file accessible.',
                'attack_scenarios': [
                    'Security Rule Discovery: Bypass security restrictions',
                    'Directory Structure: Map hidden directories and files',
                    'Authentication Bypass: Understand access control rules',
                    'Rewrite Rule Analysis: Find URL manipulation vulnerabilities'
                ]
            },
            '/config.php': {
                'title': 'Configuration File Exposed',
                'description': 'Application configuration file publicly accessible.',
                'attack_scenarios': [
                    'Database Compromise: Access database credentials',
                    'API Key Theft: Steal service integration keys',
                    'Salt/Secret Discovery: Forge sessions and tokens',
                    'Third-party Service Access: Compromise integrated services'
                ]
            },
            '/web.config': {
                'title': 'IIS Configuration Exposed',
                'description': 'IIS web.config file accessible.',
                'attack_scenarios': [
                    'Connection String Exposure: Access database credentials',
                    'Application Settings: Discover sensitive configuration',
                    'Authentication Bypass: Understand security settings'
                ]
            },
            '/.DS_Store': {
                'title': 'macOS Directory Listing Exposed',
                'description': 'macOS .DS_Store file reveals directory structure.',
                'attack_scenarios': [
                    'Directory Enumeration: Discover hidden files and folders',
                    'File Discovery: Find unlinked sensitive files',
                    'Structure Mapping: Understand application architecture'
                ]
            },
            '/composer.json': {
                'title': 'Composer Configuration Exposed',
                'description': 'PHP dependency information exposed.',
                'attack_scenarios': [
                    'Dependency Analysis: Identify vulnerable packages',
                    'Version Detection: Find outdated libraries with known exploits',
                    'Framework Discovery: Understand application stack'
                ]
            },
            '/package.json': {
                'title': 'NPM Configuration Exposed',
                'description': 'Node.js dependency information exposed.',
                'attack_scenarios': [
                    'Package Vulnerability: Identify vulnerable npm packages',
                    'Version Detection: Find exploitable library versions',
                    'Script Discovery: Learn build and deployment scripts'
                ]
            },
            '/robots.txt': {
                'title': 'Robots.txt May Expose Sensitive Paths',
                'description': 'robots.txt may reveal hidden directories.',
                'attack_scenarios': [
                    'Hidden Path Discovery: Find admin and private sections',
                    'Directory Enumeration: Map restricted areas',
                    'Sensitive File Location: Discover backup and config files'
                ]
            },
            '/.svn/entries': {
                'title': 'SVN Repository Exposed',
                'description': 'Subversion repository accessible.',
                'attack_scenarios': [
                    'Source Code Download: Access SVN repository',
                    'Version History: Read code from all revisions',
                    'Credential Exposure: Find credentials in code history'
                ]
            }
        }
        
        for path, info in sensitive_paths.items():
            try:
                test_url = self.base_domain + path
                resp = self.session.get(test_url, timeout=5)
                
                # Special handling for robots.txt
                if path == '/robots.txt' and resp.status_code == 200:
                    # Only flag if it contains potentially sensitive paths
                    if any(keyword in resp.text.lower() for keyword in ['admin', 'backup', 'private', 'secret']):
                        self.add_vulnerability(
                            vuln_type='INFORMATION_DISCLOSURE',
                            severity='LOW',
                            title=info['title'],
                            description=info['description'],
                            affected_url=test_url,
                            recommendation='Review robots.txt and remove references to sensitive directories',
                            attack_scenarios=info['attack_scenarios'],
                            cvss_score=3.7,
                            cwe_id='CWE-200'
                        )
                elif resp.status_code == 200:
                    self.add_vulnerability(
                        vuln_type='EXPOSED_SENSITIVE_PATH',
                        severity='CRITICAL',
                        title=info['title'],
                        description=info['description'],
                        affected_url=test_url,
                        recommendation=f'Restrict access to {path} using .htaccess, web.config, or server configuration. Remove file from public directory.',
                        attack_scenarios=info['attack_scenarios'],
                        cvss_score=9.1,
                        cwe_id='CWE-548'
                    )
            except:
                pass
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Server version disclosure
            if 'Server' in headers:
                server_info = headers['Server']
                self.add_vulnerability(
                    vuln_type='INFORMATION_DISCLOSURE',
                    severity='LOW',
                    title='Server Version Disclosed',
                    description=f'Server header reveals: {server_info}',
                    affected_url=self.target_url,
                    recommendation='Configure server to hide version information in response headers.',
                    attack_scenarios=[
                        'Targeted Exploit: Search for known vulnerabilities in disclosed version',
                        'Attack Fingerprinting: Identify server type for customized attacks',
                        'Automated Scanning: Use version info for automated exploit tools',
                        'Zero-Day Research: Focus on specific server version weaknesses'
                    ],
                    cvss_score=3.1,
                    cwe_id='CWE-200'
                )
            
            # X-Powered-By disclosure
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By']
                self.add_vulnerability(
                    vuln_type='INFORMATION_DISCLOSURE',
                    severity='LOW',
                    title='Technology Stack Disclosed',
                    description=f'X-Powered-By header reveals: {powered_by}',
                    affected_url=self.target_url,
                    recommendation='Remove X-Powered-By header from server configuration.',
                    attack_scenarios=[
                        'Framework Exploit: Target known vulnerabilities in disclosed framework',
                        'Technology-Specific Attack: Use framework-specific attack vectors',
                        'Version-Based Scanning: Automated scanners focus on disclosed technology'
                    ],
                    cvss_score=3.1,
                    cwe_id='CWE-200'
                )
            
            # Check for verbose error messages
            test_url = self.base_domain + '/nonexistent-page-test-12345'
            try:
                error_resp = self.session.get(test_url, timeout=5)
                error_content = error_resp.text.lower()
                
                error_patterns = [
                    ('sql', 'SQL error message'),
                    ('mysql', 'MySQL error message'),
                    ('postgresql', 'PostgreSQL error message'),
                    ('oracle', 'Oracle error message'),
                    ('stack trace', 'Stack trace'),
                    ('exception', 'Exception details'),
                    ('/var/www/', 'File path'),
                    ('c:\\', 'Windows file path'),
                    ('at line', 'Line number disclosure'),
                    ('syntax error', 'Syntax error details')
                ]
                
                for pattern, error_type in error_patterns:
                    if pattern in error_content:
                        self.add_vulnerability(
                            vuln_type='INFORMATION_DISCLOSURE',
                            severity='MEDIUM',
                            title='Verbose Error Messages',
                            description=f'Error pages expose {error_type}, revealing internal application structure.',
                            affected_url=test_url,
                            recommendation='Configure custom error pages without sensitive information. Disable debug mode in production.',
                            attack_scenarios=[
                                'Path Disclosure: Use exposed paths for targeted file access attacks',
                                'SQL Injection: Craft injection payloads based on database errors',
                                'Logic Flow Discovery: Understand application flow from stack traces',
                                'Database Schema Discovery: Learn table and column names from errors'
                            ],
                            cvss_score=5.3,
                            cwe_id='CWE-209'
                        )
                        break
            except:
                pass
                    
        except Exception as e:
            pass
    
    def check_cookies(self):
        """Check cookie security"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            if 'Set-Cookie' in response.headers:
                cookies = response.headers.get('Set-Cookie', '')
                
                # Check Secure flag
                if 'Secure' not in cookies and self.target_url.startswith('https://'):
                    self.add_vulnerability(
                        vuln_type='INSECURE_COOKIE',
                        severity='MEDIUM',
                        title='Cookies Without Secure Flag',
                        description='Session cookies can be transmitted over HTTP, exposing them to interception.',
                        affected_url=self.target_url,
                        recommendation='Add Secure flag to all cookies: Set-Cookie: name=value; Secure',
                        attack_scenarios=[
                            'Cookie Theft: Intercept cookies over insecure connections',
                            'Session Hijacking: Steal session IDs to impersonate users',
                            'Man-in-the-Middle: Capture cookies during HTTP fallback',
                            'Network Sniffing: Capture cookies on compromised WiFi networks'
                        ],
                        cvss_score=5.9,
                        cwe_id='CWE-614'
                    )
                
                # Check HttpOnly flag
                if 'HttpOnly' not in cookies:
                    self.add_vulnerability(
                        vuln_type='INSECURE_COOKIE',
                        severity='MEDIUM',
                        title='Cookies Without HttpOnly Flag',
                        description='Cookies accessible via JavaScript, vulnerable to XSS attacks.',
                        affected_url=self.target_url,
                        recommendation='Add HttpOnly flag: Set-Cookie: name=value; HttpOnly',
                        attack_scenarios=[
                            'XSS Cookie Theft: Steal cookies using JavaScript injection',
                            'Session Hijacking: Use XSS to send cookies to attacker server',
                            'Persistent Account Access: Combine XSS with cookie theft for long-term access',
                            'DOM-Based Cookie Theft: Access cookies through client-side vulnerabilities'
                        ],
                        cvss_score=6.1,
                        cwe_id='CWE-1004'
                    )
                
                # Check SameSite attribute
                if 'SameSite' not in cookies:
                    self.add_vulnerability(
                        vuln_type='INSECURE_COOKIE',
                        severity='MEDIUM',
                        title='Cookies Without SameSite Attribute',
                        description='Cookies vulnerable to Cross-Site Request Forgery (CSRF) attacks.',
                        affected_url=self.target_url,
                        recommendation='Add SameSite attribute: Set-Cookie: name=value; SameSite=Strict or Lax',
                        attack_scenarios=[
                            'CSRF Attack: Perform unauthorized actions on behalf of authenticated users',
                            'Cross-Site Timing Attack: Leak information across different sites',
                            'Login CSRF: Force user to log into attacker-controlled account',
                            'One-Click Attack: Execute actions with single malicious link click'
                        ],
                        cvss_score=6.5,
                        cwe_id='CWE-352'
                    )
                    
        except Exception as e:
            pass
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        if not self.target_url.startswith('https://'):
            return
            
        try:
            hostname = self.parsed_url.netloc.split(':')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                        self.add_vulnerability(
                            vuln_type='WEAK_SSL_TLS',
                            severity='HIGH',
                            title='Outdated SSL/TLS Version',
                            description=f'Server supports weak protocol: {version}',
                            affected_url=self.target_url,
                            recommendation='Disable SSLv2, SSLv3, TLSv1.0, TLSv1.1. Use TLS 1.2+ only.',
                            attack_scenarios=[
                                'POODLE Attack: Exploit SSLv3 padding vulnerability',
                                'BEAST Attack: Exploit TLS 1.0 cipher block chaining',
                                'Protocol Downgrade: Force connection to weak protocol version',
                                'Man-in-the-Middle: Break encryption using known protocol weaknesses'
                            ],
                            cvss_score=7.5,
                            cwe_id='CWE-327'
                        )
                    
                    # Check weak ciphers
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                        
                        for weak in weak_ciphers:
                            if weak.lower() in cipher_name.lower():
                                self.add_vulnerability(
                                    vuln_type='WEAK_CIPHER',
                                    severity='HIGH',
                                    title='Weak Cipher Suite',
                                    description=f'Server uses weak cipher: {cipher_name}',
                                    affected_url=self.target_url,
                                    recommendation='Configure server to use strong ciphers only (AES-256-GCM, ChaCha20-Poly1305)',
                                    attack_scenarios=[
                                        'Cipher Cracking: Break weak encryption algorithms',
                                        'Sweet32 Attack: Exploit 64-bit block ciphers (3DES)',
                                        'RC4 Biases: Exploit known RC4 vulnerabilities',
                                        'Brute Force: Faster cracking of weak encryption'
                                    ],
                                    cvss_score=7.5,
                                    cwe_id='CWE-327'
                                )
                                break
                            
        except Exception as e:
            pass
    
    def check_cors_misconfiguration(self):
        """Check CORS configuration"""
        try:
            # Test with evil origin
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.target_url, headers=headers, timeout=10)
            
            if 'Access-Control-Allow-Origin' in response.headers:
                cors_origin = response.headers['Access-Control-Allow-Origin']
                
                if cors_origin == '*':
                    self.add_vulnerability(
                        vuln_type='CORS_MISCONFIGURATION',
                        severity='HIGH',
                        title='Wildcard CORS Policy',
                        description='CORS policy allows any origin (*), enabling cross-origin attacks.',
                        affected_url=self.target_url,
                        recommendation='Restrict CORS to specific trusted domains only. Never use wildcard (*) for sensitive endpoints.',
                        attack_scenarios=[
                            'Data Theft: Malicious site reads sensitive API responses',
                            'Credential Theft: Steal authentication tokens from API calls',
                            'Cross-Site Request Forgery: Perform actions on behalf of users',
                            'Information Leakage: Access private data from third-party sites'
                        ],
                        cvss_score=7.5,
                        cwe_id='CWE-942'
                    )
                elif cors_origin == 'https://evil.com':
                    self.add_vulnerability(
                        vuln_type='CORS_MISCONFIGURATION',
                        severity='HIGH',
                        title='CORS Reflects Arbitrary Origins',
                        description='Server reflects any origin in CORS headers, allowing unrestricted access.',
                        affected_url=self.target_url,
                        recommendation='Implement whitelist of allowed origins instead of reflecting request origin.',
                        attack_scenarios=[
                            'API Data Exfiltration: Steal API data from attacker-controlled site',
                            'Token Theft: Capture authentication tokens cross-origin',
                            'Privacy Breach: Access user-specific data from malicious domains'
                        ],
                        cvss_score=7.5,
                        cwe_id='CWE-942'
                    )
                    
        except Exception as e:
            pass
    
    def check_content_security_policy(self):
        """Detailed CSP analysis"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            if 'Content-Security-Policy' in response.headers:
                csp = response.headers['Content-Security-Policy']
                
                # Check for unsafe-inline
                if "'unsafe-inline'" in csp:
                    self.add_vulnerability(
                        vuln_type='WEAK_CSP',
                        severity='MEDIUM',
                        title='CSP Allows Inline Scripts',
                        description='Content Security Policy allows unsafe-inline, reducing XSS protection.',
                        affected_url=self.target_url,
                        recommendation='Remove unsafe-inline from CSP. Use nonces or hashes for inline scripts.',
                        attack_scenarios=[
                            'XSS Injection: Inject inline scripts despite CSP presence',
                            'Event Handler Exploitation: Use inline event handlers for XSS',
                            'Style Injection: Inject malicious CSS for UI manipulation'
                        ],
                        cvss_score=5.3,
                        cwe_id='CWE-79'
                    )
                
                # Check for unsafe-eval
                if "'unsafe-eval'" in csp:
                    self.add_vulnerability(
                        vuln_type='WEAK_CSP',
                        severity='MEDIUM',
                        title='CSP Allows Script Evaluation',
                        description='Content Security Policy allows eval(), enabling code injection.',
                        affected_url=self.target_url,
                        recommendation='Remove unsafe-eval from CSP. Avoid using eval() in code.',
                        attack_scenarios=[
                            'Code Injection: Execute arbitrary JavaScript via eval()',
                            'DOM-Based XSS: Exploit eval() with user-controlled input',
                            'Template Injection: Inject code through template engines using eval()'
                        ],
                        cvss_score=5.3,
                        cwe_id='CWE-95'
                    )
                    
        except Exception as e:
            pass
    
    def check_common_vulnerabilities(self):
        """Check for common web vulnerabilities"""
        try:
            # Check for directory listing
            test_paths = ['/images/', '/css/', '/js/', '/uploads/', '/assets/', '/static/']
            for path in test_paths:
                try:
                    test_url = self.base_domain + path
                    resp = self.session.get(test_url, timeout=5)
                    
                    if resp.status_code == 200:
                        # Check for directory listing indicators
                        content_lower = resp.text.lower()
                        if any(indicator in content_lower for indicator in ['index of', 'directory listing', 'parent directory', '[to parent directory]']):
                            self.add_vulnerability(
                                vuln_type='DIRECTORY_LISTING',
                                severity='MEDIUM',
                                title='Directory Listing Enabled',
                                description=f'Directory listing exposed at {path}',
                                affected_url=test_url,
                                recommendation='Disable directory listing in web server configuration (Options -Indexes for Apache, autoindex off for Nginx)',
                                attack_scenarios=[
                                    'File Discovery: Find sensitive files not linked from main site',
                                    'Backup File Access: Download forgotten backup files (.bak, .old)',
                                    'Source Code Disclosure: Access unprotected source code files',
                                    'Reconnaissance: Map entire application structure',
                                    'Configuration File Discovery: Find exposed config files'
                                ],
                                cvss_score=5.3,
                                cwe_id='CWE-548'
                            )
                            break
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def check_server_configuration(self):
        """Check server configuration issues"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text
            
            # Check for default pages
            default_indicators = [
                ('Apache2 Default Page', 'Apache Default Installation', 'Apache'),
                ('Welcome to nginx', 'Nginx Default Installation', 'Nginx'),
                ('IIS Windows Server', 'IIS Default Installation', 'IIS'),
                ('cPanel', 'cPanel Installation Page', 'cPanel'),
                ('Welcome to Microsoft Internet Information Services', 'IIS Default Page', 'IIS'),
                ('Test Page for the Apache HTTP Server', 'Apache Test Page', 'Apache')
            ]
            
            for indicator, title, server_type in default_indicators:
                if indicator in content:
                    self.add_vulnerability(
                        vuln_type='SERVER_MISCONFIGURATION',
                        severity='LOW',
                        title=title,
                        description=f'Server shows default {server_type} installation page, indicating incomplete setup.',
                        affected_url=self.target_url,
                        recommendation='Replace default page with actual application content. Complete server setup.',
                        attack_scenarios=[
                            'Information Gathering: Identify server type and version',
                            'Default Credential Attack: Try default credentials for server',
                            'Known Exploit Usage: Search for server-specific vulnerabilities',
                            'Configuration Analysis: Study default setup for weaknesses'
                        ],
                        cvss_score=3.1,
                        cwe_id='CWE-16'
                    )
                    break
                    
        except Exception as e:
            pass
    
    def check_http_methods(self):
        """Check for dangerous HTTP methods"""
        try:
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']
            
            for method in dangerous_methods:
                try:
                    if method == 'OPTIONS':
                        response = self.session.options(self.target_url, timeout=5)
                        if response.status_code == 200:
                            allowed_methods = response.headers.get('Allow', '')
                            if any(m in allowed_methods for m in ['PUT', 'DELETE', 'TRACE']):
                                self.add_vulnerability(
                                    vuln_type='HTTP_METHOD_ENABLED',
                                    severity='MEDIUM',
                                    title='Dangerous HTTP Methods Enabled',
                                    description=f'Server allows dangerous HTTP methods: {allowed_methods}',
                                    affected_url=self.target_url,
                                    recommendation='Disable unnecessary HTTP methods. Only allow GET, POST, HEAD.',
                                    attack_scenarios=[
                                        'File Upload: Use PUT to upload malicious files',
                                        'Data Deletion: Use DELETE to remove resources',
                                        'XSS via TRACE: Cross-Site Tracing attacks',
                                        'Cache Poisoning: Manipulate cache with unusual methods'
                                    ],
                                    cvss_score=5.3,
                                    cwe_id='CWE-650'
                                )
                                break
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def check_open_redirects(self):
        """Check for open redirect vulnerabilities"""
        try:
            # Test common redirect parameters
            redirect_params = ['url', 'redirect', 'return', 'next', 'goto', 'target', 'dest', 'destination']
            test_domain = 'https://evil.com'
            
            for param in redirect_params:
                try:
                    test_url = f"{self.target_url}?{param}={test_domain}"
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if test_domain in location:
                            self.add_vulnerability(
                                vuln_type='OPEN_REDIRECT',
                                severity='MEDIUM',
                                title='Open Redirect Vulnerability',
                                description=f'Application redirects to arbitrary external URLs via {param} parameter',
                                affected_url=test_url,
                                recommendation='Validate redirect URLs against whitelist. Use relative URLs only.',
                                attack_scenarios=[
                                    'Phishing: Redirect users to fake login pages',
                                    'Malware Distribution: Redirect to malicious sites',
                                    'OAuth Token Theft: Steal tokens in redirect flow',
                                    'XSS Filter Bypass: Use redirect to bypass XSS filters'
                                ],
                                cvss_score=5.4,
                                cwe_id='CWE-601'
                            )
                            break
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def check_subdomain_takeover(self):
        """Check for potential subdomain takeover"""
        try:
            # Check for common subdomain takeover indicators
            response = self.session.get(self.target_url, timeout=10)
            content_lower = response.text.lower()
            
            takeover_indicators = [
                ('github.io', 'GitHub Pages'),
                ('herokuapp.com', 'Heroku'),
                ('azurewebsites.net', 'Azure'),
                ('s3.amazonaws.com', 'AWS S3'),
                ('cloudfront', 'CloudFront'),
                ('fastly', 'Fastly'),
                ('shopify', 'Shopify')
            ]
            
            for indicator, service in takeover_indicators:
                if indicator in content_lower and 'not found' in content_lower:
                    self.add_vulnerability(
                        vuln_type='SUBDOMAIN_TAKEOVER_RISK',
                        severity='MEDIUM',
                        title=f'Potential {service} Subdomain Takeover',
                        description=f'Domain points to {service} but returns "not found" error',
                        affected_url=self.target_url,
                        recommendation=f'Verify DNS records and reclaim {service} resource, or remove DNS entry',
                        attack_scenarios=[
                            'Domain Hijacking: Claim abandoned subdomain',
                            'Phishing: Host phishing content on legitimate domain',
                            'Session Cookie Theft: Steal cookies for parent domain',
                            'OAuth Exploitation: Bypass OAuth restrictions'
                        ],
                        cvss_score=6.5,
                        cwe_id='CWE-350'
                    )
                    break
                    
        except Exception as e:
            pass
    
    def check_email_disclosure(self):
        """Check for email address disclosure"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Simple email regex
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = re.findall(email_pattern, response.text)
            
            if emails and len(emails) > 3:  # Only flag if multiple emails found
                unique_emails = list(set(emails))[:5]  # Limit to 5 examples
                self.add_vulnerability(
                    vuln_type='INFORMATION_DISCLOSURE',
                    severity='LOW',
                    title='Email Addresses Disclosed',
                    description=f'Found {len(emails)} email addresses in page source. Examples: {", ".join(unique_emails[:3])}',
                    affected_url=self.target_url,
                    recommendation='Obfuscate email addresses or use contact forms instead of displaying emails directly',
                    attack_scenarios=[
                        'Spam Campaigns: Harvest emails for spam',
                        'Phishing: Target employees with spear phishing',
                        'Social Engineering: Use emails to identify key personnel',
                        'Data Mining: Build organizational structure map'
                    ],
                    cvss_score=2.7,
                    cwe_id='CWE-200'
                )
                    
        except Exception as e:
            pass
    
    def _generate_summary(self):
        """Generate scan summary with risk assessment"""
        severity_count = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        # Calculate risk score (0-100)
        risk_score = (
            severity_count.get('CRITICAL', 0) * 25 +
            severity_count.get('HIGH', 0) * 15 +
            severity_count.get('MEDIUM', 0) * 8 +
            severity_count.get('LOW', 0) * 3 +
            severity_count.get('INFO', 0) * 1
        )
        
        # Risk level classification
        if risk_score >= 75:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
        elif risk_score > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'SECURE'
        
        return {
            'total': len(self.vulnerabilities),
            'bySeverity': severity_count,
            'riskScore': min(100, risk_score),
            'riskLevel': risk_level
        }


# ==================== VERCEL HANDLER ====================

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            body = json.loads(post_data.decode('utf-8'))
            
            target_url = body.get('targetUrl')
            
            if not target_url or not target_url.startswith(('http://', 'https://')):
                self.send_error_response(400, 'Invalid URL format')
                return
            
            scanner = VulnerabilityScanner(target_url)
            results = scanner.scan()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(results).encode())
            
        except Exception as e:
            self.send_error_response(500, str(e))
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def send_error_response(self, code, message):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())
