import subprocess
import requests
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class VulnerabilityScanner:
    """
    Comprehensive vulnerability scanning
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
    
    def comprehensive_scan(self, scan_id, recon_data):
        """
        Run comprehensive vulnerability scans
        """
        all_vulnerabilities = []
        target = recon_data['target']
        live_hosts = recon_data.get('live_hosts', [])
        
        # XSS Scanning
        self.broadcaster.broadcast_tool_started(scan_id, 'XSS Scanner', target)
        xss_vulns = self._scan_xss(scan_id, target, recon_data.get('endpoints', []))
        all_vulnerabilities.extend(xss_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'XSS Scanner', 'success', len(xss_vulns))
        
        # SQL Injection Scanning
        self.broadcaster.broadcast_tool_started(scan_id, 'SQL Injection Scanner', target)
        sqli_vulns = self._scan_sqli(scan_id, target, recon_data.get('endpoints', []))
        all_vulnerabilities.extend(sqli_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'SQL Injection Scanner', 'success', len(sqli_vulns))
        
        # Directory Traversal
        self.broadcaster.broadcast_tool_started(scan_id, 'Directory Traversal Scanner', target)
        traversal_vulns = self._scan_directory_traversal(scan_id, target)
        all_vulnerabilities.extend(traversal_vulns)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Directory Traversal Scanner', 'success', len(traversal_vulns))
        
        # Security Headers
        self.broadcaster.broadcast_tool_started(scan_id, 'Security Headers Check', target)
        header_issues = self._check_security_headers(scan_id, live_hosts)
        all_vulnerabilities.extend(header_issues)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Security Headers Check', 'success', len(header_issues))
        
        # CORS Misconfiguration
        self.broadcaster.broadcast_tool_started(scan_id, 'CORS Scanner', target)
        cors_issues = self._scan_cors(scan_id, live_hosts)
        all_vulnerabilities.extend(cors_issues)
        self.broadcaster.broadcast_tool_completed(scan_id, 'CORS Scanner', 'success', len(cors_issues))
        
        # Sensitive File Exposure
        self.broadcaster.broadcast_tool_started(scan_id, 'Sensitive File Scanner', target)
        file_exposures = self._scan_sensitive_files(scan_id, target)
        all_vulnerabilities.extend(file_exposures)
        self.broadcaster.broadcast_tool_completed(scan_id, 'Sensitive File Scanner', 'success', len(file_exposures))
        
        # Broadcast all found vulnerabilities
        for vuln in all_vulnerabilities:
            self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
            self.db.add_vulnerability(scan_id, vuln)
        
        return all_vulnerabilities
    
    def _scan_xss(self, scan_id, target, endpoints):
        """
        Scan for XSS vulnerabilities
        """
        vulnerabilities = []
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            'javascript:alert(1)'
        ]
        
        test_endpoints = [target] + endpoints[:10]
        
        for endpoint in test_endpoints:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            if not params:
                # Add test parameter
                params = {'q': ['test'], 'search': ['test'], 'id': ['1']}
            
            for param_name in params.keys():
                for payload in xss_payloads[:2]:  # Test 2 payloads per param
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                        ))
                        
                        response = requests.get(test_url, timeout=5, verify=False)
                        
                        if payload in response.text and response.headers.get('Content-Type', '').startswith('text/html'):
                            vulnerabilities.append({
                                'type': 'XSS',
                                'severity': 'high',
                                'title': f'Reflected XSS in parameter: {param_name}',
                                'description': f'The parameter "{param_name}" is vulnerable to XSS injection',
                                'url': endpoint,
                                'confidence': 85,
                                'tool': 'xss_scanner',
                                'poc': f'Parameter: {param_name}\nPayload: {payload}',
                                'remediation': 'Implement proper input validation and output encoding',
                                'raw_data': {'parameter': param_name, 'payload': payload}
                            })
                            break
                    except:
                        continue
        
        return vulnerabilities
    
    def _scan_sqli(self, scan_id, target, endpoints):
        """
        Scan for SQL Injection vulnerabilities
        """
        vulnerabilities = []
        
        sqli_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "1 AND 1=2",
            "admin'--"
        ]
        
        error_patterns = [
            r'SQL syntax',
            r'mysql_fetch',
            r'ORA-\d{5}',
            r'PostgreSQL.*ERROR',
            r'SQLSTATE',
            r'Unclosed quotation mark'
        ]
        
        test_endpoints = [target] + endpoints[:10]
        
        for endpoint in test_endpoints:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            if not params:
                params = {'id': ['1'], 'user': ['admin']}
            
            for param_name in params.keys():
                for payload in sqli_payloads[:2]:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                        ))
                        
                        response = requests.get(test_url, timeout=5, verify=False)
                        
                        # Check for SQL errors
                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'critical',
                                    'title': f'SQL Injection in parameter: {param_name}',
                                    'description': f'SQL error detected when injecting payload in "{param_name}"',
                                    'url': endpoint,
                                    'confidence': 90,
                                    'tool': 'sqli_scanner',
                                    'poc': f'Parameter: {param_name}\nPayload: {payload}\nError pattern: {pattern}',
                                    'remediation': 'Use parameterized queries and prepared statements',
                                    'raw_data': {'parameter': param_name, 'payload': payload}
                                })
                                break
                    except:
                        continue
        
        return vulnerabilities
    
    def _scan_directory_traversal(self, scan_id, target):
        """
        Scan for directory traversal vulnerabilities
        """
        vulnerabilities = []
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        indicators = ['root:', '[boot loader]', '[fonts]']
        
        for payload in traversal_payloads[:2]:
            try:
                test_url = f"{target.rstrip('/')}?file={payload}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if any(indicator in response.text for indicator in indicators):
                    vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'severity': 'high',
                        'title': 'Directory Traversal Vulnerability',
                        'description': 'Application allows accessing arbitrary files on the server',
                        'url': target,
                        'confidence': 95,
                        'tool': 'traversal_scanner',
                        'poc': f'Payload: {payload}',
                        'remediation': 'Implement proper input validation and use whitelisting',
                        'raw_data': {'payload': payload}
                    })
                    break
            except:
                continue
        
        return vulnerabilities
    
    def _check_security_headers(self, scan_id, live_hosts):
        """
        Check for missing security headers
        """
        issues = []
        
        required_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME-sniffing protection missing',
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented',
            'X-XSS-Protection': 'XSS protection header missing'
        }
        
        for host_info in live_hosts[:5]:
            url = host_info.get('url')
            try:
                response = requests.get(url, timeout=5, verify=False)
                
                for header, description in required_headers.items():
                    if header not in response.headers:
                        issues.append({
                            'type': 'Security Misconfiguration',
                            'severity': 'medium',
                            'title': f'Missing Security Header: {header}',
                            'description': description,
                            'url': url,
                            'confidence': 100,
                            'tool': 'header_scanner',
                            'poc': f'Header "{header}" not found in response',
                            'remediation': f'Add the {header} header to all responses',
                            'raw_data': {'missing_header': header}
                        })
            except:
                continue
        
        return issues
    
    def _scan_cors(self, scan_id, live_hosts):
        """
        Scan for CORS misconfigurations
        """
        issues = []
        
        for host_info in live_hosts[:5]:
            url = host_info.get('url')
            try:
                response = requests.get(
                    url,
                    headers={'Origin': 'https://evil.com'},
                    timeout=5,
                    verify=False
                )
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                
                if acao == '*' or acao == 'https://evil.com':
                    issues.append({
                        'type': 'CORS Misconfiguration',
                        'severity': 'high',
                        'title': 'Insecure CORS Configuration',
                        'description': 'CORS is configured to allow any origin, enabling unauthorized access',
                        'url': url,
                        'confidence': 100,
                        'tool': 'cors_scanner',
                        'poc': f'Access-Control-Allow-Origin: {acao}',
                        'remediation': 'Configure CORS to only allow trusted origins',
                        'raw_data': {'acao_header': acao}
                    })
            except:
                continue
        
        return issues
    
    def _scan_sensitive_files(self, scan_id, target):
        """
        Scan for exposed sensitive files
        """
        issues = []
        
        sensitive_files = [
            '/.git/config',
            '/.env',
            '/backup.sql',
            '/database.sql',
            '/.aws/credentials',
            '/config.php.bak',
            '/web.config',
            '/.htaccess',
            '/phpinfo.php',
            '/readme.md'
        ]
        
        for file_path in sensitive_files:
            try:
                test_url = f"{target.rstrip('/')}{file_path}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200 and len(response.content) > 0:
                    issues.append({
                        'type': 'Sensitive File Exposure',
                        'severity': 'high' if file_path in ['/.git/config', '/.env', '/backup.sql'] else 'medium',
                        'title': f'Exposed Sensitive File: {file_path}',
                        'description': f'Sensitive file {file_path} is publicly accessible',
                        'url': test_url,
                        'confidence': 100,
                        'tool': 'file_scanner',
                        'poc': f'File accessible at: {test_url}',
                        'remediation': 'Remove or properly protect sensitive files',
                        'raw_data': {'file_path': file_path, 'size': len(response.content)}
                    })
            except:
                continue
        
        return issues