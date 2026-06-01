
"""
Network Port Scanner & TCP Server - Information & Network Security Programming
605346 - University of Petra
Phase 1 Project: Multithreaded TCP Server + Port Scanner with Thread-Safe Logging

"""

import socket
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import shutil

from crypto_utils import encrypt_message, decrypt_message
file_lock = threading.Lock()
LOGS_DIR = "scan_logs"

if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
    print(f"[+] Created logs directory using os.makedirs(): {LOGS_DIR}")


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
        print(f"[+] Backup created using shutil.copy(): {backup_path}")
    
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
    """ multi-client support"""
    print(f"[+] New connection from {addr}")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            encrypted_message = data.decode().strip()
            message = decrypt_message(encrypted_message)
            response = f"Echo: {message}\n"
            encrypted_response = encrypt_message(response)
            conn.send(encrypted_response.encode())
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        print(f"[-] Connection closed: {addr}")


def start_tcp_server(host: str = '127.0.0.1', port: int = 8888, max_clients: int = 5):    
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
    
    ports = []
    if '-' in ports_input:
        start, end = map(int, ports_input.split('-'))
        ports = list(range(start, end + 1))
    elif ',' in ports_input:
        ports = [int(p.strip()) for p in ports_input.split(',')]
    else:
        ports = [int(ports_input)]
    return ports


def main():
    parser = argparse.ArgumentParser(description="Network Tool: Port Scanner + TCP Server")
    
    parser.add_argument("--mode", choices=['scan', 'server'], default='scan',
                        help="Mode: scan (port scanner) or server (TCP server)")
    
    parser.add_argument("target", nargs='?', type=str, help="Target IP or domain (for scan mode)")
    parser.add_argument("ports", nargs='?', type=str, help="Ports: 80, 20-100, 22,80,443")
    
    parser.add_argument("--host", type=str, default='127.0.0.1', help="Server bind address (localhost only)")     
    parser.add_argument("--sport", type=int, default=8888, help="Server port")
    
    parser.add_argument("-t", "--threads", type=int, default=100, help="Max threads for scanning")
    parser.add_argument("-to", "--timeout", type=float, default=1.0, help="Connection timeout")
    
    args = parser.parse_args()
    
    if args.mode == 'server':
        print("=" * 50)
        print("  TCP MULTI-CLIENT SERVER")
        print("  Using: bind() -> listen() -> accept()")
        print("=" * 50)
        start_tcp_server(args.host, args.sport)
    
    elif args.mode == 'scan':
        if not args.target or not args.ports:
            print("Error: For scan mode, provide target and ports")
            print("Example: python scanner.py --mode scan scanme.nmap.org 20-100")
            print("Example: python scanner.py --mode scan 127.0.0.1 1-100")
            return
        
        print("=" * 50)
        print("  PORT SCANNER")
        print("  Using: ThreadPoolExecutor + Lock + os + shutil")
        print("=" * 50)
        
        ports = parse_ports(args.ports)
        scan_ports(args.target, ports, args.threads, args.timeout)


if __name__ == "__main__":
    main()