from flask import Flask, render_template, request, jsonify, send_file, url_for, abort
import sys
import os
import json
import threading
import queue
import hashlib
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
import itertools
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add tool directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'network_scanner'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'portscanner'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hash_cracker'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'enumeration'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ftp'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ssh'))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

def build_password_candidates(req, limit=500, default_chars=None):
    """
    Build a bounded list of password candidates from request inputs.
    Supports upload/server-path wordlists or on-the-fly generation.
    Returns (candidates, attempt_limit_hit, temp_paths, error_message)
    """
    wordlist_mode = req.form.get('wordlist_mode', 'upload')
    attempt_limit_hit = False
    candidates = []
    seen = set()
    temp_paths = []
    default_chars = default_chars or (string.ascii_lowercase + string.digits)

    def add_candidate(pwd):
        nonlocal attempt_limit_hit
        if not pwd or pwd in seen:
            return False
        seen.add(pwd)
        candidates.append(pwd)
        if len(candidates) >= limit:
            attempt_limit_hit = True
            return True
        return False

    try:
        if wordlist_mode == 'upload':
            uploaded_file = req.files.get('wordlist')
            wordlist_path = (req.form.get('wordlist_path') or '').strip()

            if not uploaded_file and not wordlist_path:
                return [], attempt_limit_hit, temp_paths, 'Upload a wordlist or provide a server wordlist path.'

            if uploaded_file and uploaded_file.filename:
                filename = secure_filename(uploaded_file.filename)
                if not filename:
                    return [], attempt_limit_hit, temp_paths, 'Invalid wordlist filename.'
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                uploaded_file.save(temp_path)
                temp_paths.append(temp_path)
                with open(temp_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if add_candidate(line.strip()):
                            break

            if wordlist_path:
                if not os.path.exists(wordlist_path):
                    return [], attempt_limit_hit, temp_paths, 'Specified server wordlist file does not exist.'
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if add_candidate(line.strip()):
                            break
        else:
            try:
                min_length = int(req.form.get('min_length', 1))
                max_length = int(req.form.get('max_length', 4))
            except ValueError:
                return [], attempt_limit_hit, temp_paths, 'Password lengths must be integers.'

            if min_length < 1 or max_length < 1 or min_length > max_length:
                return [], attempt_limit_hit, temp_paths, 'Invalid length range.'

            chars = req.form.get('characters', '') or default_chars
            chars = ''.join(dict.fromkeys(chars))  # remove duplicates
            if not chars:
                return [], attempt_limit_hit, temp_paths, 'Character set cannot be empty.'

            for length in range(min_length, max_length + 1):
                for combo in itertools.product(chars, repeat=length):
                    if add_candidate(''.join(combo)):
                        break
                if attempt_limit_hit:
                    break

        if not candidates:
            return [], attempt_limit_hit, temp_paths, 'No passwords available to attempt. Please adjust your inputs.'

        return candidates, attempt_limit_hit, temp_paths, None
    except Exception as exc:
        return [], attempt_limit_hit, temp_paths, f'Error preparing password candidates: {exc}'

# Import tool modules
try:
    from portscanner import portscanner
    from hash_cracker import hashcracker
except ImportError:
    pass

@app.route('/')
def index():
    return render_template('index.html')

# Network Scanner Routes
@app.route('/network_scanner')
def network_scanner_page():
    return render_template('network_scanner.html')

@app.route('/api/network_scan', methods=['POST'])
def network_scan():
    try:
        data = request.json
        cidr = data.get('cidr', '')
        
        if not cidr:
            return jsonify({'error': 'CIDR notation required'}), 400
        
        # Use network scanner logic directly
        import scapy.all as scapy
        import socket
        import ipaddress
        
        result_queue = queue.Queue()
        results = []
        
        def scan(ip):
            try:
                # Try to auto-detect interface or use default
                try:
                    from scapy.all import get_if_list
                    interfaces = get_if_list()
                    INTERFACE_NAME = interfaces[0] if interfaces else None
                except:
                    INTERFACE_NAME = None
                
                arg_request = scapy.ARP(pdst=str(ip))
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = broadcast / arg_request
                
                if INTERFACE_NAME:
                    answer = scapy.srp(packet, timeout=1, verbose=False, iface=INTERFACE_NAME)[0]
                else:
                    answer = scapy.srp(packet, timeout=1, verbose=False)[0]
                
                for sent, received in answer:
                    client_info = {'IP': received.psrc, 'MAC': received.hwsrc}
                    try:
                        hostname = socket.gethostbyaddr(client_info['IP'])[0]
                        client_info['Hostname'] = hostname
                    except socket.herror:
                        client_info['Hostname'] = 'Unknown'
                    results.append(client_info)
            except Exception as e:
                pass
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            return jsonify({'error': f'Invalid CIDR notation: {e}'}), 400
        
        # Limit scan to first 50 hosts for web interface
        hosts = list(network.hosts())[:50]
        threads = []
        
        for ip in hosts:
            thread = threading.Thread(target=scan, args=(ip,))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join(timeout=2)
        
        # Format results
        formatted_results = []
        for client in results:
            formatted_results.append({
                'ip': client.get('IP', ''),
                'mac': client.get('MAC', ''),
                'hostname': client.get('Hostname', 'Unknown')
            })
        
        return jsonify({'success': True, 'results': formatted_results})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Port Scanner Routes
@app.route('/port_scanner')
def port_scanner_page():
    return render_template('port_scanner.html')

@app.route('/api/port_scan', methods=['POST'])
def port_scan():
    try:
        data = request.json
        target = data.get('target', '')
        start_port = int(data.get('start_port', 1))
        end_port = int(data.get('end_port', 1000))
        
        if not target:
            return jsonify({'error': 'Target host required'}), 400
        
        results = []
        import socket
        import concurrent.futures
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"
                    try:
                        sock.settimeout(1)
                        banner = sock.recv(1024).decode().strip()
                    except:
                        banner = "No Banner"
                    sock.close()
                    return {'port': port, 'service': service, 'banner': banner, 'status': 'open'}
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, port): port for port in range(start_port, end_port + 1)}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        return jsonify({'success': True, 'results': results})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Hash Cracker Routes
@app.route('/hash_cracker')
def hash_cracker_page():
    return render_template('hash_cracker.html')

@app.route('/api/crack_hash', methods=['POST'])
def crack_hash():
    uploaded_wordlist_path = None
    try:
        is_json = request.content_type and 'application/json' in request.content_type.lower()
        data = request.get_json(silent=True) if is_json else request.form
        if not data:
            data = {}
        files = request.files if not is_json else request.files
        
        target_hash = (data.get('hash') or '').strip()
        hash_type = (data.get('hash_type') or 'md5').strip().lower()
        method = (data.get('method') or 'wordlist').strip().lower()
        min_length = int(data.get('min_length', 0) or 0)
        max_length = int(data.get('max_length', 0) or 0)
        characters = (data.get('characters') or '').strip()
        wordlist_path = (data.get('wordlist_path') or '').strip()
        wordlist_file = files.get('wordlist')
        
        if not target_hash:
            return jsonify({'error': 'Hash required'}), 400
        
        # Normalize method
        if method not in ('wordlist', 'bruteforce'):
            method = 'wordlist' if wordlist_file or wordlist_path else 'bruteforce'
        
        # Handle wordlist inputs (upload or server path)
        if method == 'wordlist':
            if wordlist_file and wordlist_file.filename:
                filename = secure_filename(wordlist_file.filename)
                if not filename:
                    filename = f"wordlist_{uuid.uuid4().hex}.txt"
                temp_name = f"hash_wordlist_{uuid.uuid4().hex}_{filename}"
                uploaded_wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_name)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                wordlist_file.save(uploaded_wordlist_path)
                wordlist_path = uploaded_wordlist_path
            elif wordlist_path:
                if not os.path.isabs(wordlist_path):
                    candidate_path = os.path.join(BASE_DIR, wordlist_path)
                    if os.path.exists(candidate_path):
                        wordlist_path = candidate_path
                if not os.path.exists(wordlist_path):
                    return jsonify({'error': 'Provided server wordlist path does not exist.'}), 404
            else:
                return jsonify({'error': 'Wordlist required. Upload one or provide a server path.'}), 400
            
            min_length = 0
            max_length = 0
            characters = ''
        
        # Validate brute force parameters
        if method == 'bruteforce':
            if min_length <= 0 or max_length <= 0:
                return jsonify({'error': 'Provide min_length and max_length greater than zero for brute force.'}), 400
            if max_length < min_length:
                return jsonify({'error': 'max_length must be greater than or equal to min_length.'}), 400
        
        # Determine final parameters
        char_pool = characters if characters else (string.ascii_letters + string.digits)
        wordlist_param = wordlist_path if method == 'wordlist' else None
        
        if wordlist_param and not os.path.isabs(wordlist_param):
            candidate_path = os.path.join(BASE_DIR, wordlist_param)
            if os.path.exists(candidate_path):
                wordlist_param = candidate_path
        
        # Import hash cracker function
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hash_cracker'))
        import importlib.util
        hashcracker_path = os.path.join(os.path.dirname(__file__), 'hash_cracker', 'hashcracker.py')
        spec = importlib.util.spec_from_file_location("hashcracker", hashcracker_path)
        hashcracker_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hashcracker_module)
        
        result = hashcracker_module.crack_hash(
            target_hash,
            wordlist_param,
            hash_type,
            min_length,
            max_length,
            char_pool,
            4
        )
        
        if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
            os.remove(uploaded_wordlist_path)
        
        if result:
            return jsonify({'success': True, 'password': result})
        else:
            message = 'Password not found'
            return jsonify({'success': False, 'message': message})
            
    except Exception as e:
        if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
            os.remove(uploaded_wordlist_path)
        return jsonify({'error': str(e)}), 500

# Subdomain Enumeration Routes
@app.route('/subdomain_enum')
def subdomain_enum_page():
    return render_template('subdomain_enum.html')

@app.route('/api/subdomain_enum', methods=['POST'])
def subdomain_enum():
    temp_paths = []
    try:
        is_json = request.content_type and 'application/json' in request.content_type.lower()
        data = request.get_json(silent=True) if is_json else request.form
        files = {} if is_json else request.files
        if not data:
            data = {}
        
        domain = (data.get('domain') or '').strip()
        wordlist_mode = (data.get('wordlist_mode') or 'default').strip().lower()
        attempt_limit = 200
        attempt_limit_hit = False
        subdomain_candidates = []
        seen = set()
        
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        
        def add_candidate(value):
            nonlocal attempt_limit_hit
            if not value:
                return False
            candidate = value.strip()
            if not candidate or candidate in seen:
                return False
            seen.add(candidate)
            subdomain_candidates.append(candidate)
            if len(subdomain_candidates) >= attempt_limit:
                attempt_limit_hit = True
                return True
            return False
        
        def load_from_file(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if add_candidate(line.strip()):
                            break
            except FileNotFoundError:
                raise FileNotFoundError('Specified wordlist file does not exist.')
        
        if wordlist_mode == 'default' or wordlist_mode not in ('default', 'upload', 'generate', 'server'):
            subdomains_file = os.path.join('enumeration', 'subdomains.txt')
            if not os.path.exists(subdomains_file):
                return jsonify({'error': 'Subdomains wordlist not found'}), 404
            load_from_file(subdomains_file)
        elif wordlist_mode == 'upload' or wordlist_mode == 'server':
            wordlist_file = files.get('wordlist') if not is_json else None
            wordlist_path = (data.get('wordlist_path') or '').strip()
            source_path = None
            
            if wordlist_file and wordlist_file.filename:
                filename = secure_filename(wordlist_file.filename) or 'subdomains.txt'
                temp_name = f"subdomains_{uuid.uuid4().hex}_{filename}"
                source_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_name)
                wordlist_file.save(source_path)
                temp_paths.append(source_path)
            elif wordlist_path:
                if not os.path.isabs(wordlist_path):
                    candidate_path = os.path.join(os.path.dirname(__file__), wordlist_path)
                    wordlist_path = candidate_path if os.path.exists(candidate_path) else wordlist_path
                if not os.path.exists(wordlist_path):
                    return jsonify({'error': 'Provided server wordlist path was not found'}), 404
                source_path = wordlist_path
            else:
                return jsonify({'error': 'Upload a wordlist file or provide a server path.'}), 400
            
            load_from_file(source_path)
        elif wordlist_mode == 'generate':
            try:
                min_length = int(data.get('min_length', 2) or 2)
                max_length = int(data.get('max_length', min_length) or min_length)
            except ValueError:
                return jsonify({'error': 'Min/Max length must be integers.'}), 400
            
            if min_length < 1 or max_length < 1 or min_length > max_length:
                return jsonify({'error': 'Invalid length range.'}), 400
            
            chars = (data.get('characters') or '').strip()
            if not chars:
                chars = string.ascii_lowercase + string.digits + '-'
            chars = ''.join(dict.fromkeys(chars))
            if not chars:
                return jsonify({'error': 'Character set cannot be empty.'}), 400
            
            for length in range(min_length, max_length + 1):
                for combo in itertools.product(chars, repeat=length):
                    if add_candidate(''.join(combo)):
                        break
                if attempt_limit_hit:
                    break
        
        if not subdomain_candidates:
            return jsonify({'error': 'No subdomains available to test. Adjust your wordlist options.'}), 400
        
        discovered = []
        import requests
        import threading
        
        lock = threading.Lock()
        
        def check_subdomain(subdomain):
            url = f"http://{subdomain}.{domain}"
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    with lock:
                        discovered.append({'url': url, 'status': response.status_code})
            except:
                pass
        
        threads = []
        for subdomain in subdomain_candidates:
            thread = threading.Thread(target=check_subdomain, args=(subdomain,))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join(timeout=5)
        
        return jsonify({
            'success': True,
            'results': discovered,
            'attempted': len(subdomain_candidates),
            'limit_reached': attempt_limit_hit
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        for path in temp_paths:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

# DNS Enumeration Routes
@app.route('/dns_enum')
def dns_enum_page():
    return render_template('dns_enum.html')

@app.route('/api/dns_enum', methods=['POST'])
def dns_enum():
    try:
        data = request.json
        domain = data.get('domain', '')
        
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        
        import dns.resolver
        records_type = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        results = {}
        
        resolver = dns.resolver.Resolver()
        for record in records_type:
            try:
                answers = resolver.resolve(domain, record)
                results[record] = [rdata.to_text() for rdata in answers]
            except:
                results[record] = []
        
        return jsonify({'success': True, 'results': results})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# FTP Cracker Routes
@app.route('/ftp_cracker')
def ftp_cracker_page():
    return render_template('ftp_cracker.html')

@app.route('/api/ftp_crack', methods=['POST'])
def ftp_crack():
    uploaded_wordlist_path = None
    try:
        is_json = request.content_type and 'application/json' in request.content_type.lower()
        data = request.get_json(silent=True) if is_json else request.form
        files = {} if is_json else request.files
        if not data:
            data = {}
        
        host = (data.get('host') or '').strip()
        user = (data.get('user') or '').strip()
        port = int(data.get('port', 21) or 21)
        wordlist_mode = (data.get('wordlist_mode') or ('upload' if not is_json else 'path')).strip().lower()
        attempt_limit = 500
        password_candidates = []
        attempt_limit_hit = False
        
        if not all([host, user]):
            return jsonify({'error': 'Host and username are required'}), 400
        
        if wordlist_mode == 'generate':
            min_length = int(data.get('min_length', 1) or 1)
            max_length = int(data.get('max_length', min_length) or min_length)
            if min_length > max_length or min_length < 1:
                return jsonify({'error': 'Invalid length range for generated wordlist'}), 400
            chars = data.get('characters', '')
            if not chars:
                chars = string.ascii_lowercase + string.digits
            chars = ''.join(dict.fromkeys(chars))  # remove duplicates
            if not chars:
                return jsonify({'error': 'Character set cannot be empty'}), 400
            
            for length in range(min_length, max_length + 1):
                for combo in itertools.product(chars, repeat=length):
                    password_candidates.append(''.join(combo))
                    if len(password_candidates) >= attempt_limit:
                        attempt_limit_hit = True
                        break
                if attempt_limit_hit:
                    break
        else:
            wordlist_file = files.get('wordlist') if files else None
            wordlist_path = (data.get('wordlist_path') or '').strip()
            
            if wordlist_file and wordlist_file.filename:
                filename = secure_filename(wordlist_file.filename) or 'wordlist.txt'
                uploaded_wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                wordlist_file.save(uploaded_wordlist_path)
                wordlist_path = uploaded_wordlist_path
            
            if not wordlist_path:
                return jsonify({'error': 'Provide a wordlist upload or server path'}), 400
            
            if not os.path.exists(wordlist_path):
                if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
                    os.remove(uploaded_wordlist_path)
                return jsonify({'error': 'Wordlist file not found'}), 404
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if not pwd:
                        continue
                    password_candidates.append(pwd)
                    if len(password_candidates) >= attempt_limit:
                        attempt_limit_hit = True
                        break
        
        if not password_candidates:
            if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
                os.remove(uploaded_wordlist_path)
            return jsonify({'error': 'No passwords available to attempt. Check your wordlist settings.'}), 400
        
        import ftplib
        from threading import Thread
        import queue
        
        q = queue.Queue()
        result = {'found': False, 'password': None}
        lock = threading.Lock()
        
        for password in password_candidates:
            q.put(password)
        
        def connect_ftp():
            while not q.empty() and not result['found']:
                try:
                    password = q.get(timeout=1)
                    server = ftplib.FTP()
                    server.connect(host, port, timeout=5)
                    server.login(user, password)
                    server.quit()
                    with lock:
                        result['found'] = True
                        result['password'] = password
                    with q.mutex:
                        q.queue.clear()
                except:
                    pass
                finally:
                    q.task_done()
        
        threads = []
        for _ in range(min(10, len(password_candidates)) or 1):
            thread = Thread(target=connect_ftp)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join(timeout=30)
        
        if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
            os.remove(uploaded_wordlist_path)
        
        if result['found']:
            message = 'Password found'
            if attempt_limit_hit:
                message += ' (note: only the first 500 candidates were attempted)'
            return jsonify({'success': True, 'password': result['password'], 'message': message})
        else:
            message = 'Password not found'
            if attempt_limit_hit:
                message += ' (500 candidate limit reached)'
            return jsonify({'success': False, 'message': message})
            
    except Exception as e:
        uploaded_wordlist_path = locals().get('uploaded_wordlist_path')
        if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
            os.remove(uploaded_wordlist_path)
        return jsonify({'error': str(e)}), 500

# SSH Brute Force Routes
@app.route('/ssh_brute')
def ssh_brute_page():
    return render_template('ssh_brute.html')

@app.route('/api/ssh_brute', methods=['POST'])
def ssh_brute():
    uploaded_wordlist_path = None
    try:
        is_json = request.content_type and 'application/json' in request.content_type.lower()
        data = request.get_json(silent=True) if is_json else request.form
        files = {} if is_json else request.files
        if not data:
            data = {}
        
        host = (data.get('host') or '').strip()
        user = (data.get('user') or '').strip()
        wordlist_mode = (data.get('wordlist_mode') or ('upload' if not is_json else 'path')).strip().lower()
        attempt_limit = 300
        password_candidates = []
        attempt_limit_hit = False
        
        if not all([host, user]):
            return jsonify({'error': 'Host and username are required'}), 400
        
        if wordlist_mode == 'generate':
            min_length = int(data.get('min_length', 1) or 1)
            max_length = int(data.get('max_length', min_length) or min_length)
            if min_length > max_length or min_length < 1:
                return jsonify({'error': 'Invalid length range for generated wordlist'}), 400
            chars = data.get('characters', '')
            if not chars:
                chars = string.ascii_lowercase + string.digits
            chars = ''.join(dict.fromkeys(chars))
            if not chars:
                return jsonify({'error': 'Character set cannot be empty'}), 400
            
            for length in range(min_length, max_length + 1):
                for combo in itertools.product(chars, repeat=length):
                    password_candidates.append(''.join(combo))
                    if len(password_candidates) >= attempt_limit:
                        attempt_limit_hit = True
                        break
                if attempt_limit_hit:
                    break
        else:
            wordlist_file = files.get('wordlist') if files else None
            wordlist_path = (data.get('wordlist_path') or '').strip()
            
            if wordlist_file and wordlist_file.filename:
                filename = secure_filename(wordlist_file.filename) or 'wordlist.txt'
                uploaded_wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                wordlist_file.save(uploaded_wordlist_path)
                wordlist_path = uploaded_wordlist_path
            
            if not wordlist_path:
                return jsonify({'error': 'Provide a wordlist upload or server path'}), 400
            
            if not os.path.exists(wordlist_path):
                if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
                    os.remove(uploaded_wordlist_path)
                return jsonify({'error': 'Wordlist file not found'}), 404
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if not pwd:
                        continue
                    password_candidates.append(pwd)
                    if len(password_candidates) >= attempt_limit:
                        attempt_limit_hit = True
                        break
        
        if not password_candidates:
            if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
                os.remove(uploaded_wordlist_path)
            return jsonify({'error': 'No passwords available to attempt. Check your wordlist settings.'}), 400
        
        import paramiko
        import socket
        
        for password in password_candidates:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=user, password=password, timeout=3)
                client.close()
                if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
                    os.remove(uploaded_wordlist_path)
                message = 'Password found'
                if attempt_limit_hit:
                    message += ' (note: only the first 300 candidates were attempted)'
                return jsonify({'success': True, 'password': password, 'message': message})
            except (paramiko.AuthenticationException, socket.timeout, paramiko.SSHException):
                continue
        
        if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
            os.remove(uploaded_wordlist_path)
        
        message = 'Password not found'
        if attempt_limit_hit:
            message += ' (300 candidate limit reached)'
        return jsonify({'success': False, 'message': message})
        
    except Exception as e:
        uploaded_wordlist_path = locals().get('uploaded_wordlist_path')
        if uploaded_wordlist_path and os.path.exists(uploaded_wordlist_path):
            os.remove(uploaded_wordlist_path)
        return jsonify({'error': str(e)}), 500

# PDF Tools Routes
@app.route('/pdf_tools')
def pdf_tools_page():
    return render_template('pdf_tools.html')

@app.route('/download/<path:filename>')
def download_result(filename):
    safe_name = os.path.basename(filename)
    file_path = os.path.join(app.config['RESULTS_FOLDER'], safe_name)
    if not os.path.exists(file_path):
        abort(404)
    return send_file(
        file_path,
        as_attachment=True,
        download_name=safe_name,
        mimetype='application/pdf'
    )

@app.route('/api/pdf_protect', methods=['POST'])
def pdf_protect():
    try:
        if 'pdf' not in request.files:
            return jsonify({'error': 'No PDF file provided'}), 400
        
        pdf_file = request.files['pdf']
        password = request.form.get('password', '')
        
        if pdf_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not password:
            return jsonify({'error': 'Password required'}), 400
        
        # Save uploaded file
        filename = secure_filename(pdf_file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        pdf_file.save(upload_path)
        
        # Import PyPDF2 for protection
        try:
            import PyPDF2
            pdf_read_error = getattr(
                PyPDF2.errors if hasattr(PyPDF2, 'errors') else PyPDF2,
                'PdfReadError',
                Exception
            )
        except ImportError:
            return jsonify({'error': 'PyPDF2 library not installed. Please install it: pip install PyPDF2'}), 500
        
        # Create protected PDF
        try:
            with open(upload_path, 'rb') as input_pdf_file:
                reader = PyPDF2.PdfReader(input_pdf_file)
                writer = PyPDF2.PdfWriter()
                
                # Copy all pages
                for page_num in range(len(reader.pages)):
                    writer.add_page(reader.pages[page_num])
                
                # Encrypt with password
                writer.encrypt(password)
                
                # Save protected PDF
                protected_filename = 'protected_' + filename
                protected_path = os.path.join(app.config['RESULTS_FOLDER'], protected_filename)
                
                with open(protected_path, 'wb') as output_pdf_file:
                    writer.write(output_pdf_file)
            
            # Clean up uploaded file
            if os.path.exists(upload_path):
                os.remove(upload_path)

            download_url = url_for('download_result', filename=protected_filename)

            return jsonify({
                'success': True,
                'message': f'PDF protected successfully. Saved to results folder as {protected_filename}.',
                'filename': protected_filename,
                'download_url': download_url
            })
            
        except pdf_read_error:
            if os.path.exists(upload_path):
                os.remove(upload_path)
            return jsonify({'error': 'Invalid PDF file'}), 400
        except Exception as e:
            if os.path.exists(upload_path):
                os.remove(upload_path)
            return jsonify({'error': f'Error protecting PDF: {str(e)}'}), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/pdf_crack', methods=['POST'])
def pdf_crack():
    try:
        if 'pdf' not in request.files:
            return jsonify({'error': 'No PDF file provided'}), 400
        
        pdf_file = request.files['pdf']
        method = request.form.get('method', 'wordlist')
        
        if pdf_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded PDF
        filename = secure_filename(pdf_file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        pdf_file.save(upload_path)
        
        # Import pikepdf for cracking
        try:
            import pikepdf
        except ImportError:
            os.remove(upload_path)
            return jsonify({'error': 'pikepdf library not installed. Please install it: pip install pikepdf'}), 500
        
        # Generate passwords based on method
        password_candidates = []
        attempt_limit_hit = False
        attempt_limit = 10000
        wordlist_path = None
        
        if method == 'wordlist':
            if 'wordlist' not in request.files:
                os.remove(upload_path)
                return jsonify({'error': 'Wordlist file required'}), 400
            
            wordlist_file = request.files['wordlist']
            if wordlist_file.filename == '':
                os.remove(upload_path)
                return jsonify({'error': 'No wordlist file selected'}), 400
            
            # Save wordlist
            wordlist_filename = secure_filename(wordlist_file.filename)
            wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], wordlist_filename)
            wordlist_file.save(wordlist_path)
            
            # Load passwords from wordlist (limit for web interface)
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if not pwd:
                        continue
                    password_candidates.append(pwd)
                    if len(password_candidates) >= attempt_limit:
                        attempt_limit_hit = True
                        break
        
        else:  # bruteforce
            min_length = int(request.form.get('min_length', 1))
            max_length = int(request.form.get('max_length', 4))
            chars = request.form.get('characters', '')
            if not chars:
                chars = string.ascii_lowercase + string.digits
            chars = ''.join(dict.fromkeys(chars))  # remove duplicates while preserving order
            
            for length in range(min_length, max_length + 1):
                for password_tuple in itertools.product(chars, repeat=length):
                    password_candidates.append(''.join(password_tuple))
                    if len(password_candidates) >= attempt_limit:
                        attempt_limit_hit = True
                        break
                if attempt_limit_hit:
                    break
        
        if not password_candidates:
            if os.path.exists(upload_path):
                os.remove(upload_path)
            if wordlist_path and os.path.exists(wordlist_path):
                os.remove(wordlist_path)
            return jsonify({'error': 'No passwords available to attempt. Please check your inputs.'}), 400
        
        # Try to crack PDF
        def try_password(pdf_file_path, password):
            try:
                with pikepdf.open(pdf_file_path, password=password) as pdf:
                    return password
            except pikepdf._core.PasswordError:
                return None
            except Exception:
                return None
        
        # Crack PDF using ThreadPoolExecutor
        found_password = None
        max_workers = 4
        
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit password attempts
                future_to_password = {}
                for pwd in password_candidates:
                    future = executor.submit(try_password, upload_path, pwd)
                    future_to_password[future] = pwd
                
                # Check results as they complete
                for future in as_completed(future_to_password):
                    result = future.result()
                    if result:
                        found_password = result
                        # Cancel remaining tasks
                        for f in future_to_password:
                            if not f.done():
                                f.cancel()
                        break
        except Exception as e:
            pass
        
        if found_password:
            # Open PDF with found password and save unprotected version
            try:
                with pikepdf.open(upload_path, password=found_password) as pdf:
                    cracked_filename = 'cracked_' + filename
                    cracked_path = os.path.join(app.config['RESULTS_FOLDER'], cracked_filename)
                    pdf.save(cracked_path)
                
                download_url = url_for('download_result', filename=cracked_filename)

                # Clean up uploaded files
                if os.path.exists(upload_path):
                    os.remove(upload_path)
                if wordlist_path and os.path.exists(wordlist_path):
                    os.remove(wordlist_path)
                
                return jsonify({
                    'success': True,
                    'message': f'PDF cracked successfully. Saved to results folder as {cracked_filename}.',
                    'filename': cracked_filename,
                    'password': found_password,
                    'download_url': download_url,
                    'limited_attempts': attempt_limit_hit
                })
            except Exception as e:
                # Clean up on error
                if os.path.exists(upload_path):
                    os.remove(upload_path)
                if wordlist_path and os.path.exists(wordlist_path):
                    os.remove(wordlist_path)
                return jsonify({'error': f'Error saving cracked PDF: {str(e)}'}), 500
        else:
            # Clean up uploaded files
            if os.path.exists(upload_path):
                os.remove(upload_path)
            if wordlist_path and os.path.exists(wordlist_path):
                os.remove(wordlist_path)
            message = 'Password not found. Try a different wordlist or increase password length range.'
            if attempt_limit_hit:
                message += ' (Web interface limit of 10,000 attempts reached)'
            return jsonify({'success': False, 'message': message}), 404
        
    except Exception as e:
        # Clean up on error
        if 'upload_path' in locals() and os.path.exists(upload_path):
            os.remove(upload_path)
        if 'wordlist_path' in locals() and os.path.exists(wordlist_path):
            os.remove(wordlist_path)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

