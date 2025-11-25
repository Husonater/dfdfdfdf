from flask import Flask, render_template, jsonify, request
import os
import re
import yaml

app = Flask(__name__)
LOG_FILE = '/var/log/siem_logs/suricata_alerts.log'

# Regex to parse syslog format: Timestamp Hostname Process: Message
# Example: 2025-11-25T19:49:51.080680+00:00 siem-backend kernel: eth0: renamed from veth1403c1c
LOG_PATTERN = re.compile(r'^(\S+)\s+(\S+)\s+([^:]+):\s+(.*)$')

def get_severity(message, process):
    message = message.lower()
    process = process.lower()
    
    if 'attack' in message or 'denied' in message or 'blocked' in message or 'fail' in message or 'critical' in message or 'injection' in message:
        return 'Critical', 10
    if 'error' in message or 'warn' in message or 'alert' in message:
        return 'High', 5
    if 'kernel' in process or 'notice' in message:
        return 'Medium', 2
    return 'Info', 1

def parse_details(message):
    details = {
        'src_ip': 'N/A',
        'dst_ip': 'N/A',
        'action': 'Unknown',
        'response': 'Unknown System Response'
    }
    
    # Try to find SRC= and DST= first (common in firewall logs)
    src_match = re.search(r'SRC=([\d\.]+)', message)
    if src_match:
        details['src_ip'] = src_match.group(1)
    
    dst_match = re.search(r'DST=([\d\.]+)', message)
    if dst_match:
        details['dst_ip'] = dst_match.group(1)
        
    # Fallback: Extract all IPs if SRC/DST not found
    if details['src_ip'] == 'N/A' and details['dst_ip'] == 'N/A':
        ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
        if len(ips) >= 1:
            details['src_ip'] = ips[0]
        if len(ips) >= 2:
            details['dst_ip'] = ips[1]
        
    # Infer action and system response
    lower_msg = message.lower()
    if 'block' in lower_msg or 'deny' in lower_msg or 'drop' in lower_msg:
        details['action'] = 'Blocked'
        details['response'] = 'Traffic Dropped (Silently)'
    elif 'reject' in lower_msg:
        details['action'] = 'Rejected'
        details['response'] = 'Connection Rejected (ICMP Unreachable)'
    elif 'allow' in lower_msg or 'accept' in lower_msg:
        details['action'] = 'Allowed'
        details['response'] = 'Traffic Allowed'
    elif 'alert' in lower_msg or 'attack' in lower_msg:
        details['action'] = 'Alerted'
        details['response'] = 'Alert Only (Traffic Allowed)'
        
    return details

def parse_log_line(line):
    match = LOG_PATTERN.match(line)
    if match:
        timestamp = match.group(1)
        hostname = match.group(2)
        process = match.group(3)
        message = match.group(4)
        severity, score = get_severity(message, process)
        details = parse_details(message)
        
        return {
            'timestamp': timestamp,
            'hostname': hostname,
            'process': process,
            'message': message,
            'severity': severity,
            'score': score,
            'details': details,
            'raw': line
        }
    return {
        'timestamp': '-',
        'hostname': '-',
        'process': '-',
        'message': line,
        'severity': 'Info',
        'score': 1,
        'details': {'src_ip': 'N/A', 'dst_ip': 'N/A', 'action': '-', 'response': '-'},
        'raw': line
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify({'logs': []})
    
    search_query = request.args.get('search', '').lower()
    source_filter = request.args.get('source', '').lower()
    
    parsed_logs = []
    with open(LOG_FILE, 'r') as f:
        # Read all lines
        lines = f.readlines()
        
        # Process in reverse order (newest first)
        for line in reversed(lines):
            log_entry = parse_log_line(line.strip())
            
            # Filtering
            if search_query and search_query not in log_entry['raw'].lower():
                continue
            
            if source_filter and source_filter not in log_entry['process'].lower() and source_filter not in log_entry['hostname'].lower():
                continue
                
            parsed_logs.append(log_entry)
            
            # Limit to 500 entries to prevent browser lag
            if len(parsed_logs) >= 500:
                break
    
    return jsonify({'logs': parsed_logs})

import yaml

# ... (existing imports)

TOPOLOGY_FILE = '/app/topology.yml'

def calculate_node_scores():
    scores = {}
    if not os.path.exists(LOG_FILE):
        return scores
        
    with open(LOG_FILE, 'r') as f:
        for line in f:
            entry = parse_log_line(line.strip())
            host = entry['hostname']
            if host not in scores:
                scores[host] = 0
            scores[host] = max(scores[host], entry['score'])
    return scores

import socket

def check_db_connection():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex(('db-backend', 3306))
        s.close()
        return result == 0
    except:
        return False

# --- SIMULATION ENDPOINTS ---
import random
import datetime

def generate_log_entry(attack_type):
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    if attack_type == 'ddos':
        src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        return f"{timestamp} firewall-perimeter kernel: [BLOCK] SRC={src_ip} DST=172.20.20.3 PROTO=TCP SPT={random.randint(1024,65535)} DPT=80 SYN_FLOOD"
    
    elif attack_type == 'sqli':
        payloads = ["' OR 1=1", "UNION SELECT", "DROP TABLE users"]
        payload = random.choice(payloads)
        return f"{timestamp} reverse-proxy-waf modsecurity: [CRITICAL] SQL Injection Detected: {payload} from SRC=192.168.1.66 DST=172.20.20.4"
    
    elif attack_type == 'bruteforce':
        users = ['admin', 'root', 'user', 'service']
        user = random.choice(users)
        return f"{timestamp} webserver sshd: [Failed Password] for {user} from SRC=10.0.0.5 port {random.randint(30000,40000)} ssh2"
        
    return ""

@app.route('/api/simulate/<attack_type>', methods=['POST'])
def simulate_attack(attack_type):
    if not os.path.exists(LOG_FILE):
        return jsonify({'status': 'error', 'message': 'Log file not found'})
        
    count = 1
    if attack_type == 'ddos':
        count = 20 # Generate a burst
    elif attack_type == 'bruteforce':
        count = 5
        
    with open(LOG_FILE, 'a') as f:
        for _ in range(count):
            log = generate_log_entry(attack_type)
            if log:
                f.write(log + '\n')
                
    return jsonify({'status': 'success', 'message': f'Simulated {attack_type} attack ({count} logs)'})

@app.route('/api/stats')
def get_stats():
    stats = {
        'total_logs': 0,
        'severity_counts': {'Critical': 0, 'High': 0, 'Medium': 0, 'Info': 0},
        'top_sources': {},
        'top_targets': {},
        'secure_vault_status': check_db_connection()
    }
    
    if not os.path.exists(LOG_FILE):
        return jsonify(stats)
        
    with open(LOG_FILE, 'r') as f:
        for line in f:
            entry = parse_log_line(line.strip())
            stats['total_logs'] += 1
            
            # Severity
            sev = entry['severity']
            if sev in stats['severity_counts']:
                stats['severity_counts'][sev] += 1
                
            # Top Sources (IPs)
            src_ip = entry.get('details', {}).get('src_ip', 'N/A')
            if src_ip != 'N/A' and src_ip != '-':
                stats['top_sources'][src_ip] = stats['top_sources'].get(src_ip, 0) + 1
                
            # Top Targets (Hostnames)
            host = entry['hostname']
            stats['top_targets'][host] = stats['top_targets'].get(host, 0) + 1

    # Sort and limit top lists
    stats['top_sources'] = dict(sorted(stats['top_sources'].items(), key=lambda item: item[1], reverse=True)[:5])
    stats['top_targets'] = dict(sorted(stats['top_targets'].items(), key=lambda item: item[1], reverse=True)[:5])
    
    return jsonify(stats)

@app.route('/api/topology')
def get_topology():
    if not os.path.exists(TOPOLOGY_FILE):
        return jsonify({'nodes': [], 'edges': []})
    
    node_scores = calculate_node_scores()
    
    try:
        with open(TOPOLOGY_FILE, 'r') as f:
            topo_data = yaml.safe_load(f)
        
        nodes = []
        edges = []
        
        # Parse nodes
        if 'topology' in topo_data and 'nodes' in topo_data['topology']:
            for name, details in topo_data['topology']['nodes'].items():
                kind = details.get('kind', 'unknown')
                image = details.get('image', 'unknown')
                
                # Determine group/color based on image/kind
                group = 'server'
                if ('attacker' in name or 'attacker' in image) and 'client' not in name:
                    group = 'attacker'
                elif 'firewall' in name or 'firewall' in image:
                    group = 'firewall'
                elif 'router' in name or 'frr' in image:
                    group = 'router'
                elif 'siem' in name:
                    group = 'siem'
                
                # Get severity score (default 0)
                # Map container name to hostname if possible, or just use name
                # In clab, hostname usually matches node name
                score = node_scores.get(name, 0)
                
                nodes.append({
                    'id': name,
                    'label': name,
                    'group': group,
                    'title': f"Image: {image}<br>Kind: {kind}<br>Max Severity Score: {score}",
                    'value': score # For sizing or coloring
                })

        # Parse links
        if 'topology' in topo_data and 'links' in topo_data['topology']:
            for link in topo_data['topology']['links']:
                if 'endpoints' in link:
                    # Format: ["node1:eth1", "node2:eth1"]
                    ep1 = link['endpoints'][0].split(':')[0]
                    ep2 = link['endpoints'][1].split(':')[0]
                    edges.append({
                        'from': ep1,
                        'to': ep2
                    })
                    
        return jsonify({'nodes': nodes, 'edges': edges})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
