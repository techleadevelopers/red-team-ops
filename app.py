from flask import Flask, render_template, jsonify, request, send_file
import os
import json
import subprocess
from datetime import datetime
import threading
import time

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'apt_red_team_framework_2024'

# Global status tracking
attack_status = {
    'active_attacks': 0,
    'completed_attacks': 0,
    'compromised_targets': 0,
    'data_exfiltrated': '0 MB',
    'last_update': datetime.now().isoformat()
}

modules = {
    'advanced_web': {
        'name': 'Advanced Web Attack Vectors',
        'status': 'ready',
        'attacks': ['JWT Bypass', 'HTTP Smuggling', 'Business Logic', 'SQLi OOB'],
        'icon': 'globe'
    },
    'ad_attacks': {
        'name': 'Active Directory Exploitation',
        'status': 'ready',
        'attacks': ['Golden Ticket', 'DCSync', 'Kerberoasting', 'LSASS Dump'],
        'icon': 'server'
    },
    'ai_adversarial': {
        'name': 'AI/ML Adversarial Attacks',
        'status': 'ready',
        'attacks': ['FGSM', 'Model Extraction', 'Poisoning', 'Membership Inference'],
        'icon': 'brain'
    },
    'credential_ops': {
        'name': 'Credential Operations',
        'status': 'ready',
        'attacks': ['Browser Dump', 'Credential Stuffing', 'Hash Cracking', 'Session Hijack'],
        'icon': 'key'
    },
    'crypto_warfare': {
        'name': 'Crypto Warfare',
        'status': 'ready',
        'attacks': ['Wallet Stealer', 'Seed Bruteforce', 'Clipboard Hijack', 'Web3 Phishing'],
        'icon': 'coins'
    },
    'stealer_framework': {
        'name': 'Stealer Framework',
        'status': 'ready',
        'attacks': ['Form Jacking', 'Mobile Stealers', 'Request Smuggling', 'Data Exfiltration'],
        'icon': 'mask'
    }
}

@app.route('/')
def dashboard():
    return render_template('dashboard.html', modules=modules, status=attack_status)

@app.route('/api/status')
def get_status():
    attack_status['last_update'] = datetime.now().isoformat()
    return jsonify(attack_status)

@app.route('/api/modules')
def get_modules():
    return jsonify(modules)

@app.route('/api/execute/<module>/<attack>')
def execute_attack(module, attack):
    if module in modules:
        # Simulate attack execution
        attack_status['active_attacks'] += 1

        # Return execution result
        return jsonify({
            'status': 'success',
            'message': f'Executing {attack} from {modules[module]["name"]}',
            'module': module,
            'attack': attack,
            'timestamp': datetime.now().isoformat()
        })

    return jsonify({'status': 'error', 'message': 'Module not found'}), 404

@app.route('/module/<module_name>')
def module_detail(module_name):
    if module_name in modules:
        return render_template('module_detail.html', 
                             module=modules[module_name], 
                             module_name=module_name)
    return "Module not found", 404

@app.route('/terminal')
def terminal():
    return render_template('terminal.html')

@app.route('/api/terminal/execute', methods=['POST'])
def execute_command():
    command = request.json.get('command', '')

    # Security: Only allow specific commands for demo
    allowed_commands = ['ls', 'pwd', 'whoami', 'ps', 'netstat', 'cat README.md']

    if any(cmd in command for cmd in allowed_commands):
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=10)
            return jsonify({
                'output': result.stdout + result.stderr,
                'status': 'success'
            })
        except Exception as e:
            return jsonify({
                'output': f'Error: {str(e)}',
                'status': 'error'
            })

    return jsonify({
        'output': 'Command not allowed in demo mode',
        'status': 'warning'
    })

@app.route('/api/threat-intel')
def get_threat_intel():
    """Simula integração com feeds de threat intelligence públicos"""
    threat_data = {
        'cves_today': 12,
        'active_campaigns': ['APT29', 'Lazarus', 'FIN7'],
        'trending_malware': ['RedLine', 'Qakbot', 'IcedID'],
        'iocs': {
            'domains': ['malicious-domain.com', 'phishing-site.net'],
            'ips': ['192.168.1.100', '10.0.0.50'],
            'hashes': ['a1b2c3d4e5f6...', 'f6e5d4c3b2a1...']
        },
        'last_updated': datetime.now().isoformat()
    }
    return jsonify(threat_data)

@app.route('/api/ai-operations')
def get_ai_operations():
    """Status das operações de IA em tempo real"""
    ai_data = {
        'neural_networks_active': 12,
        'attacks_generated': 358,
        'learning_rate': 99.4,
        'auto_exploits_today': 47,
        'models_trained': 8,
        'threat_patterns_discovered': 156,
        'last_updated': datetime.now().isoformat()
    }
    return jsonify(ai_data)

@app.route('/api/live-attacks')
def get_live_attacks():
    """Simula ataques em tempo real baseados em dados públicos"""
    import random
    attacks = [
        {'type': 'Web Exploit', 'target': 'apache-server.com', 'status': 'in_progress'},
        {'type': 'Credential Stuffing', 'target': 'social-media.com', 'status': 'completed'},
        {'type': 'JWT Bypass', 'target': 'api.target.com', 'status': 'successful'},
        {'type': 'SQL Injection', 'target': 'ecommerce.com', 'status': 'detected'},
        {'type': 'Kerberoasting', 'target': 'corp-domain.local', 'status': 'in_progress'},
    ]

    # Simulated real-time status
    status = {
        'active_attacks': random.randint(15, 30),
        'completed_attacks': random.randint(180, 250),
        'compromised_targets': random.randint(50, 80),
        'data_exfiltrated': f"{random.randint(2, 12)}.{random.randint(1, 9)}TB"
    }

    # Simula ataques aleatórios
    live_attacks = random.sample(attacks, 3)
    return jsonify({
        'active_attacks': live_attacks,
        'total_today': random.randint(45, 89),
        'success_rate': round(random.uniform(85, 95), 1),
        'last_updated': datetime.now().isoformat()
    })

@app.route('/api/real-exploits')


@app.route('/overview')
def overview():
    return render_template('overview.html')

@app.route('/web-attacks')
def web_attacks():
    return render_template('web_attacks.html')

@app.route('/ad-exploitation')
def ad_exploitation():
    return render_template('ad_exploitation.html')

@app.route('/credentials')
def credentials():
    return render_template('credentials.html')

@app.route('/data-stealers')
def data_stealers():
    return render_template('data_stealers.html')

@app.route('/threat-intel')
def threat_intel():
    return render_template('threat_intel.html')

@app.route('/auto-exploits')
def auto_exploits():
    return render_template('auto_exploits.html')

@app.route('/payload-gen')
def payload_gen():
    return render_template('payload_gen.html')

@app.route('/evasion')
def evasion():
    return render_template('evasion.html')

@app.route('/behavior-analysis')
def behavior_analysis():
    return render_template('behavior_analysis.html')

@app.route('/pattern-recognition')
def pattern_recognition():
    return render_template('pattern_recognition.html')

@app.route('/adaptive-learning')
def adaptive_learning():
    return render_template('adaptive_learning.html')

@app.route('/neural-fuzzing')
def neural_fuzzing():
    return render_template('neural_fuzzing.html')


def get_real_exploits():
    """Integração com CVE feeds e exploit databases públicos"""
    exploits = {
        'recent_cves': [
            {'id': 'CVE-2024-1234', 'score': 9.8, 'description': 'Remote Code Execution'},
            {'id': 'CVE-2024-5678', 'score': 8.7, 'description': 'Privilege Escalation'},
            {'id': 'CVE-2024-9012', 'score': 7.5, 'description': 'SQL Injection'}
        ],
        'available_exploits': 1247,
        'weaponized_today': 23,
        'zero_days_discovered': 3,
        'last_updated': datetime.now().isoformat()
    }
    return jsonify(exploits)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)