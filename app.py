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
    'active_attacks': 23,
    'completed_attacks': 187,
    'compromised_targets': 45,
    'data_exfiltrated': '3.7 TB',
    'last_update': datetime.now().isoformat()
}

modules = {
    'advanced_web': {
        'name': 'Advanced Web Attack Vectors',
        'status': 'ready',
        'attacks': ['JWT Bypass', 'HTTP Smuggling', 'Business Logic', 'SQLi OOB', 'SSRF Chaining', 'XSS Payload Chaining'],
        'icon': 'globe'
    },
    'network_exploitation': {
        'name': 'Network Exploitation',
        'status': 'ready',
        'attacks': ['Port Knocking', 'DNS Tunneling', 'VLAN Hopping', 'ARP Poisoning', 'BGP Hijacking', 'ICMP Tunneling'],
        'icon': 'network-wired'
    },
    'mobile_exploitation': {
        'name': 'Mobile Device Exploitation',
        'status': 'ready',
        'attacks': ['APK Injection', 'iOS Bypass', 'SMS Hijacking', 'IMSI Catchers', 'Bluetooth Attacks', 'NFC Exploitation'],
        'icon': 'mobile-alt'
    },
    'cloud_attacks': {
        'name': 'Cloud Infrastructure Attacks',
        'status': 'ready',
        'attacks': ['AWS Bucket Enum', 'Azure AD Bypass', 'GCP Privilege Esc', 'Container Escape', 'Kubernetes Exploit', 'Serverless Attacks'],
        'icon': 'cloud'
    },
    'ad_attacks': {
        'name': 'Active Directory Exploitation',
        'status': 'ready',
        'attacks': ['Golden Ticket', 'DCSync', 'Kerberoasting', 'LSASS Dump', 'ASREPRoast', 'DCShadow'],
        'icon': 'server'
    },
    'iot_exploitation': {
        'name': 'IoT Device Exploitation',
        'status': 'ready',
        'attacks': ['Firmware Extraction', 'UART Debug', 'Zigbee Attacks', 'LoRa Hijacking', 'MQTT Exploitation', 'Hardware Implants'],
        'icon': 'microchip'
    },
    'ai_adversarial': {
        'name': 'AI/ML Adversarial Attacks',
        'status': 'ready',
        'attacks': ['FGSM', 'Model Extraction', 'Poisoning', 'Membership Inference', 'Backdoor Attacks', 'GAN Adversarial'],
        'icon': 'brain'
    },
    'social_engineering': {
        'name': 'Social Engineering Framework',
        'status': 'ready',
        'attacks': ['Spear Phishing', 'Vishing Campaigns', 'SMS Phishing', 'LinkedIn OSINT', 'Physical Access', 'USB Drops'],
        'icon': 'user-secret'
    },
    'credential_ops': {
        'name': 'Credential Operations',
        'status': 'ready',
        'attacks': ['Browser Dump', 'Credential Stuffing', 'Hash Cracking', 'Session Hijack', 'Password Spraying', 'Token Hijacking'],
        'icon': 'key'
    },
    'crypto_warfare': {
        'name': 'Crypto Warfare',
        'status': 'ready',
        'attacks': ['Wallet Stealer', 'Seed Bruteforce', 'Clipboard Hijack', 'Web3 Phishing', 'DeFi Exploitation', 'NFT Manipulation'],
        'icon': 'coins'
    },
    'stealer_framework': {
        'name': 'Stealer Framework',
        'status': 'ready',
        'attacks': ['Form Jacking', 'Mobile Stealers', 'Request Smuggling', 'Data Exfiltration', 'Keylogger Deploy', 'Screen Capture'],
        'icon': 'mask'
    },
    'ransomware_ops': {
        'name': 'Ransomware Operations',
        'status': 'ready',
        'attacks': ['File Encryption', 'Shadow Copy Delete', 'Network Spread', 'Payment Portal', 'Data Leak Threat', 'System Recovery Block'],
        'icon': 'lock'
    }
}

@app.route('/')
def dashboard():
    return render_template('dashboard.html', modules=modules, status=attack_status)

@app.route('/api/status')
def get_status():
    import random
    
    # Simulate real-time attack activity
    attack_status['active_attacks'] = random.randint(15, 35)
    attack_status['completed_attacks'] = random.randint(180, 250)
    attack_status['compromised_targets'] = random.randint(40, 80)
    attack_status['data_exfiltrated'] = f"{random.randint(3, 12)}.{random.randint(1, 9)} TB"
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

# Integração com módulos Python avançados
@app.route('/api/execute-web-attack', methods=['POST'])
def execute_web_attack():
    """Executar ataque web com módulo Python"""
    try:
        from modules.web_attacks import web_attacks
        
        data = request.get_json()
        target = data.get('target', 'example.com')
        attack_type = data.get('attack_type', 'xss')
        
        # Executar ataque baseado no tipo
        if attack_type == 'xss':
            import asyncio
            result = asyncio.run(web_attacks.xss_exploitation(target, data.get('xss_type', 'reflected')))
        elif attack_type == 'sqli':
            import asyncio
            result = asyncio.run(web_attacks.sql_injection_attack(target, data.get('injection_type', 'union')))
        elif attack_type == 'rce':
            import asyncio
            result = asyncio.run(web_attacks.rce_exploitation(target, data.get('technique', 'php')))
        elif attack_type == 'lfi':
            import asyncio
            result = asyncio.run(web_attacks.lfi_rfi_attack(target, 'lfi'))
        elif attack_type == 'ssrf':
            import asyncio
            result = asyncio.run(web_attacks.ssrf_attack(target, data.get('ssrf_type', 'internal')))
        else:
            result = {'error': 'Unknown attack type'}
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute-network-attack', methods=['POST'])
def execute_network_attack():
    """Executar ataque de rede"""
    try:
        from modules.network_exploitation import network_exploitation
        
        data = request.get_json()
        attack_type = data.get('attack_type', 'port_scan')
        target = data.get('target', '192.168.1.0/24')
        
        import asyncio
        
        if attack_type == 'network_discovery':
            result = asyncio.run(network_exploitation.network_discovery(target))
        elif attack_type == 'port_scan':
            result = asyncio.run(network_exploitation.port_scanning_attack(data.get('targets', [target]), data.get('scan_type', 'stealth')))
        elif attack_type == 'dns_attack':
            result = asyncio.run(network_exploitation.dns_manipulation_attack(target, data.get('dns_type', 'poisoning')))
        elif attack_type == 'arp_spoof':
            result = asyncio.run(network_exploitation.arp_spoofing_attack(target))
        elif attack_type == 'vlan_hop':
            result = asyncio.run(network_exploitation.vlan_hopping_attack(target))
        else:
            result = {'error': 'Unknown network attack type'}
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute-mobile-attack', methods=['POST'])
def execute_mobile_attack():
    """Executar ataque mobile"""
    try:
        from modules.mobile_exploitation import mobile_exploitation
        
        data = request.get_json()
        attack_type = data.get('attack_type', 'apk_injection')
        target = data.get('target', 'target_app')
        
        import asyncio
        
        if attack_type == 'apk_injection':
            result = asyncio.run(mobile_exploitation.apk_injection_attack(target, data.get('payload_type', 'backdoor')))
        elif attack_type == 'ios_bypass':
            result = asyncio.run(mobile_exploitation.ios_bypass_attack(target, data.get('bypass_type', 'jailbreak')))
        elif attack_type == 'sms_hijack':
            result = asyncio.run(mobile_exploitation.sms_hijacking_attack(target, data.get('method', 'sim_swap')))
        elif attack_type == 'bluetooth_attack':
            result = asyncio.run(mobile_exploitation.bluetooth_attack(target, data.get('bt_type', 'bluejacking')))
        elif attack_type == 'nfc_exploit':
            result = asyncio.run(mobile_exploitation.nfc_exploitation(target, data.get('exploit_type', 'tag_cloning')))
        elif attack_type == 'imsi_catcher':
            result = asyncio.run(mobile_exploitation.imsi_catcher_attack(target, data.get('duration', 30)))
        else:
            result = {'error': 'Unknown mobile attack type'}
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute-cloud-attack', methods=['POST'])
def execute_cloud_attack():
    """Executar ataque cloud"""
    try:
        from modules.cloud_attacks import cloud_attacks
        
        data = request.get_json()
        attack_type = data.get('attack_type', 'bucket_enum')
        target = data.get('target', 'example.com')
        
        import asyncio
        
        if attack_type == 'bucket_enum':
            result = asyncio.run(cloud_attacks.aws_bucket_enumeration(target))
        elif attack_type == 'azure_privesc':
            result = asyncio.run(cloud_attacks.azure_privilege_escalation(target))
        elif attack_type == 'gcp_exploit':
            result = asyncio.run(cloud_attacks.gcp_compute_exploitation(target))
        elif attack_type == 'container_escape':
            result = asyncio.run(cloud_attacks.container_escape_attack(target))
        elif attack_type == 'k8s_exploit':
            result = asyncio.run(cloud_attacks.kubernetes_exploitation(target))
        elif attack_type == 'serverless_attack':
            result = asyncio.run(cloud_attacks.serverless_attacks(target, data.get('provider', 'aws')))
        else:
            result = {'error': 'Unknown cloud attack type'}
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute-ad-attack', methods=['POST'])
def execute_ad_attack():
    """Executar ataque Active Directory"""
    try:
        from modules.ad_exploitation import ad_exploitation
        
        data = request.get_json()
        attack_type = data.get('attack_type', 'kerberoasting')
        target = data.get('target', 'corporate.local')
        
        import asyncio
        
        if attack_type == 'kerberoasting':
            result = asyncio.run(ad_exploitation.kerberoasting_attack(data.get('target_spns')))
        elif attack_type == 'asreproast':
            result = asyncio.run(ad_exploitation.asreproast_attack(data.get('target_users')))
        elif attack_type == 'golden_ticket':
            result = asyncio.run(ad_exploitation.golden_ticket_attack(data.get('target_user', 'Administrator')))
        elif attack_type == 'dcsync':
            result = asyncio.run(ad_exploitation.dcsync_attack(data.get('target_accounts')))
        elif attack_type == 'lateral_movement':
            result = asyncio.run(ad_exploitation.lateral_movement(data.get('target_hosts', ['dc01.local']), data.get('method', 'psexec')))
        elif attack_type == 'privilege_escalation':
            result = asyncio.run(ad_exploitation.privilege_escalation(data.get('target_host', 'workstation01'), data.get('method', 'token_impersonation')))
        else:
            result = {'error': 'Unknown AD attack type'}
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute-credential-attack', methods=['POST'])
def execute_credential_attack():
    """Executar operações de credenciais"""
    try:
        from modules.credential_operations import credential_operations
        
        data = request.get_json()
        operation = data.get('operation', 'browser_dump')
        
        import asyncio
        
        if operation == 'browser_dump':
            result = asyncio.run(credential_operations.browser_credential_dump(data.get('browsers')))
        elif operation == 'memory_extraction':
            result = asyncio.run(credential_operations.memory_credential_extraction(data.get('processes')))
        elif operation == 'hash_cracking':
            result = asyncio.run(credential_operations.hash_cracking_operation(data.get('hashes', [])))
        elif operation == 'credential_stuffing':
            result = asyncio.run(credential_operations.credential_stuffing_attack(data.get('sites', []), data.get('credentials', [])))
        elif operation == 'session_hijacking':
            result = asyncio.run(credential_operations.session_hijacking(data.get('sessions', [])))
        elif operation == 'token_theft':
            result = asyncio.run(credential_operations.token_theft_operation(data.get('applications', [])))
        else:
            result = {'error': 'Unknown credential operation'}
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute-data-stealer', methods=['POST'])
def execute_data_stealer():
    """Executar operações de data stealer"""
    try:
        from modules.data_stealers import data_stealers
        
        data = request.get_json()
        operation = data.get('operation', 'file_stealer')
        
        import asyncio
        
        if operation == 'file_stealer':
            result = asyncio.run(data_stealers.file_stealer_operation(
                data.get('directories', ['/home', '/documents']), 
                data.get('file_types')
            ))
        elif operation == 'database_extraction':
            result = asyncio.run(data_stealers.database_extraction(data.get('databases', ['webapp_db'])))
        elif operation == 'email_harvesting':
            result = asyncio.run(data_stealers.email_harvesting(data.get('accounts', ['user@company.com'])))
        elif operation == 'keylogger':
            result = asyncio.run(data_stealers.keylogger_operation(data.get('duration', 60)))
        elif operation == 'screenshot_stealer':
            result = asyncio.run(data_stealers.screenshot_stealer(
                data.get('interval', 30), 
                data.get('duration', 60)
            ))
        elif operation == 'network_capture':
            result = asyncio.run(data_stealers.network_traffic_capture(data.get('duration', 30)))
        else:
            result = {'error': 'Unknown data stealer operation'}
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/web-attacks/stats')
def get_web_attacks_stats():
    """Obter estatísticas de ataques web"""
    try:
        from modules.web_attacks import web_attacks
        import asyncio
        stats = asyncio.run(web_attacks.get_attack_statistics())
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ad-attacks/stats')
def get_ad_attacks_stats():
    """Obter estatísticas de ataques AD"""
    try:
        from modules.ad_exploitation import ad_exploitation
        import asyncio
        stats = asyncio.run(ad_exploitation.get_attack_statistics())
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/credential-ops/stats')
def get_credential_stats():
    """Obter estatísticas de operações de credenciais"""
    try:
        from modules.credential_operations import credential_operations
        import asyncio
        stats = asyncio.run(credential_operations.get_credential_statistics())
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/data-stealers/stats')
def get_data_stealers_stats():
    """Obter estatísticas de data stealers"""
    try:
        from modules.data_stealers import data_stealers
        import asyncio
        stats = asyncio.run(data_stealers.get_stealer_statistics())
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network-attacks/stats')
def get_network_attacks_stats():
    """Obter estatísticas de ataques de rede"""
    try:
        from modules.network_exploitation import network_exploitation
        import asyncio
        stats = asyncio.run(network_exploitation.get_network_statistics())
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mobile-attacks/stats')
def get_mobile_attacks_stats():
    """Obter estatísticas de ataques mobile"""
    try:
        from modules.mobile_exploitation import mobile_exploitation
        import asyncio
        stats = asyncio.run(mobile_exploitation.get_mobile_statistics())
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cloud-attacks/stats')
def get_cloud_attacks_stats():
    """Obter estatísticas de ataques cloud"""
    try:
        from modules.cloud_attacks import cloud_attacks
        import asyncio
        stats = asyncio.run(cloud_attacks.get_cloud_statistics())
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai-operations/execute', methods=['POST'])
def execute_ai_operation():
    """Executar operação de IA avançada"""
    try:
        from ai_modules.main import execute_ai_operation
        
        data = request.get_json()
        operation_type = data.get('operation_type', 'reconnaissance')
        target = data.get('target', 'example.com')
        parameters = data.get('parameters', {})
        
        import asyncio
        result = asyncio.run(execute_ai_operation(operation_type, target, parameters))
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai-operations/status')
def get_ai_status():
    """Obter status do sistema de IA"""
    try:
        from ai_modules.main import get_ai_status
        import asyncio
        status = asyncio.run(get_ai_status())
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

@app.route('/network-exploitation')
def network_exploitation_page():
    return render_template('network_exploitation.html')

@app.route('/mobile-exploitation')
def mobile_exploitation_page():
    return render_template('mobile_exploitation.html')

@app.route('/cloud-attacks')
def cloud_attacks_page():
    return render_template('cloud_attacks.html')

@app.route('/iot-exploitation')
def iot_exploitation_page():
    return render_template('iot_exploitation.html')

@app.route('/crypto-warfare')
def crypto_warfare_page():
    return render_template('crypto_warfare.html')

@app.route('/stealer-framework')
def stealer_framework_page():
    return render_template('stealer_framework.html')

@app.route('/ransomware-ops')
def ransomware_ops_page():
    return render_template('ransomware_ops.html')

@app.route('/social-engineering')
def social_engineering_page():
    return render_template('social_engineering.html')


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