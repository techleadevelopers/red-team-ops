
import asyncio
import aiohttp
import dns.resolver
import socket
from typing import Dict, List, Any, Optional
import ipaddress
import subprocess
import json
from urllib.parse import urlparse
import ssl
from ai_modules.core.ai_engine import AIEngine

class TargetAnalyzerAI:
    """
    IA Avançada para Análise e Reconhecimento de Alvos
    Utiliza machine learning para análise comportamental e descoberta de vulnerabilidades
    """
    
    def __init__(self, ai_engine: AIEngine):
        self.ai_engine = ai_engine
        self.session = None
        self.scan_results = {}
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': self._get_random_user_agent()}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _get_random_user_agent(self) -> str:
        """Obter User-Agent aleatório para evasão"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        import random
        return random.choice(user_agents)
    
    async def comprehensive_target_analysis(self, target: str) -> Dict[str, Any]:
        """Análise completa de alvo usando IA"""
        
        analysis_results = {
            'target': target,
            'timestamp': asyncio.get_event_loop().time(),
            'dns_analysis': {},
            'port_analysis': {},
            'web_analysis': {},
            'ssl_analysis': {},
            'behavioral_analysis': {},
            'vulnerability_assessment': {},
            'ai_risk_score': 0.0
        }
        
        # Análise DNS
        analysis_results['dns_analysis'] = await self._analyze_dns(target)
        
        # Análise de Portas
        analysis_results['port_analysis'] = await self._analyze_ports(target)
        
        # Análise Web
        if self._is_web_target(target):
            analysis_results['web_analysis'] = await self._analyze_web_target(target)
            analysis_results['ssl_analysis'] = await self._analyze_ssl(target)
        
        # Análise Comportamental com IA
        analysis_results['behavioral_analysis'] = await self._behavioral_analysis(analysis_results)
        
        # Avaliação de Vulnerabilidades
        analysis_results['vulnerability_assessment'] = await self._assess_vulnerabilities(analysis_results)
        
        # Score de Risco calculado pela IA
        analysis_results['ai_risk_score'] = await self._calculate_ai_risk_score(analysis_results)
        
        return analysis_results
    
    async def _analyze_dns(self, target: str) -> Dict[str, Any]:
        """Análise DNS avançada"""
        dns_results = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'subdomains': [],
            'dns_anomalies': []
        }
        
        try:
            # Resolver diferentes tipos de registros
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    records = [str(rdata) for rdata in answers]
                    dns_results[f'{record_type.lower()}_records'] = records
                except:
                    pass
            
            # Análise de subdomínios
            dns_results['subdomains'] = await self._discover_subdomains(target)
            
            # Detectar anomalias DNS
            dns_results['dns_anomalies'] = await self._detect_dns_anomalies(dns_results)
            
        except Exception as e:
            dns_results['error'] = str(e)
        
        return dns_results
    
    async def _discover_subdomains(self, target: str) -> List[str]:
        """Descobrir subdomínios usando IA"""
        common_subdomains = [
            'www', 'api', 'admin', 'mail', 'ftp', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'portal', 'secure', 'vpn', 'remote'
        ]
        
        discovered_subdomains = []
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{target}"
            try:
                dns.resolver.resolve(full_domain, 'A')
                discovered_subdomains.append(full_domain)
            except:
                pass
        
        return discovered_subdomains
    
    async def _detect_dns_anomalies(self, dns_data: Dict) -> List[str]:
        """Detectar anomalias DNS usando IA"""
        anomalies = []
        
        # Verificar múltiplos A records (possível CDN ou load balancing)
        if len(dns_data.get('a_records', [])) > 3:
            anomalies.append('multiple_a_records')
        
        # Verificar registros TXT suspeitos
        for txt_record in dns_data.get('txt_records', []):
            if any(keyword in txt_record.lower() for keyword in ['spf', 'dmarc', 'dkim']):
                anomalies.append('email_security_records')
        
        # Verificar redirecionamentos CNAME
        if dns_data.get('cname_records'):
            anomalies.append('cname_redirection')
        
        return anomalies
    
    async def _analyze_ports(self, target: str) -> Dict[str, Any]:
        """Análise de portas com IA"""
        port_results = {
            'open_ports': [],
            'filtered_ports': [],
            'service_detection': {},
            'port_patterns': []
        }
        
        # Portas comuns para escanear
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        
        try:
            for port in common_ports:
                if await self._check_port(target, port):
                    port_results['open_ports'].append(port)
                    
                    # Detectar serviço
                    service = await self._detect_service(target, port)
                    if service:
                        port_results['service_detection'][port] = service
            
            # Analisar padrões de portas
            port_results['port_patterns'] = await self._analyze_port_patterns(port_results['open_ports'])
            
        except Exception as e:
            port_results['error'] = str(e)
        
        return port_results
    
    async def _check_port(self, target: str, port: int, timeout: float = 3.0) -> bool:
        """Verificar se porta está aberta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    async def _detect_service(self, target: str, port: int) -> Optional[str]:
        """Detectar serviço rodando na porta"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
        return service_map.get(port, 'Unknown')
    
    async def _analyze_port_patterns(self, open_ports: List[int]) -> List[str]:
        """Analisar padrões de portas com IA"""
        patterns = []
        
        # Detectar servidor web
        if any(port in open_ports for port in [80, 443, 8080, 8443]):
            patterns.append('web_server')
        
        # Detectar servidor de email
        if any(port in open_ports for port in [25, 110, 143, 993, 995]):
            patterns.append('email_server')
        
        # Detectar banco de dados
        if any(port in open_ports for port in [1433, 3306, 5432]):
            patterns.append('database_server')
        
        # Detectar acesso remoto
        if any(port in open_ports for port in [22, 3389]):
            patterns.append('remote_access')
        
        return patterns
    
    async def _analyze_web_target(self, target: str) -> Dict[str, Any]:
        """Análise web avançada"""
        web_results = {
            'technologies': [],
            'headers': {},
            'forms': [],
            'links': [],
            'cookies': [],
            'javascript_analysis': {},
            'security_headers': {}
        }
        
        if not self.session:
            return web_results
        
        try:
            url = f"http://{target}" if not target.startswith('http') else target
            
            async with self.session.get(url) as response:
                web_results['status_code'] = response.status
                web_results['headers'] = dict(response.headers)
                
                content = await response.text()
                
                # Detectar tecnologias
                web_results['technologies'] = await self._detect_technologies(content, web_results['headers'])
                
                # Analisar cabeçalhos de segurança
                web_results['security_headers'] = await self._analyze_security_headers(web_results['headers'])
                
                # Analisar formulários
                web_results['forms'] = await self._analyze_forms(content)
                
                # Analisar JavaScript
                web_results['javascript_analysis'] = await self._analyze_javascript(content)
                
        except Exception as e:
            web_results['error'] = str(e)
        
        return web_results
    
    async def _detect_technologies(self, content: str, headers: Dict) -> List[str]:
        """Detectar tecnologias web"""
        technologies = []
        
        # Analisar headers
        if 'server' in headers:
            server = headers['server'].lower()
            if 'apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'iis' in server:
                technologies.append('IIS')
        
        # Analisar conteúdo
        content_lower = content.lower()
        
        if 'wordpress' in content_lower:
            technologies.append('WordPress')
        if 'drupal' in content_lower:
            technologies.append('Drupal')
        if 'joomla' in content_lower:
            technologies.append('Joomla')
        if 'jquery' in content_lower:
            technologies.append('jQuery')
        if 'bootstrap' in content_lower:
            technologies.append('Bootstrap')
        if 'react' in content_lower:
            technologies.append('React')
        if 'angular' in content_lower:
            technologies.append('Angular')
        
        return technologies
    
    async def _analyze_security_headers(self, headers: Dict) -> Dict[str, Any]:
        """Analisar cabeçalhos de segurança"""
        security_analysis = {
            'present': [],
            'missing': [],
            'score': 0
        }
        
        security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'referrer-policy'
        ]
        
        for header in security_headers:
            if header in [h.lower() for h in headers.keys()]:
                security_analysis['present'].append(header)
            else:
                security_analysis['missing'].append(header)
        
        # Calcular score de segurança
        security_analysis['score'] = len(security_analysis['present']) / len(security_headers)
        
        return security_analysis
    
    async def _analyze_forms(self, content: str) -> List[Dict]:
        """Analisar formulários na página"""
        # Análise simples de formulários
        import re
        
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for form_content in form_matches:
            form_info = {
                'inputs': [],
                'action': '',
                'method': 'GET',
                'has_csrf': False
            }
            
            # Extrair inputs
            input_pattern = r'<input[^>]*>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_tag in inputs:
                if 'type=' in input_tag:
                    type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                    input_type = type_match.group(1) if type_match else 'text'
                    form_info['inputs'].append(input_type)
                
                # Verificar CSRF token
                if 'csrf' in input_tag.lower() or 'token' in input_tag.lower():
                    form_info['has_csrf'] = True
            
            forms.append(form_info)
        
        return forms
    
    async def _analyze_javascript(self, content: str) -> Dict[str, Any]:
        """Analisar JavaScript na página"""
        js_analysis = {
            'external_scripts': [],
            'inline_scripts_count': 0,
            'potential_vulnerabilities': []
        }
        
        import re
        
        # Scripts externos
        script_src_pattern = r'<script[^>]*src=["\']([^"\']*)["\'][^>]*>'
        external_scripts = re.findall(script_src_pattern, content, re.IGNORECASE)
        js_analysis['external_scripts'] = external_scripts
        
        # Scripts inline
        inline_script_pattern = r'<script[^>]*>(.*?)</script>'
        inline_scripts = re.findall(inline_script_pattern, content, re.DOTALL | re.IGNORECASE)
        js_analysis['inline_scripts_count'] = len(inline_scripts)
        
        # Verificar vulnerabilidades potenciais
        for script in inline_scripts:
            if 'eval(' in script:
                js_analysis['potential_vulnerabilities'].append('eval_usage')
            if 'innerHTML' in script:
                js_analysis['potential_vulnerabilities'].append('innerHTML_usage')
            if 'document.write' in script:
                js_analysis['potential_vulnerabilities'].append('document_write_usage')
        
        return js_analysis
    
    async def _analyze_ssl(self, target: str) -> Dict[str, Any]:
        """Análise SSL/TLS"""
        ssl_analysis = {
            'certificate_info': {},
            'ssl_vulnerabilities': [],
            'cipher_suites': [],
            'ssl_score': 0.0
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_analysis['certificate_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
                    
                    # Verificar data de expiração
                    from datetime import datetime
                    import ssl
                    
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        ssl_analysis['ssl_vulnerabilities'].append('certificate_expiring_soon')
                    
                    # Score SSL básico
                    ssl_analysis['ssl_score'] = 0.8 if days_until_expiry > 30 else 0.4
                    
        except Exception as e:
            ssl_analysis['error'] = str(e)
        
        return ssl_analysis
    
    async def _behavioral_analysis(self, analysis_data: Dict) -> Dict[str, Any]:
        """Análise comportamental usando IA"""
        behavioral_results = {
            'behavior_patterns': [],
            'anomaly_score': 0.0,
            'threat_indicators': [],
            'recommended_attacks': []
        }
        
        # Analisar padrões comportamentais
        if analysis_data.get('port_analysis', {}).get('open_ports'):
            open_ports = analysis_data['port_analysis']['open_ports']
            
            if 22 in open_ports:
                behavioral_results['recommended_attacks'].append('ssh_bruteforce')
            
            if 80 in open_ports or 443 in open_ports:
                behavioral_results['recommended_attacks'].append('web_attacks')
                
                # Verificar formulários sem CSRF
                forms = analysis_data.get('web_analysis', {}).get('forms', [])
                if any(not form.get('has_csrf', True) for form in forms):
                    behavioral_results['threat_indicators'].append('csrf_vulnerability')
            
            if 3306 in open_ports or 1433 in open_ports:
                behavioral_results['recommended_attacks'].append('database_attacks')
        
        # Calcular score de anomalia
        anomaly_factors = []
        
        # Muitas portas abertas
        if len(analysis_data.get('port_analysis', {}).get('open_ports', [])) > 10:
            anomaly_factors.append(0.3)
        
        # Headers de segurança ausentes
        security_score = analysis_data.get('web_analysis', {}).get('security_headers', {}).get('score', 1.0)
        if security_score < 0.5:
            anomaly_factors.append(0.4)
        
        # SSL fraco ou ausente
        ssl_score = analysis_data.get('ssl_analysis', {}).get('ssl_score', 1.0)
        if ssl_score < 0.5:
            anomaly_factors.append(0.3)
        
        behavioral_results['anomaly_score'] = min(sum(anomaly_factors), 1.0)
        
        return behavioral_results
    
    async def _assess_vulnerabilities(self, analysis_data: Dict) -> Dict[str, Any]:
        """Avaliar vulnerabilidades usando IA"""
        vuln_assessment = {
            'critical_vulnerabilities': [],
            'high_vulnerabilities': [],
            'medium_vulnerabilities': [],
            'low_vulnerabilities': [],
            'overall_risk_level': 'low'
        }
        
        # Avaliar vulnerabilidades baseado na análise
        
        # SSL/TLS issues
        ssl_score = analysis_data.get('ssl_analysis', {}).get('ssl_score', 1.0)
        if ssl_score < 0.3:
            vuln_assessment['critical_vulnerabilities'].append('weak_ssl_configuration')
        elif ssl_score < 0.6:
            vuln_assessment['high_vulnerabilities'].append('ssl_configuration_issues')
        
        # Security headers
        security_score = analysis_data.get('web_analysis', {}).get('security_headers', {}).get('score', 1.0)
        if security_score < 0.3:
            vuln_assessment['high_vulnerabilities'].append('missing_security_headers')
        elif security_score < 0.7:
            vuln_assessment['medium_vulnerabilities'].append('incomplete_security_headers')
        
        # Forms without CSRF
        forms = analysis_data.get('web_analysis', {}).get('forms', [])
        csrf_vulnerable_forms = [f for f in forms if not f.get('has_csrf', True)]
        if csrf_vulnerable_forms:
            vuln_assessment['medium_vulnerabilities'].append('csrf_vulnerable_forms')
        
        # JavaScript vulnerabilities
        js_vulns = analysis_data.get('web_analysis', {}).get('javascript_analysis', {}).get('potential_vulnerabilities', [])
        if 'eval_usage' in js_vulns:
            vuln_assessment['high_vulnerabilities'].append('eval_usage_detected')
        
        # Determinar nível de risco geral
        if vuln_assessment['critical_vulnerabilities']:
            vuln_assessment['overall_risk_level'] = 'critical'
        elif vuln_assessment['high_vulnerabilities']:
            vuln_assessment['overall_risk_level'] = 'high'
        elif vuln_assessment['medium_vulnerabilities']:
            vuln_assessment['overall_risk_level'] = 'medium'
        
        return vuln_assessment
    
    async def _calculate_ai_risk_score(self, analysis_data: Dict) -> float:
        """Calcular score de risco usando IA"""
        risk_factors = []
        
        # Fator de anomalia comportamental
        behavioral_anomaly = analysis_data.get('behavioral_analysis', {}).get('anomaly_score', 0.0)
        risk_factors.append(behavioral_anomaly * 0.3)
        
        # Fator de vulnerabilidades
        vuln_data = analysis_data.get('vulnerability_assessment', {})
        vuln_score = (
            len(vuln_data.get('critical_vulnerabilities', [])) * 0.4 +
            len(vuln_data.get('high_vulnerabilities', [])) * 0.3 +
            len(vuln_data.get('medium_vulnerabilities', [])) * 0.2 +
            len(vuln_data.get('low_vulnerabilities', [])) * 0.1
        ) / 10  # Normalizar
        risk_factors.append(min(vuln_score, 1.0) * 0.4)
        
        # Fator de exposição (portas abertas)
        open_ports = len(analysis_data.get('port_analysis', {}).get('open_ports', []))
        exposure_score = min(open_ports / 20, 1.0)  # Normalizar para máximo de 20 portas
        risk_factors.append(exposure_score * 0.3)
        
        # Score final
        final_risk_score = min(sum(risk_factors), 1.0)
        
        return round(final_risk_score, 3)
    
    def _is_web_target(self, target: str) -> bool:
        """Verificar se é um alvo web"""
        return target.startswith('http') or ':' not in target
