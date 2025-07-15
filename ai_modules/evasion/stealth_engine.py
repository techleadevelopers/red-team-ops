
import random
import time
import asyncio
from typing import Dict, List, Any, Optional
import hashlib
import base64
from ai_modules.core.ai_engine import AIEngine

class StealthEvasionAI:
    """
    IA Avançada para Técnicas de Evasão Stealth
    Utiliza machine learning para evadir detecção e análise comportamental
    """
    
    def __init__(self, ai_engine: AIEngine):
        self.ai_engine = ai_engine
        self.evasion_patterns = self._load_evasion_patterns()
        self.behavioral_profiles = self._load_behavioral_profiles()
        
    def _load_evasion_patterns(self):
        """Carregar padrões de evasão"""
        return {
            'timing_attacks': {
                'slow_scan': {'min_delay': 5, 'max_delay': 30, 'variance': 0.3},
                'burst_scan': {'burst_size': 5, 'burst_delay': 0.1, 'pause': 60},
                'random_intervals': {'min_delay': 1, 'max_delay': 120, 'distribution': 'exponential'}
            },
            'traffic_shaping': {
                'packet_fragmentation': True,
                'payload_padding': True,
                'protocol_tunneling': ['dns', 'icmp', 'http'],
                'traffic_mimicry': ['normal_browsing', 'update_check', 'cdn_request']
            },
            'behavioral_mimicry': {
                'user_agents': self._generate_realistic_user_agents(),
                'browser_behaviors': self._generate_browser_behaviors(),
                'session_patterns': self._generate_session_patterns()
            }
        }
    
    def _generate_realistic_user_agents(self):
        """Gerar User-Agents realísticos"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
        ]
    
    def _generate_browser_behaviors(self):
        """Gerar comportamentos de navegador"""
        return {
            'chrome': {
                'headers': {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                },
                'request_patterns': ['GET /', 'GET /favicon.ico', 'GET /robots.txt']
            },
            'firefox': {
                'headers': {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                },
                'request_patterns': ['GET /', 'GET /favicon.ico']
            }
        }
    
    def _generate_session_patterns(self):
        """Gerar padrões de sessão"""
        return {
            'normal_browsing': {
                'session_duration': (300, 1800),  # 5-30 minutos
                'pages_per_session': (3, 15),
                'think_time': (2, 30),
                'scroll_behavior': True,
                'back_button_usage': 0.2
            },
            'focused_research': {
                'session_duration': (600, 3600),  # 10-60 minutos
                'pages_per_session': (5, 25),
                'think_time': (10, 120),
                'scroll_behavior': True,
                'back_button_usage': 0.4
            }
        }
    
    def _load_behavioral_profiles(self):
        """Carregar perfis comportamentais"""
        return {
            'legitimate_user': {
                'error_tolerance': 0.1,
                'retry_behavior': True,
                'cookie_acceptance': 0.8,
                'javascript_enabled': True,
                'referrer_consistency': True
            },
            'security_researcher': {
                'error_tolerance': 0.3,
                'retry_behavior': True,
                'cookie_acceptance': 0.6,
                'javascript_enabled': True,
                'referrer_consistency': False
            },
            'automated_crawler': {
                'error_tolerance': 0.8,
                'retry_behavior': False,
                'cookie_acceptance': 0.2,
                'javascript_enabled': False,
                'referrer_consistency': True
            }
        }
    
    async def generate_stealth_session(self, target: str, attack_type: str = "recon") -> Dict[str, Any]:
        """Gerar sessão stealth personalizada"""
        
        # Selecionar perfil comportamental
        profile = await self._select_optimal_profile(target, attack_type)
        
        # Gerar configuração de sessão
        session_config = {
            'profile': profile,
            'timing_strategy': await self._generate_timing_strategy(attack_type),
            'traffic_shaping': await self._generate_traffic_shaping(),
            'headers': await self._generate_realistic_headers(profile),
            'behavioral_patterns': await self._generate_behavioral_patterns(profile),
            'evasion_techniques': await self._select_evasion_techniques(target),
            'session_metadata': {
                'created_at': time.time(),
                'target': target,
                'attack_type': attack_type,
                'session_id': self._generate_session_id()
            }
        }
        
        return session_config
    
    async def _select_optimal_profile(self, target: str, attack_type: str) -> str:
        """Selecionar perfil comportamental ótimo"""
        
        # Análise heurística para seleção de perfil
        if attack_type in ['recon', 'osint']:
            return 'legitimate_user'
        elif attack_type in ['vulnerability_scan', 'web_attack']:
            return 'security_researcher'
        elif attack_type in ['mass_scan', 'automation']:
            return 'automated_crawler'
        else:
            return random.choice(list(self.behavioral_profiles.keys()))
    
    async def _generate_timing_strategy(self, attack_type: str) -> Dict[str, Any]:
        """Gerar estratégia de timing"""
        
        strategies = {
            'recon': self.evasion_patterns['timing_attacks']['random_intervals'],
            'scan': self.evasion_patterns['timing_attacks']['slow_scan'],
            'exploit': self.evasion_patterns['timing_attacks']['burst_scan']
        }
        
        base_strategy = strategies.get(attack_type, self.evasion_patterns['timing_attacks']['random_intervals'])
        
        # Adicionar jitter inteligente
        strategy = base_strategy.copy()
        strategy['jitter'] = random.uniform(0.1, 0.5)
        strategy['adaptive_delay'] = True
        
        return strategy
    
    async def _generate_traffic_shaping(self) -> Dict[str, Any]:
        """Gerar configuração de modelagem de tráfego"""
        
        shaping_config = {
            'packet_size_variation': True,
            'inter_packet_delay': random.uniform(0.01, 0.1),
            'protocol_diversification': True,
            'payload_obfuscation': True,
            'traffic_padding': {
                'enabled': True,
                'min_padding': 64,
                'max_padding': 1024,
                'pattern': 'random'
            }
        }
        
        return shaping_config
    
    async def _generate_realistic_headers(self, profile: str) -> Dict[str, str]:
        """Gerar headers HTTP realísticos"""
        
        # Selecionar navegador base
        browser = random.choice(['chrome', 'firefox'])
        base_headers = self.evasion_patterns['behavioral_mimicry']['browser_behaviors'][browser]['headers'].copy()
        
        # Personalizar baseado no perfil
        if profile == 'security_researcher':
            base_headers['X-Forwarded-For'] = self._generate_proxy_chain()
            base_headers['Via'] = f"1.1 proxy-{random.randint(1, 999)}.example.com"
        
        # Adicionar headers de sessão realísticos
        base_headers['User-Agent'] = random.choice(self.evasion_patterns['behavioral_mimicry']['user_agents'])
        base_headers['Cache-Control'] = random.choice(['no-cache', 'max-age=0', 'no-store'])
        
        # Headers específicos do navegador
        if 'Chrome' in base_headers['User-Agent']:
            base_headers['sec-ch-ua'] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
            base_headers['sec-ch-ua-mobile'] = '?0'
            base_headers['sec-ch-ua-platform'] = '"Windows"'
        
        return base_headers
    
    def _generate_proxy_chain(self) -> str:
        """Gerar cadeia de proxy realística"""
        proxy_ips = [
            f"{random.randint(10, 192)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            for _ in range(random.randint(1, 3))
        ]
        return ', '.join(proxy_ips)
    
    async def _generate_behavioral_patterns(self, profile: str) -> Dict[str, Any]:
        """Gerar padrões comportamentais"""
        
        profile_data = self.behavioral_profiles[profile]
        session_pattern = random.choice(list(self.evasion_patterns['behavioral_mimicry']['session_patterns'].values()))
        
        behavioral_config = {
            'mouse_movements': self._generate_mouse_patterns(),
            'keyboard_timing': self._generate_keyboard_patterns(),
            'scroll_behavior': self._generate_scroll_patterns(),
            'click_patterns': self._generate_click_patterns(),
            'session_flow': self._generate_session_flow(session_pattern),
            'error_handling': self._generate_error_handling(profile_data)
        }
        
        return behavioral_config
    
    def _generate_mouse_patterns(self) -> Dict[str, Any]:
        """Gerar padrões de movimento do mouse"""
        return {
            'movement_style': random.choice(['smooth', 'jerky', 'precise']),
            'click_timing': {
                'min_delay': random.uniform(0.1, 0.5),
                'max_delay': random.uniform(0.5, 2.0),
                'variance': random.uniform(0.1, 0.3)
            },
            'hover_behavior': {
                'enabled': random.choice([True, False]),
                'duration': random.uniform(0.5, 3.0)
            }
        }
    
    def _generate_keyboard_patterns(self) -> Dict[str, Any]:
        """Gerar padrões de digitação"""
        return {
            'typing_speed': random.uniform(50, 150),  # WPM
            'error_rate': random.uniform(0.01, 0.05),
            'backspace_usage': random.uniform(0.1, 0.3),
            'pause_patterns': {
                'word_pause': random.uniform(0.1, 0.5),
                'sentence_pause': random.uniform(0.5, 2.0)
            }
        }
    
    def _generate_scroll_patterns(self) -> Dict[str, Any]:
        """Gerar padrões de scroll"""
        return {
            'scroll_speed': random.uniform(100, 500),  # pixels por segundo
            'scroll_direction': random.choice(['linear', 'random', 'reading_pattern']),
            'pause_frequency': random.uniform(0.1, 0.4),
            'scroll_back_probability': random.uniform(0.1, 0.3)
        }
    
    def _generate_click_patterns(self) -> Dict[str, Any]:
        """Gerar padrões de clique"""
        return {
            'click_accuracy': random.uniform(0.8, 1.0),
            'double_click_probability': random.uniform(0.05, 0.15),
            'right_click_probability': random.uniform(0.02, 0.08),
            'link_follow_probability': random.uniform(0.6, 0.9)
        }
    
    def _generate_session_flow(self, session_pattern: Dict) -> Dict[str, Any]:
        """Gerar fluxo de sessão"""
        duration_range = session_pattern['session_duration']
        pages_range = session_pattern['pages_per_session']
        think_time_range = session_pattern['think_time']
        
        return {
            'session_duration': random.randint(*duration_range),
            'total_pages': random.randint(*pages_range),
            'avg_think_time': random.randint(*think_time_range),
            'back_button_usage': session_pattern['back_button_usage'],
            'scroll_behavior': session_pattern['scroll_behavior']
        }
    
    def _generate_error_handling(self, profile_data: Dict) -> Dict[str, Any]:
        """Gerar comportamento de tratamento de erros"""
        return {
            'retry_on_error': profile_data['retry_behavior'],
            'error_tolerance': profile_data['error_tolerance'],
            'timeout_behavior': random.choice(['retry', 'skip', 'wait']),
            'error_logging': random.choice([True, False])
        }
    
    async def _select_evasion_techniques(self, target: str) -> List[str]:
        """Selecionar técnicas de evasão apropriadas"""
        
        available_techniques = [
            'request_randomization',
            'header_spoofing',
            'timing_randomization',
            'payload_encoding',
            'traffic_fragmentation',
            'protocol_tunneling',
            'session_rotation',
            'ip_rotation',
            'user_agent_rotation'
        ]
        
        # Selecionar baseado no tipo de alvo
        if target.startswith('http'):
            selected_techniques = [
                'request_randomization',
                'header_spoofing',
                'timing_randomization',
                'user_agent_rotation'
            ]
        else:
            selected_techniques = [
                'timing_randomization',
                'traffic_fragmentation',
                'ip_rotation'
            ]
        
        # Adicionar técnicas aleatórias
        additional = random.sample(
            [t for t in available_techniques if t not in selected_techniques],
            random.randint(1, 3)
        )
        
        return selected_techniques + additional
    
    def _generate_session_id(self) -> str:
        """Gerar ID de sessão único"""
        timestamp = str(time.time())
        random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
        session_string = f"{timestamp}_{random_data}"
        return hashlib.sha256(session_string.encode()).hexdigest()[:16]
    
    async def apply_stealth_delay(self, timing_config: Dict[str, Any]) -> None:
        """Aplicar delay stealth inteligente"""
        
        if timing_config.get('adaptive_delay'):
            # Delay adaptativo baseado em hora do dia e carga
            base_delay = timing_config.get('min_delay', 1)
            max_delay = timing_config.get('max_delay', 10)
            jitter = timing_config.get('jitter', 0.1)
            
            # Calcular delay baseado em fatores externos
            current_hour = time.localtime().tm_hour
            
            # Ajustar delay baseado na hora (simular atividade humana)
            if 9 <= current_hour <= 17:  # Horário comercial
                hour_multiplier = 1.5
            elif 22 <= current_hour or current_hour <= 6:  # Madrugada
                hour_multiplier = 0.7
            else:
                hour_multiplier = 1.0
            
            # Calcular delay final
            adjusted_delay = base_delay * hour_multiplier
            jitter_amount = adjusted_delay * jitter * random.uniform(-1, 1)
            final_delay = max(0.1, adjusted_delay + jitter_amount)
            final_delay = min(final_delay, max_delay)
            
            await asyncio.sleep(final_delay)
        
        else:
            # Delay simples
            delay = random.uniform(
                timing_config.get('min_delay', 1),
                timing_config.get('max_delay', 5)
            )
            await asyncio.sleep(delay)
    
    async def generate_polymorphic_request(self, base_request: Dict, evasion_level: int = 3) -> Dict[str, Any]:
        """Gerar requisição polimórfica"""
        
        polymorphic_request = base_request.copy()
        
        # Aplicar transformações baseadas no nível de evasão
        for level in range(evasion_level):
            transformation = random.choice([
                self._transform_headers,
                self._transform_payload,
                self._transform_parameters,
                self._transform_encoding
            ])
            
            polymorphic_request = transformation(polymorphic_request)
        
        # Adicionar metadados de evasão
        polymorphic_request['evasion_metadata'] = {
            'transformations_applied': evasion_level,
            'evasion_score': await self._calculate_evasion_score(polymorphic_request),
            'detection_probability': await self._estimate_detection_probability(polymorphic_request)
        }
        
        return polymorphic_request
    
    def _transform_headers(self, request: Dict) -> Dict:
        """Transformar headers da requisição"""
        if 'headers' not in request:
            request['headers'] = {}
        
        # Adicionar headers de ruído
        noise_headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Forwarded-Proto': 'https',
            'X-Real-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Originating-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
        
        # Adicionar alguns headers aleatórios
        selected_noise = random.sample(list(noise_headers.items()), random.randint(1, 2))
        for key, value in selected_noise:
            request['headers'][key] = value
        
        return request
    
    def _transform_payload(self, request: Dict) -> Dict:
        """Transformar payload da requisição"""
        if 'data' in request and request['data']:
            # Adicionar padding ao payload
            padding = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 20)))
            request['data'] = f"{request['data']}&_padding={padding}"
        
        return request
    
    def _transform_parameters(self, request: Dict) -> Dict:
        """Transformar parâmetros da requisição"""
        if 'params' in request and request['params']:
            # Adicionar parâmetros de ruído
            noise_params = {
                '_timestamp': str(int(time.time())),
                '_random': ''.join(random.choices('0123456789abcdef', k=8)),
                '_cache': random.choice(['no-cache', 'reload', 'force-cache'])
            }
            
            # Mesclar parâmetros
            if isinstance(request['params'], dict):
                request['params'].update(noise_params)
        
        return request
    
    def _transform_encoding(self, request: Dict) -> Dict:
        """Transformar encoding da requisição"""
        if 'headers' not in request:
            request['headers'] = {}
        
        # Variar encoding
        encodings = ['gzip', 'deflate', 'br', 'identity']
        request['headers']['Accept-Encoding'] = ', '.join(random.sample(encodings, random.randint(2, 4)))
        
        return request
    
    async def _calculate_evasion_score(self, request: Dict) -> float:
        """Calcular score de evasão"""
        score_factors = []
        
        # Fator de headers
        if 'headers' in request:
            header_count = len(request['headers'])
            header_score = min(header_count / 15, 1.0)  # Normalizar para 15 headers
            score_factors.append(header_score * 0.3)
        
        # Fator de encoding
        if 'headers' in request and 'Accept-Encoding' in request['headers']:
            encoding_count = len(request['headers']['Accept-Encoding'].split(','))
            encoding_score = min(encoding_count / 4, 1.0)
            score_factors.append(encoding_score * 0.2)
        
        # Fator de complexidade
        request_complexity = len(str(request)) / 1000  # Normalizar
        complexity_score = min(request_complexity, 1.0)
        score_factors.append(complexity_score * 0.3)
        
        # Fator de randomização
        randomization_score = 0.2  # Score base para randomização
        score_factors.append(randomization_score)
        
        return min(sum(score_factors), 1.0)
    
    async def _estimate_detection_probability(self, request: Dict) -> float:
        """Estimar probabilidade de detecção"""
        detection_factors = []
        
        # Fator de suspeição baseado em headers
        suspicious_headers = ['X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP']
        if 'headers' in request:
            suspicious_count = sum(1 for header in suspicious_headers if header in request['headers'])
            detection_factors.append(suspicious_count / len(suspicious_headers) * 0.4)
        
        # Fator de payload suspeito
        if 'data' in request and request['data']:
            payload = str(request['data']).lower()
            suspicious_patterns = ['script', 'union', 'select', 'exec', 'eval']
            pattern_matches = sum(1 for pattern in suspicious_patterns if pattern in payload)
            detection_factors.append(pattern_matches / len(suspicious_patterns) * 0.6)
        
        return min(sum(detection_factors), 1.0)
