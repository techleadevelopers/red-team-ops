
import tensorflow as tf
import numpy as np
from typing import Dict, List, Any, Tuple
import asyncio
from datetime import datetime
import json
from sklearn.ensemble import IsolationForest
from ai_modules.core.ai_engine import AIEngine

class AdversarialLearningEngine:
    """
    Sistema de Aprendizado Adversarial para Red Team AI
    Aprende continuamente com ataques para melhorar técnicas
    """
    
    def __init__(self, ai_engine: AIEngine):
        self.ai_engine = ai_engine
        self.attack_memory = []
        self.defense_patterns = {}
        self.learning_rate = 0.001
        self.adversarial_models = {}
        self.attack_success_history = []
        
    async def initialize_adversarial_networks(self):
        """Inicializar redes neurais adversariais"""
        
        # GAN para geração de payloads adversariais
        self.adversarial_models['payload_gan'] = self._create_payload_gan()
        
        # LSTM para predição de defesas
        self.adversarial_models['defense_predictor'] = self._create_defense_predictor()
        
        # CNN para análise de padrões de tráfego
        self.adversarial_models['traffic_analyzer'] = self._create_traffic_analyzer()
        
        # Transformer para contexto de ataques
        self.adversarial_models['attack_context'] = self._create_attack_transformer()
        
    def _create_payload_gan(self):
        """Criar GAN para geração de payloads adversariais"""
        
        # Generator
        generator = tf.keras.Sequential([
            tf.keras.layers.Dense(256, activation='relu', input_shape=(100,)),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dense(512, activation='relu'),
            tf.keras.layers.BatchNormalization(), 
            tf.keras.layers.Dense(1024, activation='relu'),
            tf.keras.layers.Dense(2048, activation='tanh'),
            tf.keras.layers.Reshape((128, 16))
        ])
        
        # Discriminator
        discriminator = tf.keras.Sequential([
            tf.keras.layers.Flatten(input_shape=(128, 16)),
            tf.keras.layers.Dense(1024, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(512, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        return {'generator': generator, 'discriminator': discriminator}
    
    def _create_defense_predictor(self):
        """Criar LSTM para predição de defesas"""
        model = tf.keras.Sequential([
            tf.keras.layers.LSTM(256, return_sequences=True, input_shape=(50, 100)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.LSTM(128, return_sequences=True),
            tf.keras.layers.LSTM(64),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(10, activation='softmax')  # 10 tipos de defesas
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.0001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def _create_traffic_analyzer(self):
        """Criar CNN para análise de tráfego"""
        model = tf.keras.Sequential([
            tf.keras.layers.Conv1D(64, 3, activation='relu', input_shape=(1000, 1)),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.Conv1D(128, 3, activation='relu'),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.Conv1D(256, 3, activation='relu'),
            tf.keras.layers.GlobalMaxPooling1D(),
            tf.keras.layers.Dense(512, activation='relu'),
            tf.keras.layers.Dropout(0.4),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.Dense(3, activation='softmax')  # Normal, Suspeito, Bloqueado
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.0005),
            loss='categorical_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def _create_attack_transformer(self):
        """Criar Transformer para contexto de ataques"""
        inputs = tf.keras.Input(shape=(None, 512))
        
        # Multi-head attention
        attention = tf.keras.layers.MultiHeadAttention(
            num_heads=8, key_dim=64
        )(inputs, inputs)
        
        # Add & Norm
        attention = tf.keras.layers.LayerNormalization()(attention + inputs)
        
        # Feed Forward
        ffn = tf.keras.Sequential([
            tf.keras.layers.Dense(2048, activation='relu'),
            tf.keras.layers.Dense(512)
        ])
        
        ffn_output = ffn(attention)
        output = tf.keras.layers.LayerNormalization()(ffn_output + attention)
        
        # Final layers
        pooled = tf.keras.layers.GlobalAveragePooling1D()(output)
        predictions = tf.keras.layers.Dense(256, activation='softmax')(pooled)
        
        model = tf.keras.Model(inputs=inputs, outputs=predictions)
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.0001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    async def learn_from_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Aprender com dados de ataque"""
        
        # Armazenar na memória
        self.attack_memory.append({
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_data.get('attack_type'),
            'success': attack_data.get('success', False),
            'target_response': attack_data.get('target_response'),
            'payload_used': attack_data.get('payload'),
            'detection_status': attack_data.get('detected', False),
            'evasion_techniques': attack_data.get('evasion_techniques', [])
        })
        
        # Analisar padrões de sucesso/falha
        success_pattern = await self._analyze_success_patterns()
        
        # Atualizar modelos com novos dados
        model_updates = await self._update_models_with_feedback(attack_data)
        
        # Gerar novas estratégias baseadas no aprendizado
        new_strategies = await self._generate_adaptive_strategies(attack_data)
        
        # Calcular score de aprendizado
        learning_score = await self._calculate_learning_effectiveness()
        
        return {
            'learning_status': 'completed',
            'success_pattern': success_pattern,
            'model_updates': model_updates,
            'new_strategies': new_strategies,
            'learning_score': learning_score,
            'memory_size': len(self.attack_memory),
            'recommendations': await self._generate_learning_recommendations()
        }
    
    async def _analyze_success_patterns(self) -> Dict[str, Any]:
        """Analisar padrões de sucesso nos ataques"""
        
        if len(self.attack_memory) < 10:
            return {'status': 'insufficient_data'}
        
        recent_attacks = self.attack_memory[-100:]  # Últimos 100 ataques
        
        # Análise por tipo de ataque
        attack_types_success = {}
        for attack in recent_attacks:
            attack_type = attack['attack_type']
            if attack_type not in attack_types_success:
                attack_types_success[attack_type] = {'total': 0, 'success': 0}
            
            attack_types_success[attack_type]['total'] += 1
            if attack['success']:
                attack_types_success[attack_type]['success'] += 1
        
        # Calcular taxas de sucesso
        success_rates = {}
        for attack_type, stats in attack_types_success.items():
            success_rates[attack_type] = stats['success'] / stats['total']
        
        # Análise temporal
        temporal_analysis = await self._analyze_temporal_patterns(recent_attacks)
        
        # Análise de técnicas de evasão
        evasion_effectiveness = await self._analyze_evasion_effectiveness(recent_attacks)
        
        return {
            'success_rates_by_type': success_rates,
            'temporal_patterns': temporal_analysis,
            'evasion_effectiveness': evasion_effectiveness,
            'most_effective_attack': max(success_rates.items(), key=lambda x: x[1]) if success_rates else None,
            'improvement_areas': [k for k, v in success_rates.items() if v < 0.5]
        }
    
    async def _analyze_temporal_patterns(self, attacks: List[Dict]) -> Dict[str, Any]:
        """Analisar padrões temporais nos ataques"""
        
        # Análise por hora do dia
        hour_success = {}
        for attack in attacks:
            hour = datetime.fromisoformat(attack['timestamp']).hour
            if hour not in hour_success:
                hour_success[hour] = {'total': 0, 'success': 0}
            
            hour_success[hour]['total'] += 1
            if attack['success']:
                hour_success[hour]['success'] += 1
        
        # Encontrar horários mais efetivos
        best_hours = []
        for hour, stats in hour_success.items():
            if stats['total'] >= 3:  # Pelo menos 3 ataques
                success_rate = stats['success'] / stats['total']
                if success_rate > 0.7:
                    best_hours.append(hour)
        
        return {
            'hourly_success_rates': {h: s['success']/s['total'] for h, s in hour_success.items() if s['total'] > 0},
            'best_attack_hours': best_hours,
            'pattern_confidence': len(attacks) / 100.0
        }
    
    async def _analyze_evasion_effectiveness(self, attacks: List[Dict]) -> Dict[str, Any]:
        """Analisar efetividade das técnicas de evasão"""
        
        evasion_stats = {}
        
        for attack in attacks:
            techniques = attack.get('evasion_techniques', [])
            detected = attack.get('detection_status', False)
            
            for technique in techniques:
                if technique not in evasion_stats:
                    evasion_stats[technique] = {'used': 0, 'detected': 0}
                
                evasion_stats[technique]['used'] += 1
                if detected:
                    evasion_stats[technique]['detected'] += 1
        
        # Calcular efetividade (menor detecção = maior efetividade)
        evasion_effectiveness = {}
        for technique, stats in evasion_stats.items():
            if stats['used'] >= 3:  # Pelo menos 3 usos
                detection_rate = stats['detected'] / stats['used']
                effectiveness = 1.0 - detection_rate
                evasion_effectiveness[technique] = effectiveness
        
        return {
            'technique_effectiveness': evasion_effectiveness,
            'most_effective_techniques': sorted(evasion_effectiveness.items(), key=lambda x: x[1], reverse=True)[:5],
            'techniques_to_avoid': [k for k, v in evasion_effectiveness.items() if v < 0.3]
        }
    
    async def _update_models_with_feedback(self, attack_data: Dict) -> Dict[str, Any]:
        """Atualizar modelos com feedback do ataque"""
        
        updates = {}
        
        # Simular atualização dos modelos (em implementação real, treinar com dados)
        if attack_data.get('success'):
            # Reforçar estratégias bem-sucedidas
            updates['payload_generator'] = 'positive_reinforcement'
            updates['evasion_engine'] = 'technique_reinforcement'
        else:
            # Ajustar estratégias que falharam
            updates['payload_generator'] = 'strategy_adjustment'
            updates['evasion_engine'] = 'technique_refinement'
        
        # Atualizar detector de defesas se houve detecção
        if attack_data.get('detected'):
            updates['defense_predictor'] = 'defense_pattern_learning'
        
        return updates
    
    async def _generate_adaptive_strategies(self, attack_data: Dict) -> List[Dict[str, Any]]:
        """Gerar novas estratégias adaptativas"""
        
        strategies = []
        
        # Estratégia baseada no tipo de ataque
        attack_type = attack_data.get('attack_type')
        if attack_type:
            strategies.append({
                'type': 'attack_variation',
                'base_attack': attack_type,
                'variations': await self._generate_attack_variations(attack_type),
                'confidence': 0.8
            })
        
        # Estratégia de timing adaptativo
        strategies.append({
            'type': 'adaptive_timing',
            'timing_pattern': 'exponential_backoff',
            'base_delay': 5,
            'max_delay': 300,
            'confidence': 0.9
        })
        
        # Estratégia de evasão multi-camada
        strategies.append({
            'type': 'multi_layer_evasion',
            'layers': ['encoding', 'timing', 'traffic_shaping', 'behavioral_mimicry'],
            'combination_strategy': 'random_selection',
            'confidence': 0.85
        })
        
        return strategies
    
    async def _generate_attack_variations(self, base_attack: str) -> List[str]:
        """Gerar variações do ataque base"""
        
        variations_map = {
            'xss': ['dom_xss', 'stored_xss', 'reflected_xss', 'blind_xss'],
            'sqli': ['union_sqli', 'blind_sqli', 'time_based_sqli', 'error_based_sqli'],
            'rce': ['command_injection', 'code_injection', 'deserialization', 'template_injection'],
            'lfi': ['path_traversal', 'wrapper_abuse', 'log_poisoning', 'session_poisoning']
        }
        
        return variations_map.get(base_attack, [f"{base_attack}_variant_{i}" for i in range(1, 5)])
    
    async def _calculate_learning_effectiveness(self) -> float:
        """Calcular efetividade do aprendizado"""
        
        if len(self.attack_memory) < 20:
            return 0.5  # Score neutro para poucos dados
        
        # Comparar últimos 20 ataques com 20 anteriores
        recent_attacks = self.attack_memory[-20:]
        previous_attacks = self.attack_memory[-40:-20] if len(self.attack_memory) >= 40 else []
        
        if not previous_attacks:
            return 0.6
        
        recent_success_rate = sum(1 for a in recent_attacks if a['success']) / len(recent_attacks)
        previous_success_rate = sum(1 for a in previous_attacks if a['success']) / len(previous_attacks)
        
        # Calcular melhoria
        improvement = recent_success_rate - previous_success_rate
        
        # Normalizar para 0-1
        effectiveness = max(0.0, min(1.0, 0.5 + improvement))
        
        return effectiveness
    
    async def _generate_learning_recommendations(self) -> List[str]:
        """Gerar recomendações baseadas no aprendizado"""
        
        recommendations = []
        
        if len(self.attack_memory) < 50:
            recommendations.append("Coletar mais dados de ataques para melhorar precisão")
        
        # Análise de padrões recentes
        recent_attacks = self.attack_memory[-20:] if len(self.attack_memory) >= 20 else self.attack_memory
        
        success_rate = sum(1 for a in recent_attacks if a['success']) / len(recent_attacks) if recent_attacks else 0
        
        if success_rate < 0.4:
            recommendations.append("Focar em técnicas de evasão mais avançadas")
            recommendations.append("Revisar e atualizar payloads base")
        
        detection_rate = sum(1 for a in recent_attacks if a.get('detected', False)) / len(recent_attacks) if recent_attacks else 0
        
        if detection_rate > 0.3:
            recommendations.append("Implementar técnicas de stealth mais sofisticadas")
            recommendations.append("Aumentar intervalo entre ataques")
        
        return recommendations
    
    async def get_learning_status(self) -> Dict[str, Any]:
        """Obter status do sistema de aprendizado"""
        
        return {
            'total_attacks_learned': len(self.attack_memory),
            'learning_effectiveness': await self._calculate_learning_effectiveness(),
            'active_models': list(self.adversarial_models.keys()),
            'memory_utilization': min(1.0, len(self.attack_memory) / 1000),
            'last_learning_session': self.attack_memory[-1]['timestamp'] if self.attack_memory else None,
            'adaptive_strategies_count': len(await self._generate_adaptive_strategies({})),
            'recommendations_pending': len(await self._generate_learning_recommendations())
        }
