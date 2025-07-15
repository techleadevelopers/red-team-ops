
import tensorflow as tf
import numpy as np
from typing import Dict, List, Any, Tuple
import asyncio
from datetime import datetime, timedelta
import json
from collections import defaultdict

class MetaLearningSystem:
    """
    Sistema de Meta-Aprendizado para Red Team AI
    Aprende estratégias de aprendizado otimais para diferentes cenários
    """
    
    def __init__(self):
        self.meta_models = {}
        self.learning_experiences = []
        self.strategy_effectiveness = defaultdict(list)
        self.context_memory = {}
        
    async def initialize_meta_networks(self):
        """Inicializar redes de meta-aprendizado"""
        
        # MAML (Model-Agnostic Meta-Learning)
        self.meta_models['maml'] = self._create_maml_network()
        
        # Meta-LSTM para sequências de aprendizado
        self.meta_models['meta_lstm'] = self._create_meta_lstm()
        
        # Context Encoder para análise de cenários
        self.meta_models['context_encoder'] = self._create_context_encoder()
        
        # Strategy Selector para escolha de estratégias
        self.meta_models['strategy_selector'] = self._create_strategy_selector()
        
    def _create_maml_network(self):
        """Criar rede MAML para adaptação rápida"""
        
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(512, activation='relu', input_shape=(256,)),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(32, activation='softmax')  # 32 estratégias possíveis
        ])
        
        # Usar otimizador especial para MAML
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def _create_meta_lstm(self):
        """Criar Meta-LSTM para sequências de aprendizado"""
        
        model = tf.keras.Sequential([
            tf.keras.layers.LSTM(256, return_sequences=True, input_shape=(None, 128)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.LSTM(128, return_sequences=True),
            tf.keras.layers.LSTM(64),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(16, activation='softmax')  # 16 tipos de learning strategy
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.RMSprop(learning_rate=0.0005),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def _create_context_encoder(self):
        """Criar encoder de contexto"""
        
        # Encoder para diferentes tipos de entrada
        text_input = tf.keras.Input(shape=(100,), name='text_features')
        numeric_input = tf.keras.Input(shape=(50,), name='numeric_features')
        
        # Processamento de texto
        text_processed = tf.keras.layers.Dense(64, activation='relu')(text_input)
        text_processed = tf.keras.layers.Dropout(0.2)(text_processed)
        
        # Processamento numérico
        numeric_processed = tf.keras.layers.Dense(32, activation='relu')(numeric_input)
        numeric_processed = tf.keras.layers.Dropout(0.2)(numeric_processed)
        
        # Combinação
        combined = tf.keras.layers.concatenate([text_processed, numeric_processed])
        context_encoding = tf.keras.layers.Dense(128, activation='relu')(combined)
        
        model = tf.keras.Model(
            inputs=[text_input, numeric_input],
            outputs=context_encoding
        )
        
        return model
    
    def _create_strategy_selector(self):
        """Criar seletor de estratégias"""
        
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(256, activation='relu', input_shape=(128,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(20, activation='softmax')  # 20 estratégias diferentes
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy', 'top_k_categorical_accuracy']
        )
        
        return model
    
    async def learn_learning_strategy(self, scenario_context: Dict[str, Any], learning_history: List[Dict]) -> Dict[str, Any]:
        """Aprender estratégia de aprendizado ótima para o cenário"""
        
        # Codificar contexto do cenário
        context_encoding = await self._encode_scenario_context(scenario_context)
        
        # Analisar histórico de aprendizado
        learning_patterns = await self._analyze_learning_patterns(learning_history)
        
        # Aplicar MAML para adaptação rápida
        adapted_strategy = await self._apply_maml_adaptation(context_encoding, learning_patterns)
        
        # Selecionar estratégia ótima
        optimal_strategy = await self._select_optimal_strategy(context_encoding, adapted_strategy)
        
        # Armazenar experiência
        experience = {
            'timestamp': datetime.now().isoformat(),
            'context': scenario_context,
            'context_encoding': context_encoding.tolist(),
            'selected_strategy': optimal_strategy,
            'learning_patterns': learning_patterns
        }
        
        self.learning_experiences.append(experience)
        
        return {
            'recommended_strategy': optimal_strategy,
            'strategy_confidence': await self._calculate_strategy_confidence(optimal_strategy, context_encoding),
            'adaptation_parameters': adapted_strategy,
            'meta_learning_insights': await self._generate_meta_insights()
        }
    
    async def _encode_scenario_context(self, context: Dict[str, Any]) -> np.ndarray:
        """Codificar contexto do cenário"""
        
        # Extrair features textuais
        text_features = np.zeros(100)
        text_data = context.get('target_description', '') + ' ' + context.get('attack_type', '')
        
        # Simular embedding de texto (em implementação real, usar modelo de linguagem)
        for i, char in enumerate(text_data[:100]):
            text_features[i] = ord(char) / 255.0
        
        # Extrair features numéricas
        numeric_features = np.zeros(50)
        numeric_features[0] = context.get('target_complexity', 0.5)
        numeric_features[1] = context.get('security_level', 0.5)
        numeric_features[2] = context.get('time_constraint', 1.0)
        numeric_features[3] = len(context.get('previous_attacks', []))
        numeric_features[4] = context.get('success_rate_required', 0.8)
        
        # Usar context encoder
        context_encoding = self.meta_models['context_encoder'].predict([
            text_features.reshape(1, -1),
            numeric_features.reshape(1, -1)
        ])
        
        return context_encoding[0]
    
    async def _analyze_learning_patterns(self, learning_history: List[Dict]) -> Dict[str, Any]:
        """Analisar padrões no histórico de aprendizado"""
        
        if not learning_history:
            return {
                'learning_velocity': 0.5,
                'convergence_pattern': 'unknown',
                'optimal_batch_size': 32,
                'learning_rate_preference': 0.001
            }
        
        # Analisar velocidade de aprendizado
        improvements = []
        for i in range(1, len(learning_history)):
            if 'accuracy' in learning_history[i] and 'accuracy' in learning_history[i-1]:
                improvement = learning_history[i]['accuracy'] - learning_history[i-1]['accuracy']
                improvements.append(improvement)
        
        learning_velocity = np.mean(improvements) if improvements else 0.5
        
        # Analisar padrão de convergência
        if len(improvements) >= 5:
            recent_improvements = improvements[-5:]
            if all(imp < 0.01 for imp in recent_improvements):
                convergence_pattern = 'converged'
            elif all(imp > 0 for imp in recent_improvements):
                convergence_pattern = 'improving'
            else:
                convergence_pattern = 'oscillating'
        else:
            convergence_pattern = 'insufficient_data'
        
        # Analisar preferências de hiperparâmetros
        batch_sizes = [h.get('batch_size', 32) for h in learning_history if 'batch_size' in h]
        optimal_batch_size = max(set(batch_sizes), key=batch_sizes.count) if batch_sizes else 32
        
        learning_rates = [h.get('learning_rate', 0.001) for h in learning_history if 'learning_rate' in h]
        learning_rate_preference = np.mean(learning_rates) if learning_rates else 0.001
        
        return {
            'learning_velocity': learning_velocity,
            'convergence_pattern': convergence_pattern,
            'optimal_batch_size': optimal_batch_size,
            'learning_rate_preference': learning_rate_preference,
            'total_episodes': len(learning_history),
            'average_accuracy': np.mean([h.get('accuracy', 0) for h in learning_history])
        }
    
    async def _apply_maml_adaptation(self, context_encoding: np.ndarray, learning_patterns: Dict) -> Dict[str, Any]:
        """Aplicar adaptação MAML"""
        
        # Preparar entrada para MAML
        maml_input = np.concatenate([
            context_encoding,
            [learning_patterns['learning_velocity']],
            [learning_patterns['optimal_batch_size'] / 100.0],  # Normalizar
            [learning_patterns['learning_rate_preference'] * 1000],  # Escalar
            [learning_patterns['total_episodes'] / 100.0]  # Normalizar
        ])
        
        # Preencher até 256 dimensões
        maml_input = np.pad(maml_input, (0, max(0, 256 - len(maml_input))))[:256]
        
        # Aplicar MAML
        maml_output = self.meta_models['maml'].predict(maml_input.reshape(1, -1))
        
        # Interpretar saída como parâmetros de adaptação
        adaptation_params = {
            'learning_rate_multiplier': float(maml_output[0][0]),
            'batch_size_factor': float(maml_output[0][1]),
            'regularization_strength': float(maml_output[0][2]),
            'exploration_factor': float(maml_output[0][3]),
            'convergence_threshold': float(maml_output[0][4])
        }
        
        return adaptation_params
    
    async def _select_optimal_strategy(self, context_encoding: np.ndarray, adaptation_params: Dict) -> Dict[str, Any]:
        """Selecionar estratégia ótima"""
        
        # Usar strategy selector
        strategy_probs = self.meta_models['strategy_selector'].predict(context_encoding.reshape(1, -1))
        
        # Mapear probabilidades para estratégias
        strategies = [
            'aggressive_exploration', 'conservative_exploitation', 'balanced_approach',
            'rapid_adaptation', 'stable_learning', 'multi_objective_optimization',
            'adversarial_training', 'transfer_learning', 'few_shot_learning',
            'curriculum_learning', 'active_learning', 'reinforcement_learning',
            'imitation_learning', 'self_supervised_learning', 'contrastive_learning',
            'meta_gradient_learning', 'neural_architecture_search', 'hyperparameter_optimization',
            'ensemble_learning', 'continual_learning'
        ]
        
        # Selecionar estratégia com maior probabilidade
        best_strategy_idx = np.argmax(strategy_probs[0])
        selected_strategy = strategies[best_strategy_idx]
        confidence = float(strategy_probs[0][best_strategy_idx])
        
        # Combinar com parâmetros de adaptação
        return {
            'name': selected_strategy,
            'confidence': confidence,
            'parameters': adaptation_params,
            'alternative_strategies': [
                {'name': strategies[i], 'confidence': float(strategy_probs[0][i])}
                for i in np.argsort(strategy_probs[0])[-3:][::-1]
                if i != best_strategy_idx
            ]
        }
    
    async def _calculate_strategy_confidence(self, strategy: Dict, context_encoding: np.ndarray) -> float:
        """Calcular confiança na estratégia selecionada"""
        
        # Verificar experiências similares
        similar_experiences = []
        for exp in self.learning_experiences[-50:]:  # Últimas 50 experiências
            context_similarity = self._calculate_context_similarity(
                context_encoding, np.array(exp['context_encoding'])
            )
            if context_similarity > 0.7:
                similar_experiences.append(exp)
        
        if not similar_experiences:
            return strategy['confidence'] * 0.7  # Penalizar falta de experiência
        
        # Calcular sucesso da estratégia em contextos similares
        strategy_name = strategy['name']
        successes = [
            exp for exp in similar_experiences 
            if exp['selected_strategy']['name'] == strategy_name
        ]
        
        if not successes:
            return strategy['confidence'] * 0.8
        
        # Boost se estratégia teve sucesso em contextos similares
        success_boost = min(0.3, len(successes) / len(similar_experiences))
        
        return min(1.0, strategy['confidence'] + success_boost)
    
    def _calculate_context_similarity(self, context1: np.ndarray, context2: np.ndarray) -> float:
        """Calcular similaridade entre contextos"""
        
        # Usar distância cosseno
        dot_product = np.dot(context1, context2)
        norm1 = np.linalg.norm(context1)
        norm2 = np.linalg.norm(context2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        cosine_similarity = dot_product / (norm1 * norm2)
        return max(0.0, cosine_similarity)
    
    async def _generate_meta_insights(self) -> List[str]:
        """Gerar insights do meta-aprendizado"""
        
        insights = []
        
        if len(self.learning_experiences) >= 10:
            # Analisar estratégias mais efetivas
            strategy_counts = defaultdict(int)
            for exp in self.learning_experiences[-20:]:
                strategy_counts[exp['selected_strategy']['name']] += 1
            
            most_used_strategy = max(strategy_counts.items(), key=lambda x: x[1])
            insights.append(f"Estratégia mais utilizada: {most_used_strategy[0]} ({most_used_strategy[1]} vezes)")
            
            # Analisar padrões temporais
            recent_strategies = [exp['selected_strategy']['name'] for exp in self.learning_experiences[-10:]]
            if len(set(recent_strategies)) == 1:
                insights.append("Convergência detectada: mesma estratégia consistentemente selecionada")
            elif len(set(recent_strategies)) >= 7:
                insights.append("Alta diversidade de estratégias: possível instabilidade")
            
            # Analisar confiança média
            avg_confidence = np.mean([exp['selected_strategy']['confidence'] for exp in self.learning_experiences[-10:]])
            if avg_confidence < 0.6:
                insights.append("Baixa confiança nas estratégias: considerar mais dados de treinamento")
            elif avg_confidence > 0.9:
                insights.append("Alta confiança nas estratégias: sistema bem calibrado")
        
        return insights
    
    async def get_meta_learning_status(self) -> Dict[str, Any]:
        """Obter status do sistema de meta-aprendizado"""
        
        return {
            'total_learning_experiences': len(self.learning_experiences),
            'active_meta_models': list(self.meta_models.keys()),
            'strategy_diversity': len(set(exp['selected_strategy']['name'] for exp in self.learning_experiences)),
            'average_strategy_confidence': np.mean([exp['selected_strategy']['confidence'] for exp in self.learning_experiences]) if self.learning_experiences else 0.0,
            'last_meta_learning': self.learning_experiences[-1]['timestamp'] if self.learning_experiences else None,
            'meta_insights_count': len(await self._generate_meta_insights())
        }
