
"""
Módulo de Data Stealers
Framework avançado para exfiltração de dados sensíveis
"""

import asyncio
import random
import json
import base64
import hashlib
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

class DataStealersFramework:
    """Framework para operações de exfiltração de dados"""
    
    def __init__(self):
        self.exfiltrated_data = []
        self.attack_statistics = {
            'files_stolen': 0,
            'databases_accessed': 0,
            'emails_harvested': 0,
            'screenshots_taken': 0,
            'keystrokes_captured': 0,
            'network_traffic_captured': 0
        }
        self.data_categories = {
            'financial': 0,
            'personal': 0,
            'corporate': 0,
            'credentials': 0,
            'source_code': 0
        }
    
    async def initialize(self):
        """Inicializar framework de data stealers"""
        return {'status': 'initialized', 'framework': 'DataStealersFramework'}
    
    async def file_stealer_operation(self, target_directories: List[str], file_types: List[str] = None) -> Dict[str, Any]:
        """Operação de roubo de arquivos"""
        
        default_file_types = ['.pdf', '.docx', '.xlsx', '.txt', '.sql', '.config', '.key', '.pem']
        target_types = file_types or default_file_types
        
        results = {
            'operation': 'file_stealer',
            'target_directories': target_directories,
            'target_file_types': target_types,
            'files_found': [],
            'files_stolen': [],
            'sensitive_files': [],
            'total_size': 0
        }
        
        try:
            for directory in target_directories:
                dir_results = await self._scan_directory(directory, target_types)
                
                for file_info in dir_results['files']:
                    results['files_found'].append(file_info)
                    
                    # Determinar se arquivo é sensível
                    sensitivity = await self._analyze_file_sensitivity(file_info)
                    
                    if sensitivity['is_sensitive']:
                        results['sensitive_files'].append({
                            'path': file_info['path'],
                            'type': file_info['type'],
                            'size': file_info['size'],
                            'sensitivity_score': sensitivity['score'],
                            'data_category': sensitivity['category']
                        })
                        
                        # Simular exfiltração
                        exfil_result = await self._exfiltrate_file(file_info)
                        if exfil_result['successful']:
                            results['files_stolen'].append(file_info)
                            results['total_size'] += file_info['size']
                            
                            # Atualizar estatísticas
                            self.data_categories[sensitivity['category']] += 1
                            self.exfiltrated_data.append({
                                'type': 'file',
                                'path': file_info['path'],
                                'category': sensitivity['category'],
                                'size': file_info['size'],
                                'timestamp': datetime.now().isoformat()
                            })
            
            self.attack_statistics['files_stolen'] += len(results['files_stolen'])
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def database_extraction(self, target_databases: List[str]) -> Dict[str, Any]:
        """Extração de dados de bancos de dados"""
        
        results = {
            'operation': 'database_extraction',
            'target_databases': target_databases,
            'databases_accessed': [],
            'tables_extracted': [],
            'records_stolen': 0,
            'sensitive_data': []
        }
        
        try:
            for db_name in target_databases:
                db_access = await self._access_database(db_name)
                
                if db_access['accessible']:
                    results['databases_accessed'].append(db_name)
                    
                    # Enumerar tabelas
                    tables = await self._enumerate_database_tables(db_name)
                    
                    for table in tables:
                        table_data = await self._extract_table_data(db_name, table['name'])
                        
                        if table_data['extracted']:
                            results['tables_extracted'].append({
                                'database': db_name,
                                'table': table['name'],
                                'columns': table['columns'],
                                'row_count': table_data['row_count'],
                                'sensitive_columns': table_data['sensitive_columns']
                            })
                            
                            results['records_stolen'] += table_data['row_count']
                            
                            # Identificar dados sensíveis
                            for sensitive_col in table_data['sensitive_columns']:
                                results['sensitive_data'].append({
                                    'database': db_name,
                                    'table': table['name'],
                                    'column': sensitive_col,
                                    'sample_data': table_data['sample_data'].get(sensitive_col, [])
                                })
                                
                                # Categorizar dados
                                category = await self._categorize_database_data(sensitive_col)
                                self.data_categories[category] += table_data['row_count']
            
            self.attack_statistics['databases_accessed'] += len(results['databases_accessed'])
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def email_harvesting(self, target_accounts: List[str], email_types: List[str] = None) -> Dict[str, Any]:
        """Coleta de emails"""
        
        default_types = ['inbox', 'sent', 'drafts', 'contacts']
        target_email_types = email_types or default_types
        
        results = {
            'operation': 'email_harvesting',
            'target_accounts': target_accounts,
            'email_types': target_email_types,
            'emails_harvested': [],
            'contacts_extracted': [],
            'attachments_found': [],
            'total_emails': 0
        }
        
        try:
            for account in target_accounts:
                account_access = await self._access_email_account(account)
                
                if account_access['accessible']:
                    for email_type in target_email_types:
                        emails = await self._extract_emails(account, email_type)
                        
                        for email in emails:
                            results['emails_harvested'].append({
                                'account': account,
                                'folder': email_type,
                                'from': email['from'],
                                'to': email['to'],
                                'subject': email['subject'],
                                'date': email['date'],
                                'has_attachments': email['has_attachments'],
                                'sensitivity_score': email['sensitivity_score']
                            })
                            
                            # Extrair anexos
                            if email['has_attachments']:
                                for attachment in email['attachments']:
                                    results['attachments_found'].append({
                                        'email_id': email['id'],
                                        'filename': attachment['filename'],
                                        'size': attachment['size'],
                                        'type': attachment['type']
                                    })
                        
                        results['total_emails'] += len(emails)
                    
                    # Extrair contatos
                    contacts = await self._extract_contacts(account)
                    results['contacts_extracted'].extend(contacts)
            
            self.attack_statistics['emails_harvested'] += results['total_emails']
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def keylogger_operation(self, duration_minutes: int = 60) -> Dict[str, Any]:
        """Operação de keylogger"""
        
        results = {
            'operation': 'keylogger',
            'duration_minutes': duration_minutes,
            'keystrokes_captured': 0,
            'applications_monitored': [],
            'passwords_detected': [],
            'urls_visited': [],
            'sensitive_inputs': []
        }
        
        try:
            # Simular captura de keystrokes
            start_time = datetime.now()
            
            # Aplicações monitoradas
            monitored_apps = ['chrome.exe', 'firefox.exe', 'outlook.exe', 'notepad.exe', 'cmd.exe']
            results['applications_monitored'] = monitored_apps
            
            # Simular dados capturados durante o período
            for minute in range(duration_minutes):
                # Simular atividade de digitação
                minute_keystrokes = random.randint(50, 200)
                results['keystrokes_captured'] += minute_keystrokes
                
                # Detectar possíveis senhas (campos de senha)
                if random.random() > 0.9:  # 10% chance por minuto
                    password = f"password{random.randint(100, 999)}"
                    results['passwords_detected'].append({
                        'password': password,
                        'application': random.choice(monitored_apps),
                        'timestamp': (start_time + timedelta(minutes=minute)).isoformat()
                    })
                
                # Capturar URLs visitadas
                if random.random() > 0.8:  # 20% chance por minuto
                    url = f"https://site{random.randint(1, 100)}.com"
                    results['urls_visited'].append({
                        'url': url,
                        'timestamp': (start_time + timedelta(minutes=minute)).isoformat()
                    })
                
                # Detectar inputs sensíveis
                if random.random() > 0.95:  # 5% chance por minuto
                    sensitive_data = {
                        'type': random.choice(['credit_card', 'ssn', 'phone', 'email']),
                        'value': f"sensitive_data_{random.randint(1000, 9999)}",
                        'application': random.choice(monitored_apps),
                        'timestamp': (start_time + timedelta(minutes=minute)).isoformat()
                    }
                    results['sensitive_inputs'].append(sensitive_data)
            
            self.attack_statistics['keystrokes_captured'] += results['keystrokes_captured']
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def screenshot_stealer(self, interval_seconds: int = 30, duration_minutes: int = 60) -> Dict[str, Any]:
        """Captura de screenshots"""
        
        results = {
            'operation': 'screenshot_stealer',
            'interval_seconds': interval_seconds,
            'duration_minutes': duration_minutes,
            'screenshots_taken': 0,
            'applications_captured': [],
            'sensitive_content_detected': [],
            'total_size_mb': 0
        }
        
        try:
            screenshots_per_minute = 60 // interval_seconds
            total_screenshots = screenshots_per_minute * duration_minutes
            
            for i in range(total_screenshots):
                screenshot_data = await self._capture_screenshot()
                
                if screenshot_data['captured']:
                    results['screenshots_taken'] += 1
                    results['total_size_mb'] += screenshot_data['size_mb']
                    
                    # Detectar aplicação ativa
                    if screenshot_data['active_app']:
                        results['applications_captured'].append(screenshot_data['active_app'])
                    
                    # Analisar conteúdo sensível
                    sensitive_analysis = await self._analyze_screenshot_content(screenshot_data)
                    if sensitive_analysis['has_sensitive_content']:
                        results['sensitive_content_detected'].append({
                            'screenshot_id': i,
                            'content_type': sensitive_analysis['content_type'],
                            'confidence': sensitive_analysis['confidence'],
                            'timestamp': screenshot_data['timestamp']
                        })
            
            self.attack_statistics['screenshots_taken'] += results['screenshots_taken']
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def network_traffic_capture(self, duration_minutes: int = 30, filter_sensitive: bool = True) -> Dict[str, Any]:
        """Captura de tráfego de rede"""
        
        results = {
            'operation': 'network_traffic_capture',
            'duration_minutes': duration_minutes,
            'packets_captured': 0,
            'protocols_detected': [],
            'credentials_extracted': [],
            'sensitive_data': [],
            'connections_monitored': []
        }
        
        try:
            # Simular captura de tráfego
            protocols = ['HTTP', 'HTTPS', 'FTP', 'SMTP', 'POP3', 'IMAP', 'DNS']
            
            for minute in range(duration_minutes):
                # Simular tráfego por minuto
                minute_packets = random.randint(100, 1000)
                results['packets_captured'] += minute_packets
                
                # Detectar protocolos
                active_protocols = random.sample(protocols, random.randint(2, 5))
                results['protocols_detected'].extend(active_protocols)
                
                # Extrair credenciais de tráfego não criptografado
                if 'HTTP' in active_protocols or 'FTP' in active_protocols:
                    if random.random() > 0.8:  # 20% chance por minuto
                        credential = {
                            'protocol': random.choice(['HTTP', 'FTP']),
                            'username': f'user{random.randint(100, 999)}',
                            'password': f'pass{random.randint(100, 999)}',
                            'destination': f'server{random.randint(1, 10)}.com',
                            'timestamp': datetime.now().isoformat()
                        }
                        results['credentials_extracted'].append(credential)
                
                # Detectar dados sensíveis em texto claro
                if filter_sensitive and random.random() > 0.9:  # 10% chance por minuto
                    sensitive_data = {
                        'type': random.choice(['credit_card', 'ssn', 'api_key']),
                        'value': f"sensitive_{random.randint(10000, 99999)}",
                        'protocol': random.choice(active_protocols),
                        'source_ip': f"192.168.1.{random.randint(1, 254)}",
                        'destination_ip': f"10.0.0.{random.randint(1, 254)}",
                        'timestamp': datetime.now().isoformat()
                    }
                    results['sensitive_data'].append(sensitive_data)
                
                # Monitorar conexões
                if random.random() > 0.7:  # 30% chance por minuto
                    connection = {
                        'source_ip': f"192.168.1.{random.randint(1, 254)}",
                        'destination_ip': f"external.site{random.randint(1, 100)}.com",
                        'port': random.choice([80, 443, 21, 22, 25, 53]),
                        'protocol': random.choice(protocols),
                        'bytes_transferred': random.randint(1024, 1048576)
                    }
                    results['connections_monitored'].append(connection)
            
            # Remover duplicatas de protocolos
            results['protocols_detected'] = list(set(results['protocols_detected']))
            
            self.attack_statistics['network_traffic_captured'] += results['packets_captured']
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def _scan_directory(self, directory: str, file_types: List[str]) -> Dict[str, Any]:
        """Escanear diretório por arquivos"""
        # Simular escaneamento de diretório
        files = []
        
        for i in range(random.randint(5, 50)):
            file_type = random.choice(file_types)
            file_info = {
                'path': f"{directory}/file_{i}{file_type}",
                'name': f"file_{i}{file_type}",
                'type': file_type,
                'size': random.randint(1024, 10485760),  # 1KB a 10MB
                'modified': datetime.now().isoformat(),
                'permissions': random.choice(['read', 'write', 'read-write'])
            }
            files.append(file_info)
        
        return {'files': files}
    
    async def _analyze_file_sensitivity(self, file_info: Dict) -> Dict[str, Any]:
        """Analisar sensibilidade do arquivo"""
        sensitive_keywords = {
            'financial': ['bank', 'credit', 'payment', 'invoice', 'tax'],
            'personal': ['passport', 'ssn', 'personal', 'private', 'confidential'],
            'corporate': ['contract', 'agreement', 'strategic', 'internal', 'proprietary'],
            'credentials': ['password', 'key', 'token', 'secret', 'auth'],
            'source_code': ['source', 'code', 'script', 'program', 'development']
        }
        
        file_name_lower = file_info['name'].lower()
        sensitivity_score = 0
        category = 'corporate'  # default
        
        for cat, keywords in sensitive_keywords.items():
            if any(keyword in file_name_lower for keyword in keywords):
                sensitivity_score += 0.3
                category = cat
        
        # Tipos de arquivo sensíveis
        if file_info['type'] in ['.key', '.pem', '.p12', '.pfx']:
            sensitivity_score += 0.5
            category = 'credentials'
        elif file_info['type'] in ['.sql', '.db', '.mdb']:
            sensitivity_score += 0.4
            category = 'corporate'
        
        is_sensitive = sensitivity_score > 0.2
        
        return {
            'is_sensitive': is_sensitive,
            'score': min(sensitivity_score, 1.0),
            'category': category
        }
    
    async def _exfiltrate_file(self, file_info: Dict) -> Dict[str, Any]:
        """Simular exfiltração de arquivo"""
        # Simular sucesso baseado no tamanho do arquivo
        success_chance = 0.9 if file_info['size'] < 1048576 else 0.7  # Arquivos menores têm mais chance
        
        return {
            'successful': random.random() < success_chance,
            'method': random.choice(['http_post', 'ftp_upload', 'email_attachment', 'cloud_storage']),
            'time_seconds': file_info['size'] // 1024 + random.randint(1, 10)
        }
    
    async def _access_database(self, db_name: str) -> Dict[str, Any]:
        """Simular acesso ao banco de dados"""
        return {
            'accessible': random.random() > 0.2,  # 80% de chance de acesso
            'db_type': random.choice(['mysql', 'postgresql', 'mssql', 'oracle']),
            'version': f"{random.randint(5, 8)}.{random.randint(0, 9)}"
        }
    
    async def _enumerate_database_tables(self, db_name: str) -> List[Dict]:
        """Enumerar tabelas do banco"""
        table_templates = [
            {'name': 'users', 'columns': ['id', 'username', 'password', 'email', 'created_at']},
            {'name': 'customers', 'columns': ['id', 'name', 'email', 'phone', 'address', 'credit_card']},
            {'name': 'orders', 'columns': ['id', 'customer_id', 'total', 'payment_method', 'date']},
            {'name': 'products', 'columns': ['id', 'name', 'price', 'description', 'category']},
            {'name': 'admin_logs', 'columns': ['id', 'admin_id', 'action', 'ip_address', 'timestamp']}
        ]
        
        return random.sample(table_templates, random.randint(2, len(table_templates)))
    
    async def _extract_table_data(self, db_name: str, table_name: str) -> Dict[str, Any]:
        """Extrair dados da tabela"""
        sensitive_columns = []
        sample_data = {}
        
        # Identificar colunas sensíveis
        sensitive_keywords = ['password', 'credit_card', 'ssn', 'phone', 'email', 'address']
        
        # Simular dados da tabela
        row_count = random.randint(100, 10000)
        
        return {
            'extracted': random.random() > 0.1,  # 90% de sucesso
            'row_count': row_count,
            'sensitive_columns': sensitive_columns,
            'sample_data': sample_data
        }
    
    async def _categorize_database_data(self, column_name: str) -> str:
        """Categorizar dados do banco"""
        column_lower = column_name.lower()
        
        if any(keyword in column_lower for keyword in ['password', 'token', 'key', 'secret']):
            return 'credentials'
        elif any(keyword in column_lower for keyword in ['credit', 'payment', 'invoice', 'price']):
            return 'financial'
        elif any(keyword in column_lower for keyword in ['email', 'phone', 'address', 'ssn']):
            return 'personal'
        else:
            return 'corporate'
    
    async def _access_email_account(self, account: str) -> Dict[str, Any]:
        """Simular acesso à conta de email"""
        return {
            'accessible': random.random() > 0.3,  # 70% de chance
            'protocol': random.choice(['IMAP', 'POP3', 'Exchange']),
            'folder_count': random.randint(5, 20)
        }
    
    async def _extract_emails(self, account: str, folder: str) -> List[Dict]:
        """Extrair emails da pasta"""
        emails = []
        email_count = random.randint(10, 100)
        
        for i in range(email_count):
            email = {
                'id': f"email_{i}_{account}",
                'from': f"sender{random.randint(1, 100)}@example.com",
                'to': account,
                'subject': f"Subject {i}",
                'date': datetime.now().isoformat(),
                'has_attachments': random.random() > 0.8,
                'attachments': [],
                'sensitivity_score': random.random()
            }
            
            if email['has_attachments']:
                attachment_count = random.randint(1, 3)
                for j in range(attachment_count):
                    email['attachments'].append({
                        'filename': f"attachment_{j}.{random.choice(['pdf', 'docx', 'xlsx', 'jpg'])}",
                        'size': random.randint(1024, 5242880),
                        'type': random.choice(['document', 'image', 'spreadsheet'])
                    })
            
            emails.append(email)
        
        return emails
    
    async def _extract_contacts(self, account: str) -> List[Dict]:
        """Extrair contatos da conta"""
        contacts = []
        contact_count = random.randint(50, 500)
        
        for i in range(contact_count):
            contact = {
                'name': f"Contact {i}",
                'email': f"contact{i}@example.com",
                'phone': f"+1-555-{random.randint(1000, 9999)}",
                'organization': f"Company {random.randint(1, 50)}",
                'last_contact': datetime.now().isoformat()
            }
            contacts.append(contact)
        
        return contacts
    
    async def _capture_screenshot(self) -> Dict[str, Any]:
        """Simular captura de screenshot"""
        return {
            'captured': random.random() > 0.05,  # 95% de sucesso
            'size_mb': round(random.uniform(0.5, 3.0), 2),
            'resolution': random.choice(['1920x1080', '1366x768', '2560x1440']),
            'active_app': random.choice(['chrome.exe', 'outlook.exe', 'excel.exe', 'notepad.exe']),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _analyze_screenshot_content(self, screenshot_data: Dict) -> Dict[str, Any]:
        """Analisar conteúdo sensível no screenshot"""
        # Simular análise de OCR/conteúdo
        sensitive_apps = ['outlook.exe', 'excel.exe', 'banking.exe']
        has_sensitive = screenshot_data['active_app'] in sensitive_apps
        
        if has_sensitive:
            content_type = random.choice(['financial_data', 'personal_info', 'credentials', 'corporate_data'])
            confidence = random.uniform(0.7, 0.95)
        else:
            content_type = 'none'
            confidence = 0.0
        
        return {
            'has_sensitive_content': has_sensitive,
            'content_type': content_type,
            'confidence': confidence
        }
    
    async def get_stealer_statistics(self) -> Dict[str, Any]:
        """Obter estatísticas dos data stealers"""
        return {
            'framework_status': 'operational',
            'total_data_stolen': len(self.exfiltrated_data),
            'data_categories': self.data_categories,
            'attack_statistics': self.attack_statistics,
            'success_rates': {
                'file_theft_success': min(87.3, self.attack_statistics['files_stolen'] * 0.8),
                'database_access_success': min(79.2, self.attack_statistics['databases_accessed'] * 15.8),
                'email_harvest_success': min(91.5, self.attack_statistics['emails_harvested'] * 0.1),
                'keylogger_effectiveness': min(96.1, self.attack_statistics['keystrokes_captured'] * 0.001),
                'screenshot_success': min(94.7, self.attack_statistics['screenshots_taken'] * 0.5)
            },
            'exfiltration_methods': ['http_post', 'ftp_upload', 'email_attachment', 'cloud_storage', 'dns_tunneling'],
            'last_updated': datetime.now().isoformat()
        }

# Instância global
data_stealers = DataStealersFramework()
