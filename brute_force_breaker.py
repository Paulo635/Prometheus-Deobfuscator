#!/usr/bin/env python3
"""
Script de força bruta avançado para quebrar a encriptação EPPI Brasil VOD
"""

import base64
import hashlib
import json
import re
import urllib.parse
import time
import struct
import math
import itertools
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

class BruteForceBreaker:
    def __init__(self):
        self.payload = {
            'v': "6",
            'm': "S0JeqtdFI30eW7aSUNSFBC5d7bPW3exsWoNPE0VSGj4eqKq68lYB/JL0fOKgDgGPCfiX0hiG0c5xBgdKe5LS4732vxe7y0rKk1qmZOuMrIJPmSkNiJw7q+jv+rS2uT4SagbERYHrBxmV+q7Zoql7el+w1YuPvqqv6OrMKYg/aZ/WTe3F3rT4SagbERYHrBxmV+q7Zoql7el+w1YuPvqqv6OrMKYg/aZ/WTe3F3qP0IbguZ18Bhu3oB4NKcwRCAAOlSrUocGfG79kYIMXUID8MbMLr93Ri4CNbAQXZ3ADcqSFH7RUb1GEidMddEBNd74/9D6zllRQmfpzOdnsqz9xPnJ/T92FsOGtqnloz/8CC+zEUlaBX75CrgOxP2j6dH8U0xZVcUfSzqlrYcmG9J36Nb/8aLbyMpf9bltV2iUahlNFTYvBfObUhwy0ILVQmUZKE/olwMWuryRV7IE4Qsnz3YBSq2WErM8HxkjJSGc54oV2X9fDHapYDd+GJZr8Jy1whCjP6gY1TVN6ju+u6rh5mNHkRch2S22ffbSaLfJ4TgUXa8s+Jndj4onGco6ce9m4eLhi1OWEFBnIyksGEMKLHmVFlnVP8Hulb/7uEOYo6tZL9r5tbHZYahUwLc/176o9I9/3ojdjfAVD5nsi5XGOWpHqsXk1XrTFsZOFTrh6Dda7HDfSVVpqmAs6MIjfVMuHwh7spprRzBV/vPzz76NpTM4Wh4pgIEs2onoBbVXTKXlSJW0PupsvtsbYDc1hEs32OSxhTvyZtqWDsS/gdg+kIlmC5vHs33tg=",
            's': "d06f8426db30339ae49d921d371146b18d03a5cf"
        }
        
        self.decoded_data = None
        self.signature = None
        
        # Decodifica os dados
        try:
            self.decoded_data = base64.b64decode(self.payload['m'])
            print(f"✓ Dados decodificados: {len(self.decoded_data)} bytes")
        except Exception as e:
            print(f"✗ Erro na decodificação: {e}")
            return
    
    def brute_force_aes_keys(self):
        """Tenta força bruta de chaves AES"""
        print("\n🔑 FORÇA BRUTA DE CHAVES AES")
        print("=" * 50)
        
        if not self.decoded_data:
            print("✗ Dados não decodificados")
            return
        
        # Chaves comuns para testar
        common_keys = [
            # Chaves relacionadas ao app
            "eppi", "vod", "mobile", "app", "sdk",
            "4000266", "EPPI", "brasil", "vod",
            "user", "login", "auth", "v1",
            
            # Chaves específicas
            "eppi_secret", "vod_key", "mobile_auth",
            "app_secret", "sdk_key", "brasil_secret",
            "login_key", "auth_secret", "v1_key",
            
            # Combinações
            "eppi_vod", "mobile_sdk", "brasil_auth",
            "4000266_secret", "EPPI_key", "vod_mobile",
            
            # Chaves genéricas
            "secret", "key", "password", "token", "auth",
            "123456", "password123", "admin", "root",
            
            # Chaves específicas do sistema
            "eppibrasil", "vodbrasil", "mobilevod",
            "eppi2024", "vod2024", "mobile2024",
            "brasilvod", "vodmobile", "mobilebrasil"
        ]
        
        print(f"Testando {len(common_keys)} chaves comuns...")
        
        # Tenta diferentes tamanhos de chave
        key_sizes = [16, 24, 32]  # 128, 192, 256 bits
        
        for key_size in key_sizes:
            print(f"\n🔍 Testando chaves de {key_size * 8} bits...")
            
            for key in common_keys:
                # Ajusta o tamanho da chave
                key_bytes = key.encode()
                if len(key_bytes) < key_size:
                    key_bytes = key_bytes + b'\x00' * (key_size - len(key_bytes))
                elif len(key_bytes) > key_size:
                    key_bytes = key_bytes[:key_size]
                
                # Tenta diferentes modos de operação
                modes = ['ECB', 'CBC']
                
                for mode in modes:
                    try:
                        if mode == 'ECB':
                            cipher = AES.new(key_bytes, AES.MODE_ECB)
                            decrypted = cipher.decrypt(self.decoded_data)
                        elif mode == 'CBC':
                            # Tenta diferentes IVs
                            for iv_attempt in range(5):
                                if iv_attempt == 0:
                                    # IV zero
                                    iv = b'\x00' * 16
                                elif iv_attempt == 1:
                                    # IV baseado na chave
                                    iv = hashlib.md5(key_bytes).digest()[:16]
                                elif iv_attempt == 2:
                                    # IV baseado no primeiro bloco
                                    iv = self.decoded_data[:16]
                                elif iv_attempt == 3:
                                    # IV baseado no último bloco
                                    iv = self.decoded_data[-16:]
                                else:
                                    # IV baseado em timestamp
                                    iv = struct.pack('>Q', int(time.time())) + b'\x00' * 8
                                
                                try:
                                    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                                    decrypted = cipher.decrypt(self.decoded_data)
                                    
                                    # Verifica se a decriptação parece válida
                                    if self.is_valid_decryption(decrypted):
                                        print(f"  ✓ AES-{key_size*8} {mode} encontrado!")
                                        print(f"  Chave: '{key}'")
                                        print(f"  IV: {iv.hex()}")
                                        print(f"  Dados decriptados: {decrypted[:100].hex()}...")
                                        
                                        # Tenta interpretar como texto
                                        try:
                                            text = decrypted.decode('utf-8')
                                            print(f"  Texto: {text[:200]}...")
                                            
                                            # Tenta como JSON
                                            try:
                                                json_data = json.loads(text)
                                                print(f"  ✓ JSON válido! Chaves: {list(json_data.keys())}")
                                                return key, mode, iv, decrypted
                                            except:
                                                pass
                                                
                                        except UnicodeDecodeError:
                                            print("  Não é texto UTF-8 válido")
                                        
                                        return key, mode, iv, decrypted
                                        
                                except Exception as e:
                                    continue
                    
                    except Exception as e:
                        continue
        
        print("✗ Nenhuma chave AES encontrada")
        return None, None, None, None
    
    def is_valid_decryption(self, data):
        """Verifica se a decriptação parece válida"""
        if not data:
            return False
        
        # Remove padding
        try:
            data = unpad(data, 16)
        except:
            pass
        
        # Verifica se parece ser texto
        try:
            text = data.decode('utf-8')
            
            # Verifica se contém caracteres esperados em dados de login
            expected_chars = ['user', 'pass', 'email', 'login', 'auth', 'token', 'id']
            text_lower = text.lower()
            
            for char in expected_chars:
                if char in text_lower:
                    return True
            
            # Verifica se é JSON válido
            try:
                json.loads(text)
                return True
            except:
                pass
                
        except UnicodeDecodeError:
            pass
        
        # Verifica se tem muitos bytes zero (padding)
        zero_ratio = data.count(0) / len(data)
        if zero_ratio > 0.3:  # Mais de 30% zeros
            return False
        
        # Verifica entropia
        entropy = self.calculate_entropy(data)
        if entropy < 3.0:  # Baixa entropia pode indicar texto simples
            return True
        
        return False
    
    def calculate_entropy(self, data):
        """Calcula entropia dos dados"""
        if not data:
            return 0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0
        length = len(data)
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def brute_force_hmac_keys(self):
        """Tenta força bruta de chaves HMAC"""
        print("\n🔐 FORÇA BRUTA DE CHAVES HMAC")
        print("=" * 50)
        
        signature = self.payload['s']
        test_payload = self.payload.copy()
        del test_payload['s']
        
        # Dados para hash
        data = urllib.parse.urlencode(test_payload)
        
        # Chaves comuns para testar
        common_keys = [
            # Chaves relacionadas ao app
            "secret", "key", "password", "token", "auth",
            "eppi", "vod", "mobile", "app", "sdk",
            "4000266", "EPPI", "brasil", "vod",
            "user", "login", "auth", "v1",
            
            # Chaves específicas
            "eppi_secret", "vod_key", "mobile_auth",
            "app_secret", "sdk_key", "brasil_secret",
            "login_key", "auth_secret", "v1_key",
            
            # Combinações
            "eppi_vod", "mobile_sdk", "brasil_auth",
            "4000266_secret", "EPPI_key", "vod_mobile",
            
            # Chaves genéricas
            "123456", "password123", "admin", "root",
            "default", "secret123", "key123", "auth123",
            
            # Chaves específicas do sistema
            "eppibrasil", "vodbrasil", "mobilevod",
            "eppi2024", "vod2024", "mobile2024",
            "brasilvod", "vodmobile", "mobilebrasil",
            
            # Chaves com timestamp
            "eppi2024", "vod2024", "mobile2024",
            "brasil2024", "vodbrasil2024"
        ]
        
        print(f"Testando {len(common_keys)} chaves comuns...")
        
        # Testa diferentes algoritmos HMAC
        algorithms = ['md5', 'sha1', 'sha256']
        
        for algorithm in algorithms:
            print(f"\n🔍 Testando HMAC-{algorithm.upper()}...")
            
            for key in common_keys:
                try:
                    if algorithm == 'md5':
                        hmac_hash = hashlib.new('md5', key.encode() + data.encode()).hexdigest()
                    elif algorithm == 'sha1':
                        hmac_hash = hashlib.new('sha1', key.encode() + data.encode()).hexdigest()
                    elif algorithm == 'sha256':
                        hmac_hash = hashlib.new('sha256', key.encode() + data.encode()).hexdigest()
                    
                    if hmac_hash == signature:
                        print(f"  ✓ HMAC-{algorithm.upper()} encontrado!")
                        print(f"  Chave: '{key}'")
                        print(f"  Dados: {data}")
                        return key, algorithm, data
                        
                except Exception as e:
                    continue
        
        print("✗ Nenhuma chave HMAC encontrada")
        return None, None, None
    
    def try_advanced_combinations(self):
        """Tenta combinações avançadas"""
        print("\n🚀 TENTANDO COMBINAÇÕES AVANÇADAS")
        print("=" * 50)
        
        signature = self.payload['s']
        test_payload = self.payload.copy()
        del test_payload['s']
        
        # Combinações mais complexas
        advanced_combinations = [
            # Com timestamp
            f"{urllib.parse.urlencode(test_payload)}&ts={int(time.time())}",
            f"{urllib.parse.urlencode(test_payload)}&timestamp={int(time.time())}",
            
            # Com device ID
            f"{urllib.parse.urlencode(test_payload)}&did=35e86bccb97aec8d",
            f"{urllib.parse.urlencode(test_payload)}&device_id=35e86bccb97aec8d",
            
            # Com user ID
            f"{urllib.parse.urlencode(test_payload)}&uid=-1",
            f"{urllib.parse.urlencode(test_payload)}&user_id=-1",
            
            # Com headers específicos
            f"{urllib.parse.urlencode(test_payload)}&app_id=mobile&version=4000266&brand=EPPI",
            f"{urllib.parse.urlencode(test_payload)}&mobile&4000266&EPPI",
            
            # Combinações especiais
            f"mobile&4000266&EPPI&{urllib.parse.urlencode(test_payload)}",
            f"EPPI&brasil&vod&{urllib.parse.urlencode(test_payload)}",
            f"vod&mobile&{urllib.parse.urlencode(test_payload)}&brasil",
            
            # Com chaves de hash
            f"secret&{urllib.parse.urlencode(test_payload)}",
            f"key&{urllib.parse.urlencode(test_payload)}",
            f"auth&{urllib.parse.urlencode(test_payload)}",
            
            # Invertido
            f"{urllib.parse.urlencode(test_payload)}&secret",
            f"{urllib.parse.urlencode(test_payload)}&key",
            f"{urllib.parse.urlencode(test_payload)}&auth"
        ]
        
        print(f"Testando {len(advanced_combinations)} combinações avançadas...")
        
        for i, combination in enumerate(advanced_combinations):
            # Gera diferentes tipos de hash
            md5 = hashlib.md5(combination.encode()).hexdigest()
            sha1 = hashlib.sha1(combination.encode()).hexdigest()
            sha256 = hashlib.sha256(combination.encode()).hexdigest()
            
            if sha1 == signature:
                print(f"  ✓ SHA1 encontrado! Combinação {i+1}")
                print(f"  Dados: {combination[:80]}...")
                return combination, 'sha1'
            elif md5 == signature:
                print(f"  ✓ MD5 encontrado! Combinação {i+1}")
                return combination, 'md5'
            elif sha256 == signature:
                print(f"  ✓ SHA256 encontrado! Combinação {i+1}")
                return combination, 'sha256'
        
        print("✗ Nenhuma combinação avançada encontrada")
        return None, None
    
    def run_full_brute_force(self):
        """Executa força bruta completa"""
        print("💪 INICIANDO FORÇA BRUTA COMPLETA")
        print("=" * 60)
        
        start_time = time.time()
        
        # 1. Força bruta AES
        print("\n🔑 ETAPA 1: FORÇA BRUTA AES")
        aes_result = self.brute_force_aes_keys()
        
        # 2. Força bruta HMAC
        print("\n🔐 ETAPA 2: FORÇA BRUTA HMAC")
        hmac_result = self.brute_force_hmac_keys()
        
        # 3. Combinações avançadas
        print("\n🚀 ETAPA 3: COMBINAÇÕES AVANÇADAS")
        combo_result = self.try_advanced_combinations()
        
        # Resumo
        end_time = time.time()
        total_time = end_time - start_time
        
        print("\n" + "=" * 60)
        print("📊 RESUMO DA FORÇA BRUTA")
        print("=" * 60)
        
        print(f"Tempo total: {total_time:.2f} segundos")
        
        if aes_result[0]:
            print(f"✓ AES quebrado: {aes_result[1]} com chave '{aes_result[0]}'")
            print(f"  IV: {aes_result[2].hex()}")
            print(f"  Dados decriptados: {len(aes_result[3])} bytes")
        
        if hmac_result[0]:
            print(f"✓ HMAC quebrado: {hmac_result[1].upper()} com chave '{hmac_result[0]}'")
        
        if combo_result[0]:
            print(f"✓ Assinatura quebrada: {combo_result[1].upper()}")
        
        if not any([aes_result[0], hmac_result[0], combo_result[0]]):
            print("✗ Nenhuma chave foi quebrada")
            print("\n🔧 PRÓXIMOS PASSOS:")
            print("1. Tentar mais variações de chaves")
            print("2. Análise do app Android")
            print("3. Captura de mais requisições")
            print("4. Análise de padrões de tráfego")
        
        return aes_result, hmac_result, combo_result

def main():
    """Função principal"""
    breaker = BruteForceBreaker()
    breaker.run_full_brute_force()

if __name__ == "__main__":
    main()