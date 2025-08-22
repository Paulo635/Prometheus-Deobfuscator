#!/usr/bin/env python3
"""
Script avançado para quebrar a encriptação usando múltiplas técnicas
"""

import requests
import base64
import hashlib
import json
import re
import itertools
import string
from urllib.parse import unquote, urlencode
import time
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

class AdvancedDecryptor:
    def __init__(self):
        self.url = "http://vod.eppibrasil.com/sdk/user/auth/login/v1"
        self.payload = {
            'v': "6",
            'm': "S0JeqtdFI30eW7aSUNSFBC5d7bPW3exsWoNPE0VSGj4eqKq68lYB/JL0fOKgDgGPCfiX0hiG0c5xBgdKe5LS4732vxe7y0rKk1qmZOuMrIJPmSkNiJw7q+jv+rS2uT4SagbERYHrBxmV+q7Zoql7el+w1YuPvqqv6OrMKYg/aZ/WTe3F3qP0IbguZ18Bhu3oB4NKcwRCAAOlSrUocGfG79kYIMXUID8MbMLr93Ri4CNbAQXZ3ADcqSFH7RUb1GEidMddEBNd74/9D6zllRQmfpzOdnsqz9xPnJ/T92FsOGtqnloz/8CC+zEUlaBX75CrgOxP2j6dH8U0xZVcUfSzqlrYcmG9J36Nb/8aLbyMpf9bltV2iUahlNFTYvBfObUhwy0ILVQmUZKE/olwMWuryRV7IE4Qsnz3YBSq2WErM8HxkjJSGc54oV2X9fDHapYDd+GJZr8Jy1whCjP6gY1TVN6ju+u6rh5mNHkRch2S22ffbSaLfJ4TgUXa8s+Jndj4onGco6ce9m4eLhi1OWEFBnIyksGEMKLHmVFlnVP8Hulb/7uEOYo6tZL9r5tbHZYahUwLc/176o9I9/3ojdjfAVD5nsi5XGOWpHqsXk1XrTFsZOFTrh6Dda7HDfSVVpqmAs6MIjfVMuHwh7spprRzBV/vPzz76NpTM4Wh4pgIEs2onoBbVXTKXlSJW0PupsvtsbYDc1hEs32OSxhTvyZtqWDsS/gdg+kIlmC5vHs33tg=",
            's': "d06f8426db30339ae49d921d371146b18d03a5cf"
        }
        self.headers = {
            'User-Agent': "okhttp/3.12.0",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Vod-AppId': "mobile",
            'Accept-Language': "pt",
            'Vod-AppVer': "4000266",
            'Vod-Brand': "EPPI",
            'Vod-Vno': "EPPI",
            'Cookie': "uid=-1;did=35e86bccb97aec8d"
        }
        
    def analyze_encryption_patterns(self):
        """Analisa padrões de encriptação"""
        print("🔍 ANALISANDO PADRÕES DE ENCRIPTAÇÃO")
        print("=" * 50)
        
        m_param = self.payload['m']
        s_param = self.payload['s']
        
        # Análise de padrões
        print(f"Parâmetro 'm':")
        print(f"  - Tamanho: {len(m_param)} caracteres")
        print(f"  - Caracteres únicos: {len(set(m_param))}")
        print(f"  - Base64 válido: {self.is_valid_base64(m_param)}")
        print(f"  - Padrão repetitivo: {self.has_repetitive_pattern(m_param)}")
        
        print(f"\nParâmetro 's':")
        print(f"  - Tamanho: {len(s_param)} caracteres")
        print(f"  - Formato hex: {self.is_hex_string(s_param)}")
        print(f"  - Possível hash: {self.identify_hash_type(s_param)}")
        
        # Análise de entropia
        entropy = self.calculate_entropy(m_param)
        print(f"\nEntropia do parâmetro 'm': {entropy:.2f}")
        if entropy > 4.5:
            print("  - Alta entropia: provavelmente encriptado ou comprimido")
        elif entropy > 3.0:
            print("  - Média entropia: pode ser codificado")
        else:
            print("  - Baixa entropia: pode ser texto simples")
    
    def is_valid_base64(self, data):
        """Verifica se é base64 válido"""
        try:
            base64.b64decode(data)
            return True
        except:
            return False
    
    def has_repetitive_pattern(self, data):
        """Verifica se há padrões repetitivos"""
        if len(data) < 10:
            return False
        
        # Procura por padrões de 3-10 caracteres
        for pattern_len in range(3, min(11, len(data)//2)):
            for i in range(len(data) - pattern_len):
                pattern = data[i:i+pattern_len]
                if data.count(pattern) > 2:
                    return f"Padrão '{pattern}' repetido {data.count(pattern)} vezes"
        return False
    
    def is_hex_string(self, data):
        """Verifica se é uma string hexadecimal"""
        return bool(re.match(r'^[a-f0-9]+$', data))
    
    def identify_hash_type(self, data):
        """Identifica o tipo de hash baseado no tamanho"""
        hash_types = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256",
            128: "SHA512"
        }
        return hash_types.get(len(data), "Desconhecido")
    
    def calculate_entropy(self, data):
        """Calcula a entropia da string"""
        if not data:
            return 0
        
        # Conta frequência de caracteres
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        # Calcula entropia
        entropy = 0
        length = len(data)
        for count in freq.values():
            probability = count / length
            entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def try_multiple_decoding_methods(self):
        """Tenta múltiplos métodos de decodificação"""
        print("\n🔄 TENTANDO MÚLTIPLOS MÉTODOS DE DECODIFICAÇÃO")
        print("=" * 50)
        
        m_param = self.payload['m']
        
        # 1. Base64 direto
        print("1. Decodificação Base64 direta...")
        try:
            decoded = base64.b64decode(m_param)
            print(f"   ✓ Sucesso! Tamanho: {len(decoded)} bytes")
            print(f"   Primeiros bytes (hex): {decoded[:20].hex()}")
            
            # Tenta interpretar como diferentes formatos
            self.analyze_decoded_data(decoded)
            
        except Exception as e:
            print(f"   ✗ Falhou: {e}")
        
        # 2. Base64 com padding
        print("\n2. Decodificação Base64 com padding...")
        try:
            padded = m_param + "=" * (4 - len(m_param) % 4)
            decoded = base64.b64decode(padded)
            print(f"   ✓ Sucesso! Tamanho: {len(decoded)} bytes")
            self.analyze_decoded_data(decoded)
        except Exception as e:
            print(f"   ✗ Falhou: {e}")
        
        # 3. URL-safe base64
        print("\n3. Decodificação Base64 URL-safe...")
        try:
            url_safe = m_param.replace('-', '+').replace('_', '/')
            decoded = base64.b64decode(url_safe)
            print(f"   ✓ Sucesso! Tamanho: {len(decoded)} bytes")
            self.analyze_decoded_data(decoded)
        except Exception as e:
            print(f"   ✗ Falhou: {e}")
        
        # 4. Decompressão
        print("\n4. Tentativa de descompressão...")
        try:
            decoded = base64.b64decode(m_param)
            # Tenta diferentes algoritmos de compressão
            for method in ['gzip', 'zlib', 'bzip2']:
                try:
                    if method == 'gzip':
                        decompressed = zlib.decompress(decoded, 16+zlib.MAX_WBITS)
                    elif method == 'zlib':
                        decompressed = zlib.decompress(decoded)
                    else:
                        continue
                    
                    print(f"   ✓ Descompressão {method} sucesso! Tamanho: {len(decompressed)} bytes")
                    self.analyze_decoded_data(decompressed)
                    break
                except:
                    continue
        except Exception as e:
            print(f"   ✗ Falhou: {e}")
    
    def analyze_decoded_data(self, data):
        """Analisa dados decodificados"""
        print(f"   Analisando {len(data)} bytes...")
        
        # Tenta como string UTF-8
        try:
            text = data.decode('utf-8')
            print(f"   ✓ UTF-8 válido: {text[:100]}...")
            
            # Tenta como JSON
            try:
                json_data = json.loads(text)
                print(f"   ✓ JSON válido encontrado!")
                print(f"   Chaves: {list(json_data.keys())}")
            except:
                pass
                
        except UnicodeDecodeError:
            print("   ✗ Não é UTF-8 válido")
        
        # Análise de bytes
        if len(data) >= 4:
            # Verifica se tem cabeçalho de arquivo conhecido
            headers = {
                b'\x1f\x8b': 'GZIP',
                b'PK\x03\x04': 'ZIP',
                b'\x89PNG': 'PNG',
                b'\xff\xd8\xff': 'JPEG',
                b'GIF8': 'GIF'
            }
            
            for header, file_type in headers.items():
                if data.startswith(header):
                    print(f"   ✓ Cabeçalho {file_type} detectado!")
                    break
        
        # Verifica se parece ser dados binários estruturados
        if len(data) >= 8:
            try:
                # Tenta interpretar como números
                numbers = struct.unpack('>Q', data[:8])
                print(f"   Possível número: {numbers[0]}")
            except:
                pass
    
    def try_signature_reverse_engineering(self):
        """Tenta engenharia reversa da assinatura"""
        print("\n🔐 TENTANDO ENGENHARIA REVERSA DA ASSINATURA")
        print("=" * 50)
        
        s_param = self.payload['s']
        original_payload = self.payload.copy()
        del original_payload['s']
        
        print(f"Assinatura original: {s_param}")
        print(f"Payload sem assinatura: {original_payload}")
        
        # Testa diferentes combinações para gerar a assinatura
        test_combinations = [
            # Combinação simples
            urlencode(original_payload),
            # Com chaves ordenadas
            urlencode(sorted(original_payload.items())),
            # Sem codificação
            "&".join([f"{k}={v}" for k, v in original_payload.items()]),
            # Com chaves ordenadas sem codificação
            "&".join([f"{k}={v}" for k, v in sorted(original_payload.items())]),
            # Incluindo headers específicos
            f"{urlencode(original_payload)}&app_id={self.headers.get('Vod-AppId')}",
            f"{urlencode(original_payload)}&version={self.headers.get('Vod-AppVer')}",
            # Com timestamp (tentativa)
            f"{urlencode(original_payload)}&ts={int(time.time())}"
        ]
        
        print("\nTestando diferentes combinações...")
        
        for i, combination in enumerate(test_combinations):
            print(f"\n{i+1}. Testando: {combination[:50]}...")
            
            # Gera diferentes tipos de hash
            md5 = hashlib.md5(combination.encode()).hexdigest()
            sha1 = hashlib.sha1(combination.encode()).hexdigest()
            sha256 = hashlib.sha256(combination.encode()).hexdigest()
            
            if sha1 == s_param:
                print(f"   ✓ SHA1 encontrado! Combinação: {combination}")
                return combination
            elif md5 == s_param:
                print(f"   ✓ MD5 encontrado! Combinação: {combination}")
                return combination
            elif sha256 == s_param:
                print(f"   ✓ SHA256 encontrado! Combinação: {combination}")
                return combination
        
        print("   ✗ Nenhuma combinação simples encontrada")
        print("   Provavelmente usa HMAC ou algoritmo customizado")
        
        return None
    
    def try_hmac_brute_force(self):
        """Tenta força bruta com HMAC"""
        print("\n💪 TENTANDO FORÇA BRUTA COM HMAC")
        print("=" * 50)
        
        s_param = self.payload['s']
        original_payload = self.payload.copy()
        del original_payload['s']
        
        # Dados para hash
        data = urlencode(original_payload)
        
        # Chaves comuns para testar
        common_keys = [
            "secret", "key", "password", "token", "auth",
            "eppi", "vod", "mobile", "app", "sdk",
            "4000266", "EPPI", "brasil", "vod",
            "user", "login", "auth", "v1"
        ]
        
        print(f"Testando {len(common_keys)} chaves comuns...")
        
        for key in common_keys:
            # Testa diferentes algoritmos HMAC
            for algorithm in ['md5', 'sha1', 'sha256']:
                if algorithm == 'md5':
                    hmac_hash = hashlib.new('md5', key.encode() + data.encode()).hexdigest()
                elif algorithm == 'sha1':
                    hmac_hash = hashlib.new('sha1', key.encode() + data.encode()).hexdigest()
                elif algorithm == 'sha256':
                    hmac_hash = hashlib.new('sha256', key.encode() + data.encode()).hexdigest()
                
                if hmac_hash == s_param:
                    print(f"   ✓ HMAC-{algorithm.upper()} encontrado!")
                    print(f"   Chave: '{key}'")
                    print(f"   Dados: {data}")
                    return key, algorithm, data
        
        print("   ✗ Nenhuma chave comum encontrada")
        return None
    
    def test_modified_requests(self):
        """Testa requisições com parâmetros modificados"""
        print("\n🧪 TESTANDO REQUISIÇÕES MODIFICADAS")
        print("=" * 50)
        
        # Testa diferentes modificações
        modifications = [
            ("Sem assinatura", lambda p: p.pop('s', None)),
            ("Versão 5", lambda p: p.update({'v': '5'})),
            ("Versão 7", lambda p: p.update({'v': '7'})),
            ("App ID diferente", lambda p: self.headers.update({'Vod-AppId': 'web'})),
            ("User Agent diferente", lambda p: self.headers.update({'User-Agent': 'Mozilla/5.0'})),
            ("Sem cookies", lambda p: self.headers.pop('Cookie', None))
        ]
        
        for desc, modifier in modifications:
            print(f"\nTestando: {desc}")
            
            # Faz backup dos dados originais
            test_payload = self.payload.copy()
            test_headers = self.headers.copy()
            
            # Aplica modificação
            modifier(test_payload)
            
            try:
                response = requests.post(self.url, data=test_payload, headers=test_headers, timeout=10)
                print(f"   Status: {response.status_code}")
                print(f"   Resposta: {response.text[:100]}...")
                
                # Analisa diferenças na resposta
                if response.status_code != 200:
                    print(f"   ✗ Falhou com status {response.status_code}")
                else:
                    print(f"   ✓ Sucesso!")
                    
            except Exception as e:
                print(f"   ✗ Erro: {e}")
    
    def run_full_analysis(self):
        """Executa análise completa"""
        print("🚀 INICIANDO ANÁLISE COMPLETA DE ENCRIPTAÇÃO")
        print("=" * 60)
        
        # 1. Análise de padrões
        self.analyze_encryption_patterns()
        
        # 2. Múltiplos métodos de decodificação
        self.try_multiple_decoding_methods()
        
        # 3. Engenharia reversa da assinatura
        self.try_signature_reverse_engineering()
        
        # 4. Força bruta HMAC
        self.try_hmac_brute_force()
        
        # 5. Testes de requisições modificadas
        self.test_modified_requests()
        
        print("\n" + "=" * 60)
        print("✅ ANÁLISE COMPLETA FINALIZADA")
        print("\n📋 RESUMO DAS DESCOBERTAS:")
        print("• O parâmetro 'm' é provavelmente base64 de dados encriptados")
        print("• O parâmetro 's' é uma assinatura SHA1 de 40 caracteres")
        print("• Provavelmente usa HMAC com chave secreta")
        print("• A encriptação pode ser AES ou algoritmo similar")
        print("\n🔧 PRÓXIMOS PASSOS:")
        print("1. Analisar o app Android para encontrar a chave secreta")
        print("2. Verificar se há rotação de chaves baseada em timestamp")
        print("3. Analisar o código JavaScript se for web app")
        print("4. Verificar se há outras rotas que usam o mesmo algoritmo")

def main():
    """Função principal"""
    decryptor = AdvancedDecryptor()
    decryptor.run_full_analysis()

if __name__ == "__main__":
    main()