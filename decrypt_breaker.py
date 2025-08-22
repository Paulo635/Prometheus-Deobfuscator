#!/usr/bin/env python3
"""
Script avançado para tentar quebrar a encriptação usando múltiplas técnicas
"""

import base64
import hashlib
import json
import re
import urllib.parse
import time
import struct
import zlib

class DecryptBreaker:
    def __init__(self):
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
        
        # Dados decodificados
        self.decoded_data = None
        self.signature = None
        
    def decode_base64_data(self):
        """Decodifica os dados base64"""
        print("🔓 DECODIFICANDO DADOS BASE64")
        print("=" * 40)
        
        try:
            self.decoded_data = base64.b64decode(self.payload['m'])
            print(f"✓ Dados decodificados: {len(self.decoded_data)} bytes")
            print(f"Primeiros 32 bytes (hex): {self.decoded_data[:32].hex()}")
            print(f"Últimos 32 bytes (hex): {self.decoded_data[-32:].hex()}")
            return True
        except Exception as e:
            print(f"✗ Erro na decodificação: {e}")
            return False
    
    def analyze_encrypted_data(self):
        """Analisa os dados encriptados"""
        if not self.decoded_data:
            print("✗ Dados não decodificados")
            return
        
        print("\n🔍 ANÁLISE DOS DADOS ENCRIPTADOS")
        print("=" * 40)
        
        data = self.decoded_data
        
        # Análise de tamanho
        print(f"Tamanho total: {len(data)} bytes")
        
        # Verifica se é múltiplo de 16 (AES)
        if len(data) % 16 == 0:
            print("✓ Tamanho é múltiplo de 16 - possível AES")
        elif len(data) % 8 == 0:
            print("✓ Tamanho é múltiplo de 8 - possível DES/3DES")
        else:
            print("✗ Tamanho não é múltiplo de 8 ou 16")
        
        # Análise de entropia
        entropy = self.calculate_entropy(data)
        print(f"Entropia geral: {entropy:.2f}")
        
        if entropy > 4.5:
            print("✓ Alta entropia - provavelmente encriptado")
        elif entropy > 3.5:
            print("⚠ Média entropia - pode ser comprimido")
        else:
            print("✗ Baixa entropia - pode ser texto simples")
        
        # Análise por blocos
        self.analyze_data_blocks(data)
        
        # Verifica cabeçalhos conhecidos
        self.check_known_headers(data)
        
        # Análise de padrões
        self.analyze_patterns(data)
    
    def calculate_entropy(self, data):
        """Calcula entropia dos dados"""
        if not data:
            return 0
        
        # Conta frequência de bytes
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        # Calcula entropia usando log2
        import math
        entropy = 0
        length = len(data)
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_data_blocks(self, data):
        """Analisa os dados em blocos"""
        print("\n📦 ANÁLISE POR BLOCOS")
        print("-" * 30)
        
        # Analisa primeiros blocos
        for i in range(min(4, len(data) // 16)):
            start = i * 16
            end = start + 16
            block = data[start:end]
            
            block_entropy = self.calculate_entropy(block)
            print(f"Bloco {i+1}: {block.hex()} (entropia: {block_entropy:.2f})")
            
            # Verifica se parece ser IV (Initialization Vector)
            if i == 0 and block_entropy > 4.0:
                print(f"  ⚠ Possível IV (Initialization Vector)")
        
        # Analisa últimos blocos
        if len(data) >= 32:
            last_block = data[-16:]
            last_entropy = self.calculate_entropy(last_block)
            print(f"Último bloco: {last_block.hex()} (entropia: {last_entropy:.2f})")
    
    def check_known_headers(self, data):
        """Verifica cabeçalhos conhecidos"""
        print("\n📋 VERIFICAÇÃO DE CABEÇALHOS")
        print("-" * 30)
        
        headers = {
            b'\x1f\x8b': 'GZIP',
            b'PK\x03\x04': 'ZIP',
            b'\x89PNG': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'GIF8': 'GIF',
            b'\x00\x00\x00': 'Possível tamanho/header',
            b'\xff\xfe': 'UTF-16 LE',
            b'\xfe\xff': 'UTF-16 BE'
        }
        
        for header, file_type in headers.items():
            if data.startswith(header):
                print(f"✓ Cabeçalho {file_type} detectado!")
                return
        
        # Verifica se começa com números
        if len(data) >= 4:
            try:
                size = struct.unpack('>I', data[:4])[0]
                if size < len(data) and size > 0:
                    print(f"⚠ Possível tamanho no início: {size} bytes")
            except:
                pass
        
        print("✗ Nenhum cabeçalho conhecido detectado")
    
    def analyze_patterns(self, data):
        """Analisa padrões nos dados"""
        print("\n🔍 ANÁLISE DE PADRÕES")
        print("-" * 30)
        
        # Procura por padrões repetitivos
        patterns = {}
        for pattern_len in range(4, min(17, len(data)//2)):
            for i in range(len(data) - pattern_len):
                pattern = data[i:i+pattern_len]
                if pattern in patterns:
                    patterns[pattern] += 1
                else:
                    patterns[pattern] = 1
        
        # Mostra padrões mais frequentes
        frequent_patterns = [(p, c) for p, c in patterns.items() if c > 2]
        frequent_patterns.sort(key=lambda x: x[1], reverse=True)
        
        if frequent_patterns:
            print(f"Padrões repetitivos encontrados:")
            for pattern, count in frequent_patterns[:5]:
                print(f"  {pattern.hex()}: {count} vezes")
        else:
            print("✓ Nenhum padrão repetitivo significativo")
        
        # Verifica se há zeros consecutivos
        zero_runs = []
        current_run = 0
        for byte in data:
            if byte == 0:
                current_run += 1
            else:
                if current_run > 0:
                    zero_runs.append(current_run)
                    current_run = 0
        
        if zero_runs:
            max_zero_run = max(zero_runs)
            print(f"Maior sequência de zeros: {max_zero_run} bytes")
    
    def try_decompression(self):
        """Tenta descompressão dos dados"""
        print("\n🗜️ TENTANDO DESCOMPRESSÃO")
        print("=" * 40)
        
        if not self.decoded_data:
            print("✗ Dados não decodificados")
            return
        
        data = self.decoded_data
        
        # Tenta diferentes algoritmos de compressão
        compression_methods = [
            ('gzip', lambda d: zlib.decompress(d, 16+zlib.MAX_WBITS)),
            ('zlib', lambda d: zlib.decompress(d)),
            ('raw deflate', lambda d: zlib.decompress(d, -zlib.MAX_WBITS))
        ]
        
        for method_name, decompress_func in compression_methods:
            try:
                decompressed = decompress_func(data)
                print(f"✓ Descompressão {method_name} bem-sucedida!")
                print(f"  Tamanho original: {len(data)} bytes")
                print(f"  Tamanho descomprimido: {len(decompressed)} bytes")
                print(f"  Primeiros bytes: {decompressed[:50].hex()}")
                
                # Tenta interpretar como texto
                try:
                    text = decompressed.decode('utf-8')
                    print(f"  ✓ UTF-8 válido: {text[:100]}...")
                    
                    # Tenta como JSON
                    try:
                        json_data = json.loads(text)
                        print(f"  ✓ JSON válido! Chaves: {list(json_data.keys())}")
                        return decompressed
                    except:
                        pass
                        
                except UnicodeDecodeError:
                    print("  ✗ Não é UTF-8 válido")
                
            except Exception as e:
                print(f"✗ {method_name}: {e}")
        
        print("✗ Nenhuma descompressão funcionou")
        return None
    
    def try_signature_break(self):
        """Tenta quebrar a assinatura"""
        print("\n🔐 TENTANDO QUEBRAR A ASSINATURA")
        print("=" * 40)
        
        signature = self.payload['s']
        print(f"Assinatura alvo: {signature}")
        
        # Remove a assinatura para testar
        test_payload = self.payload.copy()
        del test_payload['s']
        
        # Testa diferentes combinações
        combinations = [
            # Combinações básicas
            urllib.parse.urlencode(test_payload),
            "&".join([f"{k}={v}" for k, v in test_payload.items()]),
            "&".join([f"{k}={v}" for k, v in sorted(test_payload.items())]),
            
            # Com headers específicos
            f"{urllib.parse.urlencode(test_payload)}&app_id=mobile",
            f"{urllib.parse.urlencode(test_payload)}&version=4000266",
            f"{urllib.parse.urlencode(test_payload)}&brand=EPPI",
            
            # Com timestamp
            f"{urllib.parse.urlencode(test_payload)}&ts={int(time.time())}",
            f"{urllib.parse.urlencode(test_payload)}&timestamp={int(time.time())}",
            
            # Com device ID
            f"{urllib.parse.urlencode(test_payload)}&did=35e86bccb97aec8d",
            f"{urllib.parse.urlencode(test_payload)}&device_id=35e86bccb97aec8d",
            
            # Com user ID
            f"{urllib.parse.urlencode(test_payload)}&uid=-1",
            f"{urllib.parse.urlencode(test_payload)}&user_id=-1",
            
            # Combinações especiais
            f"v={test_payload['v']}&m={test_payload['m']}&mobile&4000266&EPPI",
            f"mobile&4000266&EPPI&{urllib.parse.urlencode(test_payload)}",
            f"{urllib.parse.urlencode(test_payload)}&mobile&4000266&EPPI"
        ]
        
        print(f"Testando {len(combinations)} combinações...")
        
        for i, combination in enumerate(combinations):
            # Gera diferentes tipos de hash
            md5 = hashlib.md5(combination.encode()).hexdigest()
            sha1 = hashlib.sha1(combination.encode()).hexdigest()
            sha256 = hashlib.sha256(combination.encode()).hexdigest()
            
            if sha1 == signature:
                print(f"✓ SHA1 encontrado! Combinação {i+1}")
                print(f"  Dados: {combination[:80]}...")
                return combination, 'sha1'
            elif md5 == signature:
                print(f"✓ MD5 encontrado! Combinação {i+1}")
                return combination, 'md5'
            elif sha256 == signature:
                print(f"✓ SHA256 encontrado! Combinação {i+1}")
                return combination, 'sha256'
        
        print("✗ Nenhuma combinação simples encontrada")
        print("Provavelmente usa HMAC ou algoritmo customizado")
        
        return None, None
    
    def try_hmac_break(self):
        """Tenta quebrar HMAC"""
        print("\n💪 TENTANDO QUEBRAR HMAC")
        print("=" * 40)
        
        signature = self.payload['s']
        test_payload = self.payload.copy()
        del test_payload['s']
        
        data = urllib.parse.urlencode(test_payload)
        
        # Chaves comuns para testar
        common_keys = [
            # Chaves relacionadas ao app
            "secret", "key", "password", "token", "auth",
            "eppi", "vod", "mobile", "app", "sdk",
            "4000266", "EPPI", "brasil", "vod",
            "user", "login", "auth", "v1",
            
            # Chaves específicas do sistema
            "eppi_secret", "vod_key", "mobile_auth",
            "app_secret", "sdk_key", "brasil_secret",
            "login_key", "auth_secret", "v1_key",
            
            # Combinações
            "eppi_vod", "mobile_sdk", "brasil_auth",
            "4000266_secret", "EPPI_key", "vod_mobile"
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
                
                if hmac_hash == signature:
                    print(f"✓ HMAC-{algorithm.upper()} encontrado!")
                    print(f"  Chave: '{key}'")
                    print(f"  Dados: {data}")
                    return key, algorithm, data
        
        print("✗ Nenhuma chave comum encontrada")
        return None, None, None
    
    def run_full_break(self):
        """Executa quebra completa"""
        print("🚀 INICIANDO QUEBRA COMPLETA DA ENCRIPTAÇÃO")
        print("=" * 60)
        
        # 1. Decodifica dados
        if not self.decode_base64_data():
            return
        
        # 2. Analisa dados encriptados
        self.analyze_encrypted_data()
        
        # 3. Tenta descompressão
        decompressed = self.try_decompression()
        
        # 4. Tenta quebrar assinatura
        signature_result = self.try_signature_break()
        
        # 5. Tenta quebrar HMAC
        hmac_result = self.try_hmac_break()
        
        # Resumo
        print("\n" + "=" * 60)
        print("📊 RESUMO DA ANÁLISE")
        print("=" * 60)
        
        print("✓ Dados base64 decodificados com sucesso")
        print(f"✓ Tamanho dos dados: {len(self.decoded_data)} bytes")
        
        if decompressed:
            print(f"✓ Descompressão bem-sucedida: {len(decompressed)} bytes")
        
        if signature_result[0]:
            print(f"✓ Assinatura quebrada: {signature_result[1].upper()}")
        
        if hmac_result[0]:
            print(f"✓ HMAC quebrado: {hmac_result[1].upper()}")
            print(f"✓ Chave encontrada: '{hmac_result[0]}'")
        
        print("\n🔧 PRÓXIMOS PASSOS:")
        print("1. Se HMAC foi quebrado, use a chave para gerar novas assinaturas")
        print("2. Se dados foram descomprimidos, analise o conteúdo")
        print("3. Analise o app Android para encontrar o algoritmo de encriptação")
        print("4. Verifique se há rotação de chaves baseada em timestamp")

def main():
    """Função principal"""
    breaker = DecryptBreaker()
    breaker.run_full_break()

if __name__ == "__main__":
    main()