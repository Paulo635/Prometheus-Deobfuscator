#!/usr/bin/env python3
"""
Script simplificado para análise da encriptação usando apenas bibliotecas padrão
"""

import base64
import hashlib
import json
import re
import urllib.parse
import time

def analyze_encryption():
    """Análise básica da encriptação"""
    print("🔓 ANÁLISE DE ENCRIPTAÇÃO - EPPI BRASIL VOD")
    print("=" * 60)
    
    # Dados da requisição
    url = "http://vod.eppibrasil.com/sdk/user/auth/login/v1"
    
    payload = {
        'v': "6",
        'm': "S0JeqtdFI30eW7aSUNSFBC5d7bPW3exsWoNPE0VSGj4eqKq68lYB/JL0fOKgDgGPCfiX0hiG0c5xBgdKe5LS4732vxe7y0rKk1qmZOuMrIJPmSkNiJw7q+jv+rS2uT4SagbERYHrBxmV+q7Zoql7el+w1YuPvqqv6OrMKYg/aZ/WTe3F3qP0IbguZ18Bhu3oB4NKcwRCAAOlSrUocGfG79kYIMXUID8MbMLr93Ri4CNbAQXZ3ADcqSFH7RUb1GEidMddEBNd74/9D6zllRQmfpzOdnsqz9xPnJ/T92FsOGtqnloz/8CC+zEUlaBX75CrgOxP2j6dH8U0xZVcUfSzqlrYcmG9J36Nb/8aLbyMpf9bltV2iUahlNFTYvBfObUhwy0ILVQmUZKE/olwMWuryRV7IE4Qsnz3YBSq2WErM8HxkjJSGc54oV2X9fDHapYDd+GJZr8Jy1whCjP6gY1TVN6ju+u6rh5mNHkRch2S22ffbSaLfJ4TgUXa8s+Jndj4onGco6ce9m4eLhi1OWEFBnIyksGEMKLHmVFlnVP8Hulb/7uEOYo6tZL9r5tbHZYahUwLc/176o9I9/3ojdjfAVD5nsi5XGOWpHqsXk1XrTFsZOFTrh6Dda7HDfSVVpqmAs6MIjfVMuHwh7spprRzBV/vPzz76NpTM4Wh4pgIEs2onoBbVXTKXlSJW0PupsvtsbYDc1hEs32OSxhTvyZtqWDsS/gdg+kIlmC5vHs33tg=",
        's': "d06f8426db30339ae49d921d371146b18d03a5cf"
    }
    
    headers = {
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
    
    print(f"URL: {url}")
    print(f"Parâmetros: {len(payload)}")
    print(f"Headers: {len(headers)}")
    
    # Análise do parâmetro 'm'
    print("\n📝 ANÁLISE DO PARÂMETRO 'm'")
    print("-" * 40)
    
    m_param = payload['m']
    print(f"Tamanho: {len(m_param)} caracteres")
    print(f"Caracteres únicos: {len(set(m_param))}")
    print(f"Primeiros 50 chars: {m_param[:50]}...")
    print(f"Últimos 50 chars: {m_param[-50:]}...")
    
    # Verifica se é base64 válido
    try:
        decoded_m = base64.b64decode(m_param)
        print(f"✓ Base64 válido! Decodificado para {len(decoded_m)} bytes")
        print(f"Primeiros bytes (hex): {decoded_m[:32].hex()}")
        
        # Análise dos dados decodificados
        analyze_decoded_data(decoded_m)
        
    except Exception as e:
        print(f"✗ Erro na decodificação base64: {e}")
        
        # Tenta com padding
        try:
            padded = m_param + "=" * (4 - len(m_param) % 4)
            decoded_m = base64.b64decode(padded)
            print(f"✓ Base64 com padding válido! {len(decoded_m)} bytes")
            analyze_decoded_data(decoded_m)
        except Exception as e2:
            print(f"✗ Também falhou com padding: {e2}")
    
    # Análise do parâmetro 's'
    print("\n🔐 ANÁLISE DO PARÂMETRO 's'")
    print("-" * 40)
    
    s_param = payload['s']
    print(f"Valor: {s_param}")
    print(f"Tamanho: {len(s_param)} caracteres")
    print(f"Formato hex: {bool(re.match(r'^[a-f0-9]+$', s_param))}")
    
    # Identifica tipo de hash
    hash_types = {
        32: "MD5",
        40: "SHA1",
        64: "SHA256",
        128: "SHA512"
    }
    
    hash_type = hash_types.get(len(s_param), "Desconhecido")
    print(f"Tipo provável: {hash_type}")
    
    # Tenta engenharia reversa da assinatura
    try_signature_reverse_engineering(payload, s_param)
    
    # Análise dos headers
    print("\n📋 ANÁLISE DOS HEADERS")
    print("-" * 40)
    
    for key, value in headers.items():
        print(f"{key}: {value}")
    
    # Análise de padrões
    print("\n🔍 ANÁLISE DE PADRÕES")
    print("-" * 40)
    
    print(f"App ID: {headers.get('Vod-AppId')}")
    print(f"Versão do App: {headers.get('Vod-AppVer')}")
    print(f"Marca: {headers.get('Vod-Brand')}")
    print(f"User Agent: {headers.get('User-Agent')}")
    
    # Verifica se é app Android
    if 'okhttp' in headers.get('User-Agent', ''):
        print("✓ Detectado: Aplicativo Android (okhttp)")
    
    if headers.get('Vod-AppId') == 'mobile':
        print("✓ Detectado: Versão mobile")
    
    # Conclusões
    print("\n📊 CONCLUSÕES")
    print("-" * 40)
    
    print("1. O parâmetro 'm' contém dados encriptados em base64")
    print("2. O parâmetro 's' é uma assinatura SHA1 (40 caracteres)")
    print("3. Provavelmente usa HMAC-SHA1 com chave secreta")
    print("4. A encriptação pode ser AES ou algoritmo similar")
    print("5. É um app Android usando okhttp")
    
    print("\n🔧 PRÓXIMOS PASSOS")
    print("-" * 40)
    
    print("1. Analisar o APK do app Android")
    print("2. Procurar por chaves de encriptação no código")
    print("3. Verificar se há rotação de chaves")
    print("4. Analisar outras rotas da API")
    
    print("\n" + "=" * 60)
    print("✅ ANÁLISE CONCLUÍDA")

def analyze_decoded_data(data):
    """Analisa dados decodificados"""
    print(f"  Analisando {len(data)} bytes...")
    
    # Tenta como string UTF-8
    try:
        text = data.decode('utf-8')
        print(f"  ✓ UTF-8 válido: {text[:100]}...")
        
        # Tenta como JSON
        try:
            json_data = json.loads(text)
            print(f"  ✓ JSON válido encontrado!")
            print(f"  Chaves: {list(json_data.keys())}")
        except:
            print("  ✗ Não é JSON válido")
            
    except UnicodeDecodeError:
        print("  ✗ Não é UTF-8 válido")
        print("  Provavelmente dados binários encriptados")
    
    # Análise de bytes
    if len(data) >= 4:
        # Verifica cabeçalhos conhecidos
        headers = {
            b'\x1f\x8b': 'GZIP',
            b'PK\x03\x04': 'ZIP',
            b'\x89PNG': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'GIF8': 'GIF'
        }
        
        for header, file_type in headers.items():
            if data.startswith(header):
                print(f"  ✓ Cabeçalho {file_type} detectado!")
                return
    
    # Verifica se parece ser dados encriptados
    if len(data) >= 16:
        # Calcula entropia dos primeiros bytes
        entropy = calculate_entropy(data[:16])
        print(f"  Entropia dos primeiros 16 bytes: {entropy:.2f}")
        
        if entropy > 4.0:
            print("  Alta entropia - provavelmente encriptado")
        elif entropy > 3.0:
            print("  Média entropia - pode ser comprimido")
        else:
            print("  Baixa entropia - pode ser texto simples")

def calculate_entropy(data):
    """Calcula entropia dos dados"""
    if not data:
        return 0
    
    # Conta frequência de bytes
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calcula entropia
    entropy = 0
    length = len(data)
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * (probability.bit_length() - 1)
    
    return entropy

def try_signature_reverse_engineering(payload, signature):
    """Tenta engenharia reversa da assinatura"""
    print("  Tentando engenharia reversa da assinatura...")
    
    # Remove a assinatura para testar
    test_payload = payload.copy()
    del test_payload['s']
    
    # Testa diferentes combinações
    test_combinations = [
        # Combinação simples
        urllib.parse.urlencode(test_payload),
        # Sem codificação
        "&".join([f"{k}={v}" for k, v in test_payload.items()]),
        # Com chaves ordenadas
        "&".join([f"{k}={v}" for k, v in sorted(test_payload.items())]),
        # Incluindo headers específicos
        f"{urllib.parse.urlencode(test_payload)}&app_id=mobile",
        f"{urllib.parse.urlencode(test_payload)}&version=4000266"
    ]
    
    print(f"  Testando {len(test_combinations)} combinações...")
    
    for i, combination in enumerate(test_combinations):
        # Gera diferentes tipos de hash
        md5 = hashlib.md5(combination.encode()).hexdigest()
        sha1 = hashlib.sha1(combination.encode()).hexdigest()
        sha256 = hashlib.sha256(combination.encode()).hexdigest()
        
        if sha1 == signature:
            print(f"  ✓ SHA1 encontrado! Combinação {i+1}")
            print(f"  Dados: {combination[:50]}...")
            return combination
        elif md5 == signature:
            print(f"  ✓ MD5 encontrado! Combinação {i+1}")
            return combination
        elif sha256 == signature:
            print(f"  ✓ SHA256 encontrado! Combinação {i+1}")
            return combination
    
    print("  ✗ Nenhuma combinação simples encontrada")
    print("  Provavelmente usa HMAC ou algoritmo customizado")
    
    return None

if __name__ == "__main__":
    analyze_encryption()