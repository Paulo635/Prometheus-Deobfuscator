#!/usr/bin/env python3
"""
Script para analisar e tentar quebrar a encriptação dos parâmetros da requisição
"""

import requests
import base64
import hashlib
import json
import re
from urllib.parse import unquote
import time

def analyze_encrypted_data():
    """Analisa os dados encriptados da requisição"""
    
    # Dados originais da requisição
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
    
    print("=== ANÁLISE DOS DADOS ENCRIPTADOS ===\n")
    
    # Análise do parâmetro 'm' (provavelmente o payload principal encriptado)
    m_param = payload['m']
    print(f"Parâmetro 'm' (tamanho: {len(m_param)} caracteres):")
    print(f"Valor: {m_param[:100]}...")
    
    # Análise do parâmetro 's' (provavelmente signature/hash)
    s_param = payload['s']
    print(f"\nParâmetro 's' (tamanho: {len(s_param)} caracteres):")
    print(f"Valor: {s_param}")
    
    # Análise do parâmetro 'v' (versão)
    v_param = payload['v']
    print(f"\nParâmetro 'v' (versão): {v_param}")
    
    return url, payload, headers

def try_base64_decoding(encrypted_data):
    """Tenta decodificar dados em base64"""
    print("\n=== TENTATIVA DE DECODIFICAÇÃO BASE64 ===")
    
    try:
        # Tenta decodificar direto
        decoded = base64.b64decode(encrypted_data)
        print(f"Decodificação direta (hex): {decoded.hex()[:100]}...")
        
        # Tenta decodificar como string
        try:
            decoded_str = decoded.decode('utf-8')
            print(f"Decodificação como UTF-8: {decoded_str[:100]}...")
        except:
            print("Não é uma string UTF-8 válida")
            
        # Tenta decodificar como JSON
        try:
            json_data = json.loads(decoded_str)
            print(f"Decodificação como JSON: {json.dumps(json_data, indent=2)[:200]}...")
        except:
            print("Não é um JSON válido")
            
    except Exception as e:
        print(f"Erro na decodificação base64: {e}")
    
    return decoded if 'decoded' in locals() else None

def analyze_signature_pattern(signature):
    """Analisa o padrão da assinatura"""
    print("\n=== ANÁLISE DA ASSINATURA ===")
    
    print(f"Assinatura: {signature}")
    print(f"Tamanho: {len(signature)} caracteres")
    print(f"Formato: {'hex' if re.match(r'^[a-f0-9]+$', signature) else 'outro'}")
    
    # Verifica se é um hash MD5, SHA1, SHA256, etc.
    hash_lengths = {
        32: "MD5",
        40: "SHA1", 
        64: "SHA256",
        128: "SHA512"
    }
    
    if len(signature) in hash_lengths:
        print(f"Possível tipo de hash: {hash_lengths[len(signature)]}")
    
    return signature

def try_reverse_engineering(payload, headers):
    """Tenta engenharia reversa dos parâmetros"""
    print("\n=== TENTATIVA DE ENGENHARIA REVERSA ===")
    
    # Analisa headers para entender o contexto
    print("Headers da requisição:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    
    # Analisa padrões nos parâmetros
    print(f"\nPadrões identificados:")
    print(f"- App ID: {headers.get('Vod-AppId')}")
    print(f"- Versão do App: {headers.get('Vod-AppVer')}")
    print(f"- Marca: {headers.get('Vod-Brand')}")
    print(f"- User Agent: {headers.get('User-Agent')}")
    
    # Tenta identificar o algoritmo de hash da assinatura
    s_param = payload['s']
    if len(s_param) == 40:  # SHA1
        print(f"\nAssinatura parece ser SHA1 (40 caracteres hex)")
        print("Possível algoritmo: HMAC-SHA1 com chave secreta")
    
    return True

def test_request_with_modified_params(url, payload, headers):
    """Testa a requisição com parâmetros modificados"""
    print("\n=== TESTE DE REQUISIÇÃO ===")
    
    try:
        # Requisição original
        print("Fazendo requisição original...")
        response = requests.post(url, data=payload, headers=headers, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Resposta: {response.text[:200]}...")
        
        # Testa com parâmetros modificados
        print("\nTestando com parâmetros modificados...")
        
        # Testa sem o parâmetro 's'
        test_payload = payload.copy()
        del test_payload['s']
        
        response2 = requests.post(url, data=test_payload, headers=headers, timeout=10)
        print(f"Sem assinatura - Status: {response2.status_code}")
        print(f"Resposta: {response2.text[:200]}...")
        
        # Testa com versão diferente
        test_payload2 = payload.copy()
        test_payload2['v'] = "5"
        
        response3 = requests.post(url, data=test_payload2, headers=headers, timeout=10)
        print(f"Versão 5 - Status: {response3.status_code}")
        print(f"Resposta: {response3.text[:200]}...")
        
    except Exception as e:
        print(f"Erro na requisição: {e}")

def generate_test_signatures(payload_data):
    """Gera assinaturas de teste para comparação"""
    print("\n=== GERAÇÃO DE ASSINATURAS DE TESTE ===")
    
    # Remove a assinatura atual para testar
    test_data = payload_data.copy()
    del test_data['s']
    
    # Gera diferentes tipos de hash
    data_string = "&".join([f"{k}={v}" for k, v in test_data.items()])
    
    print(f"Dados para hash: {data_string}")
    
    # MD5
    md5_hash = hashlib.md5(data_string.encode()).hexdigest()
    print(f"MD5: {md5_hash}")
    
    # SHA1
    sha1_hash = hashlib.sha1(data_string.encode()).hexdigest()
    print(f"SHA1: {sha1_hash}")
    
    # SHA256
    sha256_hash = hashlib.sha256(data_string.encode()).hexdigest()
    print(f"SHA256: {sha256_hash}")
    
    # Compara com a assinatura original
    original_sig = payload_data['s']
    print(f"\nAssinatura original: {original_sig}")
    
    if sha1_hash == original_sig:
        print("✓ Assinatura SHA1 simples encontrada!")
    elif md5_hash == original_sig:
        print("✓ Assinatura MD5 simples encontrada!")
    elif sha256_hash == original_sig:
        print("✓ Assinatura SHA256 simples encontrada!")
    else:
        print("✗ Nenhuma assinatura simples encontrada")
        print("Provavelmente usa HMAC ou algoritmo customizado")

def main():
    """Função principal"""
    print("🔓 ANALISADOR DE ENCRIPTAÇÃO - EPPI BRASIL VOD")
    print("=" * 60)
    
    # Analisa os dados
    url, payload, headers = analyze_encrypted_data()
    
    # Tenta decodificar o parâmetro 'm'
    decoded_m = try_base64_decoding(payload['m'])
    
    # Analisa a assinatura
    analyze_signature_pattern(payload['s'])
    
    # Tenta engenharia reversa
    try_reverse_engineering(payload, headers)
    
    # Gera assinaturas de teste
    generate_test_signatures(payload)
    
    # Testa requisições
    test_request_with_modified_params(url, payload, headers)
    
    print("\n" + "=" * 60)
    print("✅ ANÁLISE CONCLUÍDA")
    print("\nPróximos passos sugeridos:")
    print("1. Analisar o app Android para encontrar o algoritmo de hash")
    print("2. Verificar se usa HMAC com chave secreta")
    print("3. Analisar o código JavaScript se for web app")
    print("4. Verificar se há rotação de chaves ou timestamps")

if __name__ == "__main__":
    main()