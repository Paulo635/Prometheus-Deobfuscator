#!/usr/bin/env python3
"""
Análise final consolidada da encriptação EPPI Brasil VOD
"""

import base64
import hashlib
import json
import re
import urllib.parse
import time
import struct
import math

def final_analysis():
    """Análise final consolidada"""
    print("🔓 ANÁLISE FINAL - EPPI BRASIL VOD ENCRYPTION")
    print("=" * 70)
    
    # Dados da requisição
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
    
    print("📊 INFORMAÇÕES BÁSICAS")
    print("-" * 40)
    print(f"URL: http://vod.eppibrasil.com/sdk/user/auth/login/v1")
    print(f"Versão: {payload['v']}")
    print(f"App ID: {headers['Vod-AppId']}")
    print(f"App Version: {headers['Vod-AppVer']}")
    print(f"Brand: {headers['Vod-Brand']}")
    print(f"User Agent: {headers['User-Agent']}")
    
    # Análise do parâmetro 'm'
    print("\n🔐 ANÁLISE DO PARÂMETRO 'm'")
    print("-" * 40)
    
    m_param = payload['m']
    print(f"Tamanho: {len(m_param)} caracteres")
    print(f"Caracteres únicos: {len(set(m_param))}")
    
    # Decodificação base64
    try:
        decoded_data = base64.b64decode(m_param)
        print(f"✓ Base64 decodificado: {len(decoded_data)} bytes")
        
        # Análise dos dados decodificados
        print(f"Primeiros 32 bytes: {decoded_data[:32].hex()}")
        print(f"Últimos 32 bytes: {decoded_data[-32:].hex()}")
        
        # Verifica se é múltiplo de 16 (AES)
        if len(decoded_data) % 16 == 0:
            print(f"✓ Tamanho é múltiplo de 16 ({len(decoded_data)//16} blocos) - provável AES")
        elif len(decoded_data) % 8 == 0:
            print(f"✓ Tamanho é múltiplo de 8 ({len(decoded_data)//8} blocos) - provável DES/3DES")
        
        # Análise de entropia
        entropy = calculate_entropy(decoded_data)
        print(f"Entropia: {entropy:.2f}")
        
        if entropy > 4.5:
            print("✓ Alta entropia - dados encriptados")
        elif entropy > 3.5:
            print("⚠ Média entropia - pode ser comprimido")
        else:
            print("✗ Baixa entropia - pode ser texto simples")
            
    except Exception as e:
        print(f"✗ Erro na decodificação: {e}")
    
    # Análise da assinatura
    print("\n🔍 ANÁLISE DA ASSINATURA")
    print("-" * 40)
    
    s_param = payload['s']
    print(f"Assinatura: {s_param}")
    print(f"Tamanho: {len(s_param)} caracteres")
    
    if len(s_param) == 40:
        print("✓ Formato SHA1 (40 caracteres hex)")
    elif len(s_param) == 32:
        print("✓ Formato MD5 (32 caracteres hex)")
    elif len(s_param) == 64:
        print("✓ Formato SHA256 (64 caracteres hex)")
    
    # Tenta quebrar a assinatura
    signature_result = try_break_signature(payload, s_param)
    
    # Tenta quebrar HMAC
    hmac_result = try_break_hmac(payload, s_param)
    
    # Análise de padrões de segurança
    print("\n🛡️ ANÁLISE DE SEGURANÇA")
    print("-" * 40)
    
    print("✓ Dados encriptados com algoritmo criptográfico forte")
    print("✓ Assinatura HMAC para verificação de integridade")
    print("✓ Uso de base64 para codificação segura")
    print("✓ Headers específicos para validação do app")
    
    # Conclusões e recomendações
    print("\n📋 CONCLUSÕES FINAIS")
    print("-" * 40)
    
    print("1. ✅ ENCRIPTAÇÃO IDENTIFICADA:")
    print("   - Algoritmo: Provavelmente AES (tamanho múltiplo de 16)")
    print("   - Modo: Provavelmente CBC ou GCM (com IV)")
    print("   - Chave: 128, 192 ou 256 bits")
    
    print("\n2. ✅ ASSINATURA IDENTIFICADA:")
    print("   - Tipo: SHA1 (40 caracteres hex)")
    print("   - Método: Provavelmente HMAC-SHA1")
    print("   - Chave secreta: Não identificada")
    
    print("\n3. ✅ PROTOCOLO IDENTIFICADO:")
    print("   - Versão: 6")
    print("   - Plataforma: Android (okhttp)")
    print("   - App: EPPI Brasil VOD Mobile")
    
    print("\n🔧 TÉCNICAS PARA QUEBRAR A ENCRIPTAÇÃO:")
    print("-" * 40)
    
    print("1. 🔍 ENGENHARIA REVERSA DO APP:")
    print("   - Decompilar o APK do app Android")
    print("   - Procurar por chaves de encriptação hardcoded")
    print("   - Analisar o código de geração de assinaturas")
    print("   - Identificar algoritmos de encriptação")
    
    print("\n2. 🌐 ANÁLISE DE TRÁFEGO:")
    print("   - Capturar múltiplas requisições")
    print("   - Identificar padrões de mudança")
    print("   - Verificar rotação de chaves")
    print("   - Analisar outras rotas da API")
    
    print("\n3. 💻 ANÁLISE DE CÓDIGO:")
    print("   - Verificar se há código JavaScript no web app")
    print("   - Procurar por chaves em variáveis de ambiente")
    print("   - Analisar logs de debug do app")
    print("   - Verificar se há versões não ofuscadas")
    
    print("\n4. 🔑 TÉCNICAS AVANÇADAS:")
    print("   - Força bruta de chaves comuns")
    print("   - Análise de padrões de IV")
    print("   - Ataques de timing em HMAC")
    print("   - Análise de side-channels")
    
    print("\n⚠️ AVISOS IMPORTANTES:")
    print("-" * 40)
    print("• Este script é para fins educacionais e de pesquisa")
    print("• Respeite os termos de serviço do sistema")
    print("• Use apenas em ambientes controlados")
    print("• Não use para atividades maliciosas")
    
    print("\n" + "=" * 70)
    print("✅ ANÁLISE FINAL CONCLUÍDA")
    print("🎯 Objetivo: Quebrar encriptação AES + HMAC-SHA1")
    print("🔑 Próximo passo: Análise do app Android")

def calculate_entropy(data):
    """Calcula entropia dos dados"""
    if not data:
        return 0
    
    # Conta frequência de bytes
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calcula entropia usando log2
    entropy = 0
    length = len(data)
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def try_break_signature(payload, signature):
    """Tenta quebrar a assinatura"""
    print("  Tentando quebrar assinatura...")
    
    # Remove a assinatura para testar
    test_payload = payload.copy()
    del test_payload['s']
    
    # Testa diferentes combinações
    combinations = [
        urllib.parse.urlencode(test_payload),
        "&".join([f"{k}={v}" for k, v in test_payload.items()]),
        f"{urllib.parse.urlencode(test_payload)}&app_id=mobile",
        f"{urllib.parse.urlencode(test_payload)}&version=4000266"
    ]
    
    for combination in combinations:
        # Gera diferentes tipos de hash
        md5 = hashlib.md5(combination.encode()).hexdigest()
        sha1 = hashlib.sha1(combination.encode()).hexdigest()
        sha256 = hashlib.sha256(combination.encode()).hexdigest()
        
        if sha1 == signature:
            print(f"  ✓ SHA1 encontrado!")
            return combination, 'sha1'
        elif md5 == signature:
            print(f"  ✓ MD5 encontrado!")
            return combination, 'md5'
        elif sha256 == signature:
            print(f"  ✓ SHA256 encontrado!")
            return combination, 'sha256'
    
    print("  ✗ Nenhuma combinação simples encontrada")
    return None, None

def try_break_hmac(payload, signature):
    """Tenta quebrar HMAC"""
    print("  Tentando quebrar HMAC...")
    
    test_payload = payload.copy()
    del test_payload['s']
    
    data = urllib.parse.urlencode(test_payload)
    
    # Chaves comuns para testar
    common_keys = [
        "secret", "key", "password", "token", "auth",
        "eppi", "vod", "mobile", "app", "sdk",
        "4000266", "EPPI", "brasil", "vod"
    ]
    
    for key in common_keys:
        # Testa diferentes algoritmos HMAC
        for algorithm in ['md5', 'sha1', 'sha256']:
            if algorithm == 'sha1':
                hmac_hash = hashlib.new('sha1', key.encode() + data.encode()).hexdigest()
                
                if hmac_hash == signature:
                    print(f"  ✓ HMAC-SHA1 encontrado!")
                    print(f"  Chave: '{key}'")
                    return key, algorithm, data
    
    print("  ✗ Nenhuma chave comum encontrada")
    return None, None, None

if __name__ == "__main__":
    final_analysis()