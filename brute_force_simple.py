#!/usr/bin/env python3
"""
Script de força bruta simplificado para quebrar a encriptação EPPI Brasil VOD
"""

import base64
import hashlib
import json
import urllib.parse
import time
import math

def brute_force_hmac():
    """Força bruta de chaves HMAC"""
    print("🔐 FORÇA BRUTA DE CHAVES HMAC")
    print("=" * 50)
    
    signature = "d06f8426db30339ae49d921d371146b18d03a5cf"
    test_payload = {
        'v': "6",
        'm': "S0JeqtdFI30eW7aSUNSFBC5d7bPW3exsWoNPE0VSGj4eqKq68lYB/JL0fOKgDgGPCfiX0hiG0c5xBgdKe5LS4732vxe7y0rKk1qmZOuMrIJPmSkNiJw7q+jv+rS2uT4SagbERYHrBxmV+q7Zoql7el+w1YuPvqqv6OrMKYg/aZ/WTe3F3qP0IbguZ18Bhu3oB4NKcwRCAAOlSrUocGfG79kYIMXUID8MbMLr93Ri4CNbAQXZ3ADcqSFH7RUb1GEidMddEBNd74/9D6zllRQmfpzOdnsqz9xPnJ/T92FsOGtqnloz/8CC+zEUlaBX75CrgOxP2j6dH8U0xZVcUfSzqlrYcmG9J36Nb/8aLbyMpf9bltV2iUahlNFTYvBfObUhwy0ILVQmUZKE/olwMWuryRV7IE4Qsnz3YBSq2WErM8HxkjJSGc54oV2X9fDHapYDd+GJZr8Jy1whCjP6gY1TVN6ju+u6rh5mNHkRch2S22ffbSaLfJ4TgUXa8s+Jndj4onGco6ce9m4eLhi1OWEFBnIyksGEMKLHmVFlnVP8Hulb/7uEOYo6tZL9r5tbHZYahUwLc/176o9I9/3ojdjfAVD5nsi5XGOWpHqsXk1XrTFsZOFTrh6Dda7HDfSVVpqmAs6MIjfVMuHwh7spprRzBV/vPzz76NpTM4Wh4pgIEs2onoBbVXTKXlSJW0PupsvtsbYDc1hEs32OSxhTvyZtqWDsS/gdg+kIlmC5vHs33tg="
    }
    
    # Dados para hash
    data = urllib.parse.urlencode(test_payload)
    
    # Chaves comuns para testar
    common_keys = [
        "secret", "key", "password", "token", "auth",
        "eppi", "vod", "mobile", "app", "sdk",
        "4000266", "EPPI", "brasil", "vod",
        "user", "login", "auth", "v1",
        "eppi_secret", "vod_key", "mobile_auth",
        "app_secret", "sdk_key", "brasil_secret",
        "login_key", "auth_secret", "v1_key",
        "eppi_vod", "mobile_sdk", "brasil_auth",
        "4000266_secret", "EPPI_key", "vod_mobile",
        "123456", "password123", "admin", "root",
        "eppibrasil", "vodbrasil", "mobilevod",
        "eppi2024", "vod2024", "mobile2024",
        "brasilvod", "vodmobile", "mobilebrasil"
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

def try_advanced_combinations():
    """Tenta combinações avançadas"""
    print("\n🚀 TENTANDO COMBINAÇÕES AVANÇADAS")
    print("=" * 50)
    
    signature = "d06f8426db30339ae49d921d371146b18d03a5cf"
    test_payload = {
        'v': "6",
        'm': "S0JeqtdFI30eW7aSUNSFBC5d7bPW3exsWoNPE0VSGj4eqKq68lYB/JL0fOKgDgGPCfiX0hiG0c5xBgdKe5LS4732vxe7y0rKk1qmZOuMrIJPmSkNiJw7q+jv+rS2uT4SagbERYHrBxmV+q7Zoql7el+w1YuPvqqv6OrMKYg/aZ/WTe3F3qP0IbguZ18Bhu3oB4NKcwRCAAOlSrUocGfG79kYIMXUID8MbMLr93Ri4CNbAQXZ3ADcqSFH7RUb1GEidMddEBNd74/9D6zllRQmfpzOdnsqz9xPnJ/T92FsOGtqnloz/8CC+zEUlaBX75CrgOxP2j6dH8U0xZVcUfSzqlrYcmG9J36Nb/8aLbyMpf9bltV2iUahlNFTYvBfObUhwy0ILVQmUZKE/olwMWuryRV7IE4Qsnz3YBSq2WErM8HxkjJSGc54oV2X9fDHapYDd+GJZr8Jy1whCjP6gY1TVN6ju+u6rh5mNHkRch2S22ffbSaLfJ4TgUXa8s+Jndj4onGco6ce9m4eLhi1OWEFBnIyksGEMKLHmVFlnVP8Hulb/7uEOYo6tZL9r5tbHZYahUwLc/176o9I9/3ojdjfAVD5nsi5XGOWpHqsXk1XrTFsZOFTrh6Dda7HDfSVVpqmAs6MIjfVMuHwh7spprRzBV/vPzz76NpTM4Wh4pgIEs2onoBbVXTKXlSJW0PupsvtsbYDc1hEs32OSxhTvyZtqWDsS/gdg+kIlmC5vHs33tg="
    }
    
    # Combinações mais complexas
    advanced_combinations = [
        f"{urllib.parse.urlencode(test_payload)}&ts={int(time.time())}",
        f"{urllib.parse.urlencode(test_payload)}&timestamp={int(time.time())}",
        f"{urllib.parse.urlencode(test_payload)}&did=35e86bccb97aec8d",
        f"{urllib.parse.urlencode(test_payload)}&device_id=35e86bccb97aec8d",
        f"{urllib.parse.urlencode(test_payload)}&uid=-1",
        f"{urllib.parse.urlencode(test_payload)}&user_id=-1",
        f"{urllib.parse.urlencode(test_payload)}&app_id=mobile&version=4000266&brand=EPPI",
        f"{urllib.parse.urlencode(test_payload)}&mobile&4000266&EPPI",
        f"mobile&4000266&EPPI&{urllib.parse.urlencode(test_payload)}",
        f"EPPI&brasil&vod&{urllib.parse.urlencode(test_payload)}",
        f"vod&mobile&{urllib.parse.urlencode(test_payload)}&brasil",
        f"secret&{urllib.parse.urlencode(test_payload)}",
        f"key&{urllib.parse.urlencode(test_payload)}",
        f"auth&{urllib.parse.urlencode(test_payload)}",
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

def main():
    """Função principal"""
    print("💪 INICIANDO FORÇA BRUTA COMPLETA")
    print("=" * 60)
    
    start_time = time.time()
    
    # 1. Força bruta HMAC
    print("\n🔐 ETAPA 1: FORÇA BRUTA HMAC")
    hmac_result = brute_force_hmac()
    
    # 2. Combinações avançadas
    print("\n🚀 ETAPA 2: COMBINAÇÕES AVANÇADAS")
    combo_result = try_advanced_combinations()
    
    # Resumo
    end_time = time.time()
    total_time = end_time - start_time
    
    print("\n" + "=" * 60)
    print("📊 RESUMO DA FORÇA BRUTA")
    print("=" * 60)
    
    print(f"Tempo total: {total_time:.2f} segundos")
    
    if hmac_result[0]:
        print(f"✓ HMAC quebrado: {hmac_result[1].upper()} com chave '{hmac_result[0]}'")
    
    if combo_result[0]:
        print(f"✓ Assinatura quebrada: {combo_result[1].upper()}")
    
    if not any([hmac_result[0], combo_result[0]]):
        print("✗ Nenhuma chave foi quebrada")
        print("\n🔧 PRÓXIMOS PASSOS:")
        print("1. Tentar mais variações de chaves")
        print("2. Análise do app Android")
        print("3. Captura de mais requisições")
        print("4. Análise de padrões de tráfego")
    
    return hmac_result, combo_result

if __name__ == "__main__":
    main()