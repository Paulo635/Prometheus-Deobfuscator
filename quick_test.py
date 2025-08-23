#!/usr/bin/env python3
"""
Script de teste rápido para verificar a funcionalidade dos scripts de decriptação
"""

import requests
import base64
import hashlib
import json

def quick_analysis():
    """Análise rápida dos dados encriptados"""
    print("🔍 ANÁLISE RÁPIDA DOS DADOS ENCRIPTADOS")
    print("=" * 40)
    
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
    
    # 1. Análise básica
    print(f"URL: {url}")
    print(f"Parâmetro 'm': {len(payload['m'])} caracteres")
    print(f"Parâmetro 's': {len(payload['s'])} caracteres (SHA1)")
    print(f"Parâmetro 'v': {payload['v']}")
    
    # 2. Teste de decodificação base64
    print("\n📝 TESTANDO DECODIFICAÇÃO BASE64...")
    try:
        decoded_m = base64.b64decode(payload['m'])
        print(f"✓ Base64 decodificado com sucesso!")
        print(f"  Tamanho: {len(decoded_m)} bytes")
        print(f"  Primeiros bytes (hex): {decoded_m[:32].hex()}")
        
        # Tenta como string
        try:
            text = decoded_m.decode('utf-8')
            print(f"  ✓ UTF-8 válido: {text[:100]}...")
        except:
            print("  ✗ Não é UTF-8 válido")
            
    except Exception as e:
        print(f"✗ Erro na decodificação base64: {e}")
    
    # 3. Teste de assinatura
    print("\n🔐 TESTANDO ASSINATURA...")
    s_param = payload['s']
    if len(s_param) == 40:
        print("✓ Formato SHA1 detectado (40 caracteres hex)")
        
        # Testa se é hash simples dos parâmetros
        test_data = f"v={payload['v']}&m={payload['m']}"
        test_hash = hashlib.sha1(test_data.encode()).hexdigest()
        
        if test_hash == s_param:
            print("✓ Assinatura SHA1 simples encontrada!")
            print(f"  Dados: {test_data}")
        else:
            print("✗ Não é hash simples - provavelmente HMAC")
    
    # 4. Teste de requisição
    print("\n🌐 TESTANDO REQUISIÇÃO...")
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=10)
        print(f"✓ Requisição bem-sucedida!")
        print(f"  Status: {response.status_code}")
        print(f"  Resposta: {response.text[:200]}...")
        
        # Tenta parsear como JSON
        try:
            json_data = json.loads(response.text)
            print(f"  ✓ Resposta é JSON válido")
            print(f"  Chaves: {list(json_data.keys())}")
        except:
            print("  ✗ Resposta não é JSON válido")
            
    except Exception as e:
        print(f"✗ Erro na requisição: {e}")
    
    print("\n" + "=" * 40)
    print("✅ ANÁLISE RÁPIDA CONCLUÍDA")

if __name__ == "__main__":
    quick_analysis()