# 🎯 INSTRUÇÕES FINAIS - QUEBRA DE ENCRIPTAÇÃO EPPI BRASIL VOD

## 📊 RESUMO DO QUE FOI DESCOBERTO

### ✅ ENCRIPTAÇÃO IDENTIFICADA
- **Algoritmo**: AES (Advanced Encryption Standard)
- **Tamanho da chave**: 128, 192 ou 256 bits
- **Modo de operação**: Provavelmente CBC ou GCM
- **Tamanho dos dados**: 560 bytes (35 blocos de 16 bytes)
- **Entropia**: 7.66 (alta entropia = dados encriptados)

### ✅ ASSINATURA IDENTIFICADA
- **Tipo**: SHA1 (40 caracteres hex)
- **Método**: HMAC-SHA1 com chave secreta
- **Valor**: `d06f8426db30339ae49d921d371146b18d03a5cf`
- **Status**: Não foi possível quebrar com chaves comuns

### ✅ PROTOCOLO IDENTIFICADO
- **Versão**: 6
- **Plataforma**: Android (okhttp/3.12.0)
- **App**: EPPI Brasil VOD Mobile v4000266
- **URL**: `http://vod.eppibrasil.com/sdk/user/auth/login/v1`

## 🔓 COMO QUEBRAR A ENCRIPTAÇÃO

### 1. 🔍 ENGENHARIA REVERSA DO APP ANDROID
```bash
# 1. Baixe o APK do app EPPI Brasil VOD
# 2. Decompile usando ferramentas como:
#    - apktool
#    - jadx
#    - dex2jar

# 3. Procure por:
#    - Chaves de encriptação hardcoded
#    - Algoritmos de hash (HMAC-SHA1)
#    - Implementações de AES
#    - Código de geração de assinaturas
```

### 2. 🌐 ANÁLISE DE TRÁFEGO
```bash
# 1. Use ferramentas como:
#    - Burp Suite
#    - Wireshark
#    - Fiddler
#    - Charles Proxy

# 2. Capture múltiplas requisições para:
#    - Identificar padrões de mudança
#    - Verificar rotação de chaves
#    - Analisar outras rotas da API
```

### 3. 💻 ANÁLISE DE CÓDIGO
```bash
# 1. Verifique se há web app com JavaScript
# 2. Procure por chaves em:
#    - Variáveis de ambiente
#    - Arquivos de configuração
#    - Logs de debug
#    - Versões não ofuscadas
```

## 🛠️ FERRAMENTAS RECOMENDADAS

### Para Engenharia Reversa
- **apktool**: Decompilação de APKs
- **jadx**: Decompilação Java/DEX
- **dex2jar**: Conversão DEX para JAR
- **JD-GUI**: Visualização de código Java

### Para Análise de Tráfego
- **Burp Suite**: Proxy e análise de requisições
- **Wireshark**: Captura de pacotes de rede
- **Fiddler**: Proxy para aplicações
- **Charles Proxy**: Proxy para desenvolvimento

### Para Criptografia
- **OpenSSL**: Ferramentas de linha de comando
- **CyberChef**: Análise e manipulação de dados
- **Hashcat**: Quebra de hashes por força bruta
- **John the Ripper**: Quebra de senhas

## 🔑 PRÓXIMOS PASSOS

### Passo 1: Obter o APK
```bash
# Baixe o APK do app EPPI Brasil VOD
# Use sites como:
# - APKMirror
# - APKPure
# - Google Play Store (se tiver acesso)
```

### Passo 2: Decompilar
```bash
# Decompile o APK
apktool d eppi_brasil_vod.apk -o decompiled_app

# Ou use jadx
jadx -d decompiled_app eppi_brasil_vod.apk
```

### Passo 3: Procurar por Chaves
```bash
# Procure por strings relacionadas
grep -r "AES\|HMAC\|SHA1\|encrypt\|decrypt" decompiled_app/

# Procure por chaves hardcoded
grep -r "secret\|key\|password\|token" decompiled_app/
```

### Passo 4: Analisar Código
```bash
# Procure por implementações de criptografia
find decompiled_app/ -name "*.java" -exec grep -l "Cipher\|SecretKey" {} \;

# Procure por geração de assinaturas
find decompiled_app/ -name "*.java" -exec grep -l "MessageDigest\|Mac" {} \;
```

## 📋 EXEMPLO DE CÓDIGO ESPERADO

### Implementação AES (provavelmente)
```java
// Exemplo do que procurar no código
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
byte[] encrypted = cipher.doFinal(data);
```

### Implementação HMAC-SHA1 (provavelmente)
```java
// Exemplo do que procurar no código
Mac mac = Mac.getInstance("HmacSHA1");
SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA1");
mac.init(keySpec);
byte[] signature = mac.doFinal(data);
String hexSignature = bytesToHex(signature);
```

## ⚠️ AVISOS IMPORTANTES

1. **Fins Educacionais**: Este material é para pesquisa e aprendizado
2. **Termos de Serviço**: Respeite os termos do sistema EPPI
3. **Ambiente Controlado**: Use apenas em ambientes de teste
4. **Não Malicioso**: Não use para atividades prejudiciais
5. **Responsabilidade**: Você é responsável pelo uso das informações

## 🎯 OBJETIVO FINAL

**Quebrar a encriptação AES + HMAC-SHA1 para:**
- Entender como os dados são encriptados
- Gerar novas assinaturas válidas
- Modificar requisições de forma segura
- Aprender sobre implementações de segurança

## 📞 SUPORTE

Para dúvidas ou problemas:
1. Verifique os logs de erro dos scripts
2. Confirme se todas as dependências estão instaladas
3. Verifique se o servidor está acessível
4. Use os scripts em ordem: `simple_decrypt.py` → `decrypt_breaker.py` → `final_analysis.py`

---

**🚀 BOA SORTE NA QUEBRA DA ENCRIPTAÇÃO! 🚀**

*Lembre-se: O conhecimento é poder, use-o com responsabilidade.*