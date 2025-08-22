# 🔓 Scripts de Decriptação - EPPI Brasil VOD

Este conjunto de scripts Python foi criado para analisar e tentar quebrar a encriptação dos parâmetros da requisição de login do sistema EPPI Brasil VOD.

## 📁 Arquivos

- **`decrypt_analyzer.py`** - Script básico de análise e decriptação
- **`advanced_decrypt.py`** - Script avançado com múltiplas técnicas
- **`quick_test.py`** - Teste rápido para verificar funcionalidade
- **`requirements.txt`** - Dependências necessárias

## 🚀 Instalação

1. Instale as dependências:
```bash
pip install -r requirements.txt
```

2. Verifique se as bibliotecas estão funcionando:
```bash
python quick_test.py
```

## 📊 Análise dos Dados

### Parâmetros da Requisição

- **`v`**: Versão do protocolo (atualmente "6")
- **`m`**: Payload principal encriptado em base64
- **`s`**: Assinatura/hash de verificação (40 caracteres hex - SHA1)

### Headers Identificados

- **`Vod-AppId`**: "mobile" (aplicativo móvel)
- **`Vod-AppVer`**: "4000266" (versão do app)
- **`Vod-Brand`**: "EPPI" (marca)
- **`User-Agent`**: "okhttp/3.12.0" (cliente HTTP Android)

## 🔍 Técnicas de Análise

### 1. Decodificação Base64
- Decodificação direta do parâmetro `m`
- Verificação de padding
- Suporte a base64 URL-safe

### 2. Análise de Assinatura
- Identificação do tipo de hash (SHA1)
- Tentativa de engenharia reversa
- Teste de combinações de parâmetros

### 3. Força Bruta HMAC
- Teste de chaves comuns
- Múltiplos algoritmos (MD5, SHA1, SHA256)
- Análise de padrões de resposta

### 4. Testes de Requisição
- Modificação de parâmetros
- Análise de respostas de erro
- Identificação de validações

## 🎯 Como Usar

### Análise Básica
```bash
python decrypt_analyzer.py
```

### Análise Avançada
```bash
python advanced_decrypt.py
```

### Teste Rápido
```bash
python quick_test.py
```

## 📋 Resultados Esperados

### Parâmetro `m`
- **Status**: Encriptado e codificado em base64
- **Tamanho**: ~600 caracteres
- **Conteúdo**: Provavelmente dados de login encriptados

### Parâmetro `s`
- **Status**: Assinatura SHA1
- **Tamanho**: 40 caracteres hex
- **Algoritmo**: Provavelmente HMAC-SHA1 com chave secreta

## 🔧 Próximos Passos

1. **Análise do App Android**
   - Decompilar o APK
   - Procurar por chaves de encriptação
   - Analisar algoritmos de hash

2. **Engenharia Reversa**
   - Identificar a chave secreta
   - Entender o algoritmo de encriptação
   - Replicar o processo de geração

3. **Análise de Tráfego**
   - Capturar múltiplas requisições
   - Identificar padrões de mudança
   - Verificar rotação de chaves

## ⚠️ Avisos

- Este script é para fins educacionais e de pesquisa
- Respeite os termos de serviço do sistema
- Use apenas em ambientes controlados
- Não use para atividades maliciosas

## 🐛 Solução de Problemas

### Erro de Dependências
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Erro de Conexão
- Verifique a conectividade com a internet
- Confirme se o servidor está acessível
- Verifique se não há firewall bloqueando

### Erro de Timeout
- Aumente o timeout nas requisições
- Verifique a velocidade da conexão
- Tente em horários de menor tráfego

## 📞 Suporte

Para dúvidas ou problemas:
1. Verifique os logs de erro
2. Teste com `quick_test.py` primeiro
3. Verifique se todas as dependências estão instaladas
4. Confirme se o servidor está respondendo

## 🔄 Atualizações

- **v1.0**: Scripts básicos de análise
- **v1.1**: Adicionado suporte a múltiplas técnicas
- **v1.2**: Melhorias na análise de padrões
- **v1.3**: Suporte a diferentes algoritmos de hash

---

**Desenvolvido para análise de segurança e pesquisa educacional**