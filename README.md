# aws-solver

**Versão:** 1.0.0  
**Desenvolvido por:** oneplay team

---

## 📌 Sobre

**aws-solver** é um módulo Python para Kodi que resolve automaticamente o desafio WAF (Web Application Firewall) da **AWS WAF**, utilizado por sites para bloquear bots e scrapers.

Ele retorna uma sessão autenticada e pronta para uso, com o token `aws-waf-token` já configurado nos cookies, permitindo acessar sites protegidos de forma transparente.

---

## ✅ Recursos

- Resolução automática do desafio AWS WAF
- Retorna sessão `requests` autenticada e pronta para uso
- Suporte a proxy
- Compatível com a API do `requests`
- Implementado 100% em Python
- Leve e otimizado para Kodi

---

## 💻 Como usar

```python
from waf.solver import solve

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'

# Resolve o desafio e obtém a sessão autenticada
result, session = solve('https://site-protegido.com', UA)

# O token AWS WAF já está nos cookies da sessão
# Basta fazer as requisições normalmente
response = session.get('https://site-protegido.com/pagina')
print(response.text)
```

### 🌐 Com proxy

```python
result, session = solve('https://site-protegido.com', UA, proxy='http://meu-proxy:8080')

response = session.get('https://site-protegido.com/pagina')
print(response.text)
```

### 🍪 Acessando o token manualmente

```python
result, session = solve('https://site-protegido.com', UA)

token = result.get('token', '')

# Aplicando o token em uma sessão existente
session.cookies.set('aws-waf-token', token, domain='site-protegido.com')
```

### ⚠️ Tratando falha na resolução

```python
import requests

try:
    result, session = solve('https://site-protegido.com', UA)
    token = result.get('token', '')
except Exception:
    # Fallback para sessão simples sem token
    session = requests.Session()

response = session.get('https://site-protegido.com/pagina')
print(response.status_code)
```

---

## 🎖️ Créditos Especiais

Este projeto só existe graças ao trabalho brilhante de pessoas incríveis da comunidade open source.

---

### 🔑 aesgcm — gujal00

> **Repositório:** [github.com/gujal00](https://github.com/gujal00)

A implementação de criptografia **AES-GCM** usada internamente pelo aws-solver para processar e descriptografar os desafios da AWS WAF é baseada no trabalho do **gujal00**.

Criptografia aplicada corretamente em Python não é trivial — e o trabalho limpo e preciso do gujal00 tornou possível resolver desafios que, de outra forma, exigiriam uma implementação nativa muito mais complexa. Um crédito mais do que merecido. ✨

---

### 🛡️ aws-solver — switch3301

> **Repositório:** [github.com/switch3301](https://github.com/switch3301)

O núcleo de resolução do desafio AWS WAF deste módulo é baseado no trabalho incrível do **switch3301**.

Fazer engenharia reversa no sistema de proteção da AWS WAF e implementar um solver funcional em Python é um trabalho de altíssimo nível técnico. Sem esse projeto, acessar sites protegidos pela AWS WAF de forma programática seria praticamente inviável. Todo o mérito vai para o switch3301. 💪

---

*Feito com ❤️ pela **oneplay team***
