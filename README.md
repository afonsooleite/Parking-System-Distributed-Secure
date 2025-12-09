# Distributed & Secure Parking Management System (FSD 2025/26)

Sistema distribuído para gestão de parques de estacionamento, desenvolvido na UC **Fundamentos de Sistemas Distribuídos** — Universidade do Minho.

O sistema suporta:
- Comunicação TCP com sensores de lugar (multithreading)
- API REST pública para descoberta e consulta de parques
- Registo e monitorização distribuída através de um Gestor Central
- Criptografia RSA e certificados digitais (Fase 4 — Segurança)

> Objetivo: construir um ecossistema distribuído e seguro para monitorizar ocupação em tempo real e disponibilizar informação a clientes web.

---

## 📌 Fases de Implementação

| Fase | Funcionalidade |
|------|----------------|
| 1 | TCP: comunicação Lugar ↔ Parque (threads e protocolo)
| 2 | API REST: /parque, /info, /custo  
| 3 | Cliente Web dinâmico (atualização da lista de parques)  
| 4 | Segurança: RSA + Certificados + Assinaturas digitais 

> Ciclo de vida conforme o enunciado FSD2025/26 — Fases 1–4 

---

## Componentes

| Componente | Tecnologia | Função |
|-----------|------------|--------|
| Lugar | TCP + threads | Simula sensores + eventos de ocupação |
| Parque | TCP + Flask REST | Gestão de lugares + API segura |
| Gestor Central | REST (fornecido) | Registo e certificação dos parques |
| Cliente Web | HTML/JS | Consulta pública |

---

## Segurança (Fase 4)
### Certificados

- RSA Key Pair gerado pelo Parque na inicialização
- Parque regista chave pública no Gestor via `/parque_certificado`
- Gestor devolve **certificado digital em PEM** codificado em UTF-8

---

### Assinatura e validação

- Assinatura RSA com:
  - Padding: **PSS**
  - Hash: **SHA-256**
- Assinatura enviada em JSON usando codificação **cp437**
- Certificado sempre enviado no corpo de resposta

Endpoints seguros:

| URL | Método | Descrição |
|-----|--------|-----------|
| `/secure/info` | GET | Lista informações + certificado + assinatura |
| `/secure/custo?tempo=X` | GET | Assina o valor calculado |

---

## Protocolo TCP

- Pedido–Resposta
- Tratamento de erros do sensor:
  - id inválido
  - formato inválido
  - mensagens incompletas

Gestão interna do estado:
- Nome, tarifas, coordenadas, capacidade e lugares livres

---

## Cliente Web

- Consulta lista de parques no Gestor
- Seleção de parque e consumo dos endpoints
- Atualização dinâmica do estado

---

## Tecnologias

- Python 3
- Flask
- Sockets TCP
- RSA (cryptography)
- HTML / JavaScript

---





