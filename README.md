# Distributed & Secure Parking Management System (FSD 2025/26)

Sistema distribuído para gestão de parques de estacionamento, desenvolvido na UC **Fundamentos de Sistemas Distribuídos** — Universidade do Minho.

O sistema suporta:
- Comunicação TCP com sensores de lugar (multithreading)
- API REST pública para descoberta e consulta de parques
- Registo e monitorização distribuída através de um Gestor Central
- Criptografia RSA e certificados digitais (Fase 4 — Segurança)

> Objetivo: construir um ecossistema distribuído e seguro para monitorizar ocupação em tempo real e disponibilizar informação a clientes web.

---

## 🧱 Arquitetura do Sistema

    ┌───────────────────────┐
    │ Gestor de Parques     │  (fornecido pela UC)
    │ Registo + Certificados│
    └────────┬──────────────┘
             ↓
┌──────────────┐ TCP ┌──────────────┐
│ Lugar(es) │────────▶│ Parque     │
│ (sensor) │◀────────│ Estacionam. │
└──────────────┘     └──────────────┘
│ ↑
│ │ REST (HTTP)
▼ │
┌────────────────┐
│ Cliente Web    │
│ (consulta)     │  
└────────────────┘

---

## 📌 Fases de Implementação

| Fase | Funcionalidade | Estado |
|------|----------------|--------|
| 1 | TCP: comunicação Lugar ↔ Parque (threads e protocolo)
| 2 | API REST: /parque, /info, /custo  
| 3 | Cliente Web dinâmico (atualização da lista de parques)  
| 4 | Segurança: RSA + Certificados + Assinaturas digitais 

> Ciclo de vida conforme o enunciado FSD2025/26 — Fases 1–4 :contentReference[oaicite:0]{index=0}

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

Implementado de acordo com as especificações do enunciado:

### Certificados

- RSA Key Pair gerado pelo Parque na inicialização
- Parque regista chave pública no Gestor via `/parque_certificado`
- Gestor devolve **certificado digital em PEM** codificado em UTF-8

Referência: requisitos de certificação e endpoints (pág. 9 do enunciado) :contentReference[oaicite:1]{index=1}

---

### Assinatura e validação

- Assinatura RSA com:
  - Padding: **PSS**
  - Hash: **SHA-256**
- Assinatura enviada em JSON usando codificação **cp437**
- Certificado sempre enviado no corpo de resposta

Referência: Regras completas de assinaturas (pág. 11) :contentReference[oaicite:2]{index=2}

Endpoints seguros:

| URL | Método | Descrição |
|-----|--------|-----------|
| `/secure/info` | GET | Lista informações + certificado + assinatura |
| `/secure/custo?tempo=X` | GET | Assina o valor calculado |

Referência: tabela de endpoints seguros (pág. 10) :contentReference[oaicite:3]{index=3}

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





