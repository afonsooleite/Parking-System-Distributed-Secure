import requests
from flask import Flask, jsonify, request, Response
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
import json
import os
from cryptography.exceptions import InvalidSignature


#  Configurações do Cliente Web
GESTOR_HOST = "192.168.233.151"
GESTOR_PORT = 8080

app = Flask(__name__)

# Tenta carregar a chave do Gestor criada no Passo 0 #fase 4
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MANAGER_CERT_PATH = os.path.join(BASE_DIR, "manager_cert.pem")

GESTOR_PUB_KEY = None
if os.path.exists(MANAGER_CERT_PATH):
    with open(MANAGER_CERT_PATH, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
        GESTOR_PUB_KEY = cert.public_key()
else:
    print(f"⚠️ AVISO: '{MANAGER_CERT_PATH}' não encontrado. Segurança comprometida.")


def validar_resposta_segura(dados):
    """
    Valida a cadeia de confiança e integridade:
      1) Certificado assinado pelo Gestor (PKCS1v15 + SHA256)
      2) Mensagem assinada pelo Parque (PSS + SHA256)
    """
    if not GESTOR_PUB_KEY:
        raise Exception("Chave do Gestor em falta")

    cert_pem = dados.get("certificado")
    assinatura_cp437 = dados.get("assinatura")
    mensagem = dados.get("mensagem")

    if not cert_pem or not assinatura_cp437 or mensagem is None:
        raise Exception("Dados de segurança incompletos")

    # 1. Validar certificado do Parque com a chave pública do Gestor
    try:
        cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
        GESTOR_PUB_KEY.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),  # conforme enunciado
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise Exception(f"Certificado inválido: {e}")

    # 2. Validar assinatura da mensagem com a chave pública do Parque
    try:
        from cryptography.exceptions import InvalidSignature

        parque_pub_key = cert.public_key()

        # assinatura (enunciado: cp437)
        sig_bytes = assinatura_cp437.encode("cp437")

        # construir candidatos de bytes para o que pode ter sido assinado
        candidatos_msg = []

        if isinstance(mensagem, dict):
            candidatos_msg.extend([
                json.dumps(mensagem).encode("utf-8"),
                json.dumps(mensagem, separators=(",", ":")).encode("utf-8"),
                json.dumps(mensagem, sort_keys=True).encode("utf-8"),
                json.dumps(mensagem, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                json.dumps(mensagem, ensure_ascii=False).encode("utf-8"),
                json.dumps(mensagem, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            ])
        else:
            # se mensagem for string (ou outro), usar regra do enunciado para string
            candidatos_msg.append(str(mensagem).encode("utf-8"))

        # paddings a testar
        paddings = [
            ("PSS_MAX", padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            )),
            ("PSS_32", padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            )),
            ("PKCS1v15", padding.PKCS1v15()),
        ]

        last = None
        ok = False

        for msg_bytes in candidatos_msg:
            for name, pad in paddings:
                try:
                    parque_pub_key.verify(
                        sig_bytes,
                        msg_bytes,
                        pad,
                        hashes.SHA256(),
                    )
                    ok = True
                    break
                except InvalidSignature:
                    last = f"{name} -> InvalidSignature"
                except Exception as e:
                    last = f"{name} -> {type(e).__name__}: {e}"
            if ok:
                break

        if not ok:
            raise Exception(f"Assinatura inválida. Tentativas falharam. Último: {last}")

    except Exception as e:
        raise Exception(f"Assinatura da mensagem inválida: {e}")


#  API interna (backend)
@app.route("/api/parques", methods=["GET"])
def api_parques():
    """
    Vai ao Gestor de Parques buscar a lista de parques ativos.
    """
    url = f"http://{GESTOR_HOST}:{GESTOR_PORT}/parque"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        parques = resp.json()
        return jsonify(parques)
    except requests.RequestException as e:
        erro = {"erro": f"Não foi possível contactar o Gestor de Parques: {e}"}
        return jsonify(erro), 503

#novos api info e api route para a fase 4
@app.route("/api/info", methods=["GET"])
def api_info():
    ip = request.args.get("ip")
    porta = request.args.get("porta")
    
    # Chama o endpoint seguro /secure/info
    url = f"http://{ip}:{porta}/secure/info"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        dados = resp.json()
        
        mensagem = dados.get("mensagem")

        if isinstance(mensagem, str):
            try:
                mensagem = json.loads(mensagem)
            except json.JSONDecodeError:
                raise Exception("Mensagem recebida não é JSON válido")
            
        dados["mensagem"] = mensagem

        validar_resposta_segura(dados)

        return jsonify(mensagem)
        # Executa validação
        #validar_resposta_segura(dados)
        
        # Se passar, retorna apenas a mensagem para o frontend
        #return jsonify(dados["mensagem"])
        
    except Exception as e:
        return jsonify({"erro": f"Erro de Segurança/Conexão: {e}"}), 503

@app.route("/api/custo", methods=["GET"])
def api_custo():
    ip = request.args.get("ip")
    porta = request.args.get("porta")
    tempo = request.args.get("tempo")

    # Chama o endpoint seguro /secure/custo
    url = f"http://{ip}:{porta}/secure/custo"
    try:
        resp = requests.get(url, params={"tempo": tempo}, timeout=5)
        resp.raise_for_status()
        dados = resp.json()

        mensagem_original = dados.get("mensagem")

        # 1 - Guardar exatamente o que veio (para validar)
        dados_para_validar = dados.copy()

# 2. Validar assinatura SEM TOCAR NA MENSAGEM
        validar_resposta_segura(dados_para_validar)

# 3. Só agora tratar a mensagem
        mensagem = mensagem_original

        if isinstance(mensagem, str):
            mensagem = json.loads(mensagem)

# 4. Normalizar nomes
        if "valor" not in mensagem and "custo" in mensagem:
            mensagem["valor"] = mensagem["custo"]

# 5. Enviar sempre no formato esperado pelo frontend
        return jsonify({"valor": mensagem.get("valor")})
        # Executa validação
        #validar_resposta_segura(dados)
        
        #return jsonify(dados["mensagem"])
    except Exception as e:
        return jsonify({"erro": f"Erro ao calcular custo: {e}"}), 503


#  Interface Web (frontend)
@app.route("/", methods=["GET"])
def index():
    """
    Devolve a página HTML com a UI do Cliente Web.
    """
    html = """
    <!DOCTYPE html>
    <html lang="pt-PT">
    <head>
        <meta charset="UTF-8">
        <title>Cliente Web - Parques de Estacionamento</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary: #2563eb;
                --primary-dark: #1d4ed8;
                --accent: #22c55e;
                --bg-page: #020617;
                --card-bg: rgba(15, 23, 42, 0.92);
                --text-main: #e5e7eb;
                --text-muted: #9ca3af;
                --danger: #f97373;
                --shadow-soft: 0 20px 40px rgba(15, 23, 42, 0.7);
                --radius-lg: 18px;
            }

            * {
                box-sizing: border-box;
            }

            body {
                font-family: "Poppins", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                margin: 0;
                padding: 0;
                background:
                    radial-gradient(circle at 0% 0%, #1d4ed8 0, transparent 55%),
                    radial-gradient(circle at 100% 0%, #22c55e 0, transparent 55%),
                    radial-gradient(circle at 100% 100%, #0ea5e9 0, transparent 55%),
                    radial-gradient(circle at 0% 100%, #e11d48 0, transparent 55%),
                    #020617;
                color: var(--text-main);
                min-height: 100vh;
            }

            header {
                padding: 18px 32px 14px;
                position: sticky;
                top: 0;
                z-index: 10;
                backdrop-filter: blur(18px);
                background: linear-gradient(90deg, rgba(15, 23, 42, 0.95), rgba(15, 23, 42, 0.75));
                border-bottom: 1px solid rgba(148, 163, 184, 0.35);
            }

            header .top-row {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 16px;
            }

            header .title-row {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            header h1 {
                margin: 0;
                font-size: 1.6rem;
                letter-spacing: 0.04em;
                font-weight: 600;
            }

            header .subtitle {
                margin-top: 2px;
                font-size: 0.9rem;
                color: var(--text-muted);
            }

            header .logo-circle {
                width: 46px;
                height: 46px;
                border-radius: 20px;
                background: radial-gradient(circle at 30% 20%, #facc15 0, #fb923c 30%, #f97316 70%, #b91c1c 100%);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.6rem;
                box-shadow: 0 10px 25px rgba(248, 250, 252, 0.12);
            }

            header .tag {
                padding: 4px 10px;
                border-radius: 999px;
                font-size: 0.75rem;
                border: 1px solid rgba(148, 163, 184, 0.6);
                color: var(--text-muted);
                display: inline-flex;
                align-items: center;
                gap: 6px;
                background: rgba(15, 23, 42, 0.8);
            }

            header .tag-dot {
                width: 7px;
                height: 7px;
                border-radius: 50%;
                background: #22c55e;
                box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.18);
            }

            main {
                padding: 22px 20px 28px;
                max-width: 1200px;
                margin: 0 auto;
            }

            .toolbar {
                display: flex;
                align-items: center;
                gap: 14px;
                margin-bottom: 18px;
                flex-wrap: wrap;
            }

            button {
                padding: 9px 16px;
                border-radius: 999px;
                border: none;
                cursor: pointer;
                font-size: 0.95rem;
                display: inline-flex;
                align-items: center;
                gap: 8px;
                transition: transform 0.08s ease, box-shadow 0.18s ease, background 0.15s ease, color 0.15s ease, border 0.15s ease;
                font-weight: 500;
            }

            button#btn-refresh {
                background: rgba(15, 23, 42, 0.85);
                color: var(--text-main);
                border: 1px solid rgba(148, 163, 184, 0.7);
                box-shadow: 0 10px 25px rgba(15, 23, 42, 0.7);
            }

            button#btn-refresh:hover {
                background: rgba(30, 64, 175, 0.85);
                color: #e5e7eb;
                transform: translateY(-1px);
                box-shadow: 0 15px 35px rgba(37, 99, 235, 0.55);
                border-color: rgba(191, 219, 254, 0.85);
            }

            button#btn-calcular {
                background: linear-gradient(135deg, var(--primary), var(--primary-dark));
                color: #f9fafb;
                box-shadow: 0 10px 26px rgba(37, 99, 235, 0.7);
                border: 1px solid rgba(129, 140, 248, 0.8);
            }

            button#btn-calcular:hover {
                transform: translateY(-1px);
                box-shadow: 0 18px 38px rgba(59, 130, 246, 0.8);
                filter: brightness(1.05);
            }

            button .icon {
                font-size: 1.1rem;
            }

            #status {
                font-size: 0.9rem;
                color: var(--text-muted);
            }

            .status-dot {
                display: inline-block;
                width: 9px;
                height: 9px;
                border-radius: 50%;
                background: var(--accent);
                margin-right: 6px;
                box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.25);
            }

            .container {
                display: grid;
                grid-template-columns: minmax(0, 1.05fr) minmax(0, 1.25fr);
                gap: 22px;
                align-items: flex-start;
            }

            .card {
                background: var(--card-bg);
                border-radius: var(--radius-lg);
                padding: 18px 18px 14px;
                box-shadow: var(--shadow-soft);
                backdrop-filter: blur(22px);
                border: 1px solid rgba(148, 163, 184, 0.35);
                position: relative;
                overflow: hidden;
                animation: fadeInUp 0.35s ease-out;
            }

            .card::before {
                content: "";
                position: absolute;
                inset: 0;
                background: radial-gradient(circle at top right, rgba(59, 130, 246, 0.2), transparent 60%);
                opacity: 0.7;
                pointer-events: none;
            }

            .card-content {
                position: relative;
                z-index: 1;
            }

            .card-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            }

            .card-title {
                font-size: 1.05rem;
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 8px;
            }

            .card-title span.emoji {
                font-size: 1.2rem;
            }

            .card-subtitle {
                font-size: 0.8rem;
                color: var(--text-muted);
            }

            .parque-list {
                max-height: 460px;
                overflow: auto;
                padding-right: 4px;
                scrollbar-width: thin;
                scrollbar-color: #4b5563 transparent;
            }

            .parque-list::-webkit-scrollbar {
                width: 6px;
            }

            .parque-list::-webkit-scrollbar-track {
                background: transparent;
            }

            .parque-list::-webkit-scrollbar-thumb {
                background-color: #4b5563;
                border-radius: 999px;
            }

            .parque-item {
                border-radius: 14px;
                padding: 10px 11px 9px;
                cursor: pointer;
                margin-bottom: 8px;
                transition: background 0.15s ease, transform 0.08s ease, box-shadow 0.18s ease, border 0.15s ease;
                border: 1px solid rgba(55, 65, 81, 0.75);
                background: radial-gradient(circle at top left, rgba(30, 64, 175, 0.35), rgba(15, 23, 42, 0.95));
            }

            .parque-item:hover {
                transform: translateY(-1px);
                box-shadow: 0 18px 32px rgba(15, 23, 42, 0.9);
                border-color: rgba(129, 140, 248, 0.9);
            }

            .parque-item.selected {
                background: radial-gradient(circle at top left, rgba(59, 130, 246, 0.6), rgba(15, 23, 42, 0.95));
                border-color: rgba(191, 219, 254, 0.95);
                box-shadow: 0 22px 40px rgba(37, 99, 235, 0.95);
            }

            .parque-name-row {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 4px;
            }

            .parque-name {
                font-weight: 600;
                font-size: 0.95rem;
            }

            .badge-online {
                display: inline-flex;
                align-items: center;
                gap: 4px;
                padding: 2px 8px;
                border-radius: 999px;
                font-size: 0.7rem;
                background: rgba(22, 163, 74, 0.25);
                color: #bbf7d0;
                border: 1px solid rgba(74, 222, 128, 0.9);
            }

            .badge-online::before {
                content: "";
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: #22c55e;
            }

            .parque-meta {
                font-size: 0.78rem;
                color: var(--text-muted);
                line-height: 1.3;
            }

            .parque-meta strong {
                color: #e5e7eb;
            }

            .error {
                color: var(--danger);
                font-size: 0.9rem;
                margin-top: 8px;
            }

            .details-grid {
                display: grid;
                grid-template-columns: 1.1fr 1fr;
                gap: 10px 18px;
                margin-top: 6px;
                font-size: 0.9rem;
            }

            .details-label {
                color: var(--text-muted);
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.04em;
            }

            .details-value {
                font-weight: 600;
            }

            label {
                display: block;
                margin-top: 10px;
                font-size: 0.85rem;
                color: var(--text-muted);
            }

            input[type="number"] {
                margin-top: 4px;
                padding: 7px 10px;
                border-radius: 999px;
                border: 1px solid #4b5563;
                width: 120px;
                font-size: 0.95rem;
                outline: none;
                transition: border 0.15s ease, box-shadow 0.15s ease, background 0.15s ease;
                background: rgba(15, 23, 42, 0.9);
                color: var(--text-main);
            }

            input[type="number"]:focus {
                border-color: var(--primary);
                box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.4);
                background: rgba(15, 23, 42, 1);
            }

            #resultado-custo {
                margin-top: 10px;
                font-weight: 600;
                font-size: 0.95rem;
            }

            .placeholder {
                color: var(--text-muted);
                font-size: 0.9rem;
                margin-top: 4px;
            }

            .small-muted {
                font-size: 0.78rem;
                color: var(--text-muted);
                margin-top: 4px;
            }

            .ocupacao-wrapper {
                margin-top: 12px;
            }

            .ocupacao-label {
                font-size: 0.8rem;
                color: var(--text-muted);
                margin-bottom: 4px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .ocupacao-bar {
                width: 100%;
                height: 12px;
                background: rgba(148, 163, 184, 0.25); /* cinza de fundo */
                border-radius: 999px;
                overflow: hidden;
            }

            .ocupacao-bar-inner {
                height: 100%;
                width: 0%;
                border-radius: 999px;
                transition: width 0.4s ease-out, background-color 0.3s ease;
            }
            
            @media (max-width: 960px) {
                .container {
                    grid-template-columns: 1fr;
                }
                .parque-list {
                    max-height: 260px;
                }
            }

            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
        </style>
    </head>
    <body>
        <header>
            <div class="top-row">
                <div class="title-row">
                    <div class="logo-circle">🚗</div>
                    <div>
                        <h1>Cliente Web – Parques de Estacionamento</h1>
                        <div class="subtitle">Consulta em tempo real dos parques registados no Gestor</div>
                    </div>
                </div>
                <div class="tag">
                    <span class="tag-dot"></span>
                    <span>Fundamentos de Sistemas Distribuídos </span>
                </div>
            </div>
        </header>

        <main>
            <div class="toolbar">
                <button id="btn-refresh">
                    <span class="icon">🔄</span>
                    <span>Atualizar lista de parques</span>
                </button>
                <span id="status"><span class="status-dot"></span>A carregar parques...</span>
            </div>

            <div class="container">
                <div class="card">
                    <div class="card-content">
                        <div class="card-header">
                            <div>
                                <div class="card-title">
                                    <span class="emoji">📍</span>
                                    <span>Parques Disponíveis</span>
                                </div>
                                <div class="card-subtitle">Lista de parques registados e considerados ativos pelo Gestor:</div>
                            </div>
                        </div>
                        <div id="lista-parques" class="parque-list">
                            <!-- preenchido via JS -->
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-content">
                        <div class="card-header">
                            <div>
                                <div class="card-title">
                                    <span class="emoji">ℹ️</span>
                                    <span>Detalhes do Parque Selecionado</span>
                                </div>
                                <div class="card-subtitle">Informação obtida diretamente a partir da API REST de cada parque</div>
                            </div>
                        </div>
                        <div id="detalhes-parque">
                            <p class="placeholder">Selecione um parque na lista à esquerda para ver os detalhes de lotação, tarifas, localização e taxa de ocupação.</p>
                        </div>
                        <div id="simulador-custo" style="margin-top: 16px; display:none;">
                            <hr style="border:none;border-top:1px solid rgba(148, 163, 184, 0.45);margin:10px 0 14px;">
                            <div class="card-title" style="font-size:0.98rem;margin-bottom:4px;">
                                <span class="emoji">💰</span>
                                <span>Simular custo de estadia</span>
                            </div>
                            <p class="small-muted">Insira o tempo pretendido de estacionamento para estimar o valor a pagar neste parque.</p>
                            <label>
                                Tempo (em minutos):
                                <input type="number" id="input-tempo" min="0" value="60">
                            </label>
                            <div style="margin-top:10px; display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                                <button id="btn-calcular">
                                    <span class="icon">📟</span>
                                    <span>Calcular custo</span>
                                </button>
                                <div id="resultado-custo"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </main>

        <script>
            let parquesCache = [];
            let parqueSelecionado = null;

            // Helper para lidar com diferentes nomes de campos vindos de parques de outros grupos
            function getField(obj, keys, defaultValue = "N/D") {
                for (const k of keys) {
                    if (obj[k] !== undefined && obj[k] !== null) {
                        return obj[k];
                    }
                }
                return defaultValue;
            }

            function marcarSelecionado(indice) {
                document.querySelectorAll(".parque-item").forEach(el => {
                    el.classList.remove("selected");
                    if (parseInt(el.dataset.index) === indice) {
                        el.classList.add("selected");
                    }
                });
            }

            async function carregarParques() {
                const statusEl = document.getElementById("status");
                const listaEl = document.getElementById("lista-parques");
                statusEl.innerHTML = '<span class="status-dot"></span>A carregar parques...';
                listaEl.innerHTML = "";
                try {
                    const resp = await fetch("/api/parques");
                    const dados = await resp.json();

                    if (!resp.ok) {
                        throw new Error(dados.erro || "Erro a obter parques");
                    }

                    parquesCache = dados;
                    if (dados.length === 0) {
                        listaEl.innerHTML = "<p class='placeholder'>Não há parques ativos registados no Gestor.</p>";
                        statusEl.textContent = "Nenhum parque ativo.";
                        return;
                    }

                    dados.forEach((p, idx) => {
                        const div = document.createElement("div");
                        div.className = "parque-item";
                        div.dataset.index = idx;

                        const atualizado = p.atualizado || "";
                        div.innerHTML = `
                            <div class="parque-name-row">
                                <span class="parque-name">${p.nome}</span>
                                <span class="badge-online">ativo</span>
                            </div>
                            <div class="parque-meta">
                                <div><strong>Endereço:</strong> ${p.ip}:${p.porta}</div>
                                <div><strong>Atualizado:</strong> ${atualizado}</div>
                            </div>
                        `;
                        div.addEventListener("click", () => selecionarParque(idx));
                        listaEl.appendChild(div);
                    });

                    statusEl.textContent = "Lista de parques atualizada.";
                } catch (e) {
                    console.error(e);
                    listaEl.innerHTML = "<p class='error'>Erro ao carregar parques a partir do Gestor.</p>";
                    statusEl.textContent = "Erro ao contactar o Gestor.";
                }
            }

            async function selecionarParque(indice) {
                const parque = parquesCache[indice];
                if (!parque) return;

                parqueSelecionado = parque;
                marcarSelecionado(indice);

                const detalhesEl = document.getElementById("detalhes-parque");
                const simuladorEl = document.getElementById("simulador-custo");
                const resultadoCustoEl = document.getElementById("resultado-custo");
                resultadoCustoEl.textContent = "";

                detalhesEl.innerHTML = "<p class='placeholder'>A carregar detalhes do parque selecionado...</p>";

                try {
                    const params = new URLSearchParams({
                        ip: parque.ip,
                        porta: parque.porta
                    });
                    const resp = await fetch("/api/info?" + params.toString());
                    const dados = await resp.json();

                    if (!resp.ok) {
                        throw new Error(dados.erro || "Erro ao obter info do parque");
                    }

                    // Lê campos com vários nomes possíveis (para ser compatível com outros grupos)
                    const lotacao    = getField(dados, ["lotacao", "lotação", "capacidade", "capacidade_total"]);
                    const livres     = getField(dados, ["livre", "livres", "lugares_livres", "lugaresLivres"]);
                    const tarifaBase = getField(dados, ["tarifa_base", "tarifaBase"]);
                    const tarifaHora = getField(dados, ["tarifa_hora", "tarifa/h", "tarifa_h", "tarifaPorHora"]);
                    const tarifaMax  = getField(dados, ["tarifa_max", "tarifaMax", "tarifa_maxima"]);
                    const latitude   = getField(dados, ["latitude", "lat"]);
                    const longitude  = getField(dados, ["longitude", "lon", "lng"]);

                    // Cálculo da ocupação (% de lugares ocupados)
                    let ocupacaoTexto = "N/D";
                    let ocupacaoPercent = null;
                    const lotNum = parseFloat(lotacao);
                    const livNum = parseFloat(livres);
                    if (!isNaN(lotNum) && !isNaN(livNum) && lotNum > 0) {
                        const percLivre = (livNum / lotNum) * 100;
                        ocupacaoPercent = Math.round(100 - percLivre);
                        ocupacaoTexto = ocupacaoPercent + "% ocupado";
                    }

                    detalhesEl.innerHTML = `
                        <div class="details-grid">
                            <div>
                                <div class="details-label">Nome do parque</div>
                                <div class="details-value">${dados.nome}</div>
                            </div>
                            <div>
                                <div class="details-label">Lotação total</div>
                                <div class="details-value">${lotacao}</div>
                            </div>
                            <div>
                                <div class="details-label">Lugares livres</div>
                                <div class="details-value">${livres}</div>
                            </div>
                            <div>
                                <div class="details-label">Tarifa base</div>
                                <div class="details-value">${tarifaBase} €</div>
                            </div>
                            <div>
                                <div class="details-label">Tarifa por hora</div>
                                <div class="details-value">${tarifaHora} €</div>
                            </div>
                            <div>
                                <div class="details-label">Tarifa máxima</div>
                                <div class="details-value">${tarifaMax} €</div>
                            </div>
                            <div>
                                <div class="details-label">Latitude</div>
                                <div class="details-value">${latitude}</div>
                            </div>
                            <div>
                                <div class="details-label">Longitude</div>
                                <div class="details-value">${longitude}</div>
                            </div>
                        </div>

                        <div class="ocupacao-wrapper">
                            <div class="ocupacao-label">
                                <span>Taxa de ocupação</span>
                                <span>${ocupacaoTexto}</span>
                            </div>
                            <div class="ocupacao-bar">
                                <div id="ocupacao-bar-inner" class="ocupacao-bar-inner"></div>
                            </div>
                        </div>
                    `;

                    // Atualiza a barra de ocupação
                    if (ocupacaoPercent !== null) {
                        const barInner = document.getElementById("ocupacao-bar-inner");
                        const percent = Math.min(Math.max(ocupacaoPercent, 0), 100);
                        // A barra colorida mostra “quanto está ocupado”
                        barInner.style.width = percent + "%";

                        // cor consoante ocupação
                        if (percent < 50) {
                            barInner.style.backgroundColor = "#22c55e"; // verde
                        } else if (percent < 80) {
                            barInner.style.backgroundColor = "#facc15"; // amarelo
                        } else {
                            barInner.style.backgroundColor = "#ef4444"; // vermelho
                        }
                    }

                    simuladorEl.style.display = "block";
                } catch (e) {
                    console.error(e);
                    detalhesEl.innerHTML = `
                        <p class="error">Erro ao contactar o parque selecionado.</p>
                        <p class="small-muted">Endereço: ${parque.ip}:${parque.porta}</p>
                    `;
                    simuladorEl.style.display = "none";
                }
            }

           async function calcularCusto() {
    if (!parqueSelecionado) return;

    const tempoInput = document.getElementById("input-tempo");
    const tempo = tempoInput.value || "0";
    const resultadoCustoEl = document.getElementById("resultado-custo");
    resultadoCustoEl.textContent = "A calcular...";

    try {
        const params = new URLSearchParams({
            ip: parqueSelecionado.ip,
            porta: parqueSelecionado.porta,
            tempo: tempo
        });
        const resp = await fetch("/api/custo?" + params.toString());
        const dados = await resp.json();

        if (!resp.ok) {
            throw new Error(dados.erro || "Erro ao calcular custo");
        }

        // ✔️ Só aceita o campo correto "valor"
        if (dados.valor === undefined) {
            resultadoCustoEl.textContent = "Erro ao calcular o custo.";
            return;
        }

        const numero = Number(dados.valor);

        // ✔️ Se não for número válido → erro
        if (!isFinite(numero)) {
            resultadoCustoEl.textContent = "Erro ao calcular o custo.";
            return;
        }

        // ✔️ Arredonda sempre a 2 casas decimais
        const valorFormatado = numero.toFixed(2);

        resultadoCustoEl.textContent = "Custo estimado: " + valorFormatado + " €";

    } catch (e) {
        console.error(e);
        resultadoCustoEl.textContent = "Erro ao calcular o custo.";
    }
}




            document.getElementById("btn-refresh").addEventListener("click", carregarParques);
            document.getElementById("btn-calcular").addEventListener("click", calcularCusto);

            // Carregar ao entrar na página
            carregarParques();

            // Refresh automático a cada 30 segundos
            setInterval(carregarParques, 30000);
        </script>
    </body>
    </html>
    """
    return Response(html, mimetype="text/html")


def main():
    # Cliente Web a correr na porta 8000 para não colidir com o Flask do parque (5000)
    app.run(host="0.0.0.0", port=8000, debug=True)


if __name__ == "__main__":
    main()
