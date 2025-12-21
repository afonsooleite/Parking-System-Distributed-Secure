# FSD/parque/parque.py
import socket
import psutil  # pip install psutil
import requests
import threading
import time
import json
from flask import Flask, jsonify, Response, request
from FSD.config import HOST, PORT, CAPACIDADE, LOG_VERBOSO
from FSD.protocolo import (
    codificar,
    descodificar,
    ProtocoloErro,
    ParametrosInvalidos,
    ComandoInvalido,
)

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

START_TIME = time.time()


#  Classe que representa o Parque

class Parque:
    """Representa um parque de estacionamento com os seus lugares e informações."""

    def __init__(
        self,
        nome: str,
        latitude: float,
        longitude: float,
        tarifa_base: float,
        tarifa_hora: float,
        tarifa_max: float,
        capacidade: int,
    ):
        self.nome = nome
        self.localizacao = (latitude, longitude)
        self.tarifa_base = tarifa_base
        self.tarifa_hora = tarifa_hora
        self.tarifa_max = tarifa_max
        self.capacidade = capacidade

        self.mapa_nomes = {}  # nome_lugar -> id atribuído
        self.lugares = {}  # id -> estado ("LIVRE" / "OCUPADO")
        self.id_atual = 1
        self.lock = threading.Lock()

        # Mapeia cada cliente (addr) para os IDs de lugares que lhe pertencem
        self.clientes = {}

        #FASE 4: chaves e certificado
        self.certificado: str | None = None

        log(f"[SEGURANÇA] A gerar par de chaves RSA 2048 para '{self.nome}'...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    # Segurança: assinatura de mensagens
    def assinar_mensagem(self, dados):
        """
        Gera assinatura conforme regras do enunciado Fase 4:
          - Serializar JSON em utf-8 (quando for dicionário)
          - Usar RSA + PSS + SHA256
          - Devolver assinatura descodificada em 'cp437'
        """
        if isinstance(dados, dict):
            msg_bytes = json.dumps(dados).encode("utf-8")
        else:
            msg_bytes = str(dados).encode("utf-8")

        assinatura = self.private_key.sign(
            msg_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        # Enunciado: a assinatura deve ser descodificada com cp437
        return assinatura.decode("cp437")

    #Lógica normal do parque
    def registar_lugar(self) -> int:
        """Atribui um novo ID e marca o lugar como livre."""
        with self.lock:
            if len(self.lugares) >= self.capacidade:
                raise ValueError("Capacidade máxima atingida")
            lugar_id = self.id_atual
            self.lugares[lugar_id] = "LIVRE"
            self.id_atual += 1
            return lugar_id

    def atualizar_estado(self, lugar_id: int, estado: str) -> None:
        """Atualiza o estado (livre/ocupado) de um lugar."""
        with self.lock:
            if lugar_id not in self.lugares:
                raise KeyError("ID inválido")
            if estado not in ("LIVRE", "OCUPADO"):
                raise ValueError("Estado inválido")
            self.lugares[lugar_id] = estado

    def contar_ocupados(self) -> int:
        """Conta quantos lugares estão ocupados."""
        return list(self.lugares.values()).count("OCUPADO")

    def info(self) -> str:
        """Retorna um resumo textual das informações do parque."""
        livres = self.capacidade - self.contar_ocupados()
        return (
            f"Nome: {self.nome}\n"
            f"Localização (WGS84): {self.localizacao[0]}, {self.localizacao[1]}\n"
            f"Tarifa base: {self.tarifa_base:.2f}€\n"
            f"Tarifa/hora: {self.tarifa_hora:.2f}€\n"
            f"Tarifa máxima: {self.tarifa_max:.2f}€\n"
            f"Lugares livres: {livres}/{self.capacidade}\n"
        )



#  Funções auxiliares

def log(msg: str) -> None:
    """Imprime mensagens formatadas com hora (se log ativo)."""
    if LOG_VERBOSO:
        hora = time.strftime("%H:%M:%S")
        print(f"[{hora}] {msg}")


#  Servidor TCP (Lugares)

def handle_client(conn, addr, parque: Parque):
    """Trata da comunicação com um cliente (Lugar) e mantém IDs persistentes."""
    log(f"[+] Ligação estabelecida com {addr}")

    # Garante que o cliente existe no registo (pode não ter nomes ainda)
    if addr not in parque.clientes:
        parque.clientes[addr] = []

    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break

                mensagem = data.decode().strip()
                log(f"[RECEBIDO de {addr}] {mensagem}")

                try:
                    dados = descodificar(mensagem)
                    comando = dados["comando"]
                    
                    # Comando INIT (registar ou reconectar Lugar)
                    if comando == "INIT":
                        nome_lugar = dados.get("nome")

                        if not nome_lugar:
                            raise ParametrosInvalidos("Nome do lugar em falta")

                        # Se já existe esse nome, é reconexão: reutiliza o mesmo ID
                        if nome_lugar in parque.mapa_nomes:
                            lugar_id = parque.mapa_nomes[nome_lugar]
                            parque.lugares[lugar_id] = "LIVRE"

                            if addr not in parque.clientes:
                                parque.clientes[addr] = []
                            if lugar_id not in parque.clientes[addr]:
                                parque.clientes[addr].append(lugar_id)

                            resposta = codificar("OK", id=lugar_id)
                            log(f"[RECONEXÃO] {nome_lugar} retomou com ID {lugar_id}.")
                        else:
                            # Novo lugar — só se ainda houver capacidade global
                            if len(parque.lugares) >= parque.capacidade:
                                resposta = codificar("ERRO", msg="Capacidade máxima atingida")
                            else:
                                lugar_id = parque.registar_lugar()
                                parque.mapa_nomes[nome_lugar] = lugar_id
                                if addr not in parque.clientes:
                                    parque.clientes[addr] = []
                                parque.clientes[addr].append(lugar_id)
                                resposta = codificar("OK", id=lugar_id)
                                log(f"[REGISTADO] {nome_lugar} criado com ID {lugar_id}.")

                    
                    # Comando UPDATE (atualizar estado do lugar)
                    elif comando == "UPDATE":
                        if "id" not in dados or "estado" not in dados:
                            raise ParametrosInvalidos("Faltam parâmetros obrigatórios")

                        id_int = int(dados["id"])
                        estado = dados["estado"].upper()
                        parque.atualizar_estado(id_int, estado)
                        ocupados = parque.contar_ocupados()

                        resposta = codificar(
                            "OK",
                            msg=f"estado atualizado ({ocupados}/{parque.capacidade})",
                        )

                        log(
                            f"[ATUALIZADO] Lugar {id_int} -> {estado} "
                            f"({ocupados}/{parque.capacidade} ocupados)"
                        )

                    # Comando INFO (resumo do parque)
                    elif comando == "INFO":
                        resposta = codificar("OK", info=parque.info())

                    # Comando inválido
                    else:
                        raise ComandoInvalido(f"Comando inválido: {comando}")

                except (
                    ValueError,
                    KeyError,
                    ParametrosInvalidos,
                    ComandoInvalido,
                    ProtocoloErro,
                ) as e:
                    resposta = codificar("ERRO", msg=str(e))

                # Enviar resposta ao cliente
                conn.sendall(resposta.encode())

            except ConnectionResetError:
                break

    # Quando o cliente se desconecta, liberta os seus lugares (mas não apaga o mapa_nomes)
    log(f"[-] Ligação terminada: {addr}")
    if addr in parque.clientes:
        with parque.lock:
            for lid in parque.clientes[addr]:
                if lid in parque.lugares:
                    parque.lugares[lid] = "LIVRE"

#  API REST (Flask)
app = Flask(__name__)

@app.route("/info", methods=["GET"])
def info_rest():
    livres = parque.capacidade - parque.contar_ocupados()
    dados = {
        "nome": parque.nome,
        "lotacao": parque.capacidade,
        "livre": livres,
        "tarifa_base": parque.tarifa_base,
        "tarifa_hora": parque.tarifa_hora,
        "tarifa_max": parque.tarifa_max,
        "latitude": parque.localizacao[0],
        "longitude": parque.localizacao[1],
    }
    return Response(json.dumps(dados, indent=2), mimetype="application/json")


@app.route("/custo", methods=["GET"])
def custo_rest():
    """Calcula o custo de estadia no parque, dado o tempo em minutos."""
    tempo = request.args.get("tempo")
    try:
        minutos = float(tempo)
        if minutos < 0:
            raise ValueError

        custo = parque.tarifa_base + (minutos / 60) * parque.tarifa_hora
        custo = min(custo, parque.tarifa_max)

        dados = {"valor": round(custo, 2)}
        return Response(json.dumps(dados, indent=2), mimetype="application/json")

    except (TypeError, ValueError):
        erro = {"erro": "Parâmetro 'tempo' inválido ou em falta"}
        return Response(
            json.dumps(erro, indent=2), status=400, mimetype="application/json"
        )


@app.route("/ocupacao", methods=["GET"])
def ocupacao_rest():
    """Devolve a taxa de ocupação e contagem de lugares."""
    ocupados = parque.contar_ocupados()
    livres = parque.capacidade - ocupados
    percentagem = round((ocupados / parque.capacidade) * 100, 2)

    dados = {
        "ocupados": ocupados,
        "livres": livres,
        "capacidade": parque.capacidade,
        "ocupacao_percent": percentagem,
    }
    return Response(json.dumps(dados, indent=2), mimetype="application/json")


@app.route("/lugares", methods=["GET"])
def lugares_rest():
    """Lista todos os lugares com o respetivo estado."""
    with parque.lock:
        dados = [{"id": lid, "estado": estado} for lid, estado in parque.lugares.items()]
    return Response(json.dumps(dados, indent=2), mimetype="application/json")


@app.route("/health", methods=["GET"])
def health():
    """Verifica o estado técnico do parque."""
    agora = time.time()
    uptime = int(agora - START_TIME)

    tcp_ok = getattr(parque, "tcp_ok", False)
    last_gestor_ok = getattr(parque, "last_gestor_ok", 0)
    gestor_ok = (agora - last_gestor_ok) < 190  # se registou há menos de 3 min

    status = "ok" if (tcp_ok and gestor_ok) else "degraded"

    dados = {
        "Estado do Parque": status,
        "Tempo Ativo": uptime,
        "Servidor TCP Ativo": tcp_ok,
        "Gestor Sincronizado": gestor_ok,
    }
    return Response(json.dumps(dados, indent=2), mimetype="application/json")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Interface HTML simples com estado atual do parque."""
    ocupados = parque.contar_ocupados()
    livres = parque.capacidade - ocupados
    percentagem = round((ocupados / parque.capacidade) * 100, 2)

    # Gerar tabela HTML de lugares
    linhas = ""
    with parque.lock:
        for lid, estado in parque.lugares.items():
            cor = "#dc3545" if estado == "OCUPADO" else "#28a745"
            linhas += (
                f"<tr><td>{lid}</td><td style='color:{cor};font-weight:bold'>{estado}</td></tr>"
            )

    html = f"""
    <html>
    <head>
        <title>{parque.nome} - Dashboard</title>
        <meta http-equiv="refresh" content="10">
        <style>
            body {{ font-family: Arial; margin: 40px; background-color: #f7f7f7; }}
            h1 {{ color: #333; }}
            .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }}
            progress {{ width: 100%; height: 25px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            td, th {{ padding: 8px; border-bottom: 1px solid #ddd; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🏙️ {parque.nome}</h1>
            <p><b>Localização:</b> {parque.localizacao[0]}, {parque.localizacao[1]}</p>
            <p><b>Tarifas:</b> Base {parque.tarifa_base}€, Hora {parque.tarifa_hora}€, Máx {parque.tarifa_max}€</p>

            <h3>Ocupação Atual: {ocupados}/{parque.capacidade} ({percentagem}%)</h3>
            <progress value="{ocupados}" max="{parque.capacidade}"></progress>

            <table>
                <tr><th>ID</th><th>Estado</th></tr>
                {linhas}
            </table>
            <p style="font-size:0.9em;color:#777;">Atualiza automaticamente a cada 10s</p>
        </div>
    </body>
    </html>
    """
    return Response(html, mimetype="text/html")


# NOVOS ENDPOINTS SEGUROS (FASE 4)
@app.route("/secure/info", methods=["GET"])
def secure_info():
    """
    Endpoint seguro /secure/info conforme enunciado:
      - campo 'mensagem' com info do parque
      - 'assinatura' sobre a mensagem
      - 'certificado' do parque em PEM (utf-8)
    """
    livres = parque.capacidade - parque.contar_ocupados()

    mensagem = {
        "nome": parque.nome,
        "lotacao": parque.capacidade,
        "livre": livres,
        "tarifa_base": parque.tarifa_base,
        "tarifa/h": parque.tarifa_hora,
        "tarifa_max": parque.tarifa_max,
        "latitude": parque.localizacao[0],
        "longitude": parque.localizacao[1],
    }

    if not getattr(parque, "certificado", None):
        erro = {"erro": "Certificado ainda não obtido junto do Gestor."}
        return Response(
            json.dumps(erro, indent=2), status=503, mimetype="application/json"
        )

    assinatura = parque.assinar_mensagem(mensagem)

    envelope = {
        "assinatura": assinatura,
        "certificado": parque.certificado,
        "mensagem": mensagem,
    }
    return Response(json.dumps(envelope, indent=2), mimetype="application/json")


@app.route("/secure/custo", methods=["GET"])
def secure_custo():
    """
    Endpoint seguro /secure/custo?tempo=X:
      - calcula custo
      - assina mensagem {"valor": ...}
    """
    tempo = request.args.get("tempo")

    try:
        minutos = float(tempo)
        if minutos < 0:
            raise ValueError

        custo = parque.tarifa_base + (minutos / 60) * parque.tarifa_hora
        custo = min(custo, parque.tarifa_max)

        mensagem = {"valor": round(custo, 2)}

        if not getattr(parque, "certificado", None):
            erro = {"erro": "Certificado ainda não obtido junto do Gestor."}
            return Response(
                json.dumps(erro, indent=2), status=503, mimetype="application/json"
            )

        assinatura = parque.assinar_mensagem(mensagem)
        envelope = {
            "assinatura": assinatura,
            "certificado": parque.certificado,
            "mensagem": mensagem,
        }
        return Response(json.dumps(envelope, indent=2), mimetype="application/json")

    except (TypeError, ValueError):
        erro = {"erro": "Parâmetro 'tempo' inválido ou em falta"}
        return Response(
            json.dumps(erro, indent=2), status=400, mimetype="application/json"
        )


def iniciar_tcp(parque: Parque):
    """Servidor TCP para comunicação com os Lugares."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        parque.tcp_ok = True  # diz que o servidor TCP arrancou com sucesso

        log(f"[SERVIDOR] Parque '{parque.nome}' ativo em {HOST}:{PORT}")
        log(parque.info())

        while True:
            conn, addr = s.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, parque),
                daemon=True,
            )
            thread.start()


def obter_ip_vpn() -> str:
    """Tenta identificar o IP da interface VPN (10.x.x.x ou 192.168.233.x)."""
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == "AF_INET":
                ip = addr.address
                if ip.startswith("10.") or ip.startswith("192.168.233."):
                    return ip
    # Caso não encontre, devolve o IP local normal
    return socket.gethostbyname(socket.gethostname())


GESTOR_HOST = "192.168.233.151"
GESTOR_PORT = 8080


def registar_no_gestor(parque: Parque):
    """
    Regista o parque no Gestor de Parques e renova o registo a cada 3 minutos.
    Na Fase 4, também pede/atualiza o certificado digital via /parque_certificado.
    """
    while True:
        try:
            ip_local = obter_ip_vpn()

            #Registo
            url_reg = f"http://{GESTOR_HOST}:{GESTOR_PORT}/parque"
            dados_reg = {
                "nome": parque.nome,
                "ip": ip_local,
                "porta": 5000, # mesma porta usada pelo Flask
            }

            resposta = requests.post(url_reg, json=dados_reg, timeout=5)

            if resposta.status_code == 200:
                parque.last_gestor_ok = time.time()
                log(
                    f"[GESTOR] Registo efetuado com sucesso ({ip_local}:{dados_reg['porta']})"
                )
            else:
                log(f"[GESTOR] Erro no registo: {resposta.status_code} - {resposta.text}")

            #Registo certificado (Fase 4)
            pub_pem = (
                parque.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("utf-8")
                .strip()
            )

            url_cert = f"http://{GESTOR_HOST}:{GESTOR_PORT}/parque_certificado"
            dados_cert = {
                "ip": ip_local,
                "porta": 5000,
                "nome": parque.nome,
                "pubKey": pub_pem,
            }

            resp_cert = requests.post(url_cert, json=dados_cert, timeout=5)

            if resp_cert.status_code in (200, 201):
                parque.certificado = resp_cert.text.strip()
                log(
                    f"[GESTOR] Certificado digital recebido/atualizado "
                    f"(tamanho: {len(parque.certificado)} caracteres)."
                )
            else:
                log(
                    f"[GESTOR] Erro ao obter certificado: "
                    f"{resp_cert.status_code} - {resp_cert.text}"
                )

        except requests.exceptions.RequestException as e:
            log(f"[GESTOR] Falha ao contactar o Gestor: {e}")

        # Repetir o registo a cada 3 minutos (180 segundos)
        time.sleep(180)


def main():
    global parque
    parque = Parque(
        nome="Parque PL3_G3",
        latitude=41.1579,
        longitude=-8.6291,
        tarifa_base=1.0,
        tarifa_hora=0.8,
        tarifa_max=6.0,
        capacidade=CAPACIDADE,
    )

    # 1 - Servidor TCP numa thread (lugares)
    threading.Thread(target=iniciar_tcp, args=(parque,), daemon=True).start()

    # 2 - Registo no Gestor + certificado numa thread
    threading.Thread(target=registar_no_gestor, args=(parque,), daemon=True).start()

    # 3 - API REST (Flask) — corre no thread principal
    app.run(host="0.0.0.0", port=5000, threaded=True)


if __name__ == "__main__":
    main()
