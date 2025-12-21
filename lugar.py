"""Simulador de lugares de estacionamento (fase 1)."""

from __future__ import annotations

import os
import random
import socket
import sys
import threading
import time

HOSTNAME = socket.gethostname()

try:  # Permite executar o script diretamente ou como módulo do pacote FSD
    from FSD.config import (  # type: ignore[import]
        CAPACIDADE,
        HOST,
        INTERVALO_SIMULACAO,
        PL,
        PO,
        PORT,
        LUGARES_CLIENTE,
    )
    from FSD.protocolo import codificar, descodificar
except ModuleNotFoundError:  # pragma: no cover - apenas em execução direta
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from config import CAPACIDADE, HOST, INTERVALO_SIMULACAO, PL, PO, PORT
    from protocolo import codificar, descodificar


BUFFER_SIZE = 1024


def _receber_resposta(sock: socket.socket) -> str:
    """Devolve a mensagem enviada pelo Parque."""
    dados = sock.recv(BUFFER_SIZE)
    if not dados:
        raise ConnectionError("Ligação encerrada pelo Parque!")
    return dados.decode().strip()


def _obter_id(sock: socket.socket, nome_lugar: str) -> int:
    """Envia o pedido INIT com o nome do lugar e devolve o ID atribuído."""
    sock.sendall(codificar("INIT", nome=nome_lugar).encode())
    resposta = _receber_resposta(sock)
    print(f"[SERVIDOR]: {resposta}")

    dados = descodificar(resposta)
    if dados.get("comando") == "ERRO":
        print(f"[ERRO] ({nome_lugar}) {dados.get('msg')}")

    if dados.get("comando") != "OK" or "id" not in dados:
        raise ValueError(f"Resposta inesperada ao INIT: {resposta}")

    return int(dados["id"])



def _proximo_estado(estado_atual: str) -> str:
    """Calcula o próximo estado para o lugar consoante as probabilidades."""
    if estado_atual == "LIVRE" and random.random() < PO:
        return "OCUPADO"
    if estado_atual == "OCUPADO" and random.random() < PL:
        return "LIVRE"
    return estado_atual


def _enviar_atualizacao(sock: socket.socket, lugar_id: int, estado: str) -> None:
    """Comunica o estado atual do lugar ao Parque, com possibilidade de erros simulados."""

    r = random.random()
    if r < 0.05:
        # Erro de formato (mensagem mal formada)
        mensagem = "UPDATE;;id"
    elif r < 0.10:
        # Erro de ID inválido
        mensagem = codificar("UPDATE", id=9999, estado=estado)
    elif r < 0.15:
        # Erro de comando inválido
        mensagem = "START"
    elif r < 0.25:
        # Erro de estado inválido
        mensagem = codificar("UPDATE", id=lugar_id, estado="INVALIDO")
    else:
        # Mensagem correta
        mensagem = codificar("UPDATE", id=lugar_id, estado=estado)

    sock.sendall(mensagem.encode())

    resposta = _receber_resposta(sock)
    print(f"[SERVIDOR -> Lugar {lugar_id}]: {resposta}")

    dados = descodificar(resposta)
    if dados.get("comando") == "ERRO":
        print(f"[ERRO] Lugar {lugar_id}: {dados.get('msg')}")


def simular_lugar(nome_lugar: str) -> None:
    """Simula o ciclo de vida de um lugar com reconexão automática e ID persistente."""
    estado = "LIVRE"

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                print(f"[INFO] ({nome_lugar}) A tentar ligação ao Parque em {HOST}:{PORT}...")
                sock.connect((HOST, PORT))
                print(f"[OK] ({nome_lugar}) Ligação estabelecida com o Parque.")

                try:
                    lugar_id = _obter_id(sock, nome_lugar)
                except (ConnectionError, ValueError) as exc:
                    print(f"[ERRO] ({nome_lugar}) Falha ao obter ID: {exc}")
                    time.sleep(3)
                    continue

                print(f"[INFO] ({nome_lugar}) Registado com ID {lugar_id}")

                while True:
                    time.sleep(INTERVALO_SIMULACAO)
                    estado = _proximo_estado(estado)
                    _enviar_atualizacao(sock, lugar_id, estado)

        except (ConnectionError, OSError) as exc:
            print(f"[AVISO] ({nome_lugar}) Ligação perdida ({exc}). Nova tentativa em 3 segundos...")
            time.sleep(3)
            continue

        except KeyboardInterrupt:
            print(f"\n[!] ({nome_lugar}) Simulação interrompida manualmente.")
            break



def _criar_threads_lugares() -> list[threading.Thread]:
    """Cria os lugares definidos na configuração."""
    threads: list[threading.Thread] = []
    for indice in range(LUGARES_CLIENTE):
        nome_lugar = f"{HOSTNAME}-Lugar-{indice+1}"
        thread = threading.Thread(target=simular_lugar, args=(nome_lugar,), name=nome_lugar, daemon=True)
        thread.start()
        threads.append(thread)
        time.sleep(0.3)
    return threads



def main() -> None:
    """Ponto de entrada do simulador quando executado como script."""
    print(f"[INFO] Máquina '{HOSTNAME}' vai simular {LUGARES_CLIENTE} lugares.")
    _criar_threads_lugares()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Simulação terminada.")


if __name__ == "__main__":
    main()