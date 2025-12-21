# protocolo.py
DELIMITADOR = ";;"

class ProtocoloErro(Exception):
    """Exceção base para erros de protocolo."""

class FormatoInvalido(ProtocoloErro):
    pass

class ComandoInvalido(ProtocoloErro):
    pass

class ParametrosInvalidos(ProtocoloErro):
    pass


def codificar(comando: str, **kwargs) -> str:
    """
    Gera uma mensagem no formato do protocolo.
    Exemplo: codificar("UPDATE", id=3, estado="OCUPADO")
    -> "UPDATE;;id=3;;estado=OCUPADO"
    """
    partes = [comando] + [f"{k}={v}" for k, v in kwargs.items()]
    return DELIMITADOR.join(partes)


def descodificar(mensagem: str) -> dict:
    """
    Converte uma mensagem em dicionário validado.
    Aceita comandos simples (ex: "INIT") ou com parâmetros (ex: "UPDATE;;id=1;;estado=LIVRE").
    """
    partes = mensagem.split(DELIMITADOR)
    comando = partes[0].strip().upper()
    if not comando:
        raise ComandoInvalido("Comando vazio")

    dados = {}
    for p in partes[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            dados[k.strip()] = v.strip()
        elif p.strip():  # havia texto mas sem '='
            raise FormatoInvalido(f"Parâmetro mal formatado: {p}")

    return {"comando": comando, **dados}