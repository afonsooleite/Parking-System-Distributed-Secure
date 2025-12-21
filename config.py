# Configurações do Servidor

HOST = "10.8.0.181"     #IP da máquina onde corre o servidor
PORT = 54321
CAPACIDADE = 25         #Capacidade total do parque (máximo absoluto)

# Parâmetros de Simulação

PO = 0.25  # probabilidade de passar LIVRE -> OCUPADO
PL = 0.15  # probabilidade de passar OCUPADO -> LIVRE
INTERVALO_SIMULACAO = 20  # segundos entre cada atualização


# Opções de Depuração
LOG_VERBOSO = True
LUGARES_CLIENTE = 10