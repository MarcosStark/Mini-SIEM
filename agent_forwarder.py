"""
Security Operations Center (SOC) - SIEM Log Forwarder Agent
Componente: Agente de Coleta Remota (Dispositivo Monitorado)
Plataforma Alvo: Linux (Ubuntu/Debian/Kali)

Este script monitora incrementalmente arquivos de log do sistema em tempo real
e realiza o encaminhamento dos dados via requisições HTTP para a API central do SIEM.
"""

import time
import os
import urllib.request
import json

# -------------------------------------------------------------------------
# CONFIGURAÇÕES DO AGENTE
# -------------------------------------------------------------------------
# Endereço IP privado do Computador Principal onde o backend do SIEM está rodando
SIEM_API_URL = "http://192.168.18.5:8000/api/v1/ingest"

# Caminho absoluto do arquivo de log de autenticação nativo de sistemas Debian/Ubuntu
LOG_FILE_PATH = "/var/log/auth.log"

def send_log_to_siem(log_line: str) -> None:
    """
    Estrutura a linha bruta de texto em um payload JSON e realiza a transmissão
    assíncrona para a API do servidor central do SIEM.
    """
    payload = json.dumps({"log_line": log_line}).encode("utf-8")
    
    req = urllib.request.Request(
        SIEM_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            if response.status != 202:
                print(f"[-] Resposta inesperada do servidor SIEM: {response.status}")
    except Exception as e:
        print(f"[-] Falha ao transmitir evento para o SIEM Central: {e}")

def watch_log_file():
    """
    Abre o arquivo de log do Linux, move o cursor de leitura para o final do arquivo
    e entra em loop contínuo capturando e enviando novas linhas em tempo real.
    """
    print(f"[*] Inicializando monitoramento ativo do arquivo: {LOG_FILE_PATH}")
    print(f"[*] Direcionando alertas para o SIEM Central em: {SIEM_API_URL}")
    
    if not os.path.exists(LOG_FILE_PATH):
        print(f"[-] Erro crítico: O arquivo {LOG_FILE_PATH} não foi localizado.")
        print("[*] Verifique se o serviço rsyslog está ativo ou se o caminho está correto.")
        return

    try:
        with open(LOG_FILE_PATH, "r", errors="ignore") as file:
            # Move o ponteiro de leitura para o final do arquivo (estratégia similar ao 'tail -f')
            file.seek(0, os.SEEK_END)
            
            while True:
                line = file.readline()
                
                if not line:
                    time.sleep(0.5)
                    continue
                
                if line.strip():
                    send_log_to_siem(line)
                    
    except PermissionError:
        print("[-] Erro de Permissão: O agente precisa de privilégios elevados para ler os logs do sistema.")
        print("[*] Execute novamente utilizando o comando: sudo python3 agent_forwarder.py")
    except KeyboardInterrupt:
        print("\n[*] Encerrando execução do agente de coleta remota.")

if __name__ == "__main__":
    watch_log_file()