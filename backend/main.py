"""
Security Operations Center (SOC) - Mini-SIEM Engine v1.0
Componente: Backend Core (Coletor e Motor de Correlação)
Arquitetura: FastAPI / Processamento de Eventos Assíncronos

Este módulo é responsável por expor endpoints para recebimento de logs remotos
e processar strings textuais utilizando Expressões Regulares para identificar
indicadores de comprometimento (IoC) em tempo real.
"""

# Importação da biblioteca de Expressões Regulares nativa do Python
import re
# Importação de tipos estruturados para tipagem estática (Type Hinting)
from typing import List, Dict, Any
# Importação da biblioteca de manipulação de data e hora para correlação temporal
from datetime import datetime
# Importação dos componentes estruturais da API do framework FastAPI
from fastapi import FastAPI, HTTPException, status
# Importação do middleware necessário para habilitar políticas de segurança CORS
from fastapi.middleware.cors import CORSMiddleware
# Importação do componente de validação e modelagem de dados da biblioteca Pydantic
from pydantic import BaseModel

# Inicialização e configuração da instância global do FastAPI com metadados públicos
app = FastAPI(
    title="Security Tools - Mini SIEM Engine",
    description="Motor de correlação de eventos e análise de logs de segurança em tempo real.",
    version="1.0.0"
)

# Injeção das configurações de CORS para permitir requisições de front-ends desacoplados
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Permite requisições originadas de qualquer endereço de IP ou domínio
    allow_credentials=True, # Habilita suporte ao tráfego de cookies e credenciais HTTP
    allow_methods=["*"], # Permite a execução de qualquer método HTTP (GET, POST, DELETE, etc)
    allow_headers=["*"], # Permite o uso de qualquer cabeçalho de metadados nas requisições
)

# -------------------------------------------------------------------------
# PADRÕES DE REGEX (ASSINATURAS DE ATAQUE)
# -------------------------------------------------------------------------
# Compilação prévia da Regex para otimizar a performance de busca em strings de log SSH
# O padrão mapeia e isola os grupos nomeados 'timestamp', 'user' e 'ip'
SSH_AUTH_FAIL_REGEX = re.compile(
    r'(?P<timestamp>\b[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\b).*' # Captura o carimbo de data/hora do Linux
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # Captura usuário e IP de origem
)

# -------------------------------------------------------------------------
# MODELOS DE DADOS (SCHEMAS PYDANTIC)
# -------------------------------------------------------------------------
class LogPayload(BaseModel):
    """
    Define a estrutura do objeto JSON aceito pelo endpoint de ingestão.
    Valida se a entrada contém obrigatoriamente a chave string 'log_line'.
    """
    log_line: str

class AlertResponse(BaseModel):
    """
    Define a estrutura de serialização dos dados enviados para a interface gráfica.
    Garante a integridade tipada dos dados consumidos pelo JavaScript do front-end.
    """
    id: int
    timestamp: str
    event_type: str
    source_ip: str
    target_user: str
    severity: str
    raw_message: str

# -------------------------------------------------------------------------
# ARMAZENAMENTO E ESTADO EM MEMÓRIA (VOLATILE STATE)
# -------------------------------------------------------------------------
# Lista global que atua como banco de dados temporário para armazenar os alertas estruturados
ALERTS_DATABASE: List[Dict[str, Any]] = []

# Contador global incremental utilizado para gerar chaves primárias (IDs únicos) para os alertas
ALERT_COUNTER = 0

# Dicionário indexado por IP para rastrear cronologicamente os horários das tentativas falhas
IP_EVENT_TRACKER: Dict[str, List[datetime]] = {}

# -------------------------------------------------------------------------
# FUNÇÕES DE LÓGICA E CORRELAÇÃO DE SEGURANÇA
# -------------------------------------------------------------------------
def correlate_event(log_line: str) -> None:
    """
    Analisa a linha bruta de log recebida, extrai metadados via Expressão Regular 
    e aplica as regras de correlação de frequência baseadas na janela temporal.
    """
    global ALERT_COUNTER # Habilita a modificação do contador de IDs global
    
    # Executa a busca pelo padrão de falha de login SSH dentro da string bruta
    match = SSH_AUTH_FAIL_REGEX.search(log_line)
    
    # Se a linha de log corresponder à assinatura de uma falha de autenticação SSH:
    if match:
        # Extrai os grupos identificados na Regex e os transforma em um dicionário Python
        data = match.groupdict()
        source_ip = data["ip"] # Isola o endereço IP do gerador do evento
        target_user = data["user"] # Isola o nome do usuário que sofreu a tentativa de login
        
        # Captura o horário exato em que o servidor central processou a requisição
        now = datetime.now()
        
        # Caso o IP atual não possua histórico no rastreador, inicializa uma lista vazia
        if source_ip not in IP_EVENT_TRACKER:
            IP_EVENT_TRACKER[source_ip] = []
            
        # Adiciona o carimbo de data/hora atual ao histórico específico do IP atacante
        IP_EVENT_TRACKER[source_ip].append(now)
        
        # Filtra o histórico do IP mantendo apenas as tentativas ocorridas nos últimos 60 segundos
        IP_EVENT_TRACKER[source_ip] = [
            t for t in IP_EVENT_TRACKER[source_ip] if (now - t).total_seconds() <= 60
        ]
        
        # Contabiliza o volume de eventos remanescentes dentro da janela ativa de 1 minuto
        attempts_count = len(IP_EVENT_TRACKER[source_ip])
        
        # REGRA DE NEGÓCIO DO SIEM: Classificação de criticidade com base na frequência
        if attempts_count >= 5:
            severity = "CRÍTICA (Possível Brute Force Ativo)" # Condição de ataque volumétrico volumoso
        elif attempts_count >= 3:
            severity = "MÉDIA (Múltiplas Falhas de Login)" # Condição de anomalia moderada
        else:
            severity = "BAIXA (Falha Isolada de Autenticação)" # Erro de digitação comum do usuário
            
        # Incrementa o indexador sequencial de alertas
        ALERT_COUNTER += 1
        
        # Monta o objeto de incidente estruturado com os dados normalizados
        alert = {
            "id": ALERT_COUNTER,
            "timestamp": data["timestamp"],
            "event_type": "Tentativa de Acesso Não Autorizado (SSH)",
            "source_ip": source_ip,
            "target_user": target_user,
            "severity": severity,
            "raw_message": log_line.strip() # Remove espaços em branco residuais das extremidades
        }
        
        # Insere o novo alerta no índice zero da lista (Ordem cronológica inversa para exibição)
        ALERTS_DATABASE.insert(0, alert)

# -------------------------------------------------------------------------
# ENDPOINTS DA API REST
# -------------------------------------------------------------------------
@app.post("/api/v1/ingest", status_code=status.HTTP_202_ACCEPTED, tags=["Ingestão"])
async def ingest_log(payload: LogPayload):
    """
    Endpoint de recepção de telemetria. É consumido pelos agentes de coleta 
    remotos para submissão e encaminhamento de linhas de log do sistema.
    """
    # Validação de segurança primária: impede o processamento de payloads nulos ou vazios
    if not payload.log_line:
        raise HTTPException(status_code=400, detail="O conteúdo da linha de log não pode estar vazio.")
    
    # Envia a linha bruta para validação das assinaturas no motor de correlação
    correlate_event(payload.log_line)
    
    # Retorna uma confirmação assíncrona HTTP 202 sinalizando aceitação para análise
    return {"status": "processed", "correlated": True}

@app.get("/api/v1/alerts", response_model=List[AlertResponse], tags=["Monitoramento"])
async def get_alerts():
    """
    Endpoint de monitoramento. É consultado periodicamente pelo JavaScript 
    do painel visual para coletar o histórico de incidentes ativos.
    """
    # Retorna a lista atual de alertas armazenados na memória RAM do servidor
    return ALERTS_DATABASE

@app.delete("/api/v1/alerts", status_code=status.HTTP_204_NO_CONTENT, tags=["Gerenciamento"])
async def clear_alerts():
    """
    Endpoint de administração. Limpa integralmente a base de dados em memória
    volátil, redefinindo o estado dos painéis métricos do SOC.
    """
    global ALERTS_DATABASE # Permite a reatribuição da variável da lista global
    ALERTS_DATABASE.clear() # Apaga todas as entradas do banco em memória
    return None # Retorna um payload vazio acompanhado do status HTTP 204

# Bloqueio padrão para impedir a execução acidental do servidor caso seja importado como módulo
if __name__ == "__main__":
    import uvicorn
    # Inicialização física do servidor HTTP na porta 8000 escutando em todas as interfaces de rede
    uvicorn.run("main.py:app", host="0.0.0.0", port=8000, reload=True)  