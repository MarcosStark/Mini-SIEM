# 🔍 Security Tools - Mini SIEM Engine v1.0

![Python](https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow?style=for-the-badge&logo=javascript)
![Linux](https://img.shields.io/badge/Linux-Supported-FCC624?style=for-the-badge&logo=linux)

Um **SIEM (Security Information and Event Management)** leve e funcional desenvolvido em Python/FastAPI e JavaScript, focado no monitoramento e na correlação em tempo real de falhas de autenticação SSH em ambiente de rede local.

---

## 💡 Sobre o Projeto

O **Mini-SIEM** simula a arquitetura real de uma operação de SOC (*Security Operations Center*). O sistema é dividido em três camadas principais:

1. **Agente de Coleta Remota (`agent_forwarder.py`)**: Executado em uma máquina remota (Linux), atua lendo o arquivo `/var/log/auth.log` incrementalmente em tempo real (estratégia similar ao `tail -f`) e encaminhando cada evento bruto para a API Central.
2. **Backend Engine (`main.py`)**: Construído com **FastAPI**, expõe endpoints REST para ingestão e consulta. Utiliza Expressões Regulares (Regex) para extrair metadados (*Timestamp*, *IP*, *Usuário*) e aplica uma **regra de correlação temporal** (janela deslizante de 60 segundos) para determinar o nível de severidade.
3. **Painel SOC Visual (`index.html`)**: Interface web moderna em *Dark Mode* que realiza *polling* assíncrono para renderizar os alertas, atualizar métricas e destacar possíveis ataques de Força Bruta em tempo real.

---

## 🛠️ Tecnologias Utilizadas

- **Backend**: Python 3.13, FastAPI, Uvicorn, Pydantic, Regular Expressions (`re`).
- **Front-end**: HTML5, CSS3 (CSS Variables, Grid/Flexbox), JavaScript Puro (Fetch API, Async/Await).
- **Agente Remoto**: Python 3 (Apenas bibliotecas nativas: `urllib`, `json`, `os`, `time`).

---

## 📊 Regras de Correlação & Severidade

O motor analisa a frequência de falhas de autenticação vindas de um mesmo IP de origem em uma janela de **60 segundos**:

| Severidade | Condição Frequencial | Classificação no Painel |
| :--- | :--- | :--- |
| **🟢 BAIXA** | 1 a 2 tentativas falhas / min | Falha Isolada de Autenticação |
| **🟠 MÉDIA** | 3 a 4 tentativas falhas / min | Múltiplas Falhas de Login |
| **🔴 CRÍTICA** | 5+ tentativas falhas / min | **Possível Brute Force Ativo** |

---

## 🚀 Como Executar o Projeto

### Pré-requisitos
- Python 3.10 ou superior instalado no servidor central.
- Acesso à rede local entre a máquina do SIEM e a máquina monitorada.

---

### 1️⃣ Inicializando o Backend (Servidor Central)

1. Navegue até a pasta do backend:
   ```bash
   cd backend
   ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

3. Inicie o servidor escutando em todas as interfaces da rede:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

---

### 2️⃣ Abrindo o Painel Web (SOC Dashboard)

1. Navegue até a pasta `frontend/`.
2. Abra o arquivo `index.html` em qualquer navegador web.

---

### 3️⃣ Executando o Agente no Computador Monitorado (Linux)

1. Copie o arquivo `agent_forwarder.py` para a máquina Linux.
2. Verifique o IP do seu Servidor Central e ajuste a variável `SIEM_API_URL` dentro do script.
3. Execute o agente com privilégios administrativos:
   ```bash
   sudo python3 agent_forwarder.py
   ```
