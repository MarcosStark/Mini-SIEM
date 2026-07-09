/**
 * Security Tools - SIEM Dashboard Controller
 * Componente: Lógica de Front-end e Consumo de API
 * Mecanismo: Polling Assíncrono Contínuo
 */

// Constantes de configuração global do ecossistema front-end
const API_BASE_URL = "http://127.0.0.1:8000/api/v1"; // Endereço de comunicação do backend
const POLL_INTERVAL_MS = 2000;                      // Ciclo automático de atualização (2 segundos)

// Captura e inicialização de instâncias dos elementos estruturais do DOM
const alertsTbody = document.getElementById("alerts-tbody"); // Corpo receptor da tabela
const countLow = document.getElementById("count-low");       // Elemento contador de nível Baixo
const countMedium = document.getElementById("count-medium"); // Elemento contador de nível Médio
const countCritical = document.getElementById("count-critical"); // Elemento contador de nível Crítico
const btnClear = document.getElementById("btn-clear");       // Botão de controle de limpeza

/**
 * Efetua chamadas assíncronas assinaladas via Fetch API ao endpoint de listagem
 * e repassa o array de resposta obtido para a função de tratamento de tela.
 */
async function fetchAlerts() {
    try {
        // Dispara uma requisição GET HTTP nativa para buscar os incidentes salvos
        const response = await fetch(`${API_BASE_URL}/alerts`);
        
        // Dispara um erro técnico caso o backend retorne status inválido (ex: 500 ou 404)
        if (!response.ok) throw new Error("Falha ao consultar a API do SIEM.");
        
        // Realiza o parsing de conversão da string JSON de resposta em um array utilizável
        const alerts = await response.json();
        
        // Encaminha os objetos convertidos para atualização física dos componentes visuais
        renderDashboard(alerts);
    } catch (error) {
        // Captura e expõe falhas de conectividade ou rede no console do desenvolvedor
        console.error("Erro na sincronização de dados:", error);
    }
}

/**
 * Processa a re-renderização completa da tabela de segurança e recalcula
 * as somas aritméticas dos blocos de métricas superiores.
 */
function renderDashboard(alerts) {
    // Inicialização local de contadores matemáticos zerados para recontagem ativa
    let low = 0, medium = 0, critical = 0;
    
    // Zera fisicamente todas as linhas antigas existentes no corpo da tabela (evita duplicações)
    alertsTbody.innerHTML = "";

    // Itera sequencialmente sobre cada objeto de alerta presente na resposta do backend
    alerts.forEach(alert => {
        // Classifica e incrementa os contadores comparando termos chaves da string 'severity'
        if (alert.severity.includes("BAIXA")) low++;
        else if (alert.severity.includes("MÉDIA")) medium++;
        else if (alert.severity.includes("CRÍTICA")) critical++;

        // Define a classe de estilização CSS que gerenciará a colorização da célula
        let severityClass = "sev-low";
        if (alert.severity.includes("MÉDIA")) severityClass = "sev-medium";
        if (alert.severity.includes("CRÍTICA")) severityClass = "sev-critical";

        // Cria dinamicamente um novo nó de linha estrutural (tr) para inserção no documento
        const row = document.createElement("tr");
        
        // Define o conteúdo interno em formato de células (td), normalizando os dados extraídos
        row.innerHTML = `
            <td>#${alert.id}</td>
            <td>${alert.timestamp}</td>
            <td>${alert.event_type}</td>
            <td><code>${alert.source_ip}</code></td>
            <td><code>${alert.target_user}</code></td>
            <td class="${severityClass}">${alert.severity}</td>
        `;
        
        // Anexa a linha estruturada ao final do corpo da tabela ativa na tela
        alertsTbody.appendChild(row);
    });

    // Atualiza dinamicamente as strings de texto dos nós superiores do DOM com as novas somas
    countLow.textContent = low;
    countMedium.textContent = medium;
    countCritical.textContent = critical;
}

/**
 * Escuta e trata cliques físicos efetuados sobre o botão de limpeza.
 * Dispara comando DELETE para esvaziar o estado em memória volátil do SIEM.
 */
btnClear.addEventListener("click", async () => {
    try {
        // Executa a chamada HTTP utilizando explicitamente o método de deleção
        const response = await fetch(`${API_BASE_URL}/alerts`, { method: "DELETE" });
        
        // Verifica se o backend aceitou e processou sem erros (Status HTTP 204 No Content)
        if (response.status === 204) {
            // Força uma atualização imediata da tela para exibir o painel zerado
            fetchAlerts();
        }
    } catch (error) {
        console.error("Erro ao emitir comando de limpeza:", error);
    }
});

// Execução primária imediata da rotina de busca de dados ao carregar a página
fetchAlerts();

// Agenda a execução perpétua em loop della rotina de busca obedecendo o intervalo configurado
setInterval(fetchAlerts, POLL_INTERVAL_MS);