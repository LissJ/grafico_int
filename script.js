// Variáveis globais
let dadosGlobais = [];
let cvssChart, vulnTypeChart, exploitChart, serviceChart;
let filtroIP = '';
let filtroCor = ''; // <<< NOVO: guarda o valor selecionado no filtro de cor

/**
 * Lê todo o texto CSV e devolve uma “matriz” JS (array de linhas),
 * onde cada linha é um array de colunas. 
 * Essa função respeita aspas, vírgulas internas e quebras de linha dentro das aspas.
 */
function parseCSV(text) {
    const linhas = [];
    let curLine = [];
    let curCell = '';
    let insideQuotes = false;

    for (let i = 0; i < text.length; i++) {
        const char = text[i];

        if (char === '"' && (i === 0 || text[i - 1] !== '\\')) {
            insideQuotes = !insideQuotes;
            continue;
        }

        if (char === ',' && !insideQuotes) {
            curLine.push(curCell.trim());
            curCell = '';
            continue;
        }

        if ((char === '\n' || char === '\r') && !insideQuotes) {
            if (char === '\r' && text[i + 1] === '\n') {
                i++;
            }
            curLine.push(curCell.trim());
            curCell = '';
            linhas.push(curLine);
            curLine = [];
            continue;
        }

        curCell += char;
    }

    if (curCell.length > 0) {
        curLine.push(curCell.trim());
    }
    if (curLine.length > 0) {
        linhas.push(curLine);
    }

    // Remove aspas externas de cada célula
    return linhas.map(linha =>
        linha.map(cel => {
            if (cel.startsWith('"') && cel.endsWith('"')) {
                return cel.slice(1, -1);
            }
            return cel;
        })
    );
}

/**
 * Restaura o estado da dashboard quando volta da página de detalhes
 * sem exigir recarregar o CSV.
 */
window.addEventListener('pageshow', () => {
    const estadoSalvo = sessionStorage.getItem('dashboardState');
    if (estadoSalvo) {
        const { dadosGlobais: savedDados, filtroIP: savedFiltro, filtroCor: savedFiltroCor } = JSON.parse(estadoSalvo);
        dadosGlobais = savedDados;
        filtroIP = savedFiltro;
        filtroCor = savedFiltroCor; // <<< NOVO: recupera filtro de cor também

        // Ajusta os filtros na interface
        document.getElementById('filtroContainer').style.display = 'block';
        document.getElementById('ipSelect').value = filtroIP;
        document.getElementById('colorSelect').value = filtroCor; // <<< NOVO

        // Recria o select de IPs e os gráficos
        popularSelectIPs();
        gerarGraficos(
            filtroIP
                ? dadosGlobais.filter(v => v['ip'] === filtroIP)
                : dadosGlobais
        );

        // Exibe a tabela e o botão “Ver mais”, pois já havia dados carregados
        document.getElementById('timelineTable').style.display = 'table';
        document.getElementById('verMaisContainer').style.display = 'block';

        sessionStorage.removeItem('dashboardState');
    }
});

// Carrega arquivo CSV e inicializa tudo
document.getElementById('csvFile').addEventListener('change', function (e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        const text = e.target.result;

        // Usa parseCSV para lidar com vírgulas internas em aspas
        const matriz = parseCSV(text);

        // Cabeçalho
        const cabecalhos = matriz[0];

        // Dados
        dadosGlobais = matriz.slice(1).map(colunas => {
            const obj = {};
            cabecalhos.forEach((col, idx) => {
                obj[col] = colunas[idx] || '';
            });
            return obj;
        });

        popularSelectIPs();
        filtroIP = '';
        filtroCor = ''; // <<< NOVO: zera filtro de cor ao trocar o CSV
        document.getElementById('ipSelect').value = '';
        document.getElementById('colorSelect').value = ''; // <<< NOVO
        document.getElementById('filtroContainer').style.display = 'block';

        gerarGraficos(dadosGlobais);

        document.getElementById('timelineTable').style.display = 'table';
        document.getElementById('verMaisContainer').style.display = 'block';
    };
    reader.readAsText(file);
});

// Popula o <select> de IPs
function popularSelectIPs() {
    const select = document.getElementById('ipSelect');
    while (select.options.length > 1) {
        select.remove(1);
    }

    const ips = [...new Set(dadosGlobais.map(v => v['ip']).filter(ip => ip))].sort();
    ips.forEach(ip => {
        const opt = document.createElement('option');
        opt.value = ip;
        opt.textContent = ip;
        select.appendChild(opt);
    });

    select.onchange = () => {
        filtroIP = select.value;
        const filtrados = filtroIP
            ? dadosGlobais.filter(v => v['ip'] === filtroIP)
            : dadosGlobais;
        gerarGraficos(filtrados);
    };
}

// Filtra array por IP
function filtrarPorIP(dados, ip) {
    return ip ? dados.filter(v => v['ip'] === ip) : dados;
}

// Converte DD/MM/AAAA para Date
function parseDateBR(dateStr) {
    if (!dateStr) return new Date(0);
    const partes = dateStr.split('/');
    if (partes.length !== 3) return new Date(0);
    return new Date(partes[2], partes[1] - 1, partes[0]);
}

// Converte AAAA-MM-DD ou AAAA-MM-DDTHH:MM:SS para DD/MM/AAAA ou retorna tal como está
function formatDateToBR(dateStr) {
    if (!dateStr) return '';
    if (dateStr.includes('T')) {
        dateStr = dateStr.split('T')[0];
    }
    if (dateStr.includes('-')) {
        const partes = dateStr.split('-');
        if (partes.length === 3) {
            return `${partes[2]}/${partes[1]}/${partes[0]}`;
        }
    }
    return dateStr;
}

// Gera todos os gráficos e popula a tabela com clique para detalhes
function gerarGraficos(data) {
    // 1) APLICAR FILTRO DE COR ANTES DE PINTAR A TABELA:
    let dadosFiltrados = data.slice();
    if (filtroCor) {
        dadosFiltrados = dadosFiltrados.filter(v => {
            const cvss = parseFloat(v['cvss_score']) || 0;
            if (filtroCor === 'red') {
                return cvss >= 9;
            }
            if (filtroCor === 'orange') {
                return cvss >= 7 && cvss < 9;
            }
            if (filtroCor === 'green') {
                return cvss > 0 && cvss < 7;
            }
            if (filtroCor === 'gray') {
                return cvss === 0;
            }
            return true;
        });
    }

    // --- Calcula métricas (gráficos) com base em data (não muda por cor) ---
    // --- Severidades ---
    const severidades = { 'Crítica': 0, 'Alta': 0, 'Média': 0, 'Baixa': 0, 'Informativa': 0 };
    dadosFiltrados.forEach(v => {
        const cvss = parseFloat(v['cvss_score']) || 0;
        if (cvss >= 9) severidades['Crítica']++;
        else if (cvss >= 7) severidades['Alta']++;
        else if (cvss >= 4) severidades['Média']++;
        else if (cvss > 0) severidades['Baixa']++;
        else severidades['Informativa']++;
    });

    // --- Tipos de vulnerabilidade (sem "undefined") ---
    const tipos = {};
    dadosFiltrados.forEach(v => {
        const tpBruto = v['tipo_vulnerabilidade'];
        const tp = tpBruto && tpBruto.trim() !== '' ? tpBruto : 'Outro';
        tipos[tp] = (tipos[tp] || 0) + 1;
    });

    // --- Exploit disponível (Sim / Não) ---
    const exploits = { Sim: 0, Nao: 0 };
    dadosFiltrados.forEach(v => {
        const ex = v['exploit_disponivel'];
        if (ex === 'Sim') exploits['Sim']++;
        else if (ex === 'Não') exploits['Nao']++;
        // caso esteja vazio ou “undefined”, ignora
    });

    // --- Destroi gráficos antigos ---
    [cvssChart, vulnTypeChart, exploitChart, serviceChart].forEach(ch => ch && ch.destroy());

    // --- Cria CVSS Chart com legenda desabilitada (sem “undefined”) ---
    cvssChart = new Chart(document.getElementById('cvssChart'), {
        type: 'bar',
        data: {
            labels: Object.keys(severidades),
            datasets: [{
                data: Object.values(severidades),
                backgroundColor: ['#002171', '#1565C0', '#1976D2', '#42A5F5', '#90CAF9']
            }]
        },
        options: {
            indexAxis: 'y',
            scales: { x: { beginAtZero: true, precision: 0 } },
            animation: { duration: 400 },
            responsive: false,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false  // legenda removida para não exibir “undefined”
                }
            }
        }
    });

    // --- Cria Vulnerability Type Chart (sem undefined, pois labels vêm de "tipos") ---
    const labelsTipos = Object.keys(tipos);
    const dataTipos = Object.values(tipos);
    vulnTypeChart = new Chart(document.getElementById('vulnTypeChart'), {
        type: 'pie',
        data: {
            labels: labelsTipos,
            datasets: [{
                data: dataTipos,
                backgroundColor: ['#002171', '#42A5F5', '#90CAF9', '#1565C0', '#0D47A1']
            }]
        },
        options: {
            animation: { duration: 400 },
            responsive: false,
            maintainAspectRatio: false,
            // aqui a legenda será exibida com "labelsTipos" (não aparece undefined)
        }
    });

    // --- Cria Exploit Chart (vulnerabilidades por IP) sem legenda ---
    const vulnerabilidadesPorIP = {};
    dadosFiltrados.forEach(v => {
        const ip = v['ip'] && v['ip'].trim() !== '' ? v['ip'] : 'Desconhecido';
        vulnerabilidadesPorIP[ip] = (vulnerabilidadesPorIP[ip] || 0) + 1;
    });
    const labelsIPs = Object.keys(vulnerabilidadesPorIP);
    const dataIPs = Object.values(vulnerabilidadesPorIP);

    exploitChart = new Chart(document.getElementById('exploitChart'), {
        type: 'bar',
        data: {
            labels: labelsIPs,
            datasets: [{
                data: dataIPs,
                backgroundColor: '#0D47A1'
            }]
        },
        options: {
            indexAxis: 'x',
            scales: {
                y: {
                    beginAtZero: true,
                    precision: 0
                }
            },
            animation: { duration: 400 },
            responsive: false,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false  // remove legenda para não exibir “undefined”
                }
            }
        }
    });

    // --- Cria Service/Port Chart (sem undefined) sem legenda ---
    const servicos = {};
    dadosFiltrados.forEach(v => {
        const portaBruto = v['servico_porta'];
        const protocoloBruto = v['protocolo'];
        const porta = portaBruto && portaBruto.trim() !== '' ? portaBruto : 'Desconhecido';
        const protocolo = protocoloBruto && protocoloBruto.trim() !== '' ? protocoloBruto : '';
        const key = protocolo ? `${porta} (${protocolo})` : porta;
        servicos[key] = (servicos[key] || 0) + 1;
    });
    const labelsServicos = Object.keys(servicos);
    const dataServicos = Object.values(servicos);

    serviceChart = new Chart(document.getElementById('serviceChart'), {
        type: 'bar',
        data: {
            labels: labelsServicos,
            datasets: [{
                data: dataServicos,
                backgroundColor: '#42A5F5'
            }]
        },
        options: {
            indexAxis: 'y',
            scales: { x: { beginAtZero: true, precision: 0 } },
            responsive: false,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false  // remove legenda para não exibir “undefined”
                }
            }
        }
    });

    // --- Popula Tabela e adiciona clique para detalhes ---  
    const tbody = document.querySelector('#timelineTable tbody');
    tbody.innerHTML = '';

    const ordenados = dadosFiltrados
        .filter(v => v['data_descoberta'] && v['title'] && v['cve_id'])
        .sort((a, b) =>
            parseDateBR(formatDateToBR(a['data_descoberta'])) -
            parseDateBR(formatDateToBR(b['data_descoberta']))
        );

    const MAX_LINHAS = 5;
    let indiceAtual = MAX_LINHAS;

    const todasAsLinhas = [];

    ordenados.forEach((v, index) => {
        const tr = document.createElement('tr');
        tr.classList.add('linha-timeline');

        tr.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
        tr.style.opacity = index < MAX_LINHAS ? '1' : '0';
        tr.style.transform = index < MAX_LINHAS ? 'translateY(0)' : 'translateY(-20px)';
        tr.style.overflow = 'hidden';
        tr.style.display = index < MAX_LINHAS ? 'table-row' : 'none';

        ['data_descoberta', 'title', 'cve_id'].forEach((f, i) => {
            const td = document.createElement('td');
            let valor = v[f];

            if (i === 0) {
                td.textContent = formatDateToBR(valor);
            } else {
                td.textContent = valor;
            }

            td.style.padding = '6px';

            // Aplica cor na coluna cve_id com base na nota CVSS
            if (f === 'cve_id') {
                const nota = parseFloat(v['cvss_score']) || 0;

                if (nota >= 9) {
                    td.style.color = 'red';
                    td.style.fontWeight = 'bold';
                } else if (nota >= 7) {
                    td.style.color = 'orange';
                    td.style.fontWeight = 'bold';
                } else if (nota > 0) {
                    td.style.color = 'green';
                    td.style.fontWeight = 'bold';
                } else {
                    td.style.color = 'gray';
                }
            }

            tr.appendChild(td);
        });

        tr.addEventListener('click', () => {
            sessionStorage.setItem('vulnDetalhe', JSON.stringify(v));
            sessionStorage.setItem('dashboardState', JSON.stringify({
                dadosGlobais,
                filtroIP,
                filtroCor // <<< NOVO: salva também o filtro de cor
            }));
            window.location.href = 'detalhes.html';
        });

        tbody.appendChild(tr);
        todasAsLinhas.push(tr);
    });

    // Botão “Ver mais / Ver menos”
    const botao = document.getElementById('verMaisBtn');
    if (ordenados.length <= MAX_LINHAS) {
        botao.style.display = 'none';
    } else {
        botao.style.display = 'inline-block';
    }

    let estado = 'mais'; // mais, tudo, menos

    botao.addEventListener('click', () => {
        if (estado === 'mais') {
            const limite = Math.min(indiceAtual + MAX_LINHAS, todasAsLinhas.length);
            for (let i = indiceAtual; i < limite; i++) {
                const tr = todasAsLinhas[i];
                tr.style.display = 'table-row';
                setTimeout(() => {
                    tr.style.opacity = '1';
                    tr.style.transform = 'translateY(0)';
                }, (i - indiceAtual) * 100);
            }
            indiceAtual = limite;
            if (indiceAtual >= todasAsLinhas.length) {
                botao.textContent = 'Ver menos';
                estado = 'menos';
            } else {
                botao.textContent = 'Ver tudo';
                estado = 'tudo';
            }
        } else if (estado === 'tudo') {
            for (let i = indiceAtual; i < todasAsLinhas.length; i++) {
                const tr = todasAsLinhas[i];
                tr.style.display = 'table-row';
                setTimeout(() => {
                    tr.style.opacity = '1';
                    tr.style.transform = 'translateY(0)';
                }, (i - indiceAtual) * 100);
            }
            indiceAtual = todasAsLinhas.length;
            botao.textContent = 'Ver menos';
            estado = 'menos';
        } else if (estado === 'menos') {
            for (let i = MAX_LINHAS; i < todasAsLinhas.length; i++) {
                const tr = todasAsLinhas[i];
                setTimeout(() => {
                    tr.style.opacity = '0';
                    tr.style.transform = 'translateY(-20px)';
                }, (todasAsLinhas.length - i) * 60);

                setTimeout(() => {
                    tr.style.display = 'none';
                }, 400 + (todasAsLinhas.length - i) * 60);
            }
            indiceAtual = MAX_LINHAS;
            botao.textContent = 'Ver mais';
            estado = 'mais';
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const colorSelect = document.getElementById('colorSelect');
    if (colorSelect) {
        colorSelect.onchange = () => {
            filtroCor = colorSelect.value;              // guarda a cor selecionada
            const filtradosPorIP = filtroIP
                ? dadosGlobais.filter(v => v['ip'] === filtroIP)
                : dadosGlobais;
            gerarGraficos(filtradosPorIP);
        };
    }
});