let dadosGlobais = [];
let cvssChart, vulnTypeChart, exploitChart, serviceChart;
let filtroIP = '';

document.getElementById('csvFile').addEventListener('change', function (e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        const text = e.target.result;
        const linhas = text.trim().split('\n');
        const cabecalhos = linhas[0].split(';');

        dadosGlobais = linhas.slice(1).map(linha => {
            const colunas = linha.split(';');
            const objeto = {};
            cabecalhos.forEach((col, idx) => {
                objeto[col.trim()] = colunas[idx]?.trim();
            });
            return objeto;
        });

        popularSelectIPs();
        filtroIP = '';
        document.getElementById('ipSelect').value = '';
        document.getElementById('filtroContainer').style.display = 'block';
        gerarGraficos(dadosGlobais);
    };
    reader.readAsText(file);
});

function popularSelectIPs() {
    const select = document.getElementById('ipSelect');
    while (select.options.length > 1) {
        select.remove(1);
    }

    const ips = [...new Set(dadosGlobais.map(v => v['Host/IP Afetado']).filter(ip => ip))];
    ips.sort();

    ips.forEach(ip => {
        const option = document.createElement('option');
        option.value = ip;
        option.textContent = ip;
        select.appendChild(option);
    });

    select.onchange = () => {
        filtroIP = select.value;
        const dadosFiltrados = filtrarPorIP(dadosGlobais, filtroIP);
        gerarGraficos(dadosFiltrados);
    };
}

function filtrarPorIP(dados, ip) {
    if (!ip) return dados;
    return dados.filter(v => v['Host/IP Afetado'] === ip);
}

function parseDateBR(dateStr) {
    if (!dateStr) return new Date(0);
    const partes = dateStr.split('/');
    if (partes.length !== 3) return new Date(0);
    return new Date(partes[2], partes[1] - 1, partes[0]);
}

function formatDateToBR(dateStr) {
    if (!dateStr) return '';
    if (dateStr.includes('-')) {
        const partes = dateStr.split('-');
        if (partes.length === 3) {
            return `${partes[2]}/${partes[1]}/${partes[0]}`;
        }
    }
    return dateStr;
}

function gerarGraficos(data) {
    const severidades = { 'Crítica': 0, 'Alta': 0, 'Média': 0, 'Baixa': 0, 'Informativa': 0 };
    const tipos = {
        'Misconfiguration': 0,
        'Vulnerability': 0,
        'Information': 0,
        'Default Credentials': 0,
        'Exposure': 0
    };
    const exploits = { Sim: 0, Nao: 0 };

    data.forEach(vuln => {
        const cvss = parseFloat(vuln['CVSS']);
        if (cvss >= 9.0) severidades['Crítica']++;
        else if (cvss >= 7.0) severidades['Alta']++;
        else if (cvss >= 4.0) severidades['Média']++;
        else if (cvss > 0.0) severidades['Baixa']++;
        else severidades['Informativa']++;

        const tipo = vuln['Tipo da Vulnerabilidade'];
        if (!(tipo in tipos)) tipos[tipo] = 0;
        tipos[tipo]++;

        const exploit = vuln['Exploit Disponível'];
        if (exploit === 'Sim' || exploit === 'Nao') {
            exploits[exploit]++;
        }
    });

    if (cvssChart) cvssChart.destroy();
    if (vulnTypeChart) vulnTypeChart.destroy();
    if (exploitChart) exploitChart.destroy();
    if (serviceChart) serviceChart.destroy(); // <-- ESSENCIAL

    cvssChart = new Chart(document.getElementById('cvssChart'), {
        type: 'bar',
        data: {
            labels: Object.keys(severidades),
            datasets: [{
                label: 'Número de Vulnerabilidades por Severidade',
                data: Object.values(severidades),
                backgroundColor: ['#d32f2f', '#f57c00', '#fbc02d', '#0288d1', '#9e9e9e']
            }]
        },
        options: {
            indexAxis: 'y',
            animation: { duration: 400 },
            scales: { x: { beginAtZero: true, precision: 0 } }
        }
    });

    vulnTypeChart = new Chart(document.getElementById('vulnTypeChart'), {
        type: 'pie',
        data: {
            labels: Object.keys(tipos),
            datasets: [{
                label: 'Tipos de Vulnerabilidade',
                data: Object.values(tipos),
                backgroundColor: [
                    '#42a5f5', '#66bb6a', '#ef5350', '#ffa726', '#ab47bc',
                    '#26c6da', '#8d6e63', '#d4e157', '#5c6bc0'
                ]
            }]
        },
        options: { animation: { duration: 400 } }
    });

    exploitChart = new Chart(document.getElementById('exploitChart'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(exploits),
            datasets: [{
                label: 'Exploit Disponível',
                data: Object.values(exploits),
                backgroundColor: ['#43a047', '#e53935']
            }]
        },
        options: { animation: { duration: 400 } }
    });

    const servicos = {};
    data.forEach(v => {
        const chave = `${v['Serviço/Porta']} (${v['Protocolo']})`;
        servicos[chave] = (servicos[chave] || 0) + 1;
    });

    serviceChart = new Chart(document.getElementById('serviceChart'), {
        type: 'bar',
        data: {
            labels: Object.keys(servicos),
            datasets: [{
                label: 'Vulnerabilidades por Serviço/Porta',
                data: Object.values(servicos),
                backgroundColor: '#29b6f6'
            }]
        },
        options: {
            indexAxis: 'y',
            scales: { x: { beginAtZero: true, precision: 0 } }
        }
    });

    const tabela = document.getElementById('timelineTable')?.querySelector('tbody');
    if (tabela) {
        tabela.innerHTML = '';

        const ordenados = [...data]
            .filter(v => v['Data da Descoberta'] && v['Vendor/Produto'] && v['ID/CVE'])
            .sort((a, b) => parseDateBR(formatDateToBR(a['Data da Descoberta'])) - parseDateBR(b['Data da Descoberta']));

        ordenados.forEach(v => {
            const tr = document.createElement('tr');

            const tdData = document.createElement('td');
            tdData.textContent = formatDateToBR(v['Data da Descoberta']);
            tdData.style.padding = '6px';

            const tdProduto = document.createElement('td');
            tdProduto.textContent = v['Vendor/Produto'];
            tdProduto.style.padding = '6px';

            const tdCVE = document.createElement('td');
            tdCVE.textContent = v['ID/CVE'];
            tdCVE.style.padding = '6px';

            tr.appendChild(tdData);
            tr.appendChild(tdProduto);
            tr.appendChild(tdCVE);

            tabela.appendChild(tr);
        });
    }
}
