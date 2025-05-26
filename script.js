// Variáveis globais
let dadosGlobais = [];
let cvssChart, vulnTypeChart, exploitChart, serviceChart;
let filtroIP = '';

/**
 * Restaura o estado da dashboard quando volta da página de detalhes
 * sem exigir recarregar o CSV.
 */
window.addEventListener('pageshow', () => {
  const estadoSalvo = sessionStorage.getItem('dashboardState');
  if (estadoSalvo) {
    const { dadosGlobais: savedDados, filtroIP: savedFiltro } = JSON.parse(estadoSalvo);
    dadosGlobais = savedDados;
    filtroIP    = savedFiltro;

    // Exibe e ajusta o filtro
    document.getElementById('filtroContainer').style.display = 'block';
    document.getElementById('ipSelect').value = filtroIP;

    // Recria o select e os gráficos
    popularSelectIPs();
    gerarGraficos(
      filtroIP
        ? dadosGlobais.filter(v => v['Host/IP Afetado'] === filtroIP)
        : dadosGlobais
    );

    sessionStorage.removeItem('dashboardState');
  }
});


// Carrega arquivo CSV e inicializa tudo
document.getElementById('csvFile').addEventListener('change', function (e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const text       = e.target.result;
    const linhas     = text.trim().split('\n');
    const cabecalhos = linhas[0].split(';');

    dadosGlobais = linhas.slice(1).map(linha => {
      const colunas = linha.split(';');
      const obj     = {};
      cabecalhos.forEach((col, idx) => {
        obj[col.trim()] = colunas[idx]?.trim();
      });
      return obj;
    });

    popularSelectIPs();
    filtroIP = '';
    document.getElementById('ipSelect').value              = '';
    document.getElementById('filtroContainer').style.display = 'block';
    gerarGraficos(dadosGlobais);
  };
  reader.readAsText(file);
});

// Popula o <select> de IPs
function popularSelectIPs() {
  const select = document.getElementById('ipSelect');
  while (select.options.length > 1) {
    select.remove(1);
  }

  const ips = [...new Set(dadosGlobais.map(v => v['Host/IP Afetado']).filter(ip => ip))].sort();
  ips.forEach(ip => {
    const opt = document.createElement('option');
    opt.value       = ip;
    opt.textContent = ip;
    select.appendChild(opt);
  });

  select.onchange = () => {
    filtroIP = select.value;
    const filtrados = filtroIP
      ? dadosGlobais.filter(v => v['Host/IP Afetado'] === filtroIP)
      : dadosGlobais;
    gerarGraficos(filtrados);
  };
}

// Filtra array por IP
function filtrarPorIP(dados, ip) {
  return ip ? dados.filter(v => v['Host/IP Afetado'] === ip) : dados;
}

// Converte DD/MM/AAAA para Date
function parseDateBR(dateStr) {
  if (!dateStr) return new Date(0);
  const partes = dateStr.split('/');
  if (partes.length !== 3) return new Date(0);
  return new Date(partes[2], partes[1] - 1, partes[0]);
}

// Converte AAAA-MM-DD para DD/MM/AAAA ou retorna tal como está
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

// Gera todos os gráficos e popula a tabela com clique para detalhes
function gerarGraficos(data) {
  // --- Calcula métricas ---
  const severidades = { 'Crítica': 0, 'Alta': 0, 'Média': 0, 'Baixa': 0, 'Informativa': 0 };
  const tipos        = {};
  const exploits     = { Sim: 0, Nao: 0 };

  data.forEach(v => {
    const cvss = parseFloat(v['CVSS']) || 0;
    if (cvss >= 9) severidades['Crítica']++;
    else if (cvss >= 7) severidades['Alta']++;
    else if (cvss >= 4) severidades['Média']++;
    else if (cvss > 0) severidades['Baixa']++;
    else severidades['Informativa']++;

    const tp = v['Tipo da Vulnerabilidade'] || 'Outro';
    tipos[tp] = (tipos[tp] || 0) + 1;

    const ex = v['Exploit Disponível'];
    if (ex === 'Sim' || ex === 'Nao') exploits[ex]++;
  });

  // --- Destroi gráficos antigos ---
  [cvssChart, vulnTypeChart, exploitChart, serviceChart].forEach(ch => ch && ch.destroy());

  // --- Cria CVSS Chart ---
  cvssChart = new Chart(document.getElementById('cvssChart'), {
    type: 'bar',
    data: {
      labels: Object.keys(severidades),
      datasets: [{
        label: 'Número de Vulnerabilidades por Severidade',
        data: Object.values(severidades),
        backgroundColor: ['#d32f2f','#f57c00','#fbc02d','#0288d1','#9e9e9e']
      }]
    },
    options: {
      indexAxis: 'y',
      scales: { x: { beginAtZero: true, precision: 0 } },
      animation: { duration: 400 }
    }
  });

  // --- Cria Vulnerability Type Chart ---
  vulnTypeChart = new Chart(document.getElementById('vulnTypeChart'), {
    type: 'pie',
    data: {
      labels: Object.keys(tipos),
      datasets: [{ data: Object.values(tipos) }]
    },
    options: { animation: { duration: 400 } }
  });

  // --- Cria Exploit Chart ---
  exploitChart = new Chart(document.getElementById('exploitChart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(exploits),
      datasets: [{ data: Object.values(exploits) }]
    },
    options: { animation: { duration: 400 } }
  });

  // --- Cria Service/Port Chart ---
  const servicos = {};
  data.forEach(v => {
    const key = `${v['Serviço/Porta']} (${v['Protocolo']})`;
    servicos[key] = (servicos[key] || 0) + 1;
  });
  serviceChart = new Chart(document.getElementById('serviceChart'), {
    type: 'bar',
    data: {
      labels: Object.keys(servicos),
      datasets: [{ data: Object.values(servicos) }]
    },
    options: {
      indexAxis: 'y',
      scales: { x: { beginAtZero: true, precision: 0 } }
    }
  });

  // --- Popula Tabela e adiciona clique para detalhes ---
  const tbody = document.querySelector('#timelineTable tbody');
  tbody.innerHTML = '';

  const ordenados = data
    .filter(v => v['Data da Descoberta'] && v['Vendor/Produto'] && v['ID/CVE'])
    .sort((a,b) =>
      parseDateBR(formatDateToBR(a['Data da Descoberta'])) -
      parseDateBR(formatDateToBR(b['Data da Descoberta']))
    );

  ordenados.forEach(v => {
    const tr = document.createElement('tr');
    ['Data da Descoberta','Vendor/Produto','ID/CVE'].forEach((f,i) => {
      const td = document.createElement('td');
      td.textContent = i===0 ? formatDateToBR(v[f]) : v[f];
      td.style.padding = '6px';
      tr.appendChild(td);
    });

    tr.addEventListener('click', () => {
      // Salva CVE e estado da dashboard
      sessionStorage.setItem('vulnDetalhe', JSON.stringify(v));
      sessionStorage.setItem('dashboardState', JSON.stringify({
        dadosGlobais,
        filtroIP
      }));
      window.location.href = 'detalhes.html';
    });

    tbody.appendChild(tr);
  });
}
