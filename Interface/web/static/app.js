// ═══════════════════════════════════════════════════
//  tIDS · app.js  — updated for premium dashboard
// ═══════════════════════════════════════════════════

// DOM
const btnStart  = document.getElementById('btn-start');
const btnStop   = document.getElementById('btn-stop');
const statusIndicator = document.getElementById('status-indicator');
const statusText      = document.getElementById('status-text');

// Metrics
const valPktRate  = document.getElementById('val-pkt-rate');
const valByteRate = document.getElementById('val-byte-rate');
const valTcpSyn   = document.getElementById('val-tcp-syn');
const valUdp      = document.getElementById('val-udp');

const elTotalPackets = document.getElementById('total-packets');
const elTotalThreats = document.getElementById('total-threats');
const eventsTbody    = document.getElementById('events-tbody');

// State box
const alertBox       = document.getElementById('threat-alert');
const predictionText = document.getElementById('prediction-text');
const predictionDesc = document.getElementById('prediction-desc');
const stateBgText    = document.getElementById('state-bg-text');

let isCapturing  = false;
let ws           = null;
let trafficChart = null;

let totalPackets = 0;
let totalThreats = 0;

let attackCounts = {
    ARP_Spoof: 0,
    DNS_Spoof: 0,
    IGMP_Spoof: 0,
    Normal: 0,
    STP_Spoof: 0,
    SYN_Flood: 0,
    Smurf: 0,
    UDP_Flood: 0
};

const attackIds = {
    ARP_Spoof:  'count-arp-spoof',
    DNS_Spoof:  'count-dns-spoof',
    STP_Spoof:  'count-stp-spoof',
    SYN_Flood:  'count-syn-flood',
    UDP_Flood:  'count-udp-flood',
    Smurf:      'count-smurf',
    IGMP_Spoof: 'count-igmp-spoof'
};

const attackBarIds = {
    ARP_Spoof:  'bar-arp-spoof',
    DNS_Spoof:  'bar-dns-spoof',
    STP_Spoof:  'bar-stp-spoof',
    SYN_Flood:  'bar-syn-flood',
    UDP_Flood:  'bar-udp-flood',
    Smurf:      'bar-smurf',
    IGMP_Spoof: 'bar-igmp-spoof'
};

const attackCardIds = {
    ARP_Spoof:  'card-arp-spoof',
    DNS_Spoof:  'card-dns-spoof',
    STP_Spoof:  'card-stp-spoof',
    SYN_Flood:  'card-syn-flood',
    UDP_Flood:  'card-udp-flood',
    Smurf:      'card-smurf',
    IGMP_Spoof: 'card-igmp-spoof'
};

// ── Utils ──
function formatNumber(num) {
    return new Intl.NumberFormat('en-US').format(Math.round(num || 0));
}

function normalizeAttackName(prediction) {
    if (!prediction) return 'Normal';
    const p = prediction.toString().trim();
    const aliases = {
        'Normal': 'Normal', 'normal': 'Normal',
        'ARP_Spoof': 'ARP_Spoof', 'ARP Spoof': 'ARP_Spoof', 'ARP_Poisoning': 'ARP_Spoof',
        'DNS_Spoof': 'DNS_Spoof', 'DNS Spoof': 'DNS_Spoof', 'DNS_Spoofing': 'DNS_Spoof',
        'STP_Spoof': 'STP_Spoof', 'STP Spoof': 'STP_Spoof',
        'SYN_Flood': 'SYN_Flood', 'TCP_SYN_Flood': 'SYN_Flood', 'TCP SYN Flood': 'SYN_Flood',
        'UDP_Flood': 'UDP_Flood', 'UDP Flood': 'UDP_Flood',
        'Smurf': 'Smurf', 'Smurf_Attack': 'Smurf',
        'IGMP_Spoof': 'IGMP_Spoof', 'IGMP Spoof': 'IGMP_Spoof'
    };
    return aliases[p] || p;
}

// ── Attack bars ──
function updateAttackBars() {
    const nonZero = Object.values(attackCounts).filter(c => c > 0);
    const maxCount = nonZero.length > 0 ? Math.max(...nonZero) : 1;

    Object.keys(attackBarIds).forEach(attack => {
        const bar = document.getElementById(attackBarIds[attack]);
        if (!bar) return;
        bar.style.width = ((attackCounts[attack] || 0) / maxCount * 100) + '%';
    });
}

function renderAttackCounters() {
    let totalAttacks = 0;
    Object.keys(attackIds).forEach(attack => {
        totalAttacks += (attackCounts[attack] || 0);
        const el = document.getElementById(attackIds[attack]);
        if (el) el.textContent = formatNumber(attackCounts[attack] || 0);
    });

    const pastTotal = document.getElementById('past-attacks-total');
    if (pastTotal) pastTotal.textContent = formatNumber(totalAttacks);
    if (elTotalThreats) elTotalThreats.textContent = formatNumber(totalAttacks);

    // Threat bar fill (arbitrary scale — caps at 100)
    const threatBar = document.getElementById('threat-bar');
    if (threatBar) {
        const pct = Math.min(totalAttacks / 10 * 100, 100);
        threatBar.style.width = pct + '%';
    }

    updateAttackBars();
}

// ── Alert toasts ──
function showAlert(attackName, timestamp) {
    const container = document.getElementById('alert-container');
    if (!container) return;

    const readableName = 'Attack Detected: ' + attackName.replace(/_/g, ' ');
    const timeStr = new Date(timestamp * 1000).toLocaleTimeString([], { hour12: false });

    const div = document.createElement('div');
    div.className = 'alert-notification danger';
    div.innerHTML = `
        <div class="alert-notification-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
        </div>
        <div class="alert-notification-content">
            <strong class="alert-notification-title">${readableName}</strong>
            <small class="alert-notification-time">Anomaly flagged at ${timeStr}</small>
        </div>
        <button class="alert-notification-close"
            onclick="this.parentElement.classList.add('removing'); setTimeout(()=>this.parentElement.remove(),250)">×</button>
    `;

    container.appendChild(div);
    requestAnimationFrame(() => div.classList.add('visible'));

    setTimeout(() => {
        if (div.parentElement) {
            div.classList.add('removing');
            setTimeout(() => div.parentElement && div.remove(), 250);
        }
    }, 8000);
}

function incrementAttack(prediction, timestamp) {
    const attackName = normalizeAttackName(prediction);
    if (!attackCounts.hasOwnProperty(attackName)) return;

    attackCounts[attackName]++;
    totalThreats++;

    renderAttackCounters();

    if (attackName !== 'Normal') {
        showAlert(attackName, timestamp);

        const card = document.getElementById(attackCardIds[attackName]);
        if (card) {
            card.classList.add('warning');
            setTimeout(() => card.classList.remove('warning'), 1200);
        }
    }
}

// ── Load past alerts ──
async function loadPastAlerts() {
    try {
        const res = await fetch('/api/alerts');
        if (!res.ok) return;
        const result = await res.json();
        const alerts = result.alerts || [];
        alerts.forEach(alert => {
            const name = normalizeAttackName(alert.prediction);
            if (attackCounts.hasOwnProperty(name)) attackCounts[name]++;
        });
        totalThreats = alerts.length;
        renderAttackCounters();
    } catch (e) {
        console.warn('Could not load past alerts:', e);
    }
}

// ── Chart ──
function initChart() {
    const ctx = document.getElementById('trafficChart');
    if (!ctx) return;

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets/sec',
                data: [],
                borderColor: '#00e5c3',
                backgroundColor: (context) => {
                    const chart = context.chart;
                    const { ctx: c, chartArea } = chart;
                    if (!chartArea) return 'rgba(0,229,195,0.1)';
                    const gradient = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                    gradient.addColorStop(0, 'rgba(0,229,195,0.22)');
                    gradient.addColorStop(1, 'rgba(0,229,195,0.01)');
                    return gradient;
                },
                fill: true,
                tension: 0.45,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHoverBackgroundColor: '#00e5c3',
                pointHoverBorderColor: '#fff',
                pointHoverBorderWidth: 2,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 200 },
            interaction: { mode: 'index', intersect: false },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255,255,255,0.04)',
                        drawBorder: false,
                    },
                    ticks: {
                        color: '#4d6480',
                        font: { family: 'IBM Plex Mono', size: 10 },
                        maxTicksLimit: 5,
                    },
                    border: { display: false }
                },
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#4d6480',
                        font: { family: 'IBM Plex Mono', size: 10 },
                        maxTicksLimit: 8,
                        maxRotation: 0,
                    },
                    border: { display: false }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(6,13,26,0.95)',
                    borderColor: 'rgba(0,229,195,0.3)',
                    borderWidth: 1,
                    titleColor: '#00e5c3',
                    bodyColor: '#a8bdd8',
                    titleFont: { family: 'IBM Plex Mono', size: 11 },
                    bodyFont: { family: 'IBM Plex Mono', size: 11 },
                    padding: 10,
                    cornerRadius: 8,
                }
            }
        }
    });
}

function setChartColor(danger) {
    if (!trafficChart) return;
    const color = danger ? '#ff2d6b' : '#00e5c3';
    trafficChart.data.datasets[0].borderColor = color;
    trafficChart.data.datasets[0].backgroundColor = (ctx) => {
        const chart = ctx.chart;
        const { ctx: c, chartArea } = chart;
        if (!chartArea) return danger ? 'rgba(255,45,107,0.1)' : 'rgba(0,229,195,0.1)';
        const gradient = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
        if (danger) {
            gradient.addColorStop(0, 'rgba(255,45,107,0.2)');
            gradient.addColorStop(1, 'rgba(255,45,107,0.01)');
        } else {
            gradient.addColorStop(0, 'rgba(0,229,195,0.22)');
            gradient.addColorStop(1, 'rgba(0,229,195,0.01)');
        }
        return gradient;
    };
}

// ── WebSocket ──
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${window.location.host}/ws/stream`;
    try {
        ws = new WebSocket(url);
        ws.onopen = () => console.log('[tIDS] WebSocket connected');
        ws.onmessage = (event) => {
            try { handleNewData(JSON.parse(event.data)); }
            catch (e) { console.error('[tIDS] Parse error:', e); }
        };
        ws.onerror = (e) => console.error('[tIDS] WS error:', e);
        ws.onclose = () => {
            console.log('[tIDS] WS closed');
            if (isCapturing) setTimeout(connectWebSocket, 3000);
        };
    } catch (e) {
        console.error('[tIDS] WS connect error:', e);
    }
}

// ── Data handler ──
function handleNewData(data) {
    const prediction = normalizeAttackName(data.prediction);
    const isNormal   = prediction === 'Normal';

    // Metrics
    if (valPktRate)  valPktRate.textContent  = formatNumber(data.packet_rate || 0);
    if (valByteRate) valByteRate.textContent = formatNumber((data.byte_rate || 0) / 1024);
    if (valTcpSyn)   valTcpSyn.textContent   = formatNumber(data.tcp_syn || 0);
    if (valUdp)      valUdp.textContent      = formatNumber(data.udp_pkt || 0);

    totalPackets += (data.packet_rate || 0);
    if (elTotalPackets) elTotalPackets.textContent = formatNumber(totalPackets);

    // Packet bar (visual only)
    const pktBar = document.getElementById('pkt-bar');
    if (pktBar) pktBar.style.width = Math.min((data.packet_rate || 0) / 500 * 100, 100) + '%';

    const timeLabel = new Date(data.timestamp * 1000).toLocaleTimeString([], { hour12: false });

    // Chart
    if (trafficChart) {
        trafficChart.data.labels.push(timeLabel);
        trafficChart.data.datasets[0].data.push(data.packet_rate || 0);
        if (trafficChart.data.labels.length > 30) {
            trafficChart.data.labels.shift();
            trafficChart.data.datasets[0].data.shift();
        }
        setChartColor(!isNormal);
        trafficChart.update('none');
    }

    // State display
    if (isNormal) {
        alertBox.className = 'state-display safe';
        predictionText.textContent = 'Safe Mode';
        predictionDesc.textContent = 'Network behavior is normal';
        if (stateBgText) stateBgText.textContent = 'SAFE';
        incrementAttack(prediction, data.timestamp);
    } else {
        alertBox.className = 'state-display danger';
        predictionText.textContent = '⚠ ' + prediction.replace(/_/g, ' ');
        predictionDesc.textContent = 'Anomalous activity detected on the network';
        if (stateBgText) stateBgText.textContent = 'ALERT';
        incrementAttack(prediction, data.timestamp);
    }

    // Feed table row
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td>${timeLabel}</td>
        <td><span class="badge ${isNormal ? 'safe' : 'danger'}">${isNormal ? 'OK' : 'THREAT'}</span></td>
        <td style="color:${isNormal ? 'var(--teal-400)' : 'var(--danger)'}; font-weight:600">${prediction.replace(/_/g, ' ')}</td>
        <td>${formatNumber(data.packet_rate || 0)}</td>
        <td>${formatNumber((data.byte_rate || 0) / 1024)}</td>
    `;

    if (eventsTbody) {
        eventsTbody.prepend(tr);
        while (eventsTbody.children.length > 50) {
            eventsTbody.removeChild(eventsTbody.lastChild);
        }
    }
}

// ── Button handlers ──
btnStart.addEventListener('click', async () => {
    try {
        const res = await fetch('/api/start', { method: 'POST' });
        if (res.ok) {
            isCapturing = true;
            btnStart.disabled = true;
            btnStop.disabled  = false;
            statusIndicator.className = 'status-indicator active';
            statusText.textContent    = 'MONITORING';
            if (!ws || ws.readyState !== WebSocket.OPEN) connectWebSocket();
        }
    } catch (e) {
        console.error('[tIDS] Start error:', e);
        alert('Failed to start capture');
    }
});

btnStop.addEventListener('click', async () => {
    try {
        const res = await fetch('/api/stop', { method: 'POST' });
        if (res.ok) {
            isCapturing = false;
            btnStart.disabled = false;
            btnStop.disabled  = true;
            statusIndicator.className = 'status-indicator idle';
            statusText.textContent    = 'SYSTEM IDLE';
            if (ws) ws.close();

            alertBox.className = 'state-display safe';
            predictionText.textContent = 'Standing By';
            predictionDesc.textContent = 'Capture engine offline';
            if (stateBgText) stateBgText.textContent = 'IDLE';

            setChartColor(false);
            if (trafficChart) trafficChart.update();
        }
    } catch (e) {
        console.error('[tIDS] Stop error:', e);
        alert('Failed to stop capture');
    }
});

// ── Init ──
document.addEventListener('DOMContentLoaded', async () => {
    console.log('[tIDS] Initializing dashboard…');
    initChart();
    await loadPastAlerts();
    console.log('[tIDS] Ready.');
});