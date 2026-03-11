const API_URL = 'http://localhost:8000';
let currentEmailFile = null;
let currentPcapFile = null; 
let eventSource = null;
let currentlyExpandedAPI = null;
let currentQRFile = null;
let mapInstance = null;
let currentTaskId = null;
let pcapCharts = [];
let currentPcapFilename = null;
let pcapPacketRows = [];

function switchSection(sectionName, buttonElement = null) {
    document.querySelectorAll('.main-section').forEach(section => section.classList.remove('active'));
    document.querySelectorAll('.top-nav-button').forEach(btn => btn.classList.remove('active'));

    const section = document.getElementById(`${sectionName}Section`);
    if (section) section.classList.add('active');

    const navBtn = buttonElement || document.querySelector(`.top-nav-button[onclick*="${sectionName}"]`);
    if (navBtn) navBtn.classList.add('active');

    document.getElementById('errorContainer').classList.add('hidden');
}

function switchTab(tabName, buttonElement = null) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    const targetTab = document.getElementById(`${tabName}Tab`);
    if (targetTab) targetTab.classList.add('active');
    if (buttonElement) buttonElement.classList.add('active');
    
    document.getElementById('errorContainer').classList.add('hidden');
}

async function analyzeURL() {
    const urlInput = document.getElementById('urlInput');
    const analyzeBtn = document.getElementById('analyzeUrlBtn');
    const btnText = document.getElementById('urlBtnText');
    const btnLoader = document.getElementById('urlBtnLoader');
    
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('Please enter a URL');
        return;
    }
    
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        showError('URL must start with http:// or https://');
        return;
    }
    
    resetUI();
    setButtonLoading(analyzeBtn, btnText, btnLoader, true);
    
    try {
        const response = await fetch(`${API_URL}/analyze/url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                url: url,
                use_external_apis: true,
                async_mode: true,
                enable_behavioral: document.getElementById('urlEnableBehavioral').checked,
                enable_live_capture: document.getElementById('urlEnableLiveCapture').checked
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Analysis failed');
        }
        
        const data = await response.json();
        
        if (data.task_id) {
            showProgressModal();
            await streamTaskProgress(data.task_id);
        } else {
            displayResults(data);
        }
        
    } catch (error) {
        showError(`Error: ${error.message}`);
        hideProgressModal();
    } finally {
        setButtonLoading(analyzeBtn, btnText, btnLoader, false);
    }
}

async function streamTaskProgress(taskId) {
    currentTaskId = taskId;
    return new Promise((resolve, reject) => {
        if (eventSource) {
            eventSource.close();
        }
        
        eventSource = new EventSource(`${API_URL}/task/${taskId}/stream`);
        
        eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                if (data.error) {
                    showError(data.error);
                    hideProgressModal();
                    eventSource.close();
                    reject(new Error(data.error));
                    return;
                }
                
                updateProgress(data.progress, data.current_step, data.steps_completed);
                
                if (data.status === 'completed' && data.result) {
                    hideProgressModal();
                    displayResults(data.result);
                    eventSource.close();
                    resolve(data.result);
                } else if (data.status === 'failed') {
                    showError(`Analysis failed: ${data.error}`);
                    hideProgressModal();
                    eventSource.close();
                    reject(new Error(data.error));
                }
            } catch (err) {
                console.error('Error parsing SSE data:', err);
            }
        };
        
        eventSource.onerror = (error) => {
            console.error('SSE error:', error);
            eventSource.close();
            
            pollTaskStatus(taskId).then(resolve).catch(reject);
        };
    });
}

async function pollTaskStatus(taskId) {
    const maxAttempts = 60;
    let attempts = 0;
    
    while (attempts < maxAttempts) {
        try {
            const response = await fetch(`${API_URL}/task/${taskId}`);
            const data = await response.json();
            
            updateProgress(data.progress, data.current_step, data.steps_completed);
            
            if (data.status === 'completed' && data.result) {
                hideProgressModal();
                displayResults(data.result);
                return data.result;
            } else if (data.status === 'failed') {
                throw new Error(data.error);
            }
            
            await new Promise(resolve => setTimeout(resolve, 1000));
            attempts++;
            
        } catch (error) {
            hideProgressModal();
            showError(`Error checking status: ${error.message}`);
            throw error;
        }
    }
    
    throw new Error('Analysis timeout');
}

function showProgressModal() {
    const modal = document.getElementById('progressModal');
    modal.classList.remove('hidden');
    
    updateProgress(0, 'Starting analysis...', []);
}

function hideProgressModal() {
    const modal = document.getElementById('progressModal');
    modal.classList.add('hidden');
}

function updateProgress(percent, step, stepsCompleted = []) {
    const progressBar = document.getElementById('progressBar');
    const progressPercent = document.getElementById('progressPercent');
    const progressStep = document.getElementById('progressStep');
    
    progressBar.style.width = `${percent}%`;
    progressPercent.textContent = `${percent}%`;
    progressStep.textContent = step;
    progressStep.className = percent < 100 ? 'progress-step loading' : 'progress-step';
    
    const stepsList = document.getElementById('progressSteps');
    stepsList.innerHTML = '';
    
    if (stepsCompleted && stepsCompleted.length > 0) {
        stepsCompleted.forEach(completedStep => {
            const stepItem = document.createElement('div');
            stepItem.className = 'progress-step-item completed';
            stepItem.innerHTML = `
                <span class="step-icon"></span>
                <span>${completedStep}</span>
            `;
            stepsList.appendChild(stepItem);
        });
    }
}

function handleEmailFile(input) {
    const file = input.files[0];
    if (!file) return;
    
    if (!file.name.endsWith('.eml')) {
        showError('Please select a .eml file');
        input.value = '';
        return;
    }
    
    currentEmailFile = file;
    
    document.getElementById('emailFileName').textContent = file.name;
    document.getElementById('emailFileInfo').classList.remove('hidden');
    document.getElementById('analyzeEmailBtn').classList.remove('hidden');
    document.getElementById('emailUploadArea').style.display = 'none';
}

function clearEmailFile() {
    currentEmailFile = null;
    document.getElementById('emailFileInput').value = '';
    document.getElementById('emailFileInfo').classList.add('hidden');
    document.getElementById('analyzeEmailBtn').classList.add('hidden');
    document.getElementById('emailUploadArea').style.display = 'block';
}

async function analyzeEmail() {
    if (!currentEmailFile) {
        showError('Please select an email file first');
        return;
    }
    
    const analyzeBtn = document.getElementById('analyzeEmailBtn');
    const btnText = document.getElementById('emailBtnText');
    const btnLoader = document.getElementById('emailBtnLoader');
    
    resetUI();
    setButtonLoading(analyzeBtn, btnText, btnLoader, true);
    
    try {
        const formData = new FormData();
        formData.append('file', currentEmailFile);
        
        const response = await fetch(`${API_URL}/analyze/email`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Analysis failed');
        }
        
        const data = await response.json();
        displayResults(data);
        
    } catch (error) {
        showError(`Error: ${error.message}`);
    } finally {
        setButtonLoading(analyzeBtn, btnText, btnLoader, false);
    }
}

async function analyzeText() {
    const textInput = document.getElementById('textInput');
    const analyzeBtn = document.getElementById('analyzeTextBtn');
    const btnText = document.getElementById('textBtnText');
    const btnLoader = document.getElementById('textBtnLoader');
    
    const text = textInput.value.trim();
    
    if (!text) {
        showError('Please enter some text to analyze');
        return;
    }
    
    if (text.length < 10) {
        showError('Text must be at least 10 characters long');
        return;
    }
    
    resetUI();
    setButtonLoading(analyzeBtn, btnText, btnLoader, true);
    
    try {
        const response = await fetch(`${API_URL}/analyze/text`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: text })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Analysis failed');
        }
        
        const data = await response.json();
        displayResults(data);
        
    } catch (error) {
        showError(`Error: ${error.message}`);
    } finally {
        setButtonLoading(analyzeBtn, btnText, btnLoader, false);
    }
}

function handleQRFile(input) {
    const file = input.files[0];
    if (!file) return;
    
    if (!file.type.startsWith('image/')) {
        showError('Please select an image file');
        input.value = '';
        return;
    }
    
    currentQRFile = file;
    
    document.getElementById('qrFileName').textContent = file.name;
    document.getElementById('qrFileInfo').classList.remove('hidden');
    document.getElementById('analyzeQRBtn').classList.remove('hidden');
    document.getElementById('qrUploadArea').style.display = 'none';
}

function clearQRFile() {
    currentQRFile = null;
    document.getElementById('qrFileInput').value = '';
    document.getElementById('qrFileInfo').classList.add('hidden');
    document.getElementById('analyzeQRBtn').classList.add('hidden');
    document.getElementById('qrUploadArea').style.display = 'block';
}

async function analyzeQR() {
    if (!currentQRFile) return;
    
    const analyzeBtn = document.getElementById('analyzeQRBtn');
    const btnText = document.getElementById('qrBtnText');
    const btnLoader = document.getElementById('qrBtnLoader');
    
    resetUI();
    setButtonLoading(analyzeBtn, btnText, btnLoader, true);
    
    try {
        const formData = new FormData();
        formData.append('file', currentQRFile);
        formData.append('use_external_apis', 'true');
        formData.append('enable_behavioral', document.getElementById('qrEnableBehavioral').checked);
        formData.append('enable_live_capture', document.getElementById('qrEnableLiveCapture').checked);
        
        const response = await fetch(`${API_URL}/analyze/qr`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Analysis failed');
        }
        
        const data = await response.json();
                
        if (data.analysis_type === 'url_redirect' && data.task_id) {
            console.log("URL detected in QR, switching to deep scan...");
            showProgressModal();
            await streamTaskProgress(data.task_id);
            
        } else if (data.analysis_type === 'qr_text') {
            displayResults(data);
            
        } else if (data.status === 'failed') {
            showError(data.error);
        }
        
    } catch (error) {
        showError(`Error: ${error.message}`);
    } finally {
        setButtonLoading(analyzeBtn, btnText, btnLoader, false);
    }
}

function handlePcapFile(input) {
    const file = input.files[0];
    if (!file) return;
    
    // Simple extension check
    const validExts = ['.pcap', '.cap', '.pcapng'];
    const isPcap = validExts.some(ext => file.name.toLowerCase().endsWith(ext));

    if (!isPcap) {
        showError('Please select a valid capture file (.pcap, .cap, .pcapng)');
        input.value = '';
        return;
    }
    
    currentPcapFile = file;
    
    document.getElementById('pcapFileName').textContent = file.name;
    document.getElementById('pcapFileInfo').classList.remove('hidden');
    document.getElementById('analyzePcapBtn').classList.remove('hidden');
    document.getElementById('pcapUploadArea').style.display = 'none';
}

function clearPcapFile() {
    currentPcapFile = null;
    document.getElementById('pcapFileInput').value = '';
    document.getElementById('pcapFileInfo').classList.add('hidden');
    document.getElementById('analyzePcapBtn').classList.add('hidden');
    document.getElementById('pcapUploadArea').style.display = 'block';
}

async function analyzePcap() {
    if (!currentPcapFile) return;
    
    const analyzeBtn = document.getElementById('analyzePcapBtn');
    const btnText = document.getElementById('pcapBtnText');
    const btnLoader = document.getElementById('pcapBtnLoader');
    
    resetUI();
    setButtonLoading(analyzeBtn, btnText, btnLoader, true);
    
    try {
        const formData = new FormData();
        formData.append('file', currentPcapFile);
        
        // Use pseudo-progress because PCAP analysis is currently synchronous/threaded but returns one-shot
        showProgressModal();
        updateProgress(30, "Parsing Packets...", []);

        const response = await fetch(`${API_URL}/analyze/pcap`, {
            method: 'POST',
            body: formData
        });
        
        updateProgress(80, "Generating Statistics...", []);

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Analysis failed');
        }
        
        const data = await response.json();
        const normalized = {
            ...data,
            analysis_type: data.analysis_type || 'pcap'
        };
        updateProgress(100, "Complete", []);
        
        setTimeout(() => {
            hideProgressModal();
            displayResults(normalized);
        }, 500);
        
    } catch (error) {
        hideProgressModal();
        showError(`Error: ${error.message}`);
    } finally {
        setButtonLoading(analyzeBtn, btnText, btnLoader, false);
    }
}

function resizePcapCharts() {
    pcapCharts.forEach(chart => {
        try { chart.resize(); } catch (e) {}
    });
}

function renderCharts(data) {
    // Dispose old charts
    pcapCharts.forEach(chart => chart.dispose());
    pcapCharts = [];

    // 1. Protocol Distribution (Pie)
    if (data.statistics && data.statistics.protocol_distribution) {
        const protoData = Object.entries(data.statistics.protocol_distribution)
            .map(([name, value]) => ({ value, name }))
            .filter(item => item.value > 0);

        const protoChart = echarts.init(document.getElementById('protocolChart'));
        const protoOption = {
            tooltip: { trigger: 'item', backgroundColor: 'rgba(15, 23, 42, 0.9)', borderColor: '#22d3ee', textStyle: { color: '#e2e8f0' } },
            legend: { top: '5%', left: 'center', textStyle: { color: '#94a3b8' } },
            series: [{
                name: 'Protocols',
                type: 'pie',
                radius: ['40%', '70%'],
                avoidLabelOverlap: false,
                itemStyle: { borderRadius: 10, borderColor: '#0f172a', borderWidth: 2 },
                label: { show: false, position: 'center' },
                emphasis: { label: { show: true, fontSize: 40, fontWeight: 'bold', color: '#67e8f9' } },
                data: protoData
            }]
        };
        protoChart.setOption(protoOption);
        pcapCharts.push(protoChart);
    }

    // 2. Time Flow (Line)
    if (data.flow_analysis && data.flow_analysis.time_flow) {
        const timeData = Object.entries(data.flow_analysis.time_flow)
            .sort((a, b) => parseFloat(a[0]) - parseFloat(b[0])); // Sort by relative time
        
        const xData = timeData.map(item => item[0]);
        const yData = timeData.map(item => item[1]);

        const timeChart = echarts.init(document.getElementById('timeFlowChart'));
        const timeOption = {
            title: { text: 'Traffic Volume over Time', left: 'center', textStyle: { color: '#67e8f9' } },
            tooltip: { trigger: 'axis', backgroundColor: 'rgba(15, 23, 42, 0.9)', borderColor: '#22d3ee', textStyle: { color: '#e2e8f0' } },
            xAxis: { type: 'category', data: xData, name: 'Seconds', axisLabel: { color: '#94a3b8' } },
            yAxis: { type: 'value', name: 'Bytes', splitLine: { lineStyle: { color: '#334155' } }, axisLabel: { color: '#94a3b8' } },
            series: [{ data: yData, type: 'line', smooth: true, areaStyle: { color: 'rgba(34,211,238,0.2)' }, lineStyle: { color: '#22d3ee' }, itemStyle: { color: '#22d3ee' } }]
        };
        timeChart.setOption(timeOption);
        pcapCharts.push(timeChart);
    }

    // 3. Packet Lengths (Bar)
    if (data.statistics && data.statistics.packet_lengths) {
        const lenData = Object.entries(data.statistics.packet_lengths);
        const xData = lenData.map(item => item[0]);
        const yData = lenData.map(item => item[1]);

        const lenChart = echarts.init(document.getElementById('packetLenChart'));
        const lenOption = {
            title: { text: 'Packet Size Distribution', left: 'center', textStyle: { color: '#67e8f9' } },
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, backgroundColor: 'rgba(15, 23, 42, 0.9)', borderColor: '#22d3ee', textStyle: { color: '#e2e8f0' } },
            grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
            xAxis: { type: 'category', data: xData, axisLabel: { color: '#94a3b8' } },
            yAxis: { type: 'value', splitLine: { lineStyle: { color: '#334155' } }, axisLabel: { color: '#94a3b8' } },
            series: [{ name: 'Count', type: 'bar', data: yData, color: '#e879f9', itemStyle: { borderRadius: [4, 4, 0, 0] } }]
        };
        lenChart.setOption(lenOption);
        pcapCharts.push(lenChart);
    }

    requestAnimationFrame(() => {
        setTimeout(resizePcapCharts, 80);
    });
}

function renderPacketTable(rawPackets = []) {
    pcapPacketRows = (rawPackets || []).map((packet, index) => ({
        id: packet.id || index + 1,
        time: packet.time || '-',
        protocol: packet.Procotol || packet.Protocol || 'Unknown',
        source: packet.Source || 'Unknown',
        destination: packet.Destination || 'Unknown',
        length: packet.len ?? '-',
        info: packet.info || ''
    }));

    const protocolFilter = document.getElementById('packetProtocolFilter');
    if (!protocolFilter) return;
    protocolFilter.innerHTML = '<option value="">All Protocols</option>';
    [...new Set(pcapPacketRows.map(p => p.protocol).filter(Boolean))]
        .sort((a, b) => a.localeCompare(b))
        .forEach(protocol => {
            const option = document.createElement('option');
            option.value = protocol;
            option.textContent = protocol;
            protocolFilter.appendChild(option);
        });

    document.getElementById('packetSourceFilter').value = '';
    document.getElementById('packetDestFilter').value = '';
    document.getElementById('packetInfoFilter').value = '';

    applyPacketFilters();
}

function applyPacketFilters() {
    const protocolEl = document.getElementById('packetProtocolFilter');
    const sourceEl = document.getElementById('packetSourceFilter');
    const destinationEl = document.getElementById('packetDestFilter');
    const infoEl = document.getElementById('packetInfoFilter');
    const body = document.getElementById('packetTableBody');
    const meta = document.getElementById('packetTableMeta');

    if (!protocolEl || !sourceEl || !destinationEl || !infoEl || !body || !meta) return;

    const protocol = (protocolEl.value || '').toLowerCase();
    const source = (sourceEl.value || '').toLowerCase();
    const destination = (destinationEl.value || '').toLowerCase();
    const info = (infoEl.value || '').toLowerCase();

    const filtered = pcapPacketRows.filter(row => {
        if (protocol && !row.protocol.toLowerCase().includes(protocol)) return false;
        if (source && !row.source.toLowerCase().includes(source)) return false;
        if (destination && !row.destination.toLowerCase().includes(destination)) return false;
        if (info && !row.info.toLowerCase().includes(info)) return false;
        return true;
    });

    body.innerHTML = filtered.map(row => `
        <tr>
            <td>${row.id}</td>
            <td>${escapeHtml(row.time)}</td>
            <td>${escapeHtml(row.protocol)}</td>
            <td>${escapeHtml(row.source)}</td>
            <td>${escapeHtml(row.destination)}</td>
            <td>${escapeHtml(String(row.length))}</td>
            <td class="pkt-info" title="${escapeHtml(row.info)}">${escapeHtml(row.info)}</td>
        </tr>
    `).join('');

    meta.textContent = `Showing ${filtered.length} of ${pcapPacketRows.length} packets`;
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function displayGeoMap(features) {
    const geoCard = document.getElementById('geoMapCard');
    const geoDetails = document.getElementById('geoDetails');
    
    // Check if it's PCAP data or URL data
    let locations = [];
    let isPcap = false;

    if (features.geo_map && features.geo_map.ip_data) {
        // PCAP Data Structure
        isPcap = true;
        locations = features.geo_map.ip_data;
    } else if (features.geo_path) {
        // URL Data Structure
        locations = features.geo_path;
    }

    geoCard.classList.remove('hidden');
    let detailsHtml = '';

    if (!locations || locations.length === 0) {
        geoDetails.innerHTML = '<div class="tech-item"><span class="tech-label">Status:</span><span class="tech-value" style="color: #94a3b8;">No geographic endpoints or public IPs detected in this analysis.</span></div>';
        setTimeout(() => {
            if (mapInstance) {
                mapInstance.remove();
            }
            mapInstance = L.map('phishingMap').setView([20, 0], 2);
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; OSM contributors',
                maxZoom: 19
            }).addTo(mapInstance);
        }, 300);
        return;
    }

    if (isPcap) {
        // Render PCAP Geo Table in collapsed, scrollable section
        const rows = locations.map(loc => `
                <div class="tech-item" style="border-left: 3px solid #3388ff;">
                    <span class="tech-label">${loc.ip}</span>
                    <span class="tech-value">
                        ${loc.location} <br>
                        <small>Traffic: ${loc.traffic} KB</small>
                    </span>
                </div>
            `).join('');

        detailsHtml = `
            <div class="geo-collapsible">
                <button id="pcapIpToggleBtn" class="geo-collapse-toggle" onclick="toggleInlineSection('pcapIpListSection', 'pcapIpToggleBtn')">
                    <span>🧭 Captured IP Endpoints (${locations.length})</span>
                    <span class="toggle-icon">▶</span>
                </button>
                <div id="pcapIpListSection" class="geo-collapse-content collapsed">
                    <div class="geo-ip-scroll-list">${rows}</div>
                </div>
            </div>
        `;
    } else {
        // Render URL Hop Chain
        locations.forEach((hop) => {
            let color = hop.type === 'Final Destination' ? '#dc3545' : (hop.type === 'Initial' ? '#28a745' : '#3388ff');
            detailsHtml += `
                <div class="tech-item" style="border-left: 3px solid ${color}; padding-left: 10px;">
                    <span class="tech-label">Hop ${hop.hop} (${hop.type}):</span>
                    <span class="tech-value">
                        ${hop.city}, ${hop.country} 
                        <br><small style="color:#888;">${hop.domain} (${hop.ip})</small>
                    </span>
                </div>
            `;
        });
    }
    
    geoDetails.innerHTML = detailsHtml;

    setTimeout(() => {
        if (mapInstance) {
            mapInstance.remove();
        }

        // Default start
        let startLat = 0, startLon = 0;
        
        if(isPcap) {
             startLat = locations[0].coordinates[1];
             startLon = locations[0].coordinates[0];
        } else {
             startLat = locations[0].lat;
             startLon = locations[0].lon;
        }
        
        mapInstance = L.map('phishingMap').setView([startLat, startLon], 2);

        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OSM contributors',
            maxZoom: 19
        }).addTo(mapInstance);

        const latlngs = [];
        const bounds = L.latLngBounds();

        locations.forEach((loc) => {
            let coords, popupText, color;

            if (isPcap) {
                coords = [loc.coordinates[1], loc.coordinates[0]];
                popupText = `<b>${loc.ip}</b><br>${loc.location}<br>Traffic: ${loc.traffic} KB`;
                color = '#06b6d4';
            } else {
                coords = [loc.lat, loc.lon];
                popupText = `<b>${loc.domain}</b><br>${loc.city}, ${loc.country}`;
                color = loc.type === 'Final Destination' ? '#ef4444' : (loc.type === 'Initial' ? '#22c55e' : '#06b6d4');
            }

            latlngs.push(coords);
            bounds.extend(coords);
            
            L.circleMarker(coords, {
                radius: 6,
                fillColor: color,
                color: "#fff",
                weight: 2,
                opacity: 1,
                fillOpacity: 0.8
            }).addTo(mapInstance).bindPopup(popupText);
        });

        if (!isPcap && latlngs.length > 1) {
            L.polyline(latlngs, {
                color: '#ffc107',
                weight: 2,
                dashArray: '5, 5'
            }).addTo(mapInstance);
        }
        
        mapInstance.fitBounds(bounds, { padding: [50, 50] });
        mapInstance.invalidateSize();
        
    }, 300); 
}

function displayBehavioralResults(behavioral) {
    const behavioralCard = document.getElementById('behavioralCard');
    const summaryDiv = document.getElementById('behavioralSummary');
    const detailsDiv = document.getElementById('behavioralDetails');
    
    if (!behavioral || Object.keys(behavioral).length === 0) {
        behavioralCard.classList.add('hidden');
        return;
    }
    
    behavioralCard.classList.remove('hidden');
    
    if (!behavioral.success) {
        summaryDiv.innerHTML = `
            <div style="text-align: center; padding: 20px; color: #dc3545;">
                <h4>⚠️ Behavioral Analysis Failed</h4>
                <p>${behavioral.error || 'Unable to perform behavioral analysis'}</p>
            </div>
        `;
        detailsDiv.innerHTML = '';
        return;
    }
    
    summaryDiv.innerHTML = createBehavioralSummary(behavioral);
    
    detailsDiv.innerHTML = createBehavioralDetails(behavioral);
    
    const screenshot = document.getElementById('behavioralScreenshot');
    if (screenshot) {
        screenshot.addEventListener('click', () => {
            showScreenshotModal(screenshot.src);
        });
    }
}

function createBehavioralSummary(behavioral) {
    const network = behavioral.network || {};
    
    return `
        <h4 style="margin-top: 0;">📊 Analysis Summary</h4>
        <div class="behavioral-stat-grid">
            <div class="behavioral-stat-card">
                <div class="stat-label">Load Time</div>
                <div class="stat-value">${behavioral.load_time || 'N/A'}s</div>
            </div>
            <div class="behavioral-stat-card">
                <div class="stat-label">Network Requests</div>
                <div class="stat-value">${network.total_requests || 0}</div>
            </div>
            <div class="behavioral-stat-card">
                <div class="stat-label">Unique Domains</div>
                <div class="stat-value">${network.unique_domains || 0}</div>
            </div>
            <div class="behavioral-stat-card">
                <div class="stat-label">Forms Detected</div>
                <div class="stat-value">${behavioral.form_count || 0}</div>
            </div>
            ${behavioral.behavioral_indicators && behavioral.behavioral_indicators.length > 0 ? `
                <div class="behavioral-stat-card" style="border-left-color: #dc3545;">
                    <div class="stat-label">Anomalies</div>
                    <div class="stat-value" style="color: #dc3545;">${behavioral.behavioral_indicators.length}</div>
                </div>
            ` : ''}
        </div>
        
        ${behavioral.final_url !== behavioral.url ? `
            <div style="margin-top: 15px; padding: 12px; background: rgba(234, 179, 8, 0.1); border-radius: 6px; border-left: 4px solid #eab308;">
                <strong style="color: #fef08a;">⚠️ URL Redirect Detected</strong><br>
                <small style="color: #94a3b8;">Final URL: ${behavioral.final_url}</small>
            </div>
        ` : ''}
    `;
}

function createBehavioralDetails(behavioral) {
    let html = '';
    
    if (behavioral.screenshot_path) {
        const filename = behavioral.screenshot_path.split('/').pop();
        html += `
            <div class="behavioral-section">
                <h4>📸 Page Screenshot</h4>
                <div class="screenshot-container">
                    <img 
                        id="behavioralScreenshot"
                        src="${API_URL}/screenshot/${filename}" 
                        alt="Page Screenshot"
                        loading="lazy"
                    />
                    <p style="margin-top: 10px; font-size: 0.85rem; color: #666;">Click to enlarge</p>
                </div>
            </div>
        `;
    }

    if (behavioral.honeypot_submission) {
        html += createHoneypotSection(behavioral.honeypot_submission);
    }

    if (behavioral.qr_analysis) {
        html += createQRCodeSection(behavioral.qr_analysis);
    }

    if (behavioral.packet_capture_enabled) {
        const statusColor = behavioral.packet_capture_status === 'completed' ? '#198754' :
                           behavioral.packet_capture_status === 'running' ? '#0d6efd' :
                           behavioral.packet_capture_status === 'failed' ? '#dc3545' : '#6c757d';
        html += `
            <div class="behavioral-section">
                <h4>📡 Live Packet Capture</h4>
                <div style="padding: 10px; border-radius: 6px; background: #f8f9fa; border-left: 4px solid ${statusColor};">
                    <div><strong>Status:</strong> ${behavioral.packet_capture_status || 'unknown'}</div>
                    ${behavioral.packet_capture_error ? `<div style="margin-top: 6px; color: #dc3545;"><strong>Error:</strong> ${behavioral.packet_capture_error}</div>` : ''}
                </div>
            </div>
        `;
    }
    
    if (behavioral.behavioral_indicators && behavioral.behavioral_indicators.length > 0) {
        html += `
            <div class="behavioral-section">
                <h4>🚨 Behavioral Anomalies</h4>
                <ul class="anomaly-list">
                    ${behavioral.behavioral_indicators.map(indicator => {
                        const isCritical = indicator.toLowerCase().includes('obfuscated') || 
                                          indicator.toLowerCase().includes('keylogger') ||
                                          indicator.toLowerCase().includes('hidden iframe');
                        return `
                            <li class="anomaly-item ${isCritical ? 'critical' : ''}">
                                ${indicator}
                            </li>
                        `;
                    }).join('')}
                </ul>
            </div>
        `;
    }
    
    if (behavioral.network) {
        const network = behavioral.network;
        html += `
            <div class="behavioral-section">
                <h4>🌐 Network Activity</h4>
                <div class="network-info-grid">
                    <div class="network-info-item">
                        <div class="label">Total Requests</div>
                        <div class="value">${network.total_requests || 0}</div>
                    </div>
                    <div class="network-info-item">
                        <div class="label">Unique Domains</div>
                        <div class="value">${network.unique_domains || 0}</div>
                    </div>
                    <div class="network-info-item">
                        <div class="label">Third-Party Requests</div>
                        <div class="value">${network.third_party_requests || 0}</div>
                    </div>
                    <div class="network-info-item">
                        <div class="label">POST Requests</div>
                        <div class="value">${network.post_requests || 0}</div>
                    </div>
                    ${network.post_to_external > 0 ? `
                        <div class="network-info-item" style="border-left-color: #ffc107;">
                            <div class="label">POST to External</div>
                            <div class="value" style="color: #ffc107;">${network.post_to_external}</div>
                        </div>
                    ` : ''}
                    <div class="network-info-item">
                        <div class="label">Failed Requests</div>
                        <div class="value">${network.failed_requests || 0}</div>
                    </div>
                    <div class="network-info-item">
                        <div class="label">Redirects</div>
                        <div class="value">${network.redirect_count || 0}</div>
                    </div>
                </div>
                
                ${network.domains_list && network.domains_list.length > 0 ? `
                    <div style="margin-top: 15px;">
                        <strong style="color: #667eea; font-size: 0.9rem;">Domains Contacted:</strong>
                        <div class="domains-list">
                            ${network.domains_list.map(domain => `<div>${domain}</div>`).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    if (behavioral.forms && behavioral.forms.length > 0) {
        html += `
            <div class="behavioral-section">
                <h4>📝 Forms Analysis</h4>
                <div class="form-analysis-list">
                    ${behavioral.forms.map((form, index) => {
                        let formClass = 'safe';
                        let badge = 'Safe';
                        
                        if (form.has_password && form.has_email) {
                            formClass = 'dangerous';
                            badge = 'High Risk';
                        } else if (form.has_password || form.has_email) {
                            formClass = 'suspicious';
                            badge = 'Suspicious';
                        }
                        
                        return `
                            <div class="form-card ${formClass}">
                                <div class="form-card-header">
                                    <span class="form-card-title">Form ${index + 1}</span>
                                    <span class="form-badge ${formClass}">${badge}</span>
                                </div>
                                <div class="form-details">
                                    <p><strong>Action:</strong> ${form.action || 'N/A'}</p>
                                    <p><strong>Method:</strong> ${form.method.toUpperCase()}</p>
                                    <p><strong>Input Fields:</strong> ${form.input_count}</p>
                                    ${form.has_password ? '<p style="color: #dc3545;">⚠️ Contains password field</p>' : ''}
                                    ${form.has_email ? '<p style="color: #ffc107;">⚠️ Contains email field</p>' : ''}
                                    ${form.input_types && form.input_types.length > 0 ? 
                                        `<p><strong>Input Types:</strong> ${form.input_types.join(', ')}</p>` 
                                    : ''}
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
    }
    
    if (behavioral.brand_indicators && behavioral.brand_indicators.detected_brands && 
        behavioral.brand_indicators.detected_brands.length > 0) {
        html += `
            <div class="behavioral-section">
                <h4>🏢 Brand Detection</h4>
                <p style="color: #666; margin-bottom: 10px;">
                    The following brand(s) were detected in the page content:
                </p>
                <div class="brand-badges">
                    ${behavioral.brand_indicators.detected_brands.map(brand => 
                        `<span class="brand-badge">${brand.toUpperCase()}</span>`
                    ).join('')}
                </div>
                ${behavioral.brand_indicators.has_brand_impersonation ? `
                    <div style="margin-top: 15px; padding: 12px; background: rgba(234, 179, 8, 0.1); border-radius: 6px; border-left: 4px solid #eab308;">
                        <strong style="color: #fef08a;">⚠️ Possible Brand Impersonation</strong><br>
                        <small style="color: #94a3b8;">Verify this is an official ${behavioral.brand_indicators.detected_brands[0]} website</small>
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    html += `
        <div class="behavioral-section">
            <h4>📄 Page Information</h4>
            <div class="api-info-row">
                <span class="api-info-label">Page Title:</span>
                <span class="api-info-value">${behavioral.title || 'N/A'}</span>
            </div>
            <div class="api-info-row">
                <span class="api-info-label">Content Length:</span>
                <span class="api-info-value">${behavioral.content_length ? behavioral.content_length.toLocaleString() : 'N/A'} bytes</span>
            </div>
            <div class="api-info-row">
                <span class="api-info-label">Links:</span>
                <span class="api-info-value">${behavioral.link_count || 0} total (${behavioral.external_links_count || 0} external)</span>
            </div>
            <div class="api-info-row">
                <span class="api-info-label">Scripts:</span>
                <span class="api-info-value">${behavioral.script_count || 0} total (${behavioral.external_scripts_count || 0} external)</span>
            </div>
            <div class="api-info-row">
                <span class="api-info-label">Iframes:</span>
                <span class="api-info-value">${behavioral.iframe_count || 0}</span>
            </div>
            <div class="api-info-row">
                <span class="api-info-label">Images:</span>
                <span class="api-info-value">${behavioral.image_count || 0}</span>
            </div>
            ${behavioral.console_errors > 0 ? `
                <div class="api-info-row" style="color: #dc3545;">
                    <span class="api-info-label">Console Errors:</span>
                    <span class="api-info-value">${behavioral.console_errors}</span>
                </div>
            ` : ''}
        </div>
    `;
    
    return html;
}

function createHoneypotSection(honeypot) {
    if (!honeypot || !honeypot.attempted) {
        return '';
    }
    
    let html = `
        <div class="behavioral-section ${honeypot.credential_harvesting_detected ? 'honeypot-critical' : ''}">
            <h4>🍯 Honeypot Credential Test</h4>
    `;
    
    html += `
        <div style="margin-bottom: 15px;">
            <p style="margin: 5px 0;"><strong>Forms Tested:</strong> ${honeypot.forms_submitted} / ${honeypot.forms_found}</p>
        </div>
    `;
    
    if (honeypot.credential_harvesting_detected) {
        html += `
            <div class="honeypot-alert critical">
                <div class="alert-icon">🚨</div>
                <div class="alert-content">
                    <h5>CREDENTIAL HARVESTING DETECTED</h5>
                    <p>This site is actively stealing credentials and sending them to external servers.</p>
                </div>
            </div>
        `;
        
        if (honeypot.exfiltration_evidence && honeypot.exfiltration_evidence.length > 0) {
            html += `
                <div style="margin-top: 15px;">
                    <h5 style="color: #dc3545; margin-bottom: 10px;">📡 Exfiltration Evidence:</h5>
                    <div class="exfiltration-list">
            `;
            
            honeypot.exfiltration_evidence.forEach(evidence => {
                const severityClass = evidence.severity === 'critical' ? 'critical' : 'high';
                html += `
                    <div class="exfiltration-item ${severityClass}">
                        <div class="exfiltration-header">
                            <span class="severity-badge ${severityClass}">${evidence.severity.toUpperCase()}</span>
                            <span class="evidence-type">${evidence.type.replace(/_/g, ' ')}</span>
                        </div>
                        <p class="evidence-description">${evidence.description}</p>
                        ${evidence.exfiltration_url ? `
                            <div class="exfiltration-url">
                                <strong>Exfiltration URL:</strong><br>
                                <code>${evidence.exfiltration_url}</code>
                            </div>
                        ` : ''}
                        ${evidence.evidence ? `
                            <p class="evidence-detail"><em>${evidence.evidence}</em></p>
                        ` : ''}
                        ${evidence.domains ? `
                            <p class="evidence-detail"><strong>Domains:</strong> ${evidence.domains.join(', ')}</p>
                        ` : ''}
                    </div>
                `;
            });
            
            html += `
                    </div>
                </div>
            `;
        }
    } else {
        html += `
            <div class="honeypot-alert safe">
                <div class="alert-icon">✅</div>
                <div class="alert-content">
                    <h5>No Credential Harvesting Detected</h5>
                    <p>Honeypot test completed. No suspicious credential exfiltration detected.</p>
                </div>
            </div>
        `;
    }
    
    if (honeypot.submissions && honeypot.submissions.length > 0) {
        html += `
            <div class="honeypot-submissions" style="margin-top: 20px;">
                <h5 style="color: #667eea; margin-bottom: 10px;">Form Submission Details:</h5>
        `;
        
        honeypot.submissions.forEach((submission, index) => {
            if (submission.submitted) {
                const urlChanged = submission.post_submission_url !== submission.pre_submission_url;
                
                html += `
                    <div class="submission-card">
                        <div class="submission-header">
                            <strong>Form ${index + 1}</strong>
                            ${submission.harvesting_indicators && submission.harvesting_indicators.length > 0 ? 
                                '<span class="danger-badge">⚠️ Suspicious</span>' : 
                                '<span class="safe-badge">✓ Normal</span>'}
                        </div>
                        <div class="submission-details">
                            <p><strong>Method:</strong> ${submission.method ? submission.method.toUpperCase() : 'N/A'}</p>
                            <p><strong>Action:</strong> ${submission.action || 'N/A'}</p>
                            <p><strong>Fields Filled:</strong> ${submission.inputs_filled ? submission.inputs_filled.length : 0}</p>
                            ${urlChanged ? `
                                <div style="margin-top: 10px; padding: 10px; background: rgba(234, 179, 8, 0.1); border-radius: 4px; border-left: 3px solid #eab308;">
                                    <strong style="color: #fef08a;">URL Changed After Submission:</strong><br>
                                    <small style="color: #94a3b8;">From: ${submission.pre_submission_url}</small><br>
                                    <small style="color: #94a3b8;">To: ${submission.post_submission_url}</small>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            } else if (submission.skipped) {
                html += `
                    <div class="submission-card skipped">
                        <div class="submission-header">
                            <strong>Form ${index + 1}</strong>
                            <span class="skipped-badge">Skipped</span>
                        </div>
                        <p style="font-size: 0.85rem; color: #666;">${submission.reason}</p>
                    </div>
                `;
            }
        });
        
        html += `
            </div>
        `;
    }
    
    html += `</div>`;
    return html;
}

function createQRCodeSection(qrAnalysis) {
    if (!qrAnalysis || qrAnalysis.qr_codes_found === 0) {
        return '';
    }
    
    const hasPhishing = qrAnalysis.phishing_detected;
    const riskLevel = qrAnalysis.risk_level || 'none';
    
    let html = `
        <div class="behavioral-section ${hasPhishing ? 'qr-detected-' + riskLevel : ''}">
            <h4>📱 QR Code Analysis</h4>
    `;
    
    html += `
        <div style="margin-bottom: 15px;">
            <p style="margin: 5px 0;">
                <strong>QR Codes Found:</strong> 
                <span class="qr-count-badge">${qrAnalysis.qr_codes_found}</span>
            </p>
            <p style="margin: 5px 0;">
                <strong>Risk Level:</strong> 
                <span class="risk-badge risk-${riskLevel}">${riskLevel.toUpperCase()}</span>
            </p>
        </div>
    `;
    
    if (hasPhishing && (riskLevel === 'critical' || riskLevel === 'high')) {
        html += `
            <div class="qr-alert critical">
                <div class="alert-icon">🚨</div>
                <div class="alert-content">
                    <h5>QUISHING ATTACK DETECTED</h5>
                    <p>QR code(s) on this page contain phishing indicators. Scanning these codes may lead to credential theft or malware.</p>
                    <div class="attack-info">
                        <strong>Attack Type:</strong> QR Code Phishing (Quishing)<br>
                        <strong>Risk:</strong> May redirect to fake login pages or malicious downloads
                    </div>
                </div>
            </div>
        `;
    } else if (hasPhishing && riskLevel === 'medium') {
        html += `
            <div class="qr-alert warning">
                <div class="alert-icon">⚠️</div>
                <div class="alert-content">
                    <h5>Suspicious QR Code Detected</h5>
                    <p>QR code(s) show suspicious characteristics. Exercise caution before scanning.</p>
                </div>
            </div>
        `;
    } else {
        html += `
            <div class="qr-alert safe">
                <div class="alert-icon">✅</div>
                <div class="alert-content">
                    <h5>QR Codes Appear Safe</h5>
                    <p>No obvious phishing indicators detected in QR code(s).</p>
                </div>
            </div>
        `;
    }
    
    if (qrAnalysis.qr_codes && qrAnalysis.qr_codes.length > 0) {
        html += `
            <div style="margin-top: 20px;">
                <h5 style="color: #667eea; margin-bottom: 15px;">
                    🔍 QR Code Details:
                </h5>
        `;
        
        qrAnalysis.qr_codes.forEach((qr, index) => {
            const isPhishing = qr.is_phishing || false;
            const confidence = qr.confidence || 0;
            
            html += `
                <div class="qr-code-card ${isPhishing ? 'qr-suspicious' : 'qr-safe'}">
                    <div class="qr-code-header">
                        <div>
                            <strong>QR Code #${index + 1}</strong>
                            <span class="qr-type-badge">${qr.type || 'QRCODE'}</span>
                        </div>
                        ${isPhishing ? 
                            '<span class="danger-badge">⚠️ Suspicious</span>' : 
                            '<span class="safe-badge">✓ Safe</span>'}
                    </div>
                    
                    <div class="qr-code-content">
            `;
            
            if (qr.position) {
                html += `
                    <div class="qr-position-info">
                        <small>Position: (${qr.position.x}, ${qr.position.y}) • Size: ${qr.position.width}x${qr.position.height}px</small>
                    </div>
                `;
            }
            
            if (qr.is_url && qr.decoded_url) {
                html += `
                    <div class="qr-url-section">
                        <strong>Decoded URL:</strong>
                        <div class="qr-url-display">
                            <code>${escapeHtml(qr.decoded_url)}</code>
                        </div>
                `;
                
                if (qr.url_analysis) {
                    const urlInfo = qr.url_analysis;
                    html += `
                        <div class="qr-url-details">
                            <div><strong>Domain:</strong> ${urlInfo.domain || 'N/A'}</div>
                            <div><strong>Scheme:</strong> ${urlInfo.scheme || 'N/A'}</div>
                            ${urlInfo.path ? `<div><strong>Path:</strong> ${urlInfo.path}</div>` : ''}
                        </div>
                    `;
                }
                
                html += `</div>`;
                
                if (confidence > 0) {
                    html += `
                        <div class="qr-confidence">
                            <strong>Phishing Confidence:</strong>
                            <div class="confidence-bar-container">
                                <div class="confidence-bar-fill ${getConfidenceClass(confidence)}" 
                                     style="width: ${confidence * 100}%"></div>
                            </div>
                            <span class="confidence-percentage">${(confidence * 100).toFixed(0)}%</span>
                        </div>
                    `;
                }
            } else if (qr.data) {
                html += `
                    <div class="qr-data-section">
                        <strong>Decoded Data:</strong>
                        <div class="qr-data-display">
                            <code>${escapeHtml(qr.data.substring(0, 200))}${qr.data.length > 200 ? '...' : ''}</code>
                        </div>
                    </div>
                `;
            }
            
            if (qr.indicators && qr.indicators.length > 0) {
                html += `
                    <div class="qr-indicators-section">
                        <strong>Detection Indicators (${qr.indicators.length}):</strong>
                        <div class="qr-indicators-list">
                `;
                
                qr.indicators.forEach(indicator => {
                    const severity = indicator.severity || 'low';
                    html += `
                        <div class="qr-indicator-item severity-${severity}">
                            <div class="indicator-header-mini">
                                <span class="severity-badge severity-${severity}">${severity.toUpperCase()}</span>
                                <span class="indicator-type-mini">${formatIndicatorType(indicator.type)}</span>
                            </div>
                            <p class="indicator-desc-mini">${indicator.description}</p>
                            ${indicator.evidence ? 
                                `<p class="indicator-evidence-mini"><em>${indicator.evidence}</em></p>` : ''}
                        </div>
                    `;
                });
                
                html += `
                        </div>
                    </div>
                `;
            }
            
            html += `
                    </div>
                </div>
            `;
        });
        
        html += `</div>`;
    }
    
    html += `
        <div class="qr-education-info">
            <h5>ℹ️ What is QR Code Phishing (Quishing)?</h5>
            <p>Quishing attacks use QR codes to bypass traditional email and web filters. When you scan a malicious QR code:</p>
            <ol>
                <li>Your mobile device camera reads the QR code</li>
                <li>The embedded URL opens automatically or with one tap</li>
                <li>You're redirected to a fake login page or malicious site</li>
                <li>Traditional security filters can't scan QR code images</li>
            </ol>
            <p><strong>Common Quishing Tactics:</strong></p>
            <ul>
                <li>📧 Fake multi-factor authentication (MFA) prompts</li>
                <li>📦 Fake package delivery notifications</li>
                <li>💳 Fake payment requests</li>
                <li>🅿️ Fake parking violation notices</li>
                <li>🎟️ Fake event tickets</li>
            </ul>
            <p class="qr-safety-tip">
                <strong>🛡️ Safety Tip:</strong> Always verify the domain before entering credentials. 
                Legitimate companies won't ask for sensitive information via QR codes.
            </p>
        </div>
    `;
    
    html += `</div>`;
    return html;
}

function getConfidenceClass(confidence) {
    if (confidence >= 0.7) return 'confidence-critical';
    if (confidence >= 0.5) return 'confidence-high';
    if (confidence >= 0.3) return 'confidence-medium';
    return 'confidence-low';
}

function showScreenshotModal(src) {
    const modal = document.createElement('div');
    modal.className = 'screenshot-modal';
    modal.innerHTML = `<img src="${src}" alt="Full Screenshot">`;
    
    modal.addEventListener('click', () => {
        document.body.removeChild(modal);
    });
    
    document.body.appendChild(modal);
}

function displayResults(data) {
    const resultsContainer = document.getElementById('resultsContainer');
    const standardWrapper = document.getElementById('standardResultsWrapper');
    const pcapWrapper = document.getElementById('pcapResultsWrapper');
    const verdictBadge = document.getElementById('verdictBadge');
    
    // Reset Views & State
    standardWrapper.classList.add('hidden');
    pcapWrapper.classList.add('hidden');
    pcapWrapper.classList.remove('embedded-pcap');
    pcapWrapper.removeAttribute('style');
    verdictBadge.classList.add('hidden');
    document.getElementById('externalApiCard').classList.add('hidden');
    document.getElementById('behavioralCard').classList.add('hidden');
    document.getElementById('geoMapCard').classList.add('hidden');
    document.getElementById('downloadPcapBtn').classList.add('hidden');
    
    currentPcapFilename = null;

    const typeBadge = document.getElementById('analysisTypeBadge');
    typeBadge.textContent = data.analysis_type.toUpperCase();

    // 1. PCAP-ONLY VIEW (Uploaded File)
    if (data.analysis_type === 'pcap') {
        pcapWrapper.classList.remove('hidden');
        renderPcapStats(data.statistics, data.metadata);
        renderCharts(data);
        renderPacketTable(data.raw_packets || data.raw_packets_sample || []);
        
        if (data.geo_map && data.geo_map.ip_data) {
            displayGeoMap({ geo_map: data.geo_map });
        }

    // 2. STANDARD URL/EMAIL/TEXT VIEW
    } else {
        standardWrapper.classList.remove('hidden');
        verdictBadge.classList.remove('hidden');
        
        const llm = data.llm_analysis;
        const features = data.features;
        
        // Populate Standard Fields
        verdictBadge.textContent = llm.verdict;
        verdictBadge.className = `verdict-badge verdict-${llm.verdict}`;
        document.getElementById('riskScore').textContent = llm.risk_score;
        document.getElementById('confidence').textContent = `${Math.round(llm.confidence * 100)}%`;
        document.getElementById('reasoning').textContent = llm.reasoning;
        
        const indicatorsList = document.getElementById('indicatorsList');
        indicatorsList.innerHTML = '';
        if (llm.indicators && llm.indicators.length > 0) {
            llm.indicators.forEach(indicator => {
                const li = document.createElement('li');
                li.textContent = indicator;
                indicatorsList.appendChild(li);
            });
        } else {
            indicatorsList.innerHTML = '<li>No specific indicators detected</li>';
        }
        
        displayTechnicalDetails(data.analysis_type, features, data.processing_time, data);
        
        // --- HYBRID: CHECK FOR EMBEDDED PCAP ANALYSIS ---
        const behavioral = data.behavioral_analysis || {};
        const embeddedPcap = behavioral.pcap_analysis || features.pcap_analysis;

        if (embeddedPcap && embeddedPcap.status === 'success') {
            pcapWrapper.classList.remove('hidden');

            pcapWrapper.classList.add('embedded-pcap');

            renderPcapStats(embeddedPcap.statistics, embeddedPcap.metadata);
            renderCharts(embeddedPcap);
            renderPacketTable(embeddedPcap.raw_packets || embeddedPcap.raw_packets_sample || []);

            const pcapPath = behavioral.pcap_path || features.pcap_path;
            if (pcapPath) {
                currentPcapFilename = pcapPath.split('/').pop();

                document.getElementById('downloadPcapBtn').classList.remove('hidden');
            }
        }
        // ------------------------------------------------
        
        if (data.features) {
            displayGeoMap(data.features);
        }
        
        if (data.external_apis && Object.keys(data.external_apis).length > 0) {
            displayExternalAPIResults(data.external_apis);
        }
        
        if (data.behavioral_analysis) {
            displayBehavioralResults(data.behavioral_analysis);
        }
    }
    
    resultsContainer.classList.remove('hidden');
    resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    const reportBtn = document.getElementById('downloadReportBtn');
    if (data.task_id || currentTaskId) {
        reportBtn.classList.remove('hidden');
        if (data.task_id) currentTaskId = data.task_id;
    } else {
        reportBtn.classList.add('hidden');
    }
}

// Helper to render PCAP stats grid (reused by both views)
function renderPcapStats(stats, meta) {
    const grid = document.getElementById('pcapStatsGrid');
    if (!stats || !meta) return;

    grid.innerHTML = `
        <div class="tech-item">
            <span class="tech-label">Total Packets:</span>
            <span class="tech-value">${meta.packet_count}</span>
        </div>
        <div class="tech-item">
            <span class="tech-label">Duration:</span>
            <span class="tech-value">${meta.duration}s</span>
        </div>
        <div class="tech-item">
            <span class="tech-label">Main Host IP:</span>
            <span class="tech-value">${stats.host_ip}</span>
        </div>
        <div class="tech-item">
            <span class="tech-label">Processing Time:</span>
            <span class="tech-value">${meta.processing_time || 0}s</span>
        </div>
    `;
}

function downloadPcap() {
    if (!currentPcapFilename) return;
    
    const url = `${API_URL}/pcap/${currentPcapFilename}`;
    const a = document.createElement('a');
    a.href = url;
    a.download = currentPcapFilename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

async function downloadReport() {
    if (!currentTaskId) return;
    
    const btn = document.getElementById('downloadReportBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '⏳ Generating...';
    btn.disabled = true;
    
    try {
        const response = await fetch(`${API_URL}/report/${currentTaskId}/download`);
        
        if (!response.ok) throw new Error("Report generation failed");
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Forensic_Report_${currentTaskId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
    } catch (error) {
        showError("Could not generate report. System dependency (wkhtmltopdf) might be missing.");
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function displayExternalAPIResults(apiData) {
    const apiCard = document.getElementById('externalApiCard');
    const summaryDiv = document.getElementById('externalApiSummary');
    const detailsDiv = document.getElementById('externalApiDetails');
    
    apiCard.classList.remove('hidden');
    
    if (apiData.aggregated_verdict) {
        summaryDiv.innerHTML = `
            <div class="api-summary-header">
                <div>
                    <h4 style="margin: 0 0 10px 0;">Aggregated Threat Intelligence</h4>
                    <div class="api-verdict ${apiData.aggregated_verdict}">
                        ${apiData.aggregated_verdict}
                    </div>
                </div>
                <div class="api-confidence">
                    <strong>Confidence: ${Math.round(apiData.confidence * 100)}%</strong>
                    <div class="api-confidence-bar">
                        <div class="api-confidence-fill" style="width: ${apiData.confidence * 100}%"></div>
                    </div>
                </div>
            </div>
            <p style="margin: 10px 0 0 0; color: #666;">${apiData.summary || 'No summary available'}</p>
            <div class="api-summary-meta">
                <span><strong>${(apiData.results || []).length}</strong> source(s) queried</span>
                <span><strong>${(apiData.results || []).filter(r => r && r.available && !r.error).length}</strong> source(s) available</span>
            </div>
        `;
    } else {
        summaryDiv.innerHTML = `
            <p style="color: #666; font-style: italic;">External API results not available</p>
        `;
    }
    
    detailsDiv.innerHTML = '';
    
    if (apiData.results && apiData.results.length > 0) {
        apiData.results.forEach(result => {
            const card = createAPIResultCard(result);
            detailsDiv.appendChild(card);
        });
    }
}

function createAPIResultCard(result) {
    const card = document.createElement('div');
    const isAvailable = result.available && !result.error;
    
    card.className = `api-result-card ${!isAvailable ? 'unavailable' : ''}`;
    
    const apiName = result.source.replace(/_/g, ' ').toUpperCase();
    
    const statusIcon = isAvailable ? '✅' : '❌';
    
    if (!isAvailable) {
        card.innerHTML = `
            <div class="api-header">
                <span class="api-name">${apiName}</span>
                <span class="api-status">${statusIcon}</span>
            </div>
            <p class="api-error">${result.error || 'Not configured'}</p>
        `;
    } else {
        const verdict = result.verdict || 'unknown';
        const hasDetailed = result.detailed && Object.keys(result.detailed).length > 0;
        
        let summaryHTML = createAPISummary(result);
        let detailedHTML = hasDetailed ? createAPIDetailed(result) : '';
        
        card.innerHTML = `
            <div class="api-header">
                <span class="api-name">${apiName}</span>
                <span class="api-status">${statusIcon}</span>
            </div>
            <div class="api-verdict-text ${verdict}">${verdict.toUpperCase()}</div>
            ${summaryHTML}
            ${detailedHTML}
        `;
        
        if (hasDetailed) {
            const toggleBtn = card.querySelector('.api-detail-button');
            const detailedContent = card.querySelector('.api-detailed-content');
            
            if (toggleBtn && detailedContent) {
                toggleBtn.addEventListener('click', () => {
                    const isExpanding = !detailedContent.classList.contains('expanded');
                    
                    if (currentlyExpandedAPI && currentlyExpandedAPI !== detailedContent) {
                        currentlyExpandedAPI.classList.remove('expanded');
                        const prevButton = currentlyExpandedAPI.previousElementSibling;
                        if (prevButton) {
                            prevButton.classList.remove('expanded');
                        }
                    }
                    
                    toggleBtn.classList.toggle('expanded');
                    detailedContent.classList.toggle('expanded');
                    
                    if (isExpanding) {
                        currentlyExpandedAPI = detailedContent;
                        
                        setTimeout(() => {
                            card.scrollIntoView({ 
                                behavior: 'smooth', 
                                block: 'nearest' 
                            });
                        }, 100);
                    } else {
                        currentlyExpandedAPI = null;
                    }
                });
            }
        }
    }
    
    return card;
}

function createAPISummary(result) {
    let summaryHTML = '<div class="api-details">';
    
    if (result.source === 'virustotal') {
        if (result.malicious_count !== undefined) {
            summaryHTML += `
                <div class="api-stats">
                    <span class="api-stat"><strong>${result.malicious_count}</strong> Malicious</span>
                    <span class="api-stat"><strong>${result.suspicious_count}</strong> Suspicious</span>
                    <span class="api-stat"><strong>${result.harmless_count}</strong> Harmless</span>
                    ${result.undetected_count !== undefined ? 
                        `<span class="api-stat"><strong>${result.undetected_count}</strong> Undetected</span>` : ''}
                </div>
            `;
        } else if (result.message) {
            summaryHTML += `<p>${result.message}</p>`;
        }
    }
    
    if (result.source === 'google_safe_browsing') {
        if (result.threat_types && result.threat_types.length > 0) {
            summaryHTML += `
                <p><strong>Threats:</strong> ${result.threat_types.join(', ')}</p>
                <p><strong>Matches:</strong> ${result.matches}</p>
            `;
        } else if (result.detailed && result.detailed.message) {
            summaryHTML += `<p>${result.detailed.message}</p>`;
        }
    }
    
    if (result.source === 'phishtank') {
        if (result.in_database) {
            summaryHTML += `
                <p><strong>In Database:</strong> Yes</p>
                <p><strong>Verified:</strong> ${result.verified ? 'Yes' : 'No'}</p>
                ${result.phish_id ? `<p><strong>Phish ID:</strong> ${result.phish_id}</p>` : ''}
            `;
        } else if (result.detailed && result.detailed.message) {
            summaryHTML += `<p>${result.detailed.message}</p>`;
        }
    }
    
    if (result.source === 'alienvault_otx') {
        if (result.in_database) {
            summaryHTML += `
                <p><strong>In Database:</strong> Yes</p>
                <p><strong>Threat Pulses:</strong> ${result.pulse_count}</p>
                ${result.total_related_pulses ? 
                    `<p><strong>Related Pulses:</strong> ${result.total_related_pulses}</p>` : ''}
            `;
        } else if (result.message) {
            summaryHTML += `<p>${result.message}</p>`;
        } else if (result.detailed && result.detailed.message) {
            summaryHTML += `<p>${result.detailed.message}</p>`;
        }
    }
    
    summaryHTML += '</div>';
    return summaryHTML;
}

function createAPIDetailed(result) {
    const detailed = result.detailed;
    if (!detailed || Object.keys(detailed).length === 0) return '';
    
    let detailedHTML = `
        <div class="api-detailed-toggle">
            <button class="api-detail-button">
                <span>Show Detailed Information</span>
                <span class="arrow">▼</span>
            </button>
            <div class="api-detailed-content">
    `;
    
    if (result.source === 'virustotal') {
        detailedHTML += createVirusTotalDetailed(detailed);
    }
    
    if (result.source === 'google_safe_browsing') {
        detailedHTML += createSafeBrowsingDetailed(detailed);
    }
    
    if (result.source === 'phishtank') {
        detailedHTML += createPhishTankDetailed(detailed);
    }
    
    if (result.source === 'alienvault_otx') {
        detailedHTML += createAlienVaultOTXDetailed(detailed);
    }
    
    detailedHTML += `
            </div>
        </div>
    `;
    
    return detailedHTML;
}

function createVirusTotalDetailed(detailed) {
    let html = '';
    
    if (detailed.url_info) {
        html += `
            <div class="api-detail-section">
                <h5>📋 URL Information</h5>
                <div class="api-info-row">
                    <span class="api-info-label">Final URL:</span>
                    <span class="api-info-value">${detailed.url_info.final_url || 'N/A'}</span>
                </div>
                <div class="api-info-row">
                    <span class="api-info-label">Title:</span>
                    <span class="api-info-value">${detailed.url_info.title || 'N/A'}</span>
                </div>
                <div class="api-info-row">
                    <span class="api-info-label">Reputation:</span>
                    <span class="api-info-value">${detailed.url_info.reputation || 0}</span>
                </div>
                <div class="api-info-row">
                    <span class="api-info-label">Times Submitted:</span>
                    <span class="api-info-value">${detailed.url_info.times_submitted || 0}</span>
                </div>
            </div>
        `;
    }
    
    if (detailed.domain_info) {
        html += `
            <div class="api-detail-section">
                <h5>🌐 Domain Information</h5>
                <div class="api-info-row">
                    <span class="api-info-label">Creation Date:</span>
                    <span class="api-info-value">${formatTimestamp(detailed.domain_info.creation_date)}</span>
                </div>
                <div class="api-info-row">
                    <span class="api-info-label">Last Update:</span>
                    <span class="api-info-value">${formatTimestamp(detailed.domain_info.last_update_date)}</span>
                </div>
                <div class="api-info-row">
                    <span class="api-info-label">Reputation:</span>
                    <span class="api-info-value">${detailed.domain_info.reputation || 0}</span>
                </div>
            </div>
        `;
    }
    
    if (detailed.categories && Object.keys(detailed.categories).length > 0) {
        html += `
            <div class="api-detail-section">
                <h5>🏷️ Categories</h5>
                <div>
                    ${Object.entries(detailed.categories).map(([source, category]) => 
                        `<span class="api-tag">${source}: ${category}</span>`
                    ).join('')}
                </div>
            </div>
        `;
    }
    
    if (detailed.tags && detailed.tags.length > 0) {
        html += `
            <div class="api-detail-section">
                <h5>🔖 Tags</h5>
                <div>
                    ${detailed.tags.map(tag => `<span class="api-tag">${tag}</span>`).join('')}
                </div>
            </div>
        `;
    }
    
    if (detailed.threat_names && detailed.threat_names.length > 0) {
        html += `
            <div class="api-detail-section">
                <h5>⚠️ Detected Threats</h5>
                <div>
                    ${detailed.threat_names.map(name => `<span class="api-threat-name">${name}</span>`).join('')}
                </div>
            </div>
        `;
    }
    
    if (detailed.detections && detailed.detections.length > 0) {
        html += `
            <div class="api-detail-section">
                <h5>🛡️ Security Vendor Detections (Top ${detailed.detections.length})</h5>
                <div class="api-detection-list">
                    ${detailed.detections.map(detection => `
                        <div class="api-detection-item">
                            <span class="engine-name">${detection.engine}</span>
                            <span class="detection-category ${detection.category}">${detection.category}</span>
                            <br>
                            <small style="color: #666;">Result: ${detection.result}</small>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    if (detailed.whois && detailed.whois !== 'N/A') {
        html += `
            <div class="api-detail-section">
                <h5>📄 WHOIS Information</h5>
                <div class="whois-content">${escapeHtml(detailed.whois)}</div>
            </div>
        `;
    }
    
    return html;
}

function createSafeBrowsingDetailed(detailed) {
    let html = '';
    
    if (detailed.threat_details && detailed.threat_details.length > 0) {
        html += `
            <div class="api-detail-section">
                <h5>⚠️ Threat Details</h5>
                <div class="api-detection-list">
                    ${detailed.threat_details.map(threat => `
                        <div class="api-detection-item">
                            <strong>Threat Type:</strong> ${threat.threat_type}<br>
                            <strong>Platform:</strong> ${threat.platform}<br>
                            <strong>Entry Type:</strong> ${threat.threat_entry_type}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    if (detailed.summary) {
        html += `
            <div class="api-detail-section">
                <h5>📊 Summary</h5>
                <div class="api-detail-grid">
                    <div class="api-detail-item">
                        <strong>Total Matches</strong>
                        ${detailed.summary.total_matches}
                    </div>
                    <div class="api-detail-item">
                        <strong>Unique Threats</strong>
                        ${detailed.summary.unique_threats}
                    </div>
                    <div class="api-detail-item">
                        <strong>Platforms</strong>
                        ${detailed.summary.platforms_affected.join(', ')}
                    </div>
                </div>
            </div>
        `;
    }
    
    return html;
}

function createPhishTankDetailed(detailed) {
    let html = '';
    
    if (detailed.phish_id) {
        html += `
            <div class="api-detail-section">
                <h5>🎣 Phishing Details</h5>
                <div class="api-info-row">
                    <span class="api-info-label">Phish ID:</span>
                    <span class="api-info-value">${detailed.phish_id}</span>
                </div>
                ${detailed.target ? `
                    <div class="api-info-row">
                        <span class="api-info-label">Target:</span>
                        <span class="api-info-value">${detailed.target}</span>
                    </div>
                ` : ''}
                ${detailed.verified ? `
                    <div class="api-info-row">
                        <span class="api-info-label">Verified At:</span>
                        <span class="api-info-value">${formatTimestamp(detailed.verified_at)}</span>
                    </div>
                ` : ''}
                ${detailed.submission_time ? `
                    <div class="api-info-row">
                        <span class="api-info-label">Submitted:</span>
                        <span class="api-info-value">${formatTimestamp(detailed.submission_time)}</span>
                    </div>
                ` : ''}
                ${detailed.phish_detail_url ? `
                    <div class="api-info-row">
                        <span class="api-info-label">Details:</span>
                        <span class="api-info-value">
                            <a href="${detailed.phish_detail_url}" target="_blank" style="color: #667eea;">View on PhishTank</a>
                        </span>
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    return html;
}

function createAlienVaultOTXDetailed(detailed) {
    let html = '';
    
    if (detailed.pulse_count !== undefined) {
        html += `
            <div class="api-detail-section">
                <h5>📊 Threat Intelligence Summary</h5>
                <div class="api-detail-grid">
                    <div class="api-detail-item">
                        <strong>Related Pulses</strong>
                        ${detailed.pulse_count}
                    </div>
                    ${detailed.total_related_pulses ? `
                        <div class="api-detail-item">
                            <strong>Total Related</strong>
                            ${detailed.total_related_pulses}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }
    
    if (detailed.summary) {
        const summary = detailed.summary;
        
        if (summary.unique_tags && summary.unique_tags.length > 0) {
            html += `
                <div class="api-detail-section">
                    <h5>🏷️ Threat Tags</h5>
                    <div>
                        ${summary.unique_tags.map(tag => `<span class="api-tag">${tag}</span>`).join('')}
                    </div>
                </div>
            `;
        }
        
        if (summary.malware_families && summary.malware_families.length > 0) {
            html += `
                <div class="api-detail-section">
                    <h5>🦠 Malware Families</h5>
                    <div>
                        ${summary.malware_families.map(family => 
                            `<span class="api-threat-name">${family}</span>`
                        ).join('')}
                    </div>
                </div>
            `;
        }
        
        if (summary.adversaries && summary.adversaries.length > 0) {
            html += `
                <div class="api-detail-section">
                    <h5>👤 Known Adversaries</h5>
                    <div>
                        ${summary.adversaries.map(adversary => 
                            `<span class="api-threat-name">${adversary}</span>`
                        ).join('')}
                    </div>
                </div>
            `;
        }
        
        if (summary.countries_targeted && summary.countries_targeted.length > 0) {
            html += `
                <div class="api-detail-section">
                    <h5>🌍 Targeted Countries</h5>
                    <div>
                        ${summary.countries_targeted.map(country => 
                            `<span class="api-tag">${country}</span>`
                        ).join('')}
                    </div>
                </div>
            `;
        }
    }
    
    if (detailed.domain_info && Object.keys(detailed.domain_info).length > 0) {
        const domainInfo = detailed.domain_info;
        
        if (domainInfo.whois) {
            html += `
                <div class="api-detail-section">
                    <h5>🌐 Domain Information</h5>
                    <div class="api-info-row">
                        <span class="api-info-label">Registrar:</span>
                        <span class="api-info-value">${domainInfo.whois.registrar || 'Unknown'}</span>
                    </div>
                    ${domainInfo.whois.creation_date ? `
                        <div class="api-info-row">
                            <span class="api-info-label">Created:</span>
                            <span class="api-info-value">${formatTimestamp(domainInfo.whois.creation_date)}</span>
                        </div>
                    ` : ''}
                    ${domainInfo.whois.expiration_date ? `
                        <div class="api-info-row">
                            <span class="api-info-label">Expires:</span>
                            <span class="api-info-value">${formatTimestamp(domainInfo.whois.expiration_date)}</span>
                        </div>
                    ` : ''}
                </div>
            `;
        }
        
        if (domainInfo.malware_samples !== undefined) {
            html += `
                <div class="api-detail-section">
                    <h5>⚠️ Malware Samples</h5>
                    <p style="color: ${domainInfo.malware_samples > 0 ? '#dc3545' : '#28a745'}; font-weight: 600;">
                        ${domainInfo.malware_samples} malware sample${domainInfo.malware_samples !== 1 ? 's' : ''} associated
                    </p>
                </div>
            `;
        }
    }
    
    if (detailed.pulses && detailed.pulses.length > 0) {
        html += `
            <div class="api-detail-section">
                <h5>🚨 Threat Pulses (Top ${detailed.pulses.length})</h5>
                <div class="api-detection-list">
                    ${detailed.pulses.map(pulse => `
                        <div class="api-detection-item">
                            <div style="margin-bottom: 8px;">
                                <strong style="color: #667eea; font-size: 0.95rem;">${pulse.name}</strong>
                                ${pulse.adversary && pulse.adversary !== 'Unknown' ? 
                                    `<br><small style="color: #dc3545;">Adversary: ${pulse.adversary}</small>` 
                                : ''}
                            </div>
                            ${pulse.description ? 
                                `<p style="font-size: 0.85rem; color: #666; margin: 5px 0;">${pulse.description}</p>` 
                            : ''}
                            ${pulse.tags && pulse.tags.length > 0 ? 
                                `<div style="margin-top: 5px;">
                                    ${pulse.tags.slice(0, 5).map(tag => 
                                        `<span class="api-tag" style="font-size: 0.7rem;">${tag}</span>`
                                    ).join('')}
                                </div>` 
                            : ''}
                            ${pulse.malware_families && pulse.malware_families.length > 0 ? 
                                `<div style="margin-top: 5px;">
                                    <strong style="font-size: 0.75rem; color: #dc3545;">Malware: </strong>
                                    ${pulse.malware_families.map(family => 
                                        `<span class="api-threat-name" style="font-size: 0.7rem;">${family}</span>`
                                    ).join('')}
                                </div>` 
                            : ''}
                            ${pulse.created ? 
                                `<div style="margin-top: 5px; font-size: 0.75rem; color: #999;">
                                    Created: ${formatTimestamp(pulse.created)}
                                </div>` 
                            : ''}
                            ${pulse.references && pulse.references.length > 0 ? 
                                `<div style="margin-top: 5px;">
                                    <strong style="font-size: 0.75rem;">References:</strong><br>
                                    ${pulse.references.map(ref => 
                                        `<a href="${ref}" target="_blank" style="font-size: 0.75rem; color: #667eea; display: block; margin-top: 2px; text-decoration: none;">${ref.substring(0, 60)}${ref.length > 60 ? '...' : ''}</a>`
                                    ).join('')}
                                </div>` 
                            : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    return html;
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    
    if (typeof timestamp === 'number') {
        return new Date(timestamp * 1000).toLocaleString();
    }
    
    try {
        return new Date(timestamp).toLocaleString();
    } catch {
        return timestamp;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function displayTechnicalDetails(type, features, processingTime, fullResult = null) {
    const container = document.getElementById('technicalDetailsContent');
    container.innerHTML = '';
    
    if (type === 'url') {
        container.innerHTML = `
            <div class="tech-grid">
                <div class="tech-item">
                    <span class="tech-label">Domain:</span>
                    <span class="tech-value">${features.domain || 'N/A'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">SSL Valid:</span>
                    <span class="tech-value">${features.ssl_valid ? '✅ Yes' : '❌ No'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Domain Age:</span>
                    <span class="tech-value">${features.domain_age_days ? features.domain_age_days + ' days' : 'Unknown'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Has Password Field:</span>
                    <span class="tech-value">${features.has_password_field ? '⚠️ Yes' : '✅ No'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Form Count:</span>
                    <span class="tech-value">${features.form_count || 0}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Processing Time:</span>
                    <span class="tech-value">${processingTime}s</span>
                </div>
            </div>
        `;
    } else if (type === 'email') {
        container.innerHTML = `
            <div class="tech-grid">
                <div class="tech-item">
                    <span class="tech-label">From:</span>
                    <span class="tech-value">${features.from || 'Unknown'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Sender Email:</span>
                    <span class="tech-value">${features.sender_email || 'Unknown'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Subject:</span>
                    <span class="tech-value">${features.subject || 'No Subject'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">SPF Result:</span>
                    <span class="tech-value">${features.spf_result || 'Unknown'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Has DKIM:</span>
                    <span class="tech-value">${features.has_dkim ? '✅ Yes' : '❌ No'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Reply-To Mismatch:</span>
                    <span class="tech-value">${features.reply_to_mismatch ? '⚠️ Yes' : '✅ No'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Link Count:</span>
                    <span class="tech-value">${features.link_count || 0}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Has IP-based URL:</span>
                    <span class="tech-value">${features.has_ip_based_url ? '⚠️ Yes' : '✅ No'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Attachments:</span>
                    <span class="tech-value">${features.attachment_count || 0}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Suspicious Attachment:</span>
                    <span class="tech-value">${features.has_suspicious_attachment ? '⚠️ Yes' : '✅ No'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Processing Time:</span>
                    <span class="tech-value">${processingTime}s</span>
                </div>
            </div>
        `;
    } else if (type === 'text') {
        container.innerHTML = `
            <div class="tech-grid">
                <div class="tech-item">
                    <span class="tech-label">Text Length:</span>
                    <span class="tech-value">${features.length} characters</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Urgency Keywords:</span>
                    <span class="tech-value">${features.urgency_keywords || 0}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Financial Keywords:</span>
                    <span class="tech-value">${features.financial_keywords || 0}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Contains Links:</span>
                    <span class="tech-value">${features.has_links ? '⚠️ Yes' : '✅ No'}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Link Count:</span>
                    <span class="tech-value">${features.link_count || 0}</span>
                </div>
                <div class="tech-item">
                    <span class="tech-label">Processing Time:</span>
                    <span class="tech-value">${processingTime}s</span>
                </div>
            </div>
        `;
    }

    const deepScans = (fullResult && fullResult.url_deep_scans) ? fullResult.url_deep_scans : [];
    if ((type === 'email' || type === 'text') && deepScans.length > 0) {
        const scanHtml = deepScans.map((scan, idx) => `
            <div class="deep-scan-item">
                <div>
                    <div class="deep-scan-url">${scan.url}</div>
                    <small style="color:#64748b;">Task ID: ${scan.task_id}</small>
                </div>
                <button class="action-btn secondary deep-scan-btn" data-task-id="${scan.task_id}">Analyze URL #${idx + 1}</button>
            </div>
        `).join('');

        container.innerHTML += `
            <div class="deep-scan-container">
                <h4>🔎 Detected URLs (Background Deep Scan)</h4>
                <p class="help-text" style="margin-bottom:10px;">Run URL analysis with live progress for links extracted from this ${type} content.</p>
                ${scanHtml}
            </div>
        `;

        container.querySelectorAll('.deep-scan-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const taskId = btn.getAttribute('data-task-id');
                showProgressModal();
                await streamTaskProgress(taskId);
            });
        });
    }
}

function resetUI() {
    document.getElementById('resultsContainer').classList.add('hidden');
    document.getElementById('errorContainer').classList.add('hidden');
}

function resetResults() {
    document.getElementById('resultsContainer').classList.add('hidden');
    document.getElementById('errorContainer').classList.add('hidden');
    document.getElementById('downloadReportBtn').classList.add('hidden');
    document.getElementById('downloadPcapBtn').classList.add('hidden');

    currentTaskId = null;
    currentPcapFilename = null;

    if (mapInstance) {
        mapInstance.remove();
        mapInstance = null;
    }

    pcapCharts.forEach(chart => {
        try { chart.dispose(); } catch (e) {}
    });
    pcapCharts = [];
    pcapPacketRows = [];

    const packetTableBody = document.getElementById('packetTableBody');
    if (packetTableBody) packetTableBody.innerHTML = '';
    const packetTableMeta = document.getElementById('packetTableMeta');
    if (packetTableMeta) packetTableMeta.textContent = 'Showing 0 of 0 packets';
}

function setButtonLoading(button, textSpan, loaderSpan, isLoading) {
    button.disabled = isLoading;
    if (isLoading) {
        textSpan.classList.add('hidden');
        loaderSpan.classList.remove('hidden');
    } else {
        textSpan.classList.remove('hidden');
        loaderSpan.classList.add('hidden');
    }
}

function showError(message) {
    const errorContainer = document.getElementById('errorContainer');
    const errorMessage = document.getElementById('errorMessage');
    
    errorMessage.textContent = message;
    errorContainer.classList.remove('hidden');
    
    setTimeout(() => {
        errorContainer.classList.add('hidden');
    }, 5000);
}

function toggleInlineSection(sectionId, buttonId) {
    const section = document.getElementById(sectionId);
    const btn = document.getElementById(buttonId);
    if (!section || !btn) return;
    section.classList.toggle('collapsed');
    btn.classList.toggle('expanded');
}

function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    const icon = section.previousElementSibling.querySelector('.toggle-icon');
    
    section.classList.toggle('collapsed');
    icon.style.transform = section.classList.contains('collapsed') 
        ? 'rotate(-90deg)' 
        : 'rotate(0deg)';
}

const emailUploadArea = document.getElementById('emailUploadArea');
const qrUploadArea = document.getElementById('qrUploadArea');
const pcapUploadArea = document.getElementById('pcapUploadArea');

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function wireDragAndDrop(area, onDrop) {
    if (!area) return;
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        area.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        area.addEventListener(eventName, () => area.classList.add('drag-over'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        area.addEventListener(eventName, () => area.classList.remove('drag-over'), false);
    });

    area.addEventListener('drop', onDrop, false);
}

wireDragAndDrop(emailUploadArea, (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        document.getElementById('emailFileInput').files = files;
        handleEmailFile(document.getElementById('emailFileInput'));
    }
});

wireDragAndDrop(qrUploadArea, (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        document.getElementById('qrFileInput').files = files;
        handleQRFile(document.getElementById('qrFileInput'));
    }
});

wireDragAndDrop(pcapUploadArea, (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        document.getElementById('pcapFileInput').files = files;
        handlePcapFile(document.getElementById('pcapFileInput'));
    }
});

const urlInputEl = document.getElementById('urlInput');
if (urlInputEl) {
    urlInputEl.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') analyzeURL();
    });
}

window.addEventListener('resize', resizePcapCharts);