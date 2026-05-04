const socket = io();

const logLabels = window.initialLogLabels || ['ERROR', 'WARNING', 'INFO'];
const logData = window.initialLogData || [0, 0, 0];
const threatLabels = window.initialThreatLabels || ['Normal', 'Suspicious', 'Critical'];
const threatData = window.initialThreatData || [0, 0, 0];
const initialSecurity = window.initialSecurity || {};

const levelCanvas = document.getElementById('levelChart');
const threatCanvas = document.getElementById('threatChart');

// Chart.js setup
const levelChart = new Chart(levelCanvas.getContext('2d'), {
  type: 'bar',
  data: {
    labels: logLabels,
    datasets: [{
      label: 'Log Levels',
      data: logData,
      backgroundColor: ['#dc3545', '#ffc107', '#0d6efd']
    }]
  },
  options: {
    responsive: true,
    scales: {
      y: { beginAtZero: true }
    }
  }
});

const threatChart = new Chart(threatCanvas.getContext('2d'), {
  type: 'bar',
  data: {
    labels: threatLabels,
    datasets: [{
      label: 'Threat Categories',
      data: threatData,
      backgroundColor: ['#198754', '#ffc107', '#dc3545']
    }]
  },
  options: {
    responsive: true,
    scales: {
      y: { beginAtZero: true }
    }
  }
});

// Update chart with new counts
function updateChart(counts) {
  levelChart.data.datasets[0].data = [counts.ERROR || 0, counts.WARNING || 0, counts.INFO || 0];
  levelChart.update();
}

function updateThreatChart(threatCounts) {
  threatChart.data.datasets[0].data = [
    threatCounts.Normal || 0,
    threatCounts.Suspicious || 0,
    threatCounts.Critical || 0
  ];
  threatChart.update();
}

function setThreatBadge(level) {
  const badge = document.getElementById('threat-level-badge');
  if (!badge) return;

  badge.classList.remove('threat-normal', 'threat-suspicious', 'threat-critical');
  const threatLevel = (level || 'Normal').toLowerCase();
  badge.textContent = `Threat: ${level || 'Normal'}`;

  if (threatLevel === 'critical') {
    badge.classList.add('threat-critical');
  } else if (threatLevel === 'suspicious') {
    badge.classList.add('threat-suspicious');
  } else {
    badge.classList.add('threat-normal');
  }
}

function renderSuspiciousIps(suspiciousIps) {
  const list = document.getElementById('suspicious-ip-list');
  if (!list) return;

  list.innerHTML = '';

  if (!suspiciousIps || !suspiciousIps.length) {
    const empty = document.createElement('li');
    empty.className = 'list-group-item px-0 text-muted';
    empty.id = 'suspicious-ip-empty';
    empty.textContent = 'No suspicious IPs detected yet.';
    list.appendChild(empty);
    return;
  }

  suspiciousIps.forEach((item) => {
    const row = document.createElement('li');
    row.className = 'list-group-item px-0 d-flex justify-content-between align-items-start';
    row.innerHTML = `
      <div>
        <div class="fw-semibold">${item.ip || 'Unknown IP'}</div>
        <div class="small text-muted">${item.message || 'Suspicious IP detected.'}</div>
      </div>
      <span class="badge text-bg-danger rounded-pill">${item.failed_attempts || 0}</span>
    `;
    list.appendChild(row);
  });
}

function renderAttackDetections(attacks) {
  const list = document.getElementById('attack-detections');
  if (!list) return;

  list.innerHTML = '';

  if (!attacks || !attacks.length) {
    const empty = document.createElement('li');
    empty.className = 'text-muted';
    empty.id = 'attack-detections-empty';
    empty.textContent = 'No attack patterns detected yet.';
    list.appendChild(empty);
    return;
  }

  attacks.forEach((attack) => {
    const item = document.createElement('li');
    item.className = 'mb-2 p-2 rounded-3 bg-light border';
    item.innerHTML = `
      <div class="fw-semibold">Brute Force Attack</div>
      <div class="small text-muted">IP ${attack.ip || 'Unknown'} | ${attack.failed_attempts || 0} failures within ${attack.window_seconds || 0} seconds</div>
    `;
    list.appendChild(item);
  });
}

function appendSecurityAlert(alert) {
  const feed = document.getElementById('live-security-alerts');
  if (!feed) return;

  const empty = document.getElementById('security-alert-empty');
  if (empty) empty.remove();

  const wrapper = document.createElement('div');
  const severityClass = (alert.severity || 'warning').toLowerCase() === 'critical' ? 'alert-danger' : 'alert-warning';
  wrapper.className = `alert ${severityClass} py-2 px-3 mb-2`;
  wrapper.innerHTML = `
    <div class="fw-semibold">${(alert.type || 'security alert').replaceAll('_', ' ')}</div>
    <div class="small">${alert.message || 'Security event detected.'}</div>
  `;
  feed.prepend(wrapper);
}

function appendStreamLine(text) {
  const stream = document.getElementById('stream');
  if (!stream) return;

  const line = document.createElement('div');
  line.textContent = text;
  stream.appendChild(line);
  stream.scrollTop = stream.scrollHeight;
}

// keep stream bounded to avoid unbounded buffering
const STREAM_MAX_LINES = 1000;

function trimStreamBuffer() {
  const stream = document.getElementById('stream');
  if (!stream) return;
  while (stream.children.length > STREAM_MAX_LINES) {
    stream.removeChild(stream.firstChild);
  }
}

function renderStreamPreview(lines) {
  const stream = document.getElementById('stream');
  if (!stream) return;

  stream.innerHTML = '';
  (lines || []).forEach((line) => appendStreamLine(line));
}

// Handle Socket.IO events
socket.on('connect', () => {
  console.log('Connected to server');
});

socket.on('update_counts', (payload) => {
  if (payload && payload.counts) {
    updateChart(payload.counts);
    // update badges and last update
    document.getElementById('badge-error').textContent = payload.counts.ERROR || 0;
    document.getElementById('badge-warning').textContent = payload.counts.WARNING || 0;
    document.getElementById('badge-info').textContent = payload.counts.INFO || 0;
    document.getElementById('last-update').textContent = new Date().toLocaleString();
  }
});

socket.on('security_update', (payload) => {
  const security = payload || initialSecurity;
  setThreatBadge(security.threat_level || 'Normal');
  updateThreatChart(security.threat_counts || {});
  renderSuspiciousIps(security.suspicious_ips || []);
  renderAttackDetections(security.brute_force_attacks || []);

  const count = document.getElementById('security-alert-count');
  if (count) {
    count.textContent = String((security.alerts || []).length);
  }

  const summary = document.getElementById('security-summary-text');
  if (summary && security.summary) {
    summary.textContent = `${security.summary.total_lines || 0} lines scanned`;
  }
});

socket.on('security_alert', (alert) => {
  appendSecurityAlert(alert || {});
});

socket.on('new_log', (payload) => {
  appendStreamLine(payload.line || payload);
  trimStreamBuffer();
});

socket.on('monitor_error', (payload) => {
  setMonitorStatus(`Monitoring error: ${payload && payload.error ? payload.error : 'unknown'}`, true);
});

// Upload form handling
const uploadForm = document.getElementById('upload-form');
const uploadBtn = document.getElementById('upload-btn');
const reportBtn = document.getElementById('download-report');
const monitorBtn = document.getElementById('monitor-btn');
const appendLineBtn = document.getElementById('append-line-btn');
const monitorStatus = document.getElementById('monitor-status');
const alerts = document.getElementById('alerts');
const appendLinePanel = document.getElementById('append-line-panel');
const appendLineInput = document.getElementById('append-line-input');
const appendLineFilename = document.getElementById('append-line-filename');
const appendLineStatus = document.getElementById('append-line-status');
const saveLineBtn = document.getElementById('save-line-btn');
const previewLineBtn = document.getElementById('preview-line-btn');
const closeAppendPanelBtn = document.getElementById('close-append-panel-btn');
let lastUploadedFile = null;
let monitoringStarted = false;

function setMonitorStatus(message, isError = false) {
  if (!monitorStatus) return;
  monitorStatus.textContent = message;
  monitorStatus.classList.toggle('text-danger', isError);
  monitorStatus.classList.toggle('text-muted', !isError);
}

function setAppendLineStatus(message, isError = false) {
  if (!appendLineStatus) return;
  appendLineStatus.textContent = message;
  appendLineStatus.classList.toggle('text-danger', isError);
  appendLineStatus.classList.toggle('text-muted', !isError);
}

function showAppendLinePanel(show) {
  if (!appendLinePanel) return;
  appendLinePanel.classList.toggle('d-none', !show);
}

function openAppendLinePanel() {
  if (!lastUploadedFile) {
    setAppendLineStatus('Upload a file first, then add a new line.', true);
    return;
  }
  if (appendLineFilename) {
    appendLineFilename.textContent = `Appending to: ${lastUploadedFile}`;
  }

  showAppendLinePanel(true);
  if (appendLinePanel && typeof appendLinePanel.scrollIntoView === 'function') {
    appendLinePanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  if (appendLineInput && typeof appendLineInput.focus === 'function') {
    appendLineInput.focus();
  }
}

function startMonitoring(filename) {
  if (!filename) {
    setMonitorStatus('No uploaded file is available to monitor.', true);
    return;
  }

  // Ensure any previous monitor for this session is stopped first
  try {
    socket.emit('stop_monitor', {});
  } catch (e) {}

  socket.emit('monitor', { filename });
  monitoringStarted = true;
  if (monitorBtn) {
    monitorBtn.disabled = false;
    monitorBtn.textContent = `Monitoring: ${filename}`;
  }
  setMonitorStatus(`Live monitoring started for ${filename}.`);
}

async function appendNewLine() {
  if (!lastUploadedFile) {
    setAppendLineStatus('Upload a file first, then add a new line.', true);
    return;
  }

  const line = appendLineInput ? appendLineInput.value.trim() : '';
  if (!line) {
    setAppendLineStatus('Type a log line before appending it.', true);
    return;
  }

  setAppendLineStatus('Appending new line...');

  try {
    const res = await fetch('/append-line', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: lastUploadedFile, line })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Failed to append line');
    }

    if (data.counts) updateChart(data.counts);
    if (data.security) {
      setThreatBadge(data.security.threat_level || 'Normal');
      updateThreatChart(data.security.threat_counts || {});
      renderSuspiciousIps(data.security.suspicious_ips || []);
      renderAttackDetections(data.security.brute_force_attacks || []);

      const count = document.getElementById('security-alert-count');
      if (count) {
        count.textContent = String((data.security.alerts || []).length);
      }
    }

    if (data.line && !monitoringStarted) {
      appendStreamLine(data.line);
    }
    if (data.preview_lines && data.preview_lines.length && !monitoringStarted) {
      renderStreamPreview(data.preview_lines);
    }

    document.getElementById('last-update').textContent = new Date().toLocaleString();
    if (appendLineInput) appendLineInput.value = '';
    setAppendLineStatus('New line added to the uploaded log.');
  } catch (err) {
    setAppendLineStatus(err.message || 'Failed to append line.', true);
  }
}

if (appendLineBtn) {
  appendLineBtn.addEventListener('click', (ev) => {
    ev.preventDefault();
    openAppendLinePanel();
  });
}

if (previewLineBtn) {
  previewLineBtn.addEventListener('click', (ev) => {
    ev.preventDefault();
    openAppendLinePanel();
    setAppendLineStatus('Preview the line, then append it to the uploaded log.');
  });
}

if (closeAppendPanelBtn) {
  closeAppendPanelBtn.addEventListener('click', (ev) => {
    ev.preventDefault();
    showAppendLinePanel(false);
  });
}

if (saveLineBtn) {
  saveLineBtn.addEventListener('click', async (ev) => {
    ev.preventDefault();
    await appendNewLine();
  });
}

if (monitorBtn) {
  monitorBtn.addEventListener('click', (ev) => {
    ev.preventDefault();

    if (!lastUploadedFile) {
      setMonitorStatus('Upload a file first, then start monitoring.', true);
      return;
    }

    // toggle monitoring: if already started, stop it
    if (monitoringStarted) {
      socket.emit('stop_monitor', {});
      monitoringStarted = false;
      monitorBtn.textContent = 'Start Live Monitoring';
      setMonitorStatus('Live monitoring stopped.');
      return;
    }

    startMonitoring(lastUploadedFile);
  });
}

if (reportBtn) {
  reportBtn.addEventListener('click', async () => {
    const spinner = document.getElementById('pdf-spinner');
    reportBtn.disabled = true;
    if (spinner) spinner.classList.remove('d-none');

    try {
      // Cache-bust to ensure browser always receives fresh report content.
      const reportUrl = `/report?t=${Date.now()}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);

      const res = await fetch(reportUrl, {
        method: 'GET',
        cache: 'no-store',
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!res.ok) {
        throw new Error('Failed to generate report');
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'log_report.pdf';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      // Fallback to direct browser navigation if fetch-based download is blocked.
      try {
        window.open('/report', '_blank');
      } catch (e) {}
      alerts.innerHTML = '<div class="alert alert-danger">PDF request timed out. A fallback download was opened in a new tab.</div>';
    } finally {
      reportBtn.disabled = false;
      if (spinner) spinner.classList.add('d-none');
    }
  });
}

uploadForm.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  alerts.innerHTML = '';

  const input = document.getElementById('files');
  if (!input.files.length) {
    alerts.innerHTML = '<div class="alert alert-warning">Please choose at least one file.</div>';
    return;
  }

  const formData = new FormData();
  for (const file of input.files) formData.append('files', file);

  uploadBtn.disabled = true;
  document.getElementById('btn-spinner').classList.remove('d-none');

  try {
    const res = await fetch('/upload', { method: 'POST', body: formData });
    const data = await res.json();
    if (!res.ok) {
      alerts.innerHTML = `<div class="alert alert-danger">${data.error || 'Upload failed'}</div>`;
    } else {
      if (data.counts) updateChart(data.counts);
      alerts.innerHTML = `<div class="alert alert-success">Analyzed ${data.saved ? data.saved.length : 0} file(s) from temporary storage.</div>`;
      document.getElementById('last-update').textContent = new Date().toLocaleString();

      if (data.preview_lines && data.preview_lines.length) {
        renderStreamPreview(data.preview_lines);
      }

      if (data.saved && data.saved.length) {
        lastUploadedFile = data.saved[data.saved.length - 1];
        if (monitorBtn) {
          monitorBtn.disabled = false;
          monitorBtn.textContent = 'Restart Live Monitoring';
        }
        if (appendLineBtn) {
          appendLineBtn.disabled = false;
          appendLineBtn.classList.remove('d-none');
        }
        startMonitoring(lastUploadedFile);
      }

      if (data.security) {
        setThreatBadge(data.security.threat_level || 'Normal');
        updateThreatChart(data.security.threat_counts || {});
        renderSuspiciousIps(data.security.suspicious_ips || []);
        renderAttackDetections(data.security.brute_force_attacks || []);

        const count = document.getElementById('security-alert-count');
        if (count) {
          count.textContent = String((data.security.alerts || []).length);
        }
      }
    }
  } catch (err) {
    alerts.innerHTML = `<div class="alert alert-danger">Network error</div>`;
  } finally {
    uploadBtn.disabled = false;
    document.getElementById('btn-spinner').classList.add('d-none');
  }
});

// show server-side monitor stopped message
socket.on('monitor_stopped', (payload) => {
  setMonitorStatus('Monitoring stopped by server.');
  monitoringStarted = false;
  if (monitorBtn) monitorBtn.textContent = 'Start Live Monitoring';
});
