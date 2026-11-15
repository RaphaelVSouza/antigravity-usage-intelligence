const { execFile } = require('child_process');
const https = require('https');
const http = require('http');

let cachedConn = null;
let cachedQuota = null;
let lastQueryTime = 0;

// Negative cache: after failed language-server scans, back off exponentially
// (30s, 60s, ... capped at 10 min) instead of re-running PowerShell/netstat/probes every poll.
const SCAN_BACKOFF_BASE_MS = 30000;
const SCAN_BACKOFF_MAX_MS = 600000;
let scanFailures = 0;
let nextScanAt = 0;

function recordScanFailure() {
  scanFailures += 1;
  const delay = Math.min(SCAN_BACKOFF_BASE_MS * 2 ** (scanFailures - 1), SCAN_BACKOFF_MAX_MS);
  nextScanAt = Date.now() + delay;
}

function execBin(bin, args) {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: 4000 }, (err, stdout, stderr) => {
      resolve({ err, stdout: stdout ? stdout.trim() : '', stderr });
    });
  });
}

function queryStatus(port, csrfToken, protocol) {
  const lib = protocol === 'https' ? https : http;
  const body = JSON.stringify({ wrapper_data: {} });

  return new Promise((resolve) => {
    const req = lib.request(
      {
        hostname: '127.0.0.1',
        port: port,
        path: '/exa.language_server_pb.LanguageServerService/GetUserStatus',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'X-Codeium-Csrf-Token': csrfToken,
          'Connect-Protocol-Version': '1',
        },
        rejectUnauthorized: false,
        timeout: 2500,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          if (res.statusCode === 200 && data) {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              resolve(null);
            }
          } else {
            resolve(null);
          }
        });
      }
    );

    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.write(body);
    req.end();
  });
}

async function listServerCandidates() {
  if (process.platform === 'win32') {
    const psScript = "Get-CimInstance Win32_Process | Where-Object { $_.Name -like '*language_server*' -and $_.CommandLine -like '*--csrf_token*' } | Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress";
    const { stdout } = await execBin('powershell', ['-NoProfile', '-Command', psScript]);
    if (!stdout) return [];
    try {
      const parsed = JSON.parse(stdout);
      const arr = Array.isArray(parsed) ? parsed : [parsed];
      return arr
        .filter((c) => c && Number.isInteger(Number(c.ProcessId)) && Number(c.ProcessId) > 0 && c.CommandLine)
        .map((c) => ({ pid: Number(c.ProcessId), cmd: c.CommandLine }));
    } catch (e) {
      return [];
    }
  }

  // macOS / Linux: pgrep prints "<pid> <full command line>" as plain text,
  // so parse lines instead of expecting JSON.
  const { stdout } = await execBin('pgrep', ['-fa', 'language_server']);
  if (!stdout) return [];
  const out = [];
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (m && m[2].includes('--csrf_token')) {
      out.push({ pid: parseInt(m[1], 10), cmd: m[2] });
    }
  }
  return out;
}

async function listListeningPorts(pid) {
  const ports = new Set();
  if (!Number.isInteger(pid) || pid <= 0) return ports;
  try {
    if (process.platform === 'win32') {
      // Filtra o PID na coluna exata (última) em JS: evita casar PID 12 com 123.
      const { stdout: netOut } = await execBin('netstat', ['-ano']);
      if (netOut) {
        for (const line of netOut.split('\n')) {
          const cols = line.trim().split(/\s+/);
          if (cols.length < 5 || cols[cols.length - 1] !== String(pid) || cols[3] !== 'LISTENING') continue;
          const m = cols[1].match(/:(\d+)$/);
          if (m) ports.add(parseInt(m[1], 10));
        }
      }
    } else if (process.platform === 'linux') {
      const { stdout } = await execBin('ss', ['-ltnp']);
      if (stdout) {
        const pidMarker = `pid=${pid},`;
        for (const line of stdout.split('\n')) {
          if (!line.includes(pidMarker)) continue;
          const m = line.match(/:(\d+)\s/);
          if (m) ports.add(parseInt(m[1], 10));
        }
      }
    } else {
      // macOS: lsof is best-effort (may not exist -> ignored below).
      const { stdout } = await execBin('lsof', ['-aPn', '-iTCP', '-sTCP:LISTEN', '-p', String(pid)]);
      if (stdout) {
        for (const line of stdout.split('\n')) {
          const m = line.match(/:(\d+)\s+\(LISTEN\)/);
          if (m) ports.add(parseInt(m[1], 10));
        }
      }
    }
  } catch (e) {
    // Best-effort only; extension_port offsets below still apply.
  }
  return ports;
}

async function scanForLanguageServer() {
  const candidates = await listServerCandidates();

  for (const cand of candidates) {
    const cmd = cand.cmd || '';
    const pid = cand.pid;
    if (!pid || !cmd) continue;

    const tokenMatch = cmd.match(/--csrf_token[=\s]+([A-Za-z0-9\-_.=+/]+)/);
    const extPortMatch = cmd.match(/--extension_server_port[=\s]+(\d+)/);
    if (!tokenMatch) continue;

    const csrfToken = tokenMatch[1];
    const extPort = extPortMatch ? parseInt(extPortMatch[1], 10) : 0;

    // Só probe portas escutadas pelo próprio PID: o token CSRF nunca vai a portas arbitrárias.
    // (extPort, extPort+1, extPort+2 são palpites e não são usados para enviar o token.)
    const owned = await listListeningPorts(pid);
    const portList = [...owned].filter((p) => p > 0 && p < 65536).slice(0, 25);
    const probes = [];
    for (const port of portList) {
      for (const proto of ['https', 'http']) {
        probes.push(
          queryStatus(port, csrfToken, proto)
            .then((status) => ({ port, protocol: proto, status }))
            .catch(() => ({ port, protocol: proto, status: null }))
        );
      }
    }
    const settled = await Promise.allSettled(probes);
    for (const r of settled) {
      if (r.status !== 'fulfilled') continue;
      const { port, protocol, status } = r.value;
      if (status && status.userStatus) {
        return {
          port,
          protocol,
          csrfToken,
          pid,
          rawStatus: status.userStatus,
        };
      }
    }
  }

  return null;
}

function parseQuotaFromStatus(status) {
  if (!status) return null;

  const configs = status.cascadeModelConfigData?.clientModelConfigs || [];

  let geminiModel = null;
  let claudeModel = null;

  for (const m of configs) {
    if (!m.quotaInfo) continue;
    const label = m.label || '';
    if (/gemini/i.test(label) && !geminiModel) {
      geminiModel = m;
    } else if (/claude/i.test(label) && !claudeModel) {
      claudeModel = m;
    }
  }

  const result = {
    is_live: true,
    stale: false,
    fetched_at: Date.now(),
    user_name: status.name || 'User',
    user_email: status.email || '',
    tier_name: status.userTier?.name || 'Google AI Pro',
    prompt_credits: status.planStatus?.availablePromptCredits ?? null,
    flow_credits: status.planStatus?.availableFlowCredits ?? null,
    gemini: geminiModel ? {
      label: geminiModel.label,
      remaining_fraction: geminiModel.quotaInfo.remainingFraction,
      remaining_pct: Math.round((geminiModel.quotaInfo.remainingFraction ?? 1) * 100),
      used_pct: Math.round((1 - (geminiModel.quotaInfo.remainingFraction ?? 1)) * 100),
      reset_time: geminiModel.quotaInfo.resetTime,
    } : null,
    claude: claudeModel ? {
      label: claudeModel.label,
      remaining_fraction: claudeModel.quotaInfo.remainingFraction,
      remaining_pct: Math.round((claudeModel.quotaInfo.remainingFraction ?? 1) * 100),
      used_pct: Math.round((1 - (claudeModel.quotaInfo.remainingFraction ?? 1)) * 100),
      reset_time: claudeModel.quotaInfo.resetTime,
    } : null,
  };

  return result;
}

async function getLiveQuota(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && cachedQuota && (now - lastQueryTime < 15000)) {
    return cachedQuota;
  }

  // 1. Try cached connection first
  if (cachedConn) {
    const raw = await queryStatus(cachedConn.port, cachedConn.csrfToken, cachedConn.protocol);
    if (raw && raw.userStatus) {
      cachedQuota = parseQuotaFromStatus(raw.userStatus);
      lastQueryTime = now;
      return cachedQuota;
    }
    cachedConn = null;
  }

  // 2. Scan for language server (skipped during backoff; a forced refresh always scans)
  if (forceRefresh || Date.now() >= nextScanAt) {
    try {
      const conn = await scanForLanguageServer();
      if (conn) {
        scanFailures = 0;
        nextScanAt = 0;
        cachedConn = {
          port: conn.port,
          protocol: conn.protocol,
          csrfToken: conn.csrfToken,
          pid: conn.pid,
        };
        cachedQuota = parseQuotaFromStatus(conn.rawStatus);
        lastQueryTime = now;
        return cachedQuota;
      }
      recordScanFailure();
    } catch (err) {
      recordScanFailure();
    }
  }

  // Scan failed: serve last-known data explicitly marked stale
  // so the dashboard never mistakes it for a fresh reading.
  if (cachedQuota) {
    return { ...cachedQuota, stale: true };
  }
  return null;
}

module.exports = {
  getLiveQuota,
};
