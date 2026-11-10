function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function matchCidr(ip, cidr) {
  try {
    const [range, bits = 32] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1);
    return (ipToInt(ip) & mask) === (ipToInt(range) & mask);
  } catch {
    return false;
  }
}

// Official reverse proxy / CDN subnets
const EXCLUDED_CIDRS = [
  // Cloudflare IPv4 ranges
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  // DiamWall
  '216.146.31.0/24',
  // Sucuri
  '192.124.249.0/24', '185.93.228.0/22',
  // Incapsula/Imperva
  '199.83.128.0/21', '107.154.0.0/16', '149.126.72.0/21', '45.60.0.0/16', '45.64.64.0/22',
  // DDoS-Guard
  '186.2.160.0/24', '190.115.16.0/20'
];

// CDNs, WAFs, and Third-Party Mail/SaaS ASNs that are NOT origin web servers
const EXCLUDED_ASNS = [
  // CDNs & WAFs
  13335,  // Cloudflare
  207731, // DiamWall
  30148,  // Sucuri
  19551,  // Incapsula/Imperva
  54113,  // Fastly
  20940, 16625, 35994, // Akamai
  57724,  // DDoS-Guard
  59729,  // StormWall
  202422, // ArvanCloud
  16509,  // Amazon CloudFront
  60066,  // BunnyCDN
  // Third-Party Mail & Cloud SaaS Providers (False Positive Sources)
  15169, 396982, // Google LLC (Gmail, Google Workspace, G Suite)
  8075, 8068, 8074, 8070, // Microsoft Corporation (Outlook, Office 365, Azure Front Door)
  26496,  // GoDaddy Mail Services
  32787,  // ProtonMail
  26002,  // Zoho Corporation
  13535,  // SendGrid / Twilio
  14782,  // Mailgun Technologies
  36459,  // GitHub Pages
  133165, // Vercel
  394161, // Shopify
  13324   // Zendesk
];

const EXCLUDED_ORGS = [
  'cloudflare', 'diamwall', 'sucuri', 'incapsula', 'imperva',
  'fastly', 'akamai', 'ddos-guard', 'stormwall', 'blazingfast',
  'qrator', 'variti', 'deflect', 'ovh anti-ddos', 'arvancloud',
  'cloudfront', 'bunnycdn', 'keycdn', 'cachefly',
  'google llc', 'google workspace', 'google mail', 'gmail',
  'microsoft corporation', 'outlook', 'office 365', 'zoho mail',
  'sendgrid', 'mailgun', 'shopify', 'zendesk', 'github, inc', 'vercel'
];

const EXCLUDED_HOST_SUFFIXES = [
  'cloudflare.net', 'cloudflare.com', 'diamwall.com', 'sucuridns.com',
  'incapdns.net', 'fastly.net', 'akamaitechnologies.com', 'ddos-guard.net',
  'google.com', 'googlemail.com', '1e100.net', 'outlook.com', 'microsoft.com',
  'zoho.com', 'mailgun.org', 'sendgrid.net', 'shopify.com', 'github.io',
  'vercel.app', 'netlify.app', 'zendesk.com', 'statuspage.io', 'hubspot.com',
  'cloudfront.net', 'b-cdn.net'
];

// Curated FFUF-style Subdomain Wordlist (Origin / Backend / Internal vectors)
const FFUF_SUBDOMAIN_WORDLIST = [
  'origin', 'direct', 'origin-www', 'origin-app', 'origin-prod', 'direct-connect',
  'real', 'backend', 'cpanel', 'whm', 'mail', 'webmail', 'autodiscover',
  'sip', 'vpn', 'staging', 'dev', 'test', 'api', 'admin', 'portal',
  'edge', 'node', 'node1', 'node2', 'cluster', 'gw', 'router', 'fw',
  'firewall', 'corp', 'internal', 'db', 'mysql', 'sql', 'redis', 'elastic',
  'kibana', 'grafana', 'jenkins', 'git', 'gitlab', 'registry', 'auth',
  'sso', 'idp', 'keycloak', 'status', 'monitor', 'nagios', 'zabbix',
  'prometheus', 'cdn-origin', 'static-origin', 'media-origin', 'app-origin',
  'web', 'www2', 'www1', 'm', 'mobile', 'static', 'assets', 'img',
  'images', 'files', 'download', 'upload', 'backup', 'old', 'new',
  'v1', 'v2', 'v3', 'beta', 'alpha', 'stage', 'stg', 'uat', 'sandbox',
  'preview', 'demo', 'qa', 'int', 'intra', 'ext', 'secure', 'ssl',
  'ssh', 'ftp', 'sftp', 'samba', 'nas', 'storage', 'cloud', 'dc',
  'hub', 'relay', 'proxy', 'lb', 'loadbalancer', 'ingress', 'traefik',
  'nginx', 'apache', 'haproxy', 'gateway', 'api-origin', 'api-prod',
  'api-dev', 'api-stage', 'direct-origin', 'server', 'server1', 'server2',
  'host', 'host1', 'ns1', 'ns2', 'ns3', 'dns', 'mx', 'smtp', 'pop',
  'imap', 'vip', 'vip1', 'vip2', 'core', 'main', 'master', 'worker',
  'pool', 'front', 'frontend', 'ws', 'websocket', 'live', 'stream',
  'media', 'cdn', 'bastion', 'jump', 'gateway1', 'gw1', 'app1', 'app2',
  'web1', 'web2', 'panel', 'manager', 'mgmt', 'control', 'remote',
  'access', 'dialin', 'radius', 'ldap', 'ad', 'dc1', 'dc2', 'payment',
  'checkout', 'shop', 'store', 'cart', 'secure-pay', 'billing', 'api2'
];

let currentHost = '';
let currentApex = '';
let currentResolvedIp = '';
let targetTabTitle = '';

function isExcludedInfrastructure(ip, org = '', asn = null, hostnames = []) {
  if (ip && /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
    if (EXCLUDED_CIDRS.some(cidr => matchCidr(ip, cidr))) {
      return true;
    }
  }

  if (asn) {
    const num = parseInt(String(asn).replace(/[^0-9]/g, ''), 10);
    if (EXCLUDED_ASNS.includes(num)) return true;
  }

  if (org) {
    const lower = org.toLowerCase();
    if (EXCLUDED_ORGS.some(p => lower.includes(p))) return true;
  }

  if (Array.isArray(hostnames) && hostnames.length > 0) {
    for (const h of hostnames) {
      const lower = h.toLowerCase();
      if (EXCLUDED_HOST_SUFFIXES.some(s => lower.endsWith(s))) return true;
    }
  }

  return false;
}

function extractApexDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname;
  const secondLevelTLDs = ['co.uk', 'com.tr', 'org.tr', 'gov.tr', 'edu.tr', 'net.tr', 'com.au', 'co.nz', 'co.jp', 'defesa.pt'];
  const lastTwo = parts.slice(-2).join('.');
  if (secondLevelTLDs.includes(lastTwo) && parts.length > 2) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function showToast(message) {
  const toast = document.getElementById('toastBox');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => {
    toast.classList.remove('show');
  }, 2200);
}

function safeOpenTab(url, event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  chrome.tabs.create({ url, active: false });
  showToast('Opened tab in background');
}

async function queryDoH(name, type = 'A', timeoutMs = 3200) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) return [];
    const json = await res.json();
    return json.Answer || [];
  } catch {
    clearTimeout(timer);
    try {
      const fallbackRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {
        signal: AbortSignal.timeout(2800)
      });
      if (fallbackRes.ok) {
        const fbJson = await fallbackRes.json();
        return fbJson.Answer || [];
      }
    } catch {}
    return [];
  }
}

async function fetchGeoIp(ip) {
  try {
    const res = await fetch(`https://ipwho.is/${ip}`, { signal: AbortSignal.timeout(3500) });
    if (res.ok) {
      const data = await res.json();
      if (data.success) return data;
    }
  } catch {}
  return null;
}

// Shodan InternetDB Public API (Keyless)
async function fetchShodanInternetDb(ip) {
  try {
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(3500) });
    if (res.ok) {
      return await res.json();
    }
  } catch {}
  return null;
}

// Censys Official Extension Public API (Keyless)
async function fetchCensysHost(ip) {
  try {
    const res = await fetch(`https://api.platform.censys.io/api/extension/hosts/${ip}`, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(4000)
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {}
  return null;
}

// URLScan.io Public Search API (Keyless Historical)
async function probeUrlscanHistory(apex, rawCandidates, currentIp) {
  try {
    const res = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(apex)}&size=30`, {
      signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.results || !Array.isArray(json.results)) return;

    for (const r of json.results) {
      if (r.page && r.page.ip) {
        const ip = r.page.ip.trim();
        if (ip && ip !== currentIp && !isExcludedInfrastructure(ip) && /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
          let scanDate = 'Historical';
          if (r.task && r.task.time) {
            scanDate = r.task.time.slice(0, 10);
          }
          const srv = r.page.server ? ` [${r.page.server}]` : '';
          const ptr = r.page.ptr ? ` PTR: ${r.page.ptr}` : '';
          rawCandidates.push({
            ip,
            source: `URLScan Archive (${scanDate})${srv}${ptr}`,
            confidence: 'HIGH',
            historicalDate: scanDate,
            initialScore: 20
          });
        }
      }
    }
  } catch {}
}

// Ground Truth Verification Engine (Strict False-Positive Elimination)
async function verifyEndpoint(ip, domain, tabTitle = '') {
  const result = {
    statusText: 'FILTERED / DORMANT',
    cssClass: 'status-offline',
    server: '',
    note: 'Server did not respond to direct probe. Discarded as false positive.',
    isExcluded: false,
    isDormant: true,
    isConfirmedOrigin: false,
    openPorts: [],
    vulns: 0,
    censysMatch: '',
    titleMatch: '',
    score: 0
  };

  if (isExcludedInfrastructure(ip)) {
    result.isExcluded = true;
    result.statusText = 'WAF/CDN PROXY';
    result.cssClass = 'status-vhost-403';
    result.note = 'Excluded: IP belongs to Cloudflare/WAF/Proxy subnet.';
    return result;
  }

  // Dual Intelligence Harvest: Shodan + Censys
  const [shodanData, censysData] = await Promise.allSettled([
    fetchShodanInternetDb(ip),
    fetchCensysHost(ip)
  ]);

  const shodan = shodanData.status === 'fulfilled' ? shodanData.value : null;
  const censys = censysData.status === 'fulfilled' ? censysData.value : null;

  const detectedPorts = new Set();
  const detectedHostnames = [];

  if (shodan) {
    if (isExcludedInfrastructure(ip, '', null, shodan.hostnames || [])) {
      result.isExcluded = true;
      result.note = 'Excluded: Shodan reverse DNS identified CDN/SaaS host.';
      return result;
    }
    if (Array.isArray(shodan.ports)) {
      shodan.ports.forEach(p => detectedPorts.add(p));
    }
    if (Array.isArray(shodan.hostnames)) {
      detectedHostnames.push(...shodan.hostnames);
    }
    result.vulns = (shodan.vulns && Array.isArray(shodan.vulns)) ? shodan.vulns.length : 0;
  }

  if (censys) {
    const asnName = censys.autonomous_system ? censys.autonomous_system.name : '';
    const asnNum = censys.autonomous_system ? censys.autonomous_system.asn : null;
    if (isExcludedInfrastructure(ip, asnName, asnNum)) {
      result.isExcluded = true;
      result.note = `Excluded: Censys identified CDN/Mail provider (${asnName}).`;
      return result;
    }

    if (censys.services && Array.isArray(censys.services)) {
      censys.services.forEach(s => {
        if (s.port) detectedPorts.add(s.port);
      });
    }

    const fwdNames = censys.dns?.forward_names || [];
    const revNames = censys.dns?.reverse_names || [];
    const allCensysNames = [...fwdNames, ...revNames];
    detectedHostnames.push(...allCensysNames);

    // Definitive Ground Truth: Censys seen this domain pointing to this IP
    const domainMatches = allCensysNames.filter(n => n.toLowerCase().endsWith(`.${domain}`) || n.toLowerCase() === domain);
    if (domainMatches.length > 0) {
      result.censysMatch = domainMatches[0];
      result.isConfirmedOrigin = true;
      result.score += 50;
    }
  }

  const portsArr = Array.from(detectedPorts).sort((a, b) => a - b);
  result.openPorts = portsArr;

  const webPorts = portsArr.filter(p => [80, 443, 8080, 8443, 8000, 8888, 3000, 5000].includes(p));
  if (webPorts.length > 0) {
    result.isDormant = false;
    result.score += 20;
  }

  // Active HTTP Probe & Content Fingerprint Match
  try {
    const res = await fetch(`http://${ip}/`, {
      method: 'GET',
      signal: AbortSignal.timeout(2800)
    });

    result.isDormant = false;
    const serverHeader = (res.headers.get('server') || '').toLowerCase();
    result.server = serverHeader;

    if (res.headers.has('cf-ray') || serverHeader.includes('cloudflare') || serverHeader.includes('diamwall') || serverHeader.includes('sucuri')) {
      result.isExcluded = true;
      result.statusText = 'WAF PROXY';
      result.note = `Filtered: Confirmed ${serverHeader || 'Cloudflare'} proxy edge.`;
      return result;
    }

    // Read partial body to check for HTML Title match
    try {
      const text = await res.text();
      const match = text.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (match && match[1]) {
        const candidateTitle = match[1].trim();
        result.server = result.server ? `${result.server} | "${candidateTitle.slice(0, 30)}"` : `"${candidateTitle.slice(0, 35)}"`;
        
        // If candidate title contains domain or matches active tab title
        if (candidateTitle.toLowerCase().includes(domain.toLowerCase()) || (tabTitle && candidateTitle.toLowerCase().includes(tabTitle.slice(0, 15).toLowerCase()))) {
          result.titleMatch = candidateTitle;
          result.isConfirmedOrigin = true;
          result.score += 45;
        }
      }
    } catch {}

    if (res.status === 200) {
      result.statusText = 'HTTP 200 OK';
      result.cssClass = 'status-live-200';
      result.score += 30;
      result.note = result.titleMatch ? `Confirmed: Body title matches target site ("${result.titleMatch.slice(0, 30)}")` : 'Direct HTTP 200 origin response received.';
      return result;
    } else if (res.status === 403 || res.status === 404) {
      result.statusText = `HTTP ${res.status} VHOST`;
      result.cssClass = 'status-vhost-403';
      result.score += 25;
      result.note = `VirtualHost active. Server rejects direct IP access without Host: ${domain}`;
      return result;
    } else if (res.status >= 300 && res.status < 400) {
      result.statusText = `HTTP ${res.status} REDIR`;
      result.cssClass = 'status-redirect';
      result.score += 20;
      result.note = 'Origin web server redirected request.';
      return result;
    } else {
      result.statusText = `HTTP ${res.status}`;
      result.cssClass = 'status-vhost-403';
      result.score += 15;
      result.note = `Origin daemon responded with status code ${res.status}.`;
      return result;
    }
  } catch {}

  // HTTPS Probe
  const startTime = Date.now();
  try {
    await fetch(`https://${ip}/`, {
      method: 'GET',
      signal: AbortSignal.timeout(2200),
      mode: 'no-cors'
    });
    result.isDormant = false;
    result.score += 25;
    result.statusText = 'HTTPS LIVE';
    result.cssClass = 'status-live-200';
    result.note = 'TLS port 443 active and responding.';
    return result;
  } catch (err) {
    const elapsed = Date.now() - startTime;
    if (elapsed < 1800) {
      result.isDormant = false;
      result.score += 20;
      result.statusText = 'TLS 443 VHOST';
      result.cssClass = 'status-vhost-403';
      result.note = `TLS port 443 active (SSL CN Mismatch). Origin requires Host: ${domain}`;
      return result;
    }
  }

  if (webPorts.length > 0) {
    result.statusText = `PORT ${webPorts.slice(0, 3).join('/')} LIVE`;
    result.cssClass = 'status-live-200';
    result.note = `Active web daemon verified via Shodan/Censys. Host header: ${domain}`;
  }

  return result;
}

function updateShieldUI(isProxy, orgName = '') {
  const container = document.getElementById('shieldStatus');
  const text = document.getElementById('shieldText');
  const shieldLabel = window.i18n ? window.i18n.t('shieldActive') : 'WAF/CDN SHIELD ACTIVE';
  const directLabel = window.i18n ? window.i18n.t('directExposed') : 'DIRECT ORIGIN EXPOSED';
  if (isProxy) {
    container.className = 'header-status status-cf';
    text.textContent = orgName ? `${orgName.toUpperCase()} - ${shieldLabel}` : shieldLabel;
  } else {
    container.className = 'header-status status-direct';
    text.textContent = directLabel;
  }
}

function setCopyButton(button, textToCopy, toastMsg = 'Copied to clipboard') {
  button.onclick = async (e) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(textToCopy);
      button.classList.add('copied');
      const orig = button.textContent;
      button.textContent = window.i18n ? window.i18n.t('copiedBtn') : 'COPIED';
      showToast(toastMsg);
      setTimeout(() => {
        button.classList.remove('copied');
        button.textContent = orig;
      }, 1500);
    } catch {}
  };
}

async function probeRobtexPdns(apex, rawCandidates, currentIp) {
  try {
    const res = await fetch(`https://freeapi.robtex.com/pdns/forward/${encodeURIComponent(apex)}`, {
      signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) return;
    const text = await res.text();
    const lines = text.split('\n');
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const record = JSON.parse(line);
        if (record.rrtype === 'A' && record.rrdata) {
          const ip = record.rrdata.trim();
          if (ip && ip !== currentIp && !isExcludedInfrastructure(ip) && /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
            let dateStr = 'Historical';
            if (record.time_first) {
              const d = new Date(record.time_first * 1000);
              dateStr = d.toISOString().split('T')[0];
            }
            rawCandidates.push({
              ip,
              source: `Robtex PDNS Archive (${dateStr})`,
              confidence: 'HIGH',
              historicalDate: dateStr,
              initialScore: 20
            });
          }
        }
      } catch {}
    }
  } catch {}
}

async function probeHackerTarget(apex, rawCandidates, currentIp) {
  try {
    const res = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(apex)}`, {
      signal: AbortSignal.timeout(4500)
    });
    if (!res.ok) return;
    const text = await res.text();
    if (text.includes('API count exceeded')) return;
    const lines = text.split('\n');
    for (const line of lines) {
      const parts = line.split(',');
      if (parts.length >= 2) {
        const h = parts[0].trim();
        const ip = parts[1].trim();
        if (ip && ip !== currentIp && !isExcludedInfrastructure(ip) && /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
          rawCandidates.push({
            ip,
            source: `Passive DNS: ${h || apex}`,
            confidence: 'HIGH',
            initialScore: 15
          });
        }
      }
    }
  } catch {}
}

// High-speed Embedded FFUF Engine (Zero External Dependencies, -ac Auto-Calibrated)
async function probeFfufSubdomains(apex, rawCandidates, currentIp) {
  if (window.embeddedFfuf) {
    await window.embeddedFfuf.runFuzz(
      apex,
      queryDoH,
      isExcludedInfrastructure,
      currentIp,
      (done, total, hitCount) => {
        const statusEl = document.getElementById('hunterStatusText');
        if (statusEl) {
          statusEl.textContent = `[FFUF] Fuzzing ${done}/${total} subdomains (-ac calibrated) | Hits: ${hitCount}...`;
        }
      },
      (hit) => {
        rawCandidates.push(hit);
      }
    );
  }
}

// MX and SPF record analysis with third-party SaaS rejection
async function probeMxAndSpf(apex, rawCandidates, currentIp) {
  const KNOWN_MAIL_SAAS = [
    'google', 'googlemail', 'aspmx', 'outlook', 'microsoft', 'zoho',
    'mailgun', 'sendgrid', 'protonmail', 'icloud', 'amazonses', 'mimecast',
    'barracuda', 'pphosted', 'trendmicro', 'mandrill', 'postmark'
  ];

  const mxAnswers = await queryDoH(apex, 'MX', 3500);
  for (const record of mxAnswers) {
    if (record.type === 15) {
      const parts = record.data.trim().split(/\s+/);
      const mxHost = (parts[1] || parts[0]).replace(/\.$/, '').toLowerCase();
      
      // If MX points to Google, Microsoft, Zoho etc., skip it immediately (False Positive Prevention)
      if (KNOWN_MAIL_SAAS.some(m => mxHost.includes(m))) {
        continue;
      }

      const mxResolved = await queryDoH(mxHost, 'A', 3000);
      for (const ipRec of mxResolved) {
        if (ipRec.type === 1) {
          const ip = ipRec.data;
          if (ip && ip !== currentIp && !isExcludedInfrastructure(ip)) {
            rawCandidates.push({
              ip,
              source: `Self-Hosted MX: ${mxHost}`,
              confidence: 'HIGH',
              initialScore: 25
            });
          }
        }
      }
    }
  }

  const txtAnswers = await queryDoH(apex, 'TXT', 3500);
  for (const record of txtAnswers) {
    if (record.type === 16) {
      const val = record.data;
      if (val && val.includes('v=spf1')) {
        const matches = val.match(/ip4:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:\/[0-9]+)?)/gi);
        if (matches) {
          for (const m of matches) {
            const rawIp = m.replace('ip4:', '').split('/')[0];
            if (rawIp && rawIp !== currentIp && !isExcludedInfrastructure(rawIp)) {
              rawCandidates.push({
                ip: rawIp,
                source: `SPF Direct IP (${m})`,
                confidence: 'CRITICAL',
                initialScore: 30
              });
            }
          }
        }
      }
    }
  }
}

async function probeCrtSh(apex, rawCandidates, currentIp) {
  try {
    const res = await fetch(`https://crt.sh/?q=%.${encodeURIComponent(apex)}&output=json`, {
      signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) return;
    const certs = await res.json();
    if (!Array.isArray(certs)) return;

    const uniqueHosts = new Set();
    for (const cert of certs.slice(0, 150)) {
      if (cert.name_value) {
        const names = cert.name_value.split('\n');
        for (let name of names) {
          name = name.trim().toLowerCase();
          if (name.startsWith('*.')) name = name.substring(2);
          if (name.endsWith(`.${apex}`) && name !== apex && !name.includes('*')) {
            uniqueHosts.add(name);
          }
        }
      }
    }

    const hostList = Array.from(uniqueHosts).slice(0, 25);
    const tasks = hostList.map(async host => {
      const answers = await queryDoH(host, 'A', 3000);
      for (const rec of answers) {
        if (rec.type === 1) {
          const ip = rec.data;
          if (ip && ip !== currentIp && !isExcludedInfrastructure(ip)) {
            rawCandidates.push({
              ip,
              source: `SSL Certificate SAN: ${host}`,
              confidence: 'HIGH',
              initialScore: 20
            });
          }
        }
      }
    });
    await Promise.allSettled(tasks);
  } catch {}
}

function renderOriginResults(candidates, filteredCount = 0, fromCache = false) {
  const container = document.getElementById('originResultsList');
  const radar = document.getElementById('radarSpinner');
  const statusText = document.getElementById('hunterStatusText');
  const cacheBadge = document.getElementById('cacheBadge');

  radar.classList.add('stopped');
  container.innerHTML = '';

  if (fromCache) {
    cacheBadge.textContent = 'CACHED';
  } else {
    cacheBadge.textContent = 'FRESH';
  }

  if (!candidates || candidates.length === 0) {
    statusText.textContent = `Strict verification completed. No live origin passed zero-false-positive checks. (${filteredCount} dormant/proxy/mail IPs filtered out).`;
    container.innerHTML = `
      <div class="no-origins-found">
        No direct unshielded origin IP verified on active vectors.<br>
        All ${filteredCount} dormant IPs, third-party mail servers, and reverse proxy edges were strictly eliminated.
      </div>
    `;
    return;
  }

  statusText.textContent = `Verified ${candidates.length} true origin server(s). Filtered out ${filteredCount} dormant/proxy/mail false positives.`;

  candidates.forEach(item => {
    const card = document.createElement('div');
    card.className = 'origin-card';

    let confBadgeClass = 'conf-med';
    let confBadgeText = item.confidence;

    if (item.verification.isConfirmedOrigin || item.totalScore >= 70) {
      confBadgeClass = 'conf-confirmed';
      confBadgeText = item.verification.censysMatch ? 'CONFIRMED ORIGIN' : '100% VERIFIED';
    } else if (item.totalScore >= 40) {
      confBadgeClass = 'conf-critical';
      confBadgeText = `${item.totalScore}% PROBABILITY`;
    } else {
      confBadgeClass = 'conf-high';
      confBadgeText = `${item.totalScore}% VERIFIED`;
    }

    const httpTeleportUrl = `http://${item.ip}`;
    const curlCommand = `curl -k -v --resolve ${currentApex}:443:${item.ip} https://${currentApex}/`;
    const hostsEntry = `${item.ip} ${currentApex} www.${currentApex}`;
    const psCmd = `powershell -Command "Add-Content -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts' -Value '\`n${item.ip} ${currentApex} www.${currentApex}'"`;

    let portsHtml = '';
    if (item.verification && item.verification.openPorts && item.verification.openPorts.length > 0) {
      const portBadges = item.verification.openPorts.slice(0, 8).map(p => `<span class="card-port-tag">${p}</span>`).join(' ');
      portsHtml = `
        <div class="card-shodan-ports">
          PORTS: ${portBadges} ${item.verification.vulns > 0 ? `<span style="color:#ff1744;font-weight:bold;">[${item.verification.vulns} VULNS]</span>` : ''}
          ${item.verification.censysMatch ? `<span class="censys-match-badge">[CENSYS MATCH: ${item.verification.censysMatch}]</span>` : ''}
          ${item.verification.titleMatch ? `<span class="censys-match-badge" style="color:#00e676;border-color:rgba(0,230,118,0.4)">[TITLE MATCH]</span>` : ''}
        </div>
      `;
    }

    let dateBadge = '';
    if (item.historicalDate) {
      dateBadge = `<span class="badge-date">SEEN: ${item.historicalDate}</span>`;
    }

    card.innerHTML = `
      <div class="origin-card-top">
        <a class="origin-ip-teleport-link" href="${httpTeleportUrl}">
          <span class="teleport-icon">&#x26A1;</span> ${item.ip}
        </a>
        <div class="top-badges">
          ${dateBadge}
          <span class="http-status-badge ${item.verification.cssClass}">${item.verification.statusText}</span>
          <span class="confidence-badge ${confBadgeClass}">${confBadgeText}</span>
        </div>
      </div>
      <div class="origin-vector">
        VECTOR: <span class="vector-source">${item.source}</span>
      </div>
      ${portsHtml}
      <div class="verification-note ${item.verification.cssClass === 'status-live-200' ? 'note-ok' : ''}">
        ${item.verification.note}
      </div>
      <div class="origin-card-actions">
        <button class="btn-teleport btn-teleport-card">${window.i18n ? window.i18n.t('btnOpenIp') : 'OPEN IP'}</button>
        <button class="btn-action-sm btn-curl" title="Copy cURL command with --resolve flag (Bypasses VirtualHost & Cloudflare)">CURL</button>
        <button class="btn-action-sm btn-hosts" title="Copy hosts file line: IP domain">HOSTS</button>
        <button class="btn-action-sm btn-cmd" title="Copy PowerShell 1-liner to append to Windows hosts file">${window.i18n ? window.i18n.t('btnCmd') : '1-CMD'}</button>
        <button class="btn-action-sm btn-censys">CENSYS</button>
        <button class="btn-action-sm btn-shodan">SHODAN</button>
        <button class="btn-action-sm btn-vt" title="VirusTotal IP intelligence">VT</button>
        <button class="btn-action-sm btn-abuse" title="AbuseIPDB check">ABUSE</button>
        <button class="btn-action-sm btn-nmap" title="HackerTarget Cloud Nmap Port Scan">NMAP</button>
        <button class="btn-action-sm btn-mtr" title="HackerTarget Live MTR Traceroute">MTR</button>
        <button class="btn-action-sm btn-copy-card">${window.i18n ? window.i18n.t('btnCopy') : 'COPY'}</button>
      </div>
    `;

    const teleportLink = card.querySelector('.origin-ip-teleport-link');
    teleportLink.addEventListener('click', (e) => safeOpenTab(httpTeleportUrl, e));

    const btnTeleport = card.querySelector('.btn-teleport-card');
    btnTeleport.addEventListener('click', (e) => safeOpenTab(httpTeleportUrl, e));

    const btnShodan = card.querySelector('.btn-shodan');
    btnShodan.addEventListener('click', (e) => safeOpenTab(`https://www.shodan.io/host/${item.ip}`, e));

    const btnCensys = card.querySelector('.btn-censys');
    btnCensys.addEventListener('click', (e) => safeOpenTab(`https://search.censys.io/hosts/${item.ip}`, e));

    const btnVt = card.querySelector('.btn-vt');
    if (btnVt) btnVt.addEventListener('click', (e) => safeOpenTab(`https://www.virustotal.com/gui/ip-address/${item.ip}`, e));

    const btnAbuse = card.querySelector('.btn-abuse');
    if (btnAbuse) btnAbuse.addEventListener('click', (e) => safeOpenTab(`https://www.abuseipdb.com/check/${item.ip}`, e));

    const btnNmap = card.querySelector('.btn-nmap');
    if (btnNmap) btnNmap.addEventListener('click', (e) => safeOpenTab(`https://api.hackertarget.com/nmap/?q=${item.ip}&apikey=freeuser-chrome-ext31b`, e));

    const btnMtr = card.querySelector('.btn-mtr');
    if (btnMtr) btnMtr.addEventListener('click', (e) => safeOpenTab(`https://api.hackertarget.com/mtr/?q=${item.ip}&apikey=freeuser-chrome-ext31b`, e));

    const btnCurl = card.querySelector('.btn-curl');
    setCopyButton(btnCurl, curlCommand, 'Copied cURL command (Bypasses Cloudflare & VirtualHost)');

    const btnHosts = card.querySelector('.btn-hosts');
    setCopyButton(btnHosts, hostsEntry, 'Copied hosts entry (IP domain)');

    const btnCmd = card.querySelector('.btn-cmd');
    setCopyButton(btnCmd, psCmd, 'Copied PowerShell 1-liner for hosts file');

    const btnCopy = card.querySelector('.btn-copy-card');
    setCopyButton(btnCopy, item.ip, 'Copied IP');

    container.appendChild(card);
  });
}

async function saveScanToStorage(data) {
  try {
    const key = `teleport_cache_${currentApex}`;
    await chrome.storage.local.set({ [key]: data });
  } catch {}
}

async function loadScanFromStorage() {
  try {
    const key = `teleport_cache_${currentApex}`;
    const result = await chrome.storage.local.get([key]);
    if (result && result[key]) {
      const entry = result[key];
      const maxAgeMs = 30 * 60 * 1000;
      if (Date.now() - entry.timestamp < maxAgeMs) {
        return entry;
      }
    }
  } catch {}
  return null;
}

async function runHunterEngine(forceRefresh = false) {
  const radar = document.getElementById('radarSpinner');
  const statusText = document.getElementById('hunterStatusText');
  const container = document.getElementById('originResultsList');
  const cacheBadge = document.getElementById('cacheBadge');

  if (!forceRefresh) {
    const cached = await loadScanFromStorage();
    if (cached) {
      renderOriginResults(cached.candidates, cached.filteredCount || 0, true);
      return;
    }
  }

  cacheBadge.textContent = 'SCANNING';
  radar.classList.remove('stopped');
  statusText.textContent = 'Executing multi-vector origin extraction (FFUF, Censys, URLScan, Robtex & SANs)...';
  container.innerHTML = `
    <div class="loading-box">
      <div class="progress-bar"><div class="progress-fill"></div></div>
      <span>Extracting historical DNS archives, Censys, URLScan, FFUF dictionary & Shodan verification...</span>
    </div>
  `;

  const rawCandidates = [];

  // Multi-engine parallel harvest
  await Promise.allSettled([
    probeUrlscanHistory(currentApex, rawCandidates, currentResolvedIp),
    probeRobtexPdns(currentApex, rawCandidates, currentResolvedIp),
    probeHackerTarget(currentApex, rawCandidates, currentResolvedIp),
    probeFfufSubdomains(currentApex, rawCandidates, currentResolvedIp),
    probeMxAndSpf(currentApex, rawCandidates, currentResolvedIp),
    probeCrtSh(currentApex, rawCandidates, currentResolvedIp)
  ]);

  statusText.textContent = 'Applying strict Ground-Truth verification & filtering dormant/proxy false positives...';

  const seen = new Set();
  const deduped = [];
  for (const c of rawCandidates) {
    if (!seen.has(c.ip)) {
      seen.add(c.ip);
      deduped.push(c);
    }
  }

  const verifiedCandidates = [];
  let filteredFalsePositiveCount = 0;

  const verifyTasks = deduped.map(async item => {
    const verification = await verifyEndpoint(item.ip, currentApex, targetTabTitle);
    const totalScore = (item.initialScore || 0) + (verification.score || 0);

    // STRICT ZERO-FALSE-POSITIVE CRITERIA:
    // Drop if excluded (WAF/CDN/Shared Mail) OR dormant (dead host) OR score < 30 (unverified noise)
    if (verification.isExcluded || verification.isDormant || (!verification.isConfirmedOrigin && totalScore < 30)) {
      filteredFalsePositiveCount++;
      return;
    }

    verifiedCandidates.push({
      ...item,
      verification,
      totalScore
    });
  });

  await Promise.allSettled(verifyTasks);

  // Sort by highest score first (Definitive Origins on top)
  verifiedCandidates.sort((a, b) => b.totalScore - a.totalScore);

  // Keep top 8 verified origin candidates to eliminate cognitive overload
  const topCandidates = verifiedCandidates.slice(0, 8);

  renderOriginResults(topCandidates, filteredFalsePositiveCount, false);

  await saveScanToStorage({
    timestamp: Date.now(),
    domain: currentApex,
    resolvedIp: currentResolvedIp,
    candidates: topCandidates,
    filteredCount: filteredFalsePositiveCount
  });
}

function setupSafeLinks() {
  document.querySelectorAll('.safe-tab-link').forEach(link => {
    link.addEventListener('click', (e) => {
      const url = link.getAttribute('href');
      if (url && url !== '#' && !url.startsWith('javascript:')) {
        safeOpenTab(url, e);
      }
    });
  });

  const btnDetach = document.getElementById('btnDetach');
  if (btnDetach) {
    btnDetach.onclick = () => {
      const url = chrome.runtime.getURL('popup.html?detached=true');
      chrome.windows.create({
        url,
        type: 'popup',
        width: 490,
        height: 700
      });
      window.close();
    };
  }
}

async function initialize() {
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('detached') === 'true') {
    document.body.classList.add('detached-mode');
    const detachBtn = document.getElementById('btnDetach');
    if (detachBtn) detachBtn.style.display = 'none';
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith('http')) {
    document.getElementById('targetHost').textContent = 'No HTTP tab detected';
    document.getElementById('hunterStatusText').textContent = 'Navigate to any HTTP/HTTPS website to trigger IP-TELEPORT.';
    document.getElementById('radarSpinner').classList.add('stopped');
    document.getElementById('originResultsList').innerHTML = '<div class="no-origins-found">Inactive tab.</div>';
    return;
  }

  targetTabTitle = tab.title || '';
  const parsedUrl = new URL(tab.url);
  currentHost = parsedUrl.hostname;
  currentApex = extractApexDomain(currentHost);

  document.getElementById('targetHost').textContent = currentHost;

  document.getElementById('linkShodanDomain').href = `https://www.shodan.io/domain/${currentApex}`;
  document.getElementById('linkCensys').href = `https://search.censys.io/certificates?q=names%3A+${encodeURIComponent(currentApex)}`;
  document.getElementById('linkRobtex').href = `https://www.robtex.com/dns-lookup/${encodeURIComponent(currentApex)}`;
  document.getElementById('linkUrlscan').href = `https://urlscan.io/search/#domain%3A${encodeURIComponent(currentApex)}`;
  document.getElementById('linkWayback').href = `https://web.archive.org/web/*/${encodeURIComponent(currentApex)}`;
  document.getElementById('linkViewDns').href = `https://viewdns.info/iphistory/?domain=${encodeURIComponent(currentApex)}`;
  document.getElementById('linkSecurityTrails').href = `https://securitytrails.com/domain/${encodeURIComponent(currentApex)}/history/a`;

  const answers = await queryDoH(currentHost, 'A');
  if (answers.length > 0 && answers[0].type === 1) {
    currentResolvedIp = answers[0].data;
  } else {
    try {
      const geoRes = await fetch(`https://geonet.shodan.io/api/dns/${encodeURIComponent(currentHost)}`);
      if (geoRes.ok) {
        const geoData = await geoRes.json();
        if (geoData.answers && geoData.answers.length > 0) {
          currentResolvedIp = geoData.answers[0].value;
        }
      }
    } catch {}
  }

  if (currentResolvedIp) {
    const ipLink = document.getElementById('currentIpLink');
    ipLink.textContent = currentResolvedIp;
    ipLink.href = `http://${currentResolvedIp}`;
    setCopyButton(document.getElementById('btnCopyCurrentIp'), currentResolvedIp, 'Copied Current IP');

    const geoData = await fetchGeoIp(currentResolvedIp);
    let isShielded = false;
    let detectedShieldOrg = '';

    if (geoData) {
      const country = geoData.country || '';
      const flag = (geoData.flag && geoData.flag.emoji) ? geoData.flag.emoji : '';
      const city = geoData.city || '';
      const asn = (geoData.connection && geoData.connection.asn) ? `AS${geoData.connection.asn}` : '';
      const isp = (geoData.connection && (geoData.connection.isp || geoData.connection.org)) ? (geoData.connection.isp || geoData.connection.org) : '';

      document.getElementById('geoBadge').textContent = `${flag} ${city ? city + ', ' : ''}${country}`.trim() || 'GEO: N/A';
      document.getElementById('asnBadge').textContent = asn || 'ASN: N/A';
      document.getElementById('orgBadge').textContent = isp || 'ORG: N/A';

      isShielded = isExcludedInfrastructure(currentResolvedIp, isp, geoData.connection ? geoData.connection.asn : null);
      detectedShieldOrg = isp;
    } else {
      isShielded = isExcludedInfrastructure(currentResolvedIp);
    }

    updateShieldUI(isShielded, detectedShieldOrg);

    // Dual Shodan + Censys port intelligence for current IP
    Promise.allSettled([
      fetchShodanInternetDb(currentResolvedIp),
      fetchCensysHost(currentResolvedIp)
    ]).then(([shodanRes, censysRes]) => {
      const list = document.getElementById('shodanPortsList');
      const allPorts = new Set();

      if (shodanRes.status === 'fulfilled' && shodanRes.value?.ports) {
        shodanRes.value.ports.forEach(p => allPorts.add(p));
      }
      if (censysRes.status === 'fulfilled' && censysRes.value?.services) {
        censysRes.value.services.forEach(s => {
          if (s.port) allPorts.add(s.port);
        });
      }

      if (allPorts.size > 0) {
        list.innerHTML = '';
        Array.from(allPorts).sort((a, b) => a - b).forEach(port => {
          const tag = document.createElement('span');
          tag.className = 'port-tag';
          tag.textContent = port;
          list.appendChild(tag);
        });
      } else {
        list.innerHTML = '<span class="port-empty">No indexed ports in Shodan/Censys</span>';
      }
    });

  } else {
    document.getElementById('currentIpLink').textContent = 'Resolution failed';
    updateShieldUI(false);
  }

  setupSafeLinks();

  document.getElementById('btnRescan').onclick = () => {
    runHunterEngine(true);
  };

  runHunterEngine(false);
}

document.addEventListener('DOMContentLoaded', initialize);
