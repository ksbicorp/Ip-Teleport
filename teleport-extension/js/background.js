const CACHE = new Map();

function extractHostname(url) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    return parsed.hostname;
  } catch {
    return null;
  }
}

async function resolveHostIp(hostname) {
  if (CACHE.has(hostname)) {
    return CACHE.get(hostname);
  }

  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    if (!res.ok) throw new Error('DoH error');
    const data = await res.json();
    if (data.Answer && data.Answer.length > 0) {
      const aRecords = data.Answer.filter(rec => rec.type === 1);
      if (aRecords.length > 0) {
        const ip = aRecords[0].data;
        CACHE.set(hostname, ip);
        return ip;
      }
    }
  } catch {}

  try {
    const res = await fetch(`https://geonet.shodan.io/api/dns/${encodeURIComponent(hostname)}`);
    if (res.ok) {
      const data = await res.json();
      if (data.answers && data.answers.length > 0) {
        const ip = data.answers[0].value;
        CACHE.set(hostname, ip);
        return ip;
      }
    }
  } catch {}

  return null;
}

function isCloudflareIp(ip) {
  if (!ip) return false;
  const cfPrefixes = [
    '173.245.', '103.21.', '103.22.', '103.31.', '141.101.',
    '108.162.', '190.93.', '188.114.', '197.234.', '198.41.',
    '162.158.', '104.16.', '104.17.', '104.18.', '104.19.',
    '104.20.', '104.21.', '104.22.', '104.23.', '104.24.',
    '104.25.', '104.26.', '104.27.', '104.28.', '104.29.',
    '104.30.', '104.31.', '172.64.', '172.65.', '172.66.',
    '172.67.', '172.68.', '172.69.', '172.70.', '172.71.',
    '131.0.72.'
  ];
  return cfPrefixes.some(p => ip.startsWith(p));
}

async function updateTabBadge(tabId, url) {
  const hostname = extractHostname(url);
  if (!hostname) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  const ip = await resolveHostIp(hostname);
  if (ip && isCloudflareIp(ip)) {
    chrome.action.setBadgeText({ tabId, text: 'CF' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#f38020' });
  } else if (ip) {
    chrome.action.setBadgeText({ tabId, text: 'OK' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#00d26a' });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    updateTabBadge(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url) {
      updateTabBadge(activeInfo.tabId, tab.url);
    }
  } catch {}
});
