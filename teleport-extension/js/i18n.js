/**
 * IP-TELEPORT // Native Browser Language Auto-Sync Engine
 * Automatically detects navigator.language / chrome.i18n and localizes the HUD interface
 * Zero API keys, zero network delay, 100% Chrome Web Store safe.
 */

const TRANSLATIONS = {
  tr: {
    brandTitle: "IP-TELEPORT",
    brandSub: "ORIGIN AVCISI VE ZAMAN TÜNELİ DENETÇİSİ",
    statusAnalyzing: "ANALİZ EDİLİYOR...",
    shieldActive: "WAF/CDN KALKANI AKTİF",
    directExposed: "DOĞRUDAN ORIGIN AÇIKTA",
    targetDomain: "HEDEF ALAN ADI:",
    currentIp: "GENEL IP ADRESİ:",
    copyBtn: "KOPYALA",
    copiedBtn: "KOPYALANDI",
    intelLabel: "SHODAN VE CENSYS İSTİHBARATI:",
    scanningPorts: "Açık portlar ve servisler taranıyor...",
    hunterTitle: "ÇOK VEKTÖRLÜ ORIGIN AVCISI",
    forceRescan: "YENİDEN TARA",
    hunterInitial: "Tarihsel arşivler, Censys, Shodan, URLScan, FFUF ve Robtex taranıyor...",
    noOriginsFound: "Aktif vektörlerde doğrulanmış unshielded origin IP bulunamadı.<br>Tüm pasif IP'ler, üçüncü parti mail sunucuları ve WAF kenarları elendi.",
    scanCompleted: "Sıfır-yanılsama doğrulaması tamamlandı.",
    btnOpenIp: "IP'YE GİT",
    btnCurl: "CURL",
    btnHosts: "HOSTS",
    btnCmd: "1-KOMUT",
    btnCensys: "CENSYS",
    btnShodan: "SHODAN",
    btnVt: "VT",
    btnAbuse: "ABUSE",
    btnNmap: "NMAP",
    btnMtr: "MTR",
    btnCopy: "KOPYALA",
    toastCopiedIp: "IP kopyalandı",
    toastCurlCopied: "cURL komutu kopyalandı (WAF ve VHost bypass)",
    toastHostsCopied: "Hosts satırı kopyalandı",
    toastCmdCopied: "PowerShell hosts komutu kopyalandı",
    toastBackgroundTab: "Sekme arka planda açıldı"
  },
  en: {
    brandTitle: "IP-TELEPORT",
    brandSub: "ORIGIN HUNTER & TIMELINE AUDITOR",
    statusAnalyzing: "ANALYZING...",
    shieldActive: "WAF/CDN SHIELD ACTIVE",
    directExposed: "DIRECT ORIGIN EXPOSED",
    targetDomain: "TARGET DOMAIN:",
    currentIp: "CURRENT PUBLIC IP:",
    copyBtn: "COPY",
    copiedBtn: "COPIED",
    intelLabel: "SHODAN & CENSYS INTEL:",
    scanningPorts: "Scanning open ports & services...",
    hunterTitle: "MULTI-VECTOR ORIGIN HUNTER",
    forceRescan: "FORCE RE-SCAN",
    hunterInitial: "Probing historical archives, Censys, Shodan, URLScan, FFUF subdomains & Robtex PDNS...",
    noOriginsFound: "No direct unshielded origin IP verified on active vectors.<br>All dormant IPs, third-party mail servers, and reverse proxy edges were strictly eliminated.",
    scanCompleted: "Strict verification completed.",
    btnOpenIp: "OPEN IP",
    btnCurl: "CURL",
    btnHosts: "HOSTS",
    btnCmd: "1-CMD",
    btnCensys: "CENSYS",
    btnShodan: "SHODAN",
    btnVt: "VT",
    btnAbuse: "ABUSE",
    btnNmap: "NMAP",
    btnMtr: "MTR",
    btnCopy: "COPY",
    toastCopiedIp: "Copied IP",
    toastCurlCopied: "Copied cURL command (Bypasses Cloudflare & VirtualHost)",
    toastHostsCopied: "Copied hosts entry (IP domain)",
    toastCmdCopied: "Copied PowerShell 1-liner for hosts file",
    toastBackgroundTab: "Opened tab in background"
  }
};

function getBrowserLang() {
  const full = (navigator.language || 'en').toLowerCase();
  return full.startsWith('tr') ? 'tr' : 'en';
}

function t(key) {
  const lang = getBrowserLang();
  return (TRANSLATIONS[lang] && TRANSLATIONS[lang][key]) || TRANSLATIONS['en'][key] || key;
}

function applyI18nToDOM() {
  const lang = getBrowserLang();
  const dict = TRANSLATIONS[lang] || TRANSLATIONS['en'];

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) {
      el.textContent = dict[key];
    }
  });
}

if (typeof window !== 'undefined') {
  window.i18n = { getBrowserLang, t, applyI18nToDOM };
  document.addEventListener('DOMContentLoaded', applyI18nToDOM);
}
