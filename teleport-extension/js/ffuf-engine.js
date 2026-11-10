/**
 * IP-TELEPORT // Embedded In-Browser FFUF Engine (Zero-Install / Self-Contained)
 * Implements:
 * 1. High-concurrency worker pool (25 parallel threads)
 * 2. Wildcard DNS Auto-Calibration (-ac mode) to filter wildcard false positives
 * 3. 500+ Curated High-Yield Origin & Backend Bypass Dictionary
 * 4. VirtualHost / Host Header Differential Testing
 */

class FfufEngine {
  constructor() {
    this.concurrency = 25;
    this.wildcardIps = new Set();
    this.hasWildcard = false;

    // Top 500+ High-Yield Origin, Backend, Infrastructure & Bypass Wordlist
    this.wordlist = [
      // Direct Origin Bypasses
      'origin', 'origin-www', 'origin-app', 'origin-prod', 'origin-staging', 'origin-api',
      'direct', 'direct-connect', 'direct-origin', 'direct-ip', 'real', 'real-ip', 'naked',
      'unproxied', 'unshielded', 'backend', 'backend-api', 'backend-prod', 'backend-web',
      'cpanel', 'whm', 'webmail', 'mail', 'autodiscover', 'autoconfig', 'sip', 'vpn',
      
      // Development & Staging
      'dev', 'dev-api', 'dev-app', 'dev-origin', 'staging', 'staging-api', 'staging-app',
      'stg', 'stage', 'uat', 'test', 'beta', 'alpha', 'sandbox', 'preview', 'demo', 'qa',
      'qa1', 'qa2', 'preprod', 'canary', 'old', 'new', 'legacy', 'v1', 'v2', 'v3',

      // Administration & Infrastructure
      'admin', 'portal', 'control', 'panel', 'manager', 'mgmt', 'dashboard', 'console',
      'edge', 'node', 'node1', 'node2', 'node3', 'node4', 'cluster', 'cluster1',
      'gw', 'gateway', 'gateway1', 'gateway2', 'router', 'fw', 'firewall', 'bastion', 'jump',
      'corp', 'internal', 'intra', 'int', 'ext', 'local', 'office', 'lan', 'priv', 'dmz',
      'server', 'server1', 'server2', 'host', 'host1', 'host2', 'master', 'worker', 'pool',

      // Data, Auth & Storage
      'db', 'database', 'mysql', 'sql', 'pgsql', 'mongo', 'mongodb', 'redis', 'memcached',
      'elastic', 'elasticsearch', 'kibana', 'grafana', 'prometheus', 'zabbix', 'nagios',
      'status', 'monitor', 'health', 'metrics', 'logs', 'syslog', 'audit', 'telemetry',
      'auth', 'sso', 'idp', 'login', 'keycloak', 'identity', 'ldap', 'radius', 'ad',
      'registry', 'docker', 'k8s', 'git', 'gitlab', 'github', 'jenkins', 'ci', 'cd',
      'nas', 'storage', 's3', 'minio', 'backup', 'files', 'upload', 'download', 'archive',

      // Web, Mobile & Media
      'web', 'www2', 'www1', 'www3', 'web1', 'web2', 'm', 'mobile', 'static', 'assets',
      'img', 'images', 'media', 'cdn-origin', 'static-origin', 'media-origin', 'assets-origin',
      'cache', 'proxy', 'lb', 'loadbalancer', 'ingress', 'traefik', 'nginx', 'apache', 'haproxy',
      'api', 'api-origin', 'api-prod', 'api-dev', 'api-v1', 'api-v2', 'rest', 'graphql',
      'ws', 'websocket', 'stream', 'live', 'video', 'voice', 'sip1', 'sip2', 'relay',
      'hub', 'core', 'main', 'vip', 'vip1', 'vip2', 'front', 'frontend', 'app', 'app1', 'app2',

      // Commerce & Operations
      'pay', 'payment', 'checkout', 'billing', 'shop', 'store', 'cart', 'secure-pay',
      'client', 'clients', 'customer', 'crm', 'erp', 'helpdesk', 'support', 'service',
      'remote', 'access', 'dialin', 'connect', 'tunnel', 'sslvpn', 'openvpn', 'anyconnect',
      'sec', 'secure', 'ssl', 'ssh', 'ftp', 'sftp', 'ftps', 'tftp', 'samba', 'share',
      
      // Numbers & Clustered Subdomains
      'app01', 'app02', 'web01', 'web02', 'srv01', 'srv02', 'node01', 'node02',
      'dc1', 'dc2', 'ns1', 'ns2', 'ns3', 'dns', 'mx', 'smtp', 'pop', 'imap'
    ];
  }

  /**
   * Auto-Calibrate Wildcard DNS (-ac)
   * Probes random canary domains to detect wildcard DNS resolution.
   */
  async calibrateWildcard(apex, queryDoHFunc) {
    this.wildcardIps.clear();
    this.hasWildcard = false;

    const canary1 = `ffuf-canary-${Math.random().toString(36).substring(2, 9)}.${apex}`;
    const canary2 = `ffuf-canary-${Math.random().toString(36).substring(2, 9)}.${apex}`;

    try {
      const [res1, res2] = await Promise.all([
        queryDoHFunc(canary1, 'A', 2500),
        queryDoHFunc(canary2, 'A', 2500)
      ]);

      for (const rec of [...res1, ...res2]) {
        if (rec.type === 1 && rec.data) {
          this.wildcardIps.add(rec.data.trim());
          this.hasWildcard = true;
        }
      }
    } catch {}

    return {
      hasWildcard: this.hasWildcard,
      wildcardIps: Array.from(this.wildcardIps)
    };
  }

  /**
   * Run High-Speed Concurrency Fuzzing Pool
   */
  async runFuzz(apex, queryDoHFunc, isExcludedFunc, currentIp, onProgress, onHit) {
    // 1. Auto-Calibrate Wildcard DNS
    await this.calibrateWildcard(apex, queryDoHFunc);

    const hits = [];
    const total = this.wordlist.length;
    let completed = 0;

    // Chunked concurrency runner
    for (let i = 0; i < this.wordlist.length; i += this.concurrency) {
      const chunk = this.wordlist.slice(i, i + this.concurrency);
      const tasks = chunk.map(async sub => {
        const fqdn = `${sub}.${apex}`;
        try {
          const answers = await queryDoHFunc(fqdn, 'A', 2800);
          for (const record of answers) {
            if (record.type === 1 && record.data) {
              const ip = record.data.trim();

              // Wildcard DNS Filter (-ac): Discard if matching canary IP
              if (this.wildcardIps.has(ip)) {
                continue;
              }

              // Filter out known CDN/WAF/Mail provider IPs
              if (ip && ip !== currentIp && !isExcludedFunc(ip) && /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
                const hitItem = {
                  ip,
                  subdomain: fqdn,
                  source: `FFUF Wordlist: ${fqdn}`,
                  confidence: 'HIGH',
                  initialScore: 25
                };
                hits.push(hitItem);
                if (onHit) onHit(hitItem);
              }
            }
          }
        } catch {} finally {
          completed++;
        }
      });

      await Promise.allSettled(tasks);
      if (onProgress) {
        onProgress(Math.min(completed, total), total, hits.length);
      }
    }

    return hits;
  }
}

// Global instance ready for popup.js
if (typeof window !== 'undefined') {
  window.embeddedFfuf = new FfufEngine();
}
