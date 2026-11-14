//! Outbound email notifications (Task #27).
//!
//! SMTP is entirely optional. When `SMTP_ENABLED` is not `true` (or the host is
//! missing), the mailer is a no-op so local development and CI never attempt an
//! outbound network connection. Every send is fire-and-forget: SMTP latency or
//! failure can never break an HTTP request.

use crate::db::{get_conn, DbPool};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::sync::Arc;
use std::time::Duration;

pub struct Mailer {
    transport: Option<Arc<AsyncSmtpTransport<Tokio1Executor>>>,
    from: String,
    fallback_recipients: Vec<String>,
    min_severity: String,
}

impl Mailer {
    /// Build the mailer from environment variables. Never panics and never
    /// prevents startup: a misconfigured SMTP server only disables email.
    pub fn from_env() -> Self {
        let enabled = std::env::var("SMTP_ENABLED")
            .unwrap_or_default()
            .eq_ignore_ascii_case("true");
        let from = std::env::var("SMTP_FROM")
            .unwrap_or_else(|_| "CyberWatch IDS <no-reply@localhost>".to_string());
        let fallback_recipients =
            split_list(&std::env::var("ALERT_EMAIL_TO").unwrap_or_default());
        let min_severity = std::env::var("ALERT_EMAIL_MIN_SEVERITY")
            .unwrap_or_else(|_| "CRITICAL".to_string())
            .to_uppercase();

        if !enabled {
            tracing::info!("[Mailer] disabled: set SMTP_ENABLED=true and SMTP_HOST to enable");
            return Self {
                transport: None,
                from,
                fallback_recipients,
                min_severity,
            };
        }

        let host = std::env::var("SMTP_HOST").unwrap_or_default();
        if host.trim().is_empty() {
            tracing::info!("[Mailer] disabled: SMTP_ENABLED=true but SMTP_HOST is empty");
            return Self {
                transport: None,
                from,
                fallback_recipients,
                min_severity,
            };
        }

        let port: u16 = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(587);
        let username = std::env::var("SMTP_USERNAME").unwrap_or_default();
        let password = std::env::var("SMTP_PASSWORD").unwrap_or_default();
        let mode = std::env::var("SMTP_TLS_MODE")
            .unwrap_or_else(|_| "starttls".to_string())
            .to_lowercase();

        let built = (|| -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
            let builder = match mode.as_str() {
                "none" => {
                    tracing::warn!("[Mailer] SMTP_TLS_MODE=none (plaintext) — local dev only");
                    AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host.clone())
                }
                "implicit" => AsyncSmtpTransport::<Tokio1Executor>::relay(&host)?,
                _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)?,
            };

            let builder = builder.port(port).timeout(Some(Duration::from_secs(15)));
            let builder = if username.is_empty() {
                builder
            } else {
                builder.credentials(Credentials::new(username.clone(), password.clone()))
            };

            let transport: AsyncSmtpTransport<Tokio1Executor> = builder.build();
            Ok(transport)
        })();

        match built {
            Ok(transport) => {
                tracing::info!("[Mailer] SMTP ready: {}:{} (mode={})", host, port, mode);
                Self {
                    transport: Some(Arc::new(transport)),
                    from,
                    fallback_recipients,
                    min_severity,
                }
            }
            Err(e) => {
                tracing::error!("[Mailer] SMTP setup failed for {}: {} — email disabled", host, e);
                Self {
                    transport: None,
                    from,
                    fallback_recipients,
                    min_severity,
                }
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.transport.is_some()
    }

    pub fn min_severity(&self) -> &str {
        &self.min_severity
    }

    pub fn fallback_recipients(&self) -> &[String] {
        &self.fallback_recipients
    }

    /// Send a single HTML email. No-op when SMTP is not configured.
    pub async fn send(&self, to: &str, subject: &str, html: &str) -> anyhow::Result<()> {
        let transport = match &self.transport {
            Some(t) => t.clone(),
            None => {
                tracing::debug!("[Mailer] skip (disabled) to={} subject={}", to, subject);
                return Ok(());
            }
        };

        let message = Message::builder()
            .from(self.from.parse()?)
            .to(to.parse()?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html.to_string())?;

        transport.send(message).await?;
        tracing::info!("[Mailer] sent to={} subject={}", to, subject);
        Ok(())
    }
}

/// Fire-and-forget send. Callers never await SMTP.
pub fn spawn_send(mailer: Arc<Mailer>, recipients: Vec<String>, subject: String, html: String) {
    if !mailer.is_enabled() || recipients.is_empty() {
        return;
    }
    tokio::spawn(async move {
        for to in recipients {
            if let Err(e) = mailer.send(&to, &subject, &html).await {
                tracing::warn!("[Mailer] failed to send to {}: {}", to, e);
            }
        }
    });
}

/// Is email alerting enabled in this organization's settings JSON?
pub fn org_email_alerts_enabled(pool: &DbPool, org_id: &str) -> bool {
    let conn = match get_conn(pool) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let raw: Option<String> = conn
        .query_row(
            "SELECT settings FROM organizations WHERE id = ?",
            [org_id],
            |row| row.get(0),
        )
        .ok();

    raw.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("emailAlerts").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

/// Alert recipients = active admins of the org. Caller may fall back to
/// `ALERT_EMAIL_TO` when this is empty.
pub fn org_alert_recipients(pool: &DbPool, org_id: &str) -> Vec<String> {
    let conn = match get_conn(pool) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut stmt = match conn.prepare(
        "SELECT email FROM users WHERE org_id = ? AND status = 'active' AND role = 'admin'",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    match stmt.query_map([org_id], |row| row.get::<_, String>(0)) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

fn severity_rank(s: &str) -> i32 {
    match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// True when `severity` is at least as urgent as the configured threshold.
pub fn meets_threshold(severity: &str, min_severity: &str) -> bool {
    severity_rank(severity) >= severity_rank(min_severity)
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Escape attacker-controlled data before embedding it in an HTML email.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn welcome_email(name: &str, org_name: &str) -> (String, String) {
    let subject = "Selamat datang di CyberWatch IDS".to_string();
    let html = format!(
        r#"<!DOCTYPE html><html><body style="margin:0;padding:24px;background:#0b1220;font-family:Arial,sans-serif;color:#e2e8f0">
<div style="max-width:560px;margin:auto;background:#111c2e;border:1px solid #1e293b;border-radius:12px;padding:28px">
  <h1 style="margin:0 0 8px;font-size:20px;color:#00d9ff">CyberWatch IDS</h1>
  <p style="margin:0 0 20px;font-size:13px;color:#94a3b8">Security Monitoring &amp; Intrusion Detection</p>
  <p>Halo <strong>{name}</strong>,</p>
  <p>Organisasi <strong>{org}</strong> berhasil dibuat. Akun Anda berperan sebagai <strong>admin</strong> dan siap digunakan.</p>
  <p style="font-size:13px;color:#94a3b8">Mulai dari dashboard untuk memantau event, mengelola user, membuat API key, dan menjalankan attack simulator.</p>
  <hr style="border:0;border-top:1px solid #1e293b;margin:24px 0">
  <p style="font-size:12px;color:#64748b">Email ini dikirim otomatis. Jika Anda tidak merasa mendaftar, abaikan pesan ini.</p>
</div></body></html>"#,
        name = escape_html(name),
        org = escape_html(org_name),
    );
    (subject, html)
}

pub fn alert_email(
    severity: &str,
    attack_type: &str,
    rule_name: &str,
    source_ip: &str,
    path: &str,
    timestamp: &str,
) -> (String, String) {
    let subject = format!("[CyberWatch IDS] {} alert: {}", severity, attack_type);
    let color = if severity == "CRITICAL" { "#ef4444" } else { "#f59e0b" };
    let html = format!(
        r#"<!DOCTYPE html><html><body style="margin:0;padding:24px;background:#0b1220;font-family:Arial,sans-serif;color:#e2e8f0">
<div style="max-width:560px;margin:auto;background:#111c2e;border:1px solid #1e293b;border-radius:12px;padding:28px">
  <h1 style="margin:0 0 8px;font-size:20px;color:#00d9ff">CyberWatch IDS</h1>
  <p style="margin:0 0 20px;font-size:13px;color:#94a3b8">Security alert notification</p>
  <div style="display:inline-block;padding:6px 12px;border-radius:6px;background:{color};color:#fff;font-weight:bold;font-size:13px">{severity}</div>
  <table style="width:100%;margin-top:20px;border-collapse:collapse;font-size:13px">
    <tr><td style="padding:6px 0;color:#94a3b8">Attack type</td><td>{attack}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Rule</td><td>{rule}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Source IP</td><td>{ip}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Path</td><td>{path}</td></tr>
    <tr><td style="padding:6px 0;color:#94a3b8">Detected at</td><td>{time}</td></tr>
  </table>
  <p style="margin-top:20px;font-size:13px;color:#94a3b8">Buka dashboard untuk melihat detail event dan menindaklanjuti insiden.</p>
  <hr style="border:0;border-top:1px solid #1e293b;margin:24px 0">
  <p style="font-size:12px;color:#64748b">Email ini dikirim otomatis karena email alert diaktifkan untuk organisasi Anda.</p>
</div></body></html>"#,
        color = color,
        severity = escape_html(severity),
        attack = escape_html(attack_type),
        rule = escape_html(rule_name),
        ip = escape_html(source_ip),
        path = escape_html(path),
        time = escape_html(timestamp),
    );
    (subject, html)
}
