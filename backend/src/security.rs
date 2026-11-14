//! Security hardening middleware (OWASP-aligned) for the CyberWatch IDS backend.
//!
//! Provides:
//! - `security_headers`: injects OWASP-recommended HTTP response headers.
//! - `cors_layer`: builds a CORS policy from the `CORS_ALLOWED_ORIGINS` env var,
//!   defaulting to a restrictive same-origin-only policy.

use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// OWASP-recommended security headers applied to every HTTP response.
///
/// Headers set:
/// - `X-Content-Type-Options: nosniff` — disable MIME sniffing.
/// - `X-Frame-Options: DENY` — prevent clickjacking (also enforced via CSP frame-ancestors).
/// - `X-XSS-Protection: 0` — disable legacy XSS auditor; CSP is the real defense.
/// - `Referrer-Policy: strict-origin-when-cross-origin` — limit referrer leakage.
/// - `Content-Security-Policy` — lock down resource loading to same-origin.
/// - `Permissions-Policy` — disable powerful features not needed by the app.
/// - `Strict-Transport-Security` — only when `HSTS_ENABLED=true` (TLS-terminating proxy in front).
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::X_XSS_PROTECTION, HeaderValue::from_static("0"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self' data:; \
             connect-src 'self' ws: wss:; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'",
        ),
    );
    headers.insert(
        axum::http::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=()"),
    );

    // HSTS should only be emitted when the app is served behind a TLS-terminating
    // proxy (nginx/Caddy/cloud LB). Enabling it on plain HTTP would break local dev.
    if std::env::var("HSTS_ENABLED").unwrap_or_default() == "true" {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    response
}

/// Build a CORS layer.
///
/// Reads `CORS_ALLOWED_ORIGINS` (comma-separated list of origins, e.g.
/// `https://app.cyberwatch.example,https://dashboard.example`).
///
/// Secure default: when the variable is empty, the API is restricted to
/// same-origin requests only (no cross-origin access). This prevents arbitrary
/// websites from calling the API from a victim's browser.
pub fn cors_layer() -> CorsLayer {
    let raw = std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();

    // `AllowOrigin::list` panics on a wildcard; handle "*" explicitly instead.
    let allow_any_origin = raw.split(',').any(|s| s.trim() == "*");
    if allow_any_origin {
        tracing::warn!(
            "[Security] CORS_ALLOWED_ORIGINS contains '*' — allowing ANY origin. \
             Not recommended for production; set explicit origins instead."
        );
    }

    let origins = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "*")
        .filter_map(|s| s.parse::<HeaderValue>().ok())
        .collect::<Vec<_>>();

    let methods = [
        axum::http::Method::GET,
        axum::http::Method::POST,
        axum::http::Method::PUT,
        axum::http::Method::DELETE,
        axum::http::Method::OPTIONS,
    ];

    let allow_headers = [
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        axum::http::HeaderName::from_static("x-api-key"),
    ];

    let base = CorsLayer::new()
        .allow_methods(methods)
        .allow_headers(allow_headers);

    if allow_any_origin {
        base.allow_origin(AllowOrigin::any())
    } else if origins.is_empty() {
        tracing::warn!(
            "[Security] CORS_ALLOWED_ORIGINS not set — API restricted to same-origin requests. \
             Set it (comma-separated) to allow cross-origin access in production."
        );
        base
    } else {
        base.allow_origin(AllowOrigin::list(origins))
    }
}
