use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use rand::Rng;
use sha2::{Digest, Sha256};

/// JWT claims payload
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // user id
    pub email: String,
    pub name: String,
    pub role: String,     // admin | analyst | viewer
    pub org_id: String,
    pub org_name: String,
    pub iat: usize,       // issued at (unix timestamp)
    pub exp: usize,       // expiry (unix timestamp)
}

/// Authenticated user extracted from JWT (used in Axum extractors)
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub org_id: String,
    pub org_name: String,
}

const JWT_EXPIRY_DAYS: i64 = 7;

fn jwt_secret() -> String {
    std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "cyberwatch-ids-rust-secret-key-change-in-production".to_string())
}

/// Hash a password using Argon2id
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Hash failed: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored Argon2 hash
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        }
        Err(_) => false,
    }
}

/// Sign a JWT token for a user
pub fn sign_jwt(
    user_id: &str,
    email: &str,
    name: &str,
    role: &str,
    org_id: &str,
    org_name: &str,
) -> anyhow::Result<String> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        name: name.to_string(),
        role: role.to_string(),
        org_id: org_id.to_string(),
        org_name: org_name.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + Duration::days(JWT_EXPIRY_DAYS)).timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
    .map_err(|e| anyhow::anyhow!("JWT sign failed: {}", e))?;

    Ok(token)
}

/// Verify a JWT token and return claims
pub fn verify_jwt(token: &str) -> Option<Claims> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|data| data.claims)
}

/// Extract auth user from Bearer token or API key
pub fn extract_auth_user(
    auth_header: Option<&str>,
    api_key_header: Option<&str>,
) -> Option<AuthUser> {
    // Try Bearer token first
    if let Some(header) = auth_header {
        if let Some(token) = header.strip_prefix("Bearer ") {
            if let Some(claims) = verify_jwt(token) {
                return Some(AuthUser {
                    id: claims.sub,
                    email: claims.email,
                    name: claims.name,
                    role: claims.role,
                    org_id: claims.org_id,
                    org_name: claims.org_name,
                });
            }
        }
    }
    // API key auth needs DB access, so it is resolved by
    // `routes::auth::extract_ingest_principal` for ingest endpoints.
    let _ = api_key_header;
    None
}

/// Hash an API key for storage and lookup. Keys are 192-bit random tokens, so a
/// fast cryptographic hash is sufficient (unlike user passwords, which use
/// Argon2id). The raw key is shown once at creation and never persisted.
pub fn hash_api_key(key: &str) -> String {
    let digest = Sha256::digest(key.trim().as_bytes());
    hex_encode(digest.as_slice())
}

/// Generate a random API key with cw_ prefix
pub fn generate_api_key() -> String {
    let bytes: [u8; 24] = rand::thread_rng().gen();
    format!("cw_{}", hex_encode(&bytes))
}

/// Generate a unique ID with prefix
pub fn gen_id(prefix: &str) -> String {
    format!("{}{}", prefix, uuid::Uuid::new_v4())
}

/// Create a slug from organization name
pub fn slugify(name: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let suffix: String = (0..6)
        .map(|_| {
            let n = rand::thread_rng().gen_range(0..16);
            char::from_digit(n, 16).unwrap_or('0')
        })
        .collect();
    format!("{}-{}", slug, suffix)
}

/// Hex encode bytes to string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
