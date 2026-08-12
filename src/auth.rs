use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::http::{HeaderMap, header};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::oauth::OAuthBearerAuthenticator;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessScope {
    Tech,
    Private,
}

impl AccessScope {
    pub fn allows_private(self) -> bool {
        matches!(self, Self::Private)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialId {
    KeyA,
    KeyB,
    /// A non-secret, server-derived identifier for one issued OAuth token.
    OAuth([u8; 8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSubject {
    pub credential_id: CredentialId,
    pub scope: AccessScope,
}

/// The OAuth-specific part of an authenticated identity.  It deliberately
/// contains no bearer token or client data that could be logged as a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthIdentity {
    pub scope: AccessScope,
    pub credential_fingerprint: [u8; 8],
}

#[derive(Clone)]
pub struct Authenticator {
    api_keys: ApiKeyAuthenticator,
    oauth: Option<OAuthBearerAuthenticator>,
}

#[derive(Clone)]
struct ApiKeyAuthenticator {
    key_a: Arc<[u8]>,
    key_b: Arc<[u8]>,
    fingerprint_a: Arc<str>,
    fingerprint_b: Arc<str>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator").finish_non_exhaustive()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("missing API key")]
    Missing,
    #[error("invalid API key")]
    Invalid,
}

impl Authenticator {
    pub fn new(key_a: impl AsRef<[u8]>, key_b: impl AsRef<[u8]>) -> Self {
        let key_a = key_a.as_ref();
        let key_b = key_b.as_ref();
        let audit_salt = derive_audit_salt(key_a);
        Self {
            api_keys: ApiKeyAuthenticator {
                key_a: Arc::from(key_a),
                key_b: Arc::from(key_b),
                fingerprint_a: fingerprint(&audit_salt, key_a),
                fingerprint_b: fingerprint(&audit_salt, key_b),
            },
            oauth: None,
        }
    }

    /// Adds OAuth Bearer support while preserving the existing x-api-key
    /// behavior for migration and local compatibility.
    pub fn with_oauth(
        key_a: impl AsRef<[u8]>,
        key_b: impl AsRef<[u8]>,
        oauth: OAuthBearerAuthenticator,
    ) -> Self {
        let mut authenticator = Self::new(key_a, key_b);
        authenticator.oauth = Some(oauth);
        authenticator
    }

    /// Returns an HMAC-derived, non-secret identifier for audit records.
    pub fn fingerprint(&self, credential_id: CredentialId) -> Arc<str> {
        match credential_id {
            CredentialId::KeyA => self.api_keys.fingerprint_a.clone(),
            CredentialId::KeyB => self.api_keys.fingerprint_b.clone(),
            CredentialId::OAuth(fingerprint) => Arc::from(hex_prefix(&fingerprint)),
        }
    }

    pub fn authenticate_headers(&self, headers: &HeaderMap) -> Result<AuthSubject, AuthError> {
        if let Some(value) = headers.get(header::AUTHORIZATION) {
            let value = value.to_str().map_err(|_| AuthError::Invalid)?;
            let (scheme, token) = value.split_once(' ').ok_or(AuthError::Invalid)?;
            if !scheme.eq_ignore_ascii_case("Bearer")
                || token.is_empty()
                || token.contains(char::is_whitespace)
            {
                return Err(AuthError::Invalid);
            }
            let identity = self
                .oauth
                .as_ref()
                .ok_or(AuthError::Invalid)?
                .authenticate_bearer(token)
                .map_err(|_| AuthError::Invalid)?;
            return Ok(AuthSubject {
                credential_id: CredentialId::OAuth(identity.credential_fingerprint),
                scope: identity.scope,
            });
        }

        self.authenticate_api_key_headers(headers)
    }

    fn authenticate_api_key_headers(&self, headers: &HeaderMap) -> Result<AuthSubject, AuthError> {
        let value = headers
            .get("x-api-key")
            .ok_or(AuthError::Missing)?
            .to_str()
            .map_err(|_| AuthError::Invalid)?;
        self.authenticate_key(value)
    }

    pub fn authenticate_key(&self, candidate: &str) -> Result<AuthSubject, AuthError> {
        let candidate = candidate.as_bytes();
        if constant_time_equal(candidate, &self.api_keys.key_a) {
            return Ok(AuthSubject {
                credential_id: CredentialId::KeyA,
                scope: AccessScope::Tech,
            });
        }
        if constant_time_equal(candidate, &self.api_keys.key_b) {
            return Ok(AuthSubject {
                credential_id: CredentialId::KeyB,
                scope: AccessScope::Private,
            });
        }
        Err(AuthError::Invalid)
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn derive_audit_salt(key_a: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key_a).expect("HMAC accepts arbitrary key lengths");
    mac.update(b"engram-mcp/audit-salt/v1");
    let digest = mac.finalize().into_bytes();
    let mut salt = [0_u8; 32];
    salt.copy_from_slice(&digest);
    salt
}

fn fingerprint(audit_salt: &[u8; 32], credential: &[u8]) -> Arc<str> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(audit_salt).expect("HMAC accepts arbitrary key lengths");
    mac.update(credential);
    let digest = mac.finalize().into_bytes();
    Arc::from(
        digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_second: f64,
    buckets: Arc<Mutex<HashMap<CredentialId, Bucket>>>,
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    updated_at: Instant,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("rate limit exceeded")]
pub struct RateLimitError;

impl RateLimiter {
    pub fn new(requests_per_minute: u32, burst: u32) -> Self {
        Self {
            capacity: f64::from(burst),
            refill_per_second: f64::from(requests_per_minute) / 60.0,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn check(&self, subject: AuthSubject) -> Result<(), RateLimitError> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned");
        let bucket = buckets.entry(subject.credential_id).or_insert(Bucket {
            tokens: self.capacity,
            updated_at: now,
        });
        let elapsed = now.duration_since(bucket.updated_at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_second).min(self.capacity);
        bucket.updated_at = now;

        if bucket.tokens < 1.0 {
            return Err(RateLimitError);
        }
        bucket.tokens -= 1.0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    #[test]
    fn maps_keys_to_their_scopes() {
        let auth = Authenticator::new("tech-secret", "private-secret");
        assert_eq!(
            auth.authenticate_key("tech-secret").unwrap().scope,
            AccessScope::Tech
        );
        assert_eq!(
            auth.authenticate_key("private-secret").unwrap().scope,
            AccessScope::Private
        );
    }

    #[test]
    fn rejects_missing_or_invalid_keys() {
        let auth = Authenticator::new("tech-secret", "private-secret");
        assert_eq!(
            auth.authenticate_headers(&HeaderMap::new()),
            Err(AuthError::Missing)
        );
        assert_eq!(auth.authenticate_key("wrong"), Err(AuthError::Invalid));
    }

    #[test]
    fn accepts_api_key_header() {
        let auth = Authenticator::new("tech-secret", "private-secret");
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("private-secret"));
        assert_eq!(
            auth.authenticate_headers(&headers).unwrap().credential_id,
            CredentialId::KeyB
        );
    }

    #[test]
    fn bearer_header_does_not_fall_back_to_an_api_key() {
        let auth = Authenticator::new("tech-secret", "private-secret");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer no-token"),
        );
        headers.insert("x-api-key", HeaderValue::from_static("private-secret"));
        assert_eq!(auth.authenticate_headers(&headers), Err(AuthError::Invalid));
    }

    #[test]
    fn audit_fingerprints_are_stable_and_do_not_equal_the_keys() {
        let auth = Authenticator::new("tech-secret", "private-secret");
        assert_eq!(auth.fingerprint(CredentialId::KeyA).as_ref().len(), 16);
        assert_ne!(auth.fingerprint(CredentialId::KeyA).as_ref(), "tech-secret");
        assert_ne!(
            auth.fingerprint(CredentialId::KeyA),
            auth.fingerprint(CredentialId::KeyB)
        );
    }

    #[test]
    fn rate_limiter_enforces_burst_per_credential() {
        let limiter = RateLimiter::new(1, 2);
        let subject = AuthSubject {
            credential_id: CredentialId::KeyA,
            scope: AccessScope::Tech,
        };
        assert!(limiter.check(subject).is_ok());
        assert!(limiter.check(subject).is_ok());
        assert_eq!(limiter.check(subject), Err(RateLimitError));
    }
}
