use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;

use crate::{
    auth::{AccessScope, OAuthIdentity},
    config::OAuthConfig,
};

pub const SCOPE_TECH: &str = "kb:tech";
pub const SCOPE_PRIVATE: &str = "kb:private";

const APPROVAL_REQUEST_TTL_SECONDS: u64 = 300;
const MAX_REDIRECT_URIS: usize = 8;
const MAX_CLIENT_ID_LENGTH: usize = 8_192;
const MAX_FORM_VALUE_LENGTH: usize = 8_192;
const ACCESS_TOKEN_PREFIX: &str = "at_";
const REFRESH_TOKEN_PREFIX: &str = "rt_";
const TOKEN_CLAIMS_VERSION: u8 = 1;
const REFRESH_STATE_VERSION: u8 = 1;
const REFRESH_STATE_FILE: &str = "refresh-token-families-v1.json";
const MAX_REFRESH_STATE_BYTES: u64 = 1_048_576;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("OAuth configuration is invalid")]
    InvalidConfiguration,
    #[error("OAuth authorization request is invalid")]
    InvalidAuthorizationRequest,
    #[error("OAuth client is invalid")]
    InvalidClient,
    #[error("OAuth authorization code is invalid")]
    InvalidGrant,
    #[error("OAuth scope is invalid")]
    InvalidScope,
    #[error("OAuth resource indicator is invalid")]
    InvalidTarget,
    #[error("OAuth request is invalid")]
    InvalidRequest,
    #[error("OAuth owner authentication failed")]
    InvalidOwner,
    #[error("secure random generation failed")]
    Entropy,
    #[error("OAuth internal state is unavailable")]
    Internal,
}

impl OAuthError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidAuthorizationRequest | Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidOwner => "access_denied",
            Self::InvalidConfiguration | Self::Entropy | Self::Internal => "server_error",
        }
    }
}

#[derive(Clone)]
pub struct OAuthBearerAuthenticator {
    state: Arc<OAuthState>,
}

struct OAuthState {
    issuer: Arc<str>,
    resource: Arc<str>,
    owner_secret: Arc<[u8]>,
    signing_key: Arc<[u8]>,
    access_token_ttl_seconds: u64,
    authorization_code_ttl_seconds: u64,
    refresh_token_ttl_seconds: u64,
    authorization_codes: Mutex<HashMap<[u8; 32], AuthorizationCode>>,
    refresh_tokens: RefreshTokenStore,
}

#[derive(Clone)]
pub struct OAuthService {
    bearer: OAuthBearerAuthenticator,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizationQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub resource: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalForm {
    pub request: String,
    pub owner_secret: String,
    pub decision: String,
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub resource: String,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub scope: Option<String>,
    pub application_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct RegistrationResponse {
    pub client_id: String,
    pub client_id_issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<&'static str>,
    pub response_types: Vec<&'static str>,
    pub token_endpoint_auth_method: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedApprovalRequest {
    client_id: String,
    redirect_uri: String,
    requested_scopes: ScopeGrant,
    state: Option<String>,
    resource: String,
    code_challenge: String,
    expires_at: u64,
}

#[derive(Debug, Clone)]
struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    scopes: ScopeGrant,
    resource: String,
    code_challenge: String,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenClaims {
    version: u8,
    token_id: String,
    family_id: String,
    scopes: ScopeGrant,
    audience: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshTokenClaims {
    version: u8,
    family_id: String,
    token_id: String,
    client_binding: String,
    scopes: ScopeGrant,
    audience: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshTokenFamily {
    active_token_hash: String,
    expires_at: u64,
    revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshTokenState {
    version: u8,
    families: HashMap<String, RefreshTokenFamily>,
}

impl Default for RefreshTokenState {
    fn default() -> Self {
        Self {
            version: REFRESH_STATE_VERSION,
            families: HashMap::new(),
        }
    }
}

struct RefreshTokenStore {
    path: PathBuf,
    state: Mutex<RefreshTokenState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientIdPayload {
    version: u8,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: ClientAuthenticationMethod,
    scopes: ScopeGrant,
    issued_at: u64,
}

#[derive(Debug, Clone)]
struct RegisteredClient {
    client_id: String,
    redirect_uris: BTreeSet<String>,
    token_endpoint_auth_method: ClientAuthenticationMethod,
    scopes: ScopeGrant,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ClientAuthenticationMethod {
    None,
    ClientSecretPost,
    ClientSecretBasic,
}

impl ClientAuthenticationMethod {
    fn parse(value: Option<&str>) -> Result<Self, OAuthError> {
        match value.unwrap_or("none") {
            "none" => Ok(Self::None),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            _ => Err(OAuthError::InvalidClient),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretBasic => "client_secret_basic",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ScopeGrant(BTreeSet<String>);

impl ScopeGrant {
    fn parse(value: &str) -> Result<Self, OAuthError> {
        if value.len() > 256 {
            return Err(OAuthError::InvalidScope);
        }
        let scopes = value
            .split_whitespace()
            .map(ToOwned::to_owned)
            .collect::<BTreeSet<_>>();
        if scopes.is_empty()
            || scopes
                .iter()
                .any(|scope| scope != SCOPE_TECH && scope != SCOPE_PRIVATE)
        {
            return Err(OAuthError::InvalidScope);
        }
        Ok(Self(scopes))
    }

    /// Both scopes: the client-side cap must not block a `kb:private` request,
    /// because DCR clients cannot know to ask for it.  The actual grant is
    /// still gated by the owner's explicit scope choice on the consent page.
    fn default_for_new_client() -> Self {
        Self(BTreeSet::from([
            SCOPE_TECH.to_owned(),
            SCOPE_PRIVATE.to_owned(),
        ]))
    }

    /// Registration-time scopes from real clients include values this server
    /// does not define (Claude sends its own).  Unknown scopes are dropped, as
    /// RFC 7591 lets the server adjust requested metadata; with none left the
    /// client falls back to the default grant cap.
    fn parse_lenient(value: &str) -> Self {
        let scopes = value
            .split_whitespace()
            .filter(|scope| *scope == SCOPE_TECH || *scope == SCOPE_PRIVATE)
            .map(ToOwned::to_owned)
            .collect::<BTreeSet<_>>();
        if scopes.is_empty() {
            Self::default_for_new_client()
        } else {
            Self(scopes)
        }
    }

    fn access_scope(&self) -> AccessScope {
        if self.0.contains(SCOPE_PRIVATE) {
            AccessScope::Private
        } else {
            AccessScope::Tech
        }
    }

    fn allows(&self, requested: &Self) -> bool {
        requested.0.iter().all(|scope| {
            self.0.contains(scope) || (scope == SCOPE_TECH && self.0.contains(SCOPE_PRIVATE))
        })
    }

    fn is_subset_of(&self, requested: &Self) -> bool {
        self.0.is_subset(&requested.0)
    }

    fn is_valid(&self) -> bool {
        !self.0.is_empty()
            && self
                .0
                .iter()
                .all(|scope| scope == SCOPE_TECH || scope == SCOPE_PRIVATE)
    }

    fn as_string(&self) -> String {
        self.values().collect::<Vec<_>>().join(" ")
    }

    fn values(&self) -> impl Iterator<Item = &str> {
        [SCOPE_TECH, SCOPE_PRIVATE]
            .into_iter()
            .filter(|scope| self.0.contains(*scope))
    }
}

impl RefreshTokenStore {
    fn open(state_dir: &Path) -> Result<Self, OAuthError> {
        fs::create_dir_all(state_dir).map_err(|_| OAuthError::Internal)?;
        if !fs::metadata(state_dir)
            .map_err(|_| OAuthError::Internal)?
            .is_dir()
        {
            return Err(OAuthError::InvalidConfiguration);
        }

        let path = state_dir.join(REFRESH_STATE_FILE);
        let state = match fs::metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.len() > MAX_REFRESH_STATE_BYTES {
                    return Err(OAuthError::InvalidConfiguration);
                }
                let contents = fs::read(&path).map_err(|_| OAuthError::Internal)?;
                let state: RefreshTokenState = serde_json::from_slice(&contents)
                    .map_err(|_| OAuthError::InvalidConfiguration)?;
                if state.version != REFRESH_STATE_VERSION {
                    return Err(OAuthError::InvalidConfiguration);
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                RefreshTokenState::default()
            }
            Err(_) => return Err(OAuthError::Internal),
        };

        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn create_family(
        &self,
        family_id: &str,
        active_token_hash: String,
        expires_at: u64,
        now: u64,
    ) -> Result<(), OAuthError> {
        let mut state = self.state.lock().map_err(|_| OAuthError::Internal)?;
        let mut next = state.clone();
        next.families.retain(|_, family| family.expires_at > now);
        if next.families.contains_key(family_id) {
            return Err(OAuthError::Entropy);
        }
        next.families.insert(
            family_id.to_owned(),
            RefreshTokenFamily {
                active_token_hash,
                expires_at,
                revoked: false,
            },
        );
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    fn rotate(
        &self,
        family_id: &str,
        presented_token_hash: &str,
        next_token_hash: String,
        expires_at: u64,
        now: u64,
    ) -> Result<(), OAuthError> {
        let mut state = self.state.lock().map_err(|_| OAuthError::Internal)?;
        let mut next = state.clone();
        let mut changed = false;
        let before_prune = next.families.len();
        next.families.retain(|_, family| family.expires_at > now);
        changed |= next.families.len() != before_prune;

        let Some(family) = next.families.get_mut(family_id) else {
            if changed {
                self.persist(&next)?;
                *state = next;
            }
            return Err(OAuthError::InvalidGrant);
        };

        if family.revoked
            || !constant_time_equal(
                family.active_token_hash.as_bytes(),
                presented_token_hash.as_bytes(),
            )
        {
            if !family.revoked {
                family.revoked = true;
                changed = true;
            }
            if changed {
                self.persist(&next)?;
                *state = next;
            }
            return Err(OAuthError::InvalidGrant);
        }

        family.active_token_hash = next_token_hash;
        family.expires_at = expires_at;
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    fn is_active(&self, family_id: &str, now: u64) -> Result<bool, OAuthError> {
        let state = self.state.lock().map_err(|_| OAuthError::Internal)?;
        Ok(state
            .families
            .get(family_id)
            .is_some_and(|family| !family.revoked && family.expires_at > now))
    }

    fn persist(&self, state: &RefreshTokenState) -> Result<(), OAuthError> {
        let serialized = serde_json::to_vec(state).map_err(|_| OAuthError::Internal)?;
        let temporary = self
            .path
            .with_file_name(format!("{REFRESH_STATE_FILE}.tmp"));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)
            .map_err(|_| OAuthError::Internal)?;
        file.write_all(&serialized)
            .map_err(|_| OAuthError::Internal)?;
        file.sync_all().map_err(|_| OAuthError::Internal)?;
        drop(file);
        fs::rename(&temporary, &self.path).map_err(|_| OAuthError::Internal)
    }
}

impl OAuthBearerAuthenticator {
    pub fn new(config: &OAuthConfig) -> Result<Self, OAuthError> {
        config
            .validate()
            .map_err(|_| OAuthError::InvalidConfiguration)?;
        let refresh_tokens = RefreshTokenStore::open(&config.refresh_state_dir)?;
        Ok(Self {
            state: Arc::new(OAuthState {
                issuer: Arc::from(config.issuer.as_str()),
                resource: Arc::from(config.resource.as_str()),
                owner_secret: Arc::from(config.owner_secret.as_bytes()),
                signing_key: Arc::from(config.signing_key.as_bytes()),
                access_token_ttl_seconds: config.access_token_ttl_seconds,
                authorization_code_ttl_seconds: config.authorization_code_ttl_seconds,
                refresh_token_ttl_seconds: config.refresh_token_ttl_seconds,
                authorization_codes: Mutex::new(HashMap::new()),
                refresh_tokens,
            }),
        })
    }

    pub fn authenticate_bearer(&self, token: &str) -> Result<OAuthIdentity, OAuthError> {
        if token.len() > MAX_FORM_VALUE_LENGTH || !token.starts_with(ACCESS_TOKEN_PREFIX) {
            return Err(OAuthError::InvalidGrant);
        }
        let claims: AccessTokenClaims = self
            .verify_token(
                ACCESS_TOKEN_PREFIX,
                b"engram-mcp/oauth/access-token/v1",
                token,
            )
            .map_err(|_| OAuthError::InvalidGrant)?;
        let now = now_unix();
        if claims.version != TOKEN_CLAIMS_VERSION
            || !claims.scopes.is_valid()
            || claims.family_id.is_empty()
            || claims.audience != self.state.resource.as_ref()
            || claims.expires_at <= now
        {
            return Err(OAuthError::InvalidGrant);
        }
        if !self
            .state
            .refresh_tokens
            .is_active(&claims.family_id, now)?
        {
            return Err(OAuthError::InvalidGrant);
        }
        Ok(OAuthIdentity {
            scope: claims.scopes.access_scope(),
            credential_fingerprint: self.audit_fingerprint(&self.token_hash(token)),
        })
    }

    fn issue_access_token(
        &self,
        scopes: ScopeGrant,
        resource: &str,
        family_id: &str,
    ) -> Result<(String, u64), OAuthError> {
        if resource != self.state.resource.as_ref() || !scopes.is_valid() || family_id.is_empty() {
            return Err(OAuthError::InvalidTarget);
        }
        let issued_at = now_unix();
        let claims = AccessTokenClaims {
            version: TOKEN_CLAIMS_VERSION,
            token_id: self.random_value("ati_")?,
            family_id: family_id.to_owned(),
            scopes,
            audience: resource.to_owned(),
            issued_at,
            expires_at: issued_at.saturating_add(self.state.access_token_ttl_seconds),
        };
        let signed = self.sign(b"engram-mcp/oauth/access-token/v1", &claims)?;
        Ok((
            format!("{ACCESS_TOKEN_PREFIX}{signed}"),
            self.state.access_token_ttl_seconds,
        ))
    }

    fn issue_token_pair(
        &self,
        scopes: ScopeGrant,
        resource: &str,
        client_id: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let issued_at = now_unix();
        let family_id = self.random_value("rf_")?;
        let (access_token, expires_in) =
            self.issue_access_token(scopes.clone(), resource, &family_id)?;
        let token_id = self.random_value("rti_")?;
        let refresh_claims = RefreshTokenClaims {
            version: TOKEN_CLAIMS_VERSION,
            family_id: family_id.clone(),
            token_id: token_id.clone(),
            client_binding: self.client_binding(client_id),
            scopes: scopes.clone(),
            audience: resource.to_owned(),
            issued_at,
            expires_at: issued_at.saturating_add(self.state.refresh_token_ttl_seconds),
        };
        let signed = self.sign(b"engram-mcp/oauth/refresh-token/v1", &refresh_claims)?;
        let refresh_token = format!("{REFRESH_TOKEN_PREFIX}{signed}");
        self.state.refresh_tokens.create_family(
            &family_id,
            self.refresh_token_id_hash(&token_id),
            refresh_claims.expires_at,
            issued_at,
        )?;
        Ok(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer",
            expires_in,
            scope: scopes.as_string(),
        })
    }

    fn token_hash(&self, token: &str) -> [u8; 32] {
        self.mac(b"engram-mcp/oauth/token-hash/v1", token.as_bytes())
    }

    fn refresh_token_id_hash(&self, token_id: &str) -> String {
        URL_SAFE_NO_PAD.encode(self.mac(
            b"engram-mcp/oauth/refresh-token-id-hash/v1",
            token_id.as_bytes(),
        ))
    }

    fn client_binding(&self, client_id: &str) -> String {
        URL_SAFE_NO_PAD.encode(self.mac(
            b"engram-mcp/oauth/refresh-client-binding/v1",
            client_id.as_bytes(),
        ))
    }

    fn audit_fingerprint(&self, token_hash: &[u8; 32]) -> [u8; 8] {
        let digest = self.mac(b"engram-mcp/oauth/audit-fingerprint/v1", token_hash);
        let mut fingerprint = [0_u8; 8];
        fingerprint.copy_from_slice(&digest[..8]);
        fingerprint
    }

    fn random_value(&self, prefix: &str) -> Result<String, OAuthError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| OAuthError::Entropy)?;
        Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
    }

    fn mac(&self, label: &[u8], value: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.state.signing_key)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(label);
        mac.update(&[0]);
        mac.update(value);
        let digest = mac.finalize().into_bytes();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        bytes
    }

    fn sign<T: Serialize>(&self, label: &[u8], value: &T) -> Result<String, OAuthError> {
        let payload = serde_json::to_vec(value).map_err(|_| OAuthError::Internal)?;
        let signature = self.mac(label, &payload);
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn verify<T: DeserializeOwned>(&self, label: &[u8], value: &str) -> Result<T, OAuthError> {
        let (encoded_payload, encoded_signature) =
            value.split_once('.').ok_or(OAuthError::InvalidRequest)?;
        let payload = URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .map_err(|_| OAuthError::InvalidRequest)?;
        let signature = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .map_err(|_| OAuthError::InvalidRequest)?;
        let expected = self.mac(label, &payload);
        if signature.len() != expected.len() || !bool::from(signature.ct_eq(&expected)) {
            return Err(OAuthError::InvalidRequest);
        }
        serde_json::from_slice(&payload).map_err(|_| OAuthError::InvalidRequest)
    }

    fn verify_token<T: DeserializeOwned>(
        &self,
        prefix: &str,
        label: &[u8],
        token: &str,
    ) -> Result<T, OAuthError> {
        let signed = token
            .strip_prefix(prefix)
            .ok_or(OAuthError::InvalidRequest)?;
        self.verify(label, signed)
    }
}

impl OAuthService {
    pub fn new(config: &OAuthConfig) -> Result<Self, OAuthError> {
        Ok(Self {
            bearer: OAuthBearerAuthenticator::new(config)?,
        })
    }

    pub fn bearer_authenticator(&self) -> OAuthBearerAuthenticator {
        self.bearer.clone()
    }

    pub fn issuer(&self) -> &str {
        &self.bearer.state.issuer
    }

    pub fn resource(&self) -> &str {
        &self.bearer.state.resource
    }

    pub fn protected_resource_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource", self.issuer())
    }

    pub fn authorization_server_metadata(&self) -> serde_json::Value {
        let issuer = self.issuer();
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth/authorize"),
            "token_endpoint": format!("{issuer}/oauth/token"),
            "registration_endpoint": format!("{issuer}/oauth/register"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": [SCOPE_TECH, SCOPE_PRIVATE],
            "authorization_response_iss_parameter_supported": true,
        })
    }

    pub fn protected_resource_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "resource": self.resource(),
            "authorization_servers": [self.issuer()],
            "scopes_supported": [SCOPE_TECH, SCOPE_PRIVATE],
            "bearer_methods_supported": ["header"],
        })
    }

    pub fn begin_authorization(&self, query: AuthorizationQuery) -> Result<String, OAuthError> {
        self.validate_authorization_query(&query)?;
        let client = self.client_from_id(&query.client_id)?;
        if !client.redirect_uris.contains(&query.redirect_uri) {
            return Err(OAuthError::InvalidAuthorizationRequest);
        }
        // RFC 6749 permits an omitted scope.  In that case the client can only
        // request the capability baked into its signed registration.
        let requested_scopes = query
            .scope
            .as_deref()
            .map(ScopeGrant::parse)
            .transpose()?
            .unwrap_or_else(|| client.scopes.clone());
        if !client.scopes.allows(&requested_scopes) {
            return Err(OAuthError::InvalidScope);
        }
        let request = SignedApprovalRequest {
            client_id: query.client_id,
            redirect_uri: query.redirect_uri,
            requested_scopes,
            state: query.state,
            resource: query.resource,
            code_challenge: query.code_challenge,
            expires_at: now_unix().saturating_add(APPROVAL_REQUEST_TTL_SECONDS),
        };
        let signed = self
            .bearer
            .sign(b"engram-mcp/oauth/approval-request/v1", &request)?;
        Ok(render_approval_page(&signed, &request))
    }

    pub fn complete_authorization(
        &self,
        form: ApprovalForm,
    ) -> Result<AuthorizationRedirect, OAuthError> {
        if form.request.len() > MAX_FORM_VALUE_LENGTH
            || form.owner_secret.len() > MAX_FORM_VALUE_LENGTH
            || form.scope.len() > 256
        {
            return Err(OAuthError::InvalidRequest);
        }
        let request: SignedApprovalRequest = self
            .bearer
            .verify(b"engram-mcp/oauth/approval-request/v1", &form.request)?;
        if request.expires_at <= now_unix() {
            return Err(OAuthError::InvalidRequest);
        }
        let client = self.client_from_id(&request.client_id)?;
        if !client.redirect_uris.contains(&request.redirect_uri)
            || !client.scopes.allows(&request.requested_scopes)
            || request.resource != self.resource()
        {
            return Err(OAuthError::InvalidAuthorizationRequest);
        }
        if form.decision == "deny" {
            return Ok(AuthorizationRedirect::Denied(self.redirect_url(
                &request.redirect_uri,
                request.state.as_deref(),
                None,
                Some("access_denied"),
            )?));
        }
        if form.decision != "approve"
            || !constant_time_equal(
                form.owner_secret.as_bytes(),
                &self.bearer.state.owner_secret,
            )
        {
            return Err(OAuthError::InvalidOwner);
        }
        let granted_scopes = ScopeGrant::parse(&form.scope)?;
        if !granted_scopes.is_subset_of(&request.requested_scopes)
            || !client.scopes.allows(&granted_scopes)
        {
            return Err(OAuthError::InvalidScope);
        }

        let code = self.bearer.random_value("ac_")?;
        let code_hash = self.bearer.token_hash(&code);
        let record = AuthorizationCode {
            client_id: request.client_id,
            redirect_uri: request.redirect_uri.clone(),
            scopes: granted_scopes,
            resource: request.resource,
            code_challenge: request.code_challenge,
            expires_at: now_unix().saturating_add(self.bearer.state.authorization_code_ttl_seconds),
        };
        let mut codes = self
            .bearer
            .state
            .authorization_codes
            .lock()
            .map_err(|_| OAuthError::Internal)?;
        codes.retain(|_, record| record.expires_at > now_unix());
        codes.insert(code_hash, record);
        Ok(AuthorizationRedirect::Approved(self.redirect_url(
            &request.redirect_uri,
            request.state.as_deref(),
            Some(&code),
            None,
        )?))
    }

    pub fn exchange_token(
        &self,
        request: TokenRequest,
        authorization_header: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        match request.grant_type.as_str() {
            "authorization_code" => self.exchange_authorization_code(request, authorization_header),
            "refresh_token" => self.exchange_refresh_token(request, authorization_header),
            _ => Err(OAuthError::InvalidGrant),
        }
    }

    fn exchange_authorization_code(
        &self,
        request: TokenRequest,
        authorization_header: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let code = request.code.as_deref().ok_or(OAuthError::InvalidGrant)?;
        let redirect_uri = request
            .redirect_uri
            .as_deref()
            .ok_or(OAuthError::InvalidGrant)?;
        let code_verifier = request
            .code_verifier
            .as_deref()
            .ok_or(OAuthError::InvalidGrant)?;
        if code.len() > MAX_FORM_VALUE_LENGTH
            || code_verifier.len() > 128
            || redirect_uri.len() > MAX_FORM_VALUE_LENGTH
            || request.resource != self.resource()
        {
            return Err(OAuthError::InvalidGrant);
        }
        let client = self.authenticate_client(&request, authorization_header)?;
        let code_hash = self.bearer.token_hash(code);
        // A code is consumed before PKCE verification, preventing repeated guesses.
        let record = self
            .bearer
            .state
            .authorization_codes
            .lock()
            .map_err(|_| OAuthError::Internal)?
            .remove(&code_hash)
            .ok_or(OAuthError::InvalidGrant)?;
        if record.expires_at <= now_unix()
            || record.client_id != client.client_id
            || record.redirect_uri != redirect_uri
            || record.resource != request.resource
            || !verify_pkce(code_verifier, &record.code_challenge)
        {
            return Err(OAuthError::InvalidGrant);
        }
        self.bearer
            .issue_token_pair(record.scopes, &record.resource, &client.client_id)
    }

    fn exchange_refresh_token(
        &self,
        request: TokenRequest,
        authorization_header: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let refresh_token = request
            .refresh_token
            .as_deref()
            .ok_or(OAuthError::InvalidGrant)?;
        if refresh_token.len() > MAX_FORM_VALUE_LENGTH || request.resource != self.resource() {
            return Err(OAuthError::InvalidGrant);
        }
        let client = self.authenticate_client(&request, authorization_header)?;
        let claims: RefreshTokenClaims = self
            .bearer
            .verify_token(
                REFRESH_TOKEN_PREFIX,
                b"engram-mcp/oauth/refresh-token/v1",
                refresh_token,
            )
            .map_err(|_| OAuthError::InvalidGrant)?;
        let now = now_unix();
        if claims.version != TOKEN_CLAIMS_VERSION
            || !claims.scopes.is_valid()
            || claims.audience != self.resource()
            || claims.expires_at <= now
            || !constant_time_equal(
                claims.client_binding.as_bytes(),
                self.bearer.client_binding(&client.client_id).as_bytes(),
            )
        {
            return Err(OAuthError::InvalidGrant);
        }

        let scopes = request
            .scope
            .as_deref()
            .map(ScopeGrant::parse)
            .transpose()?
            .unwrap_or_else(|| claims.scopes.clone());
        if !claims.scopes.allows(&scopes) {
            return Err(OAuthError::InvalidScope);
        }

        let (access_token, expires_in) =
            self.bearer
                .issue_access_token(scopes.clone(), self.resource(), &claims.family_id)?;
        let next_token_id = self.bearer.random_value("rti_")?;
        let next_claims = RefreshTokenClaims {
            version: TOKEN_CLAIMS_VERSION,
            family_id: claims.family_id.clone(),
            token_id: next_token_id.clone(),
            client_binding: self.bearer.client_binding(&client.client_id),
            scopes: scopes.clone(),
            audience: self.resource().to_owned(),
            issued_at: now,
            expires_at: now.saturating_add(self.bearer.state.refresh_token_ttl_seconds),
        };
        let signed = self
            .bearer
            .sign(b"engram-mcp/oauth/refresh-token/v1", &next_claims)?;
        let next_refresh_token = format!("{REFRESH_TOKEN_PREFIX}{signed}");
        self.bearer.state.refresh_tokens.rotate(
            &claims.family_id,
            &self.bearer.refresh_token_id_hash(&claims.token_id),
            self.bearer.refresh_token_id_hash(&next_token_id),
            next_claims.expires_at,
            now,
        )?;
        Ok(TokenResponse {
            access_token,
            refresh_token: next_refresh_token,
            token_type: "Bearer",
            expires_in,
            scope: scopes.as_string(),
        })
    }

    pub fn register_client(
        &self,
        request: RegistrationRequest,
    ) -> Result<RegistrationResponse, OAuthError> {
        if request.redirect_uris.is_empty() || request.redirect_uris.len() > MAX_REDIRECT_URIS {
            return Err(OAuthError::InvalidClient);
        }
        // Claude registers with ["authorization_code", "refresh_token"], both
        // of which are supported by this authorization server.
        if !request.grant_types.is_empty()
            && (!request
                .grant_types
                .iter()
                .any(|grant| grant == "authorization_code")
                || request
                    .grant_types
                    .iter()
                    .any(|grant| grant != "authorization_code" && grant != "refresh_token"))
        {
            return Err(OAuthError::InvalidClient);
        }
        if !request.response_types.is_empty()
            && (request.response_types.len() != 1 || request.response_types[0] != "code")
        {
            return Err(OAuthError::InvalidClient);
        }
        let method =
            ClientAuthenticationMethod::parse(request.token_endpoint_auth_method.as_deref())?;
        let application_type = request.application_type.as_deref().unwrap_or("web");
        if application_type != "web" && application_type != "native" {
            return Err(OAuthError::InvalidClient);
        }
        let redirect_uris = request
            .redirect_uris
            .iter()
            .map(|uri| validate_redirect_uri(uri, application_type).map(|_| uri.clone()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if redirect_uris.len() != request.redirect_uris.len() {
            return Err(OAuthError::InvalidClient);
        }
        let scopes = match request.scope {
            Some(value) => ScopeGrant::parse_lenient(&value),
            None => ScopeGrant::default_for_new_client(),
        };
        let issued_at = now_unix();
        let payload = ClientIdPayload {
            version: 1,
            redirect_uris: redirect_uris.iter().cloned().collect(),
            token_endpoint_auth_method: method,
            scopes: scopes.clone(),
            issued_at,
        };
        let client_id = format!(
            "dcr.{}",
            self.bearer
                .sign(b"engram-mcp/oauth/dynamic-client/v1", &payload)?
        );
        let client_secret = match method {
            ClientAuthenticationMethod::None => None,
            ClientAuthenticationMethod::ClientSecretPost
            | ClientAuthenticationMethod::ClientSecretBasic => Some(self.client_secret(&client_id)),
        };
        Ok(RegistrationResponse {
            client_id,
            client_id_issued_at: issued_at,
            client_secret,
            client_secret_expires_at: (method != ClientAuthenticationMethod::None).then_some(0),
            redirect_uris: redirect_uris.into_iter().collect(),
            grant_types: vec!["authorization_code", "refresh_token"],
            response_types: vec!["code"],
            token_endpoint_auth_method: method.as_str().to_owned(),
            scope: scopes.as_string(),
        })
    }

    fn validate_authorization_query(&self, query: &AuthorizationQuery) -> Result<(), OAuthError> {
        if query.response_type != "code"
            || query.client_id.is_empty()
            || query.client_id.len() > MAX_CLIENT_ID_LENGTH
            || query.redirect_uri.len() > MAX_FORM_VALUE_LENGTH
            || query.resource != self.resource()
            || query.code_challenge_method != "S256"
            || !valid_code_challenge(&query.code_challenge)
            || query
                .state
                .as_ref()
                .is_some_and(|state| state.len() > 2_048)
        {
            return Err(OAuthError::InvalidAuthorizationRequest);
        }
        Ok(())
    }

    fn client_from_id(&self, client_id: &str) -> Result<RegisteredClient, OAuthError> {
        if client_id.len() > MAX_CLIENT_ID_LENGTH {
            return Err(OAuthError::InvalidClient);
        }
        let encoded = client_id
            .strip_prefix("dcr.")
            .ok_or(OAuthError::InvalidClient)?;
        let payload: ClientIdPayload = self
            .bearer
            .verify(b"engram-mcp/oauth/dynamic-client/v1", encoded)
            .map_err(|_| OAuthError::InvalidClient)?;
        if payload.version != 1
            || payload.redirect_uris.is_empty()
            || payload.redirect_uris.len() > MAX_REDIRECT_URIS
        {
            return Err(OAuthError::InvalidClient);
        }
        let redirect_uris = payload
            .redirect_uris
            .iter()
            .map(|uri| {
                validate_redirect_uri(uri, "native")
                    .or_else(|_| validate_redirect_uri(uri, "web"))
                    .map(|_| uri.clone())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if redirect_uris.len() != payload.redirect_uris.len() {
            return Err(OAuthError::InvalidClient);
        }
        Ok(RegisteredClient {
            client_id: client_id.to_owned(),
            redirect_uris,
            token_endpoint_auth_method: payload.token_endpoint_auth_method,
            scopes: payload.scopes,
        })
    }

    fn authenticate_client(
        &self,
        request: &TokenRequest,
        authorization_header: Option<&str>,
    ) -> Result<RegisteredClient, OAuthError> {
        let basic = authorization_header
            .map(parse_basic_credentials)
            .transpose()?;
        if basic.is_some() && (request.client_id.is_some() || request.client_secret.is_some()) {
            return Err(OAuthError::InvalidClient);
        }
        let client_id = basic
            .as_ref()
            .map(|(client_id, _)| client_id.as_str())
            .or(request.client_id.as_deref())
            .ok_or(OAuthError::InvalidClient)?;
        let client = self.client_from_id(client_id)?;
        match client.token_endpoint_auth_method {
            ClientAuthenticationMethod::None => {
                if basic.is_some() || request.client_secret.is_some() {
                    return Err(OAuthError::InvalidClient);
                }
            }
            ClientAuthenticationMethod::ClientSecretPost => {
                if basic.is_some() {
                    return Err(OAuthError::InvalidClient);
                }
                let secret = request
                    .client_secret
                    .as_deref()
                    .ok_or(OAuthError::InvalidClient)?;
                if !constant_time_equal(secret.as_bytes(), self.client_secret(client_id).as_bytes())
                {
                    return Err(OAuthError::InvalidClient);
                }
            }
            ClientAuthenticationMethod::ClientSecretBasic => {
                let secret = basic
                    .as_ref()
                    .map(|(_, secret)| secret.as_str())
                    .ok_or(OAuthError::InvalidClient)?;
                if !constant_time_equal(secret.as_bytes(), self.client_secret(client_id).as_bytes())
                {
                    return Err(OAuthError::InvalidClient);
                }
            }
        }
        Ok(client)
    }

    fn client_secret(&self, client_id: &str) -> String {
        let digest = self.bearer.mac(
            b"engram-mcp/oauth/dynamic-client-secret/v1",
            client_id.as_bytes(),
        );
        format!("dcs_{}", URL_SAFE_NO_PAD.encode(digest))
    }

    fn redirect_url(
        &self,
        redirect_uri: &str,
        state: Option<&str>,
        code: Option<&str>,
        error: Option<&str>,
    ) -> Result<String, OAuthError> {
        let mut url =
            Url::parse(redirect_uri).map_err(|_| OAuthError::InvalidAuthorizationRequest)?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("iss", self.issuer());
            if let Some(state) = state {
                pairs.append_pair("state", state);
            }
            if let Some(code) = code {
                pairs.append_pair("code", code);
            }
            if let Some(error) = error {
                pairs.append_pair("error", error);
            }
        }
        Ok(url.to_string())
    }
}

pub enum AuthorizationRedirect {
    Approved(String),
    Denied(String),
}

fn validate_redirect_uri(value: &str, application_type: &str) -> Result<(), OAuthError> {
    if value.len() > 2_048 {
        return Err(OAuthError::InvalidClient);
    }
    let uri = Url::parse(value).map_err(|_| OAuthError::InvalidClient)?;
    if uri.fragment().is_some() || !uri.username().is_empty() || uri.password().is_some() {
        return Err(OAuthError::InvalidClient);
    }
    if uri.scheme() == "https" && uri.host_str().is_some() {
        return Ok(());
    }
    let local_host = matches!(
        uri.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("::1")
    );
    if application_type == "native" && uri.scheme() == "http" && local_host {
        return Ok(());
    }
    Err(OAuthError::InvalidClient)
}

fn parse_basic_credentials(value: &str) -> Result<(String, String), OAuthError> {
    let (scheme, encoded) = value.split_once(' ').ok_or(OAuthError::InvalidClient)?;
    if !scheme.eq_ignore_ascii_case("Basic") || encoded.is_empty() {
        return Err(OAuthError::InvalidClient);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .map_err(|_| OAuthError::InvalidClient)?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| OAuthError::InvalidClient)?;
    let (client_id, secret) = decoded.split_once(':').ok_or(OAuthError::InvalidClient)?;
    if client_id.is_empty() || secret.is_empty() {
        return Err(OAuthError::InvalidClient);
    }
    Ok((client_id.to_owned(), secret.to_owned()))
}

fn valid_code_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_code_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    if !valid_code_verifier(verifier) {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let calculated = URL_SAFE_NO_PAD.encode(digest);
    constant_time_equal(calculated.as_bytes(), challenge.as_bytes())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn render_approval_page(request: &str, approval: &SignedApprovalRequest) -> String {
    let scope_options = approval
        .requested_scopes
        .values()
        .enumerate()
        .map(|(index, scope)| {
            let checked = if index == 0 { " checked" } else { "" };
            format!(
                "<label><input type=\"radio\" name=\"scope\" value=\"{}\"{}> {}</label>",
                escape_html(scope),
                checked,
                escape_html(scope),
            )
        })
        .collect::<Vec<_>>()
        .join("<br>");
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Engram MCP authorization</title></head><body><main><h1>Authorize Engram MCP</h1><p>Client: <code>{}</code></p><p>Redirect URI: <code>{}</code></p><p>Resource: <code>{}</code></p><form method=\"post\" action=\"/oauth/authorize\"><input type=\"hidden\" name=\"request\" value=\"{}\"><label>Owner secret <input type=\"password\" name=\"owner_secret\" autocomplete=\"current-password\" required></label><fieldset><legend>Grant scope</legend>{}</fieldset><button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button><button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></main></body></html>",
        escape_html(&approval.client_id),
        escape_html(&approval.redirect_uri),
        escape_html(&approval.resource),
        escape_html(request),
        scope_options,
    )
}

fn escape_html(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#x27;".to_owned(),
            _ => character.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OAuthConfig {
        OAuthConfig {
            issuer: "https://engram.example.test".into(),
            resource: "https://engram.example.test/mcp".into(),
            owner_secret: "owner-secret-for-oauth-unit-test".into(),
            signing_key: "signing-key-for-oauth-unit-test-with-sufficient-length".into(),
            access_token_ttl_seconds: 60,
            authorization_code_ttl_seconds: 60,
            refresh_state_dir: std::env::temp_dir().join("engram-mcp-oauth-unit-tests"),
            refresh_token_ttl_seconds: 60,
        }
    }

    #[test]
    fn scopes_map_to_the_existing_access_scopes() {
        assert_eq!(
            ScopeGrant::parse(SCOPE_TECH).unwrap().access_scope(),
            AccessScope::Tech
        );
        assert_eq!(
            ScopeGrant::parse(SCOPE_PRIVATE).unwrap().access_scope(),
            AccessScope::Private
        );
        assert_eq!(
            ScopeGrant::parse("kb:tech kb:private")
                .unwrap()
                .access_scope(),
            AccessScope::Private
        );
        assert!(
            ScopeGrant::parse(SCOPE_TECH)
                .unwrap()
                .is_subset_of(&ScopeGrant::parse("kb:tech kb:private").unwrap())
        );
        assert!(
            !ScopeGrant::parse(SCOPE_PRIVATE)
                .unwrap()
                .is_subset_of(&ScopeGrant::parse(SCOPE_TECH).unwrap())
        );
        assert!(ScopeGrant::parse("kb:unknown").is_err());
    }

    #[test]
    fn client_registration_is_signed_and_rejects_tampering() {
        let oauth = OAuthService::new(&config()).unwrap();
        let registered = oauth
            .register_client(RegistrationRequest {
                redirect_uris: vec!["https://client.example.test/callback".into()],
                grant_types: vec!["authorization_code".into()],
                response_types: vec!["code".into()],
                token_endpoint_auth_method: Some("client_secret_post".into()),
                scope: Some(SCOPE_PRIVATE.into()),
                application_type: Some("web".into()),
            })
            .unwrap();
        assert!(oauth.client_from_id(&registered.client_id).is_ok());
        assert!(
            oauth
                .client_from_id(&format!("{}x", registered.client_id))
                .is_err()
        );
    }

    #[test]
    fn omitted_authorization_scope_uses_the_registered_client_scope() {
        let oauth = OAuthService::new(&config()).unwrap();
        let registered = oauth
            .register_client(RegistrationRequest {
                redirect_uris: vec!["https://client.example.test/callback".into()],
                grant_types: vec![],
                response_types: vec![],
                token_endpoint_auth_method: Some("none".into()),
                scope: None,
                application_type: Some("web".into()),
            })
            .unwrap();

        let page = oauth
            .begin_authorization(AuthorizationQuery {
                response_type: "code".into(),
                client_id: registered.client_id,
                redirect_uri: "https://client.example.test/callback".into(),
                scope: None,
                state: None,
                resource: "https://engram.example.test/mcp".into(),
                code_challenge: "A".repeat(43),
                code_challenge_method: "S256".into(),
            })
            .unwrap();
        assert!(page.contains(SCOPE_TECH));
        assert!(page.contains(SCOPE_PRIVATE));
    }

    #[test]
    fn claude_style_registration_with_refresh_token_and_foreign_scope_succeeds() {
        let oauth = OAuthService::new(&config()).unwrap();
        let registered = oauth
            .register_client(RegistrationRequest {
                redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".into()],
                grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                response_types: vec!["code".into()],
                token_endpoint_auth_method: Some("client_secret_post".into()),
                scope: Some("claudeai".into()),
                application_type: None,
            })
            .unwrap();
        assert_eq!(
            registered.grant_types,
            vec!["authorization_code", "refresh_token"]
        );
        assert_eq!(registered.scope, "kb:tech kb:private");

        let refresh_only = oauth.register_client(RegistrationRequest {
            redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".into()],
            grant_types: vec!["refresh_token".into()],
            response_types: vec![],
            token_endpoint_auth_method: Some("none".into()),
            scope: None,
            application_type: None,
        });
        assert!(refresh_only.is_err());
    }
}
