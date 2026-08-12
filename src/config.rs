use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};

use thiserror::Error;
use url::Url;

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_MAX_READ_BYTES: usize = 65_536;
const DEFAULT_MAX_SEARCH_RESPONSE_BYTES: usize = 24_576;
const DEFAULT_MAX_SEARCH_FILE_BYTES: usize = 1_048_576;
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 60;
const DEFAULT_RATE_LIMIT_BURST: u32 = 10;
const DEFAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS: u64 = 900;
const DEFAULT_OAUTH_AUTHORIZATION_CODE_TTL_SECONDS: u64 = 300;
const DEFAULT_OAUTH_REFRESH_TOKEN_TTL_SECONDS: u64 = 1_209_600;
const DEFAULT_KB_PUBLIC_DIRS: &[&str] = &["10_tech", "20_projects"];
const DEFAULT_KB_PRIVATE_DIRS: &[&str] = &["90_private"];

/// Top-level knowledge-base directories visible to each OAuth/API-key scope.
///
/// `kb:private` inherits every public directory and adds `private`. The
/// top-level `INDEX.md` is intentionally visible to both scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDirectories {
    public: BTreeSet<String>,
    private: BTreeSet<String>,
}

impl ScopeDirectories {
    pub fn new(public: BTreeSet<String>, private: BTreeSet<String>) -> Result<Self, ConfigError> {
        if public.is_empty()
            || public
                .iter()
                .any(|directory| !is_safe_top_level_directory(directory))
        {
            return Err(ConfigError::InvalidScopeDirectories("KB_PUBLIC_DIRS"));
        }
        if private.is_empty()
            || private
                .iter()
                .any(|directory| !is_safe_top_level_directory(directory))
        {
            return Err(ConfigError::InvalidScopeDirectories("KB_PRIVATE_DIRS"));
        }
        if public.iter().any(|directory| private.contains(directory)) {
            return Err(ConfigError::OverlappingScopeDirectories);
        }
        Ok(Self { public, private })
    }

    pub fn allows_public(&self, directory: &str) -> bool {
        self.public.contains(directory)
    }

    pub fn allows_private(&self, directory: &str) -> bool {
        self.private.contains(directory)
    }

    pub fn public_directories(&self) -> impl Iterator<Item = &str> {
        self.public.iter().map(String::as_str)
    }

    pub fn private_directories(&self) -> impl Iterator<Item = &str> {
        self.private.iter().map(String::as_str)
    }
}

impl Default for ScopeDirectories {
    fn default() -> Self {
        Self {
            public: DEFAULT_KB_PUBLIC_DIRS
                .iter()
                .map(|directory| (*directory).to_owned())
                .collect(),
            private: DEFAULT_KB_PRIVATE_DIRS
                .iter()
                .map(|directory| (*directory).to_owned())
                .collect(),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub kb_root: PathBuf,
    pub scope_directories: ScopeDirectories,
    pub key_a: String,
    pub key_b: String,
    pub bind_addr: SocketAddr,
    pub allowed_hosts: BTreeSet<String>,
    pub allowed_origins: BTreeSet<String>,
    pub max_read_bytes: usize,
    pub max_search_response_bytes: usize,
    pub max_search_file_bytes: usize,
    pub rate_limit_per_minute: u32,
    pub rate_limit_burst: u32,
    pub oauth: OAuthConfig,
}

#[derive(Clone)]
pub struct OAuthConfig {
    /// Canonical HTTPS issuer, without a trailing slash.
    pub issuer: String,
    /// Canonical HTTPS URI of this MCP resource, normally ending in `/mcp`.
    pub resource: String,
    /// High-entropy secret entered by the resource owner in the local consent page.
    pub owner_secret: String,
    /// Server-only HMAC key for codes, tokens, signed client registrations, and audit IDs.
    pub signing_key: String,
    pub access_token_ttl_seconds: u64,
    pub authorization_code_ttl_seconds: u64,
    /// Writable, persistent directory for refresh-token rotation and revocation state.
    pub refresh_state_dir: PathBuf,
    pub refresh_token_ttl_seconds: u64,
}

impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthConfig")
            .field("issuer", &self.issuer)
            .field("resource", &self.resource)
            .field("owner_secret", &"[redacted]")
            .field("signing_key", &"[redacted]")
            .field("access_token_ttl_seconds", &self.access_token_ttl_seconds)
            .field(
                "authorization_code_ttl_seconds",
                &self.authorization_code_ttl_seconds,
            )
            .field("refresh_state_dir", &self.refresh_state_dir)
            .field("refresh_token_ttl_seconds", &self.refresh_token_ttl_seconds)
            .finish()
    }
}

impl OAuthConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let issuer = Url::parse(&self.issuer).map_err(|_| ConfigError::InvalidOAuthIssuer)?;
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || issuer.path() != "/"
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || self.issuer.ends_with('/')
        {
            return Err(ConfigError::InvalidOAuthIssuer);
        }

        let resource = Url::parse(&self.resource).map_err(|_| ConfigError::InvalidOAuthResource)?;
        if resource.scheme() != "https"
            || resource.host_str().is_none()
            || resource.query().is_some()
            || resource.fragment().is_some()
            || resource.origin() != issuer.origin()
        {
            return Err(ConfigError::InvalidOAuthResource);
        }
        if self.owner_secret.len() < 20 {
            return Err(ConfigError::WeakSecret("OAUTH_OWNER_SECRET"));
        }
        if self.signing_key.len() < 32 {
            return Err(ConfigError::WeakSecret("OAUTH_SIGNING_KEY"));
        }
        if !self.refresh_state_dir.is_absolute() {
            return Err(ConfigError::InvalidOAuthStateDir);
        }
        Ok(())
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("kb_root", &self.kb_root)
            .field("scope_directories", &self.scope_directories)
            .field("key_a", &"[redacted]")
            .field("key_b", &"[redacted]")
            .field("bind_addr", &self.bind_addr)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .field("max_read_bytes", &self.max_read_bytes)
            .field("max_search_response_bytes", &self.max_search_response_bytes)
            .field("max_search_file_bytes", &self.max_search_file_bytes)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field("rate_limit_burst", &self.rate_limit_burst)
            .field("oauth", &self.oauth)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),
    #[error("environment variable {0} must not be empty")]
    Empty(&'static str),
    #[error("KB_ROOT is not a readable directory")]
    InvalidKbRoot,
    #[error("KB_KEY_A and KB_KEY_B must be different")]
    DuplicateKeys,
    #[error("{0} must contain one or more safe top-level directory names")]
    InvalidScopeDirectories(&'static str),
    #[error("KB_PUBLIC_DIRS and KB_PRIVATE_DIRS must not overlap")]
    OverlappingScopeDirectories,
    #[error("invalid socket address in MCP_BIND_ADDR")]
    InvalidBindAddress,
    #[error("invalid integer in {0}")]
    InvalidInteger(&'static str),
    #[error("{0} is outside its allowed range")]
    OutOfRange(&'static str),
    #[error("MCP_ALLOWED_HOSTS must contain at least one host")]
    MissingAllowedHosts,
    #[error("OAUTH_ISSUER must be an HTTPS origin without a trailing slash")]
    InvalidOAuthIssuer,
    #[error("OAUTH_RESOURCE must be an HTTPS resource URI on the OAUTH_ISSUER origin")]
    InvalidOAuthResource,
    #[error("{0} must be a high-entropy secret of sufficient length")]
    WeakSecret(&'static str),
    #[error("OAUTH_STATE_DIR must be an absolute writable directory path")]
    InvalidOAuthStateDir,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let kb_root = PathBuf::from(required(&lookup, "KB_ROOT")?);
        if !Path::new(&kb_root).is_dir() {
            return Err(ConfigError::InvalidKbRoot);
        }
        let scope_directories = ScopeDirectories::new(
            parse_directory_set(&lookup, "KB_PUBLIC_DIRS", DEFAULT_KB_PUBLIC_DIRS)?,
            parse_directory_set(&lookup, "KB_PRIVATE_DIRS", DEFAULT_KB_PRIVATE_DIRS)?,
        )?;

        let key_a = required(&lookup, "KB_KEY_A")?;
        let key_b = required(&lookup, "KB_KEY_B")?;
        if key_a == key_b {
            return Err(ConfigError::DuplicateKeys);
        }

        let bind_addr = optional(&lookup, "MCP_BIND_ADDR")
            .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_owned())
            .parse()
            .map_err(|_| ConfigError::InvalidBindAddress)?;

        let allowed_hosts = parse_set(required(&lookup, "MCP_ALLOWED_HOSTS")?);
        if allowed_hosts.is_empty() {
            return Err(ConfigError::MissingAllowedHosts);
        }

        let allowed_origins = optional(&lookup, "ALLOWED_ORIGINS")
            .map(parse_set)
            .unwrap_or_default();

        let max_read_bytes = parse_usize(
            &lookup,
            "MAX_READ_BYTES",
            DEFAULT_MAX_READ_BYTES,
            8_192,
            262_144,
        )?;
        let max_search_response_bytes = parse_usize(
            &lookup,
            "MAX_SEARCH_RESPONSE_BYTES",
            DEFAULT_MAX_SEARCH_RESPONSE_BYTES,
            8_192,
            65_536,
        )?;
        let max_search_file_bytes = parse_usize(
            &lookup,
            "MAX_SEARCH_FILE_BYTES",
            DEFAULT_MAX_SEARCH_FILE_BYTES,
            max_read_bytes,
            4 * 1024 * 1024,
        )?;
        let rate_limit_per_minute = parse_u32(
            &lookup,
            "RATE_LIMIT_PER_MINUTE",
            DEFAULT_RATE_LIMIT_PER_MINUTE,
            1,
            600,
        )?;
        let rate_limit_burst = parse_u32(
            &lookup,
            "RATE_LIMIT_BURST",
            DEFAULT_RATE_LIMIT_BURST,
            1,
            rate_limit_per_minute,
        )?;

        let oauth = OAuthConfig {
            issuer: required(&lookup, "OAUTH_ISSUER")?,
            resource: required(&lookup, "OAUTH_RESOURCE")?,
            owner_secret: required(&lookup, "OAUTH_OWNER_SECRET")?,
            signing_key: required(&lookup, "OAUTH_SIGNING_KEY")?,
            access_token_ttl_seconds: parse_u64(
                &lookup,
                "OAUTH_ACCESS_TOKEN_TTL_SECONDS",
                DEFAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS,
                60,
                3_600,
            )?,
            authorization_code_ttl_seconds: parse_u64(
                &lookup,
                "OAUTH_AUTHORIZATION_CODE_TTL_SECONDS",
                DEFAULT_OAUTH_AUTHORIZATION_CODE_TTL_SECONDS,
                60,
                600,
            )?,
            refresh_state_dir: PathBuf::from(required(&lookup, "OAUTH_STATE_DIR")?),
            refresh_token_ttl_seconds: parse_u64(
                &lookup,
                "OAUTH_REFRESH_TOKEN_TTL_SECONDS",
                DEFAULT_OAUTH_REFRESH_TOKEN_TTL_SECONDS,
                60,
                2_592_000,
            )?,
        };
        oauth.validate()?;

        Ok(Self {
            kb_root,
            scope_directories,
            key_a,
            key_b,
            bind_addr,
            allowed_hosts,
            allowed_origins,
            max_read_bytes,
            max_search_response_bytes,
            max_search_file_bytes,
            rate_limit_per_minute,
            rate_limit_burst,
            oauth,
        })
    }
}

fn required<F>(lookup: &F, key: &'static str) -> Result<String, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        Some(_) => Err(ConfigError::Empty(key)),
        None => Err(ConfigError::Missing(key)),
    }
}

fn optional<F>(lookup: &F, key: &'static str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key).filter(|value| !value.trim().is_empty())
}

fn parse_set(value: String) -> BTreeSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_directory_set<F>(
    lookup: &F,
    key: &'static str,
    default: &[&str],
) -> Result<BTreeSet<String>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = optional(lookup, key).unwrap_or_else(|| default.join(","));
    let mut directories = BTreeSet::new();
    for directory in value.split(',').map(str::trim) {
        if !is_safe_top_level_directory(directory) {
            return Err(ConfigError::InvalidScopeDirectories(key));
        }
        directories.insert(directory.to_owned());
    }
    if directories.is_empty() {
        return Err(ConfigError::InvalidScopeDirectories(key));
    }
    Ok(directories)
}

fn is_safe_top_level_directory(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value.contains(['/', '\\', '\0', ':'])
    {
        return false;
    }
    matches!(
        Path::new(value).components().next(),
        Some(Component::Normal(_))
    ) && Path::new(value).components().count() == 1
}

fn parse_usize<F>(
    lookup: &F,
    key: &'static str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = optional(lookup, key)
        .map(|value| value.parse().map_err(|_| ConfigError::InvalidInteger(key)))
        .transpose()?
        .unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(ConfigError::OutOfRange(key));
    }
    Ok(value)
}

fn parse_u32<F>(
    lookup: &F,
    key: &'static str,
    default: u32,
    min: u32,
    max: u32,
) -> Result<u32, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = optional(lookup, key)
        .map(|value| value.parse().map_err(|_| ConfigError::InvalidInteger(key)))
        .transpose()?
        .unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(ConfigError::OutOfRange(key));
    }
    Ok(value)
}

fn parse_u64<F>(
    lookup: &F,
    key: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = optional(lookup, key)
        .map(|value| value.parse().map_err(|_| ConfigError::InvalidInteger(key)))
        .transpose()?
        .unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(ConfigError::OutOfRange(key));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::TempDir;

    use super::*;

    fn values(root: &TempDir) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("KB_ROOT".into(), root.path().display().to_string()),
            ("KB_KEY_A".into(), "tech-key".into()),
            ("KB_KEY_B".into(), "private-key".into()),
            ("MCP_ALLOWED_HOSTS".into(), "engram.example.test".into()),
            ("OAUTH_ISSUER".into(), "https://engram.example.test".into()),
            (
                "OAUTH_RESOURCE".into(),
                "https://engram.example.test/mcp".into(),
            ),
            (
                "OAUTH_OWNER_SECRET".into(),
                "owner-secret-for-config-test".into(),
            ),
            (
                "OAUTH_SIGNING_KEY".into(),
                "signing-key-for-config-test-with-sufficient-length".into(),
            ),
            (
                "OAUTH_STATE_DIR".into(),
                root.path().join("oauth-state").display().to_string(),
            ),
        ])
    }

    #[test]
    fn rejects_missing_required_value() {
        let root = TempDir::new().unwrap();
        let mut source = values(&root);
        source.remove("KB_KEY_A");
        assert!(matches!(
            Config::from_lookup(|key| source.get(key).cloned()),
            Err(ConfigError::Missing("KB_KEY_A"))
        ));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let root = TempDir::new().unwrap();
        let mut source = values(&root);
        source.insert("KB_KEY_B".into(), "tech-key".into());
        assert!(matches!(
            Config::from_lookup(|key| source.get(key).cloned()),
            Err(ConfigError::DuplicateKeys)
        ));
    }

    #[test]
    fn applies_safe_defaults() {
        let root = TempDir::new().unwrap();
        let source = values(&root);
        let config = Config::from_lookup(|key| source.get(key).cloned()).unwrap();
        assert_eq!(config.max_read_bytes, DEFAULT_MAX_READ_BYTES);
        assert_eq!(config.rate_limit_burst, DEFAULT_RATE_LIMIT_BURST);
        assert_eq!(config.bind_addr.to_string(), DEFAULT_BIND_ADDR);
        assert_eq!(
            config.oauth.access_token_ttl_seconds,
            DEFAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS
        );
        assert_eq!(
            config.oauth.refresh_token_ttl_seconds,
            DEFAULT_OAUTH_REFRESH_TOKEN_TTL_SECONDS
        );
        assert!(config.scope_directories.allows_public("10_tech"));
        assert!(config.scope_directories.allows_public("20_projects"));
        assert!(config.scope_directories.allows_private("90_private"));
    }

    #[test]
    fn accepts_custom_scope_directories() {
        let root = TempDir::new().unwrap();
        let mut source = values(&root);
        source.insert("KB_PUBLIC_DIRS".into(), "docs,projects".into());
        source.insert("KB_PRIVATE_DIRS".into(), "personal".into());
        let config = Config::from_lookup(|key| source.get(key).cloned()).unwrap();
        assert!(config.scope_directories.allows_public("docs"));
        assert!(config.scope_directories.allows_public("projects"));
        assert!(config.scope_directories.allows_private("personal"));
        assert!(!config.scope_directories.allows_public("10_tech"));
    }

    #[test]
    fn rejects_unsafe_or_overlapping_scope_directories() {
        let root = TempDir::new().unwrap();
        let mut source = values(&root);
        source.insert("KB_PUBLIC_DIRS".into(), "../outside".into());
        assert!(matches!(
            Config::from_lookup(|key| source.get(key).cloned()),
            Err(ConfigError::InvalidScopeDirectories("KB_PUBLIC_DIRS"))
        ));

        source.insert("KB_PUBLIC_DIRS".into(), "shared".into());
        source.insert("KB_PRIVATE_DIRS".into(), "shared".into());
        assert!(matches!(
            Config::from_lookup(|key| source.get(key).cloned()),
            Err(ConfigError::OverlappingScopeDirectories)
        ));

        assert!(matches!(
            ScopeDirectories::new(
                BTreeSet::from(["../outside".to_owned()]),
                BTreeSet::from(["private".to_owned()]),
            ),
            Err(ConfigError::InvalidScopeDirectories("KB_PUBLIC_DIRS"))
        ));
    }

    #[test]
    fn rejects_out_of_range_response_limit() {
        let root = TempDir::new().unwrap();
        let mut source = values(&root);
        source.insert("MAX_SEARCH_RESPONSE_BYTES".into(), "1".into());
        assert!(matches!(
            Config::from_lookup(|key| source.get(key).cloned()),
            Err(ConfigError::OutOfRange("MAX_SEARCH_RESPONSE_BYTES"))
        ));
    }
}
