use std::{collections::BTreeSet, net::SocketAddr};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use engram_mcp::{
    config::{Config, OAuthConfig, ScopeDirectories},
    http,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;
use url::Url;

const ISSUER: &str = "https://engram.test";
const RESOURCE: &str = "https://engram.test/mcp";
const OWNER_SECRET: &str = "owner-secret-for-oauth-test-only";
const SIGNING_KEY: &str = "signing-key-for-oauth-test-only-with-sufficient-length";
const REDIRECT_URI: &str = "https://client.test/oauth/callback";
const PKCE_VERIFIER: &str = "correct-pkce-verifier-for-oauth-test-with-at-least-forty-three-bytes";

fn prepare_kb(root: &TempDir) {
    std::fs::create_dir_all(root.path().join("10_tech/rust")).unwrap();
    std::fs::create_dir_all(root.path().join("90_private")).unwrap();
    std::fs::write(root.path().join("INDEX.md"), "# Engram\n").unwrap();
    std::fs::write(
        root.path().join("10_tech/rust/needle.md"),
        "---\ntitle: Public needle\n---\nneedle body\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("90_private/secret.md"),
        "---\ntitle: Private note\n---\nprivate-only-term\n",
    )
    .unwrap();
}

fn test_config(
    root: &TempDir,
    access_token_ttl_seconds: u64,
    refresh_token_ttl_seconds: u64,
) -> Config {
    Config {
        kb_root: root.path().to_path_buf(),
        scope_directories: ScopeDirectories::default(),
        key_a: "tech-secret".into(),
        key_b: "private-secret".into(),
        bind_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        allowed_hosts: BTreeSet::from(["engram.test".into()]),
        allowed_origins: BTreeSet::from(["https://allowed.test".into()]),
        max_read_bytes: 65_536,
        max_search_response_bytes: 24_576,
        max_search_file_bytes: 1_048_576,
        rate_limit_per_minute: 600,
        rate_limit_burst: 100,
        oauth: OAuthConfig {
            issuer: ISSUER.into(),
            resource: RESOURCE.into(),
            owner_secret: OWNER_SECRET.into(),
            signing_key: SIGNING_KEY.into(),
            access_token_ttl_seconds,
            authorization_code_ttl_seconds: 60,
            refresh_state_dir: root.path().join("oauth-state"),
            refresh_token_ttl_seconds,
        },
    }
}

fn app_with_ttls(
    access_token_ttl_seconds: u64,
    refresh_token_ttl_seconds: u64,
) -> (TempDir, Router) {
    let root = TempDir::new().unwrap();
    prepare_kb(&root);
    let config = test_config(&root, access_token_ttl_seconds, refresh_token_ttl_seconds);
    (root, http::router(&config).unwrap())
}

fn app(access_token_ttl_seconds: u64) -> (TempDir, Router) {
    app_with_ttls(access_token_ttl_seconds, 60)
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn text_body(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![char::from(byte)]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn register_public_client(app: Router) -> String {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header(header::HOST, "engram.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "redirect_uris": [REDIRECT_URI],
                        "grant_types": ["authorization_code", "refresh_token"],
                        "response_types": ["code"],
                        "token_endpoint_auth_method": "none",
                        "scope": "kb:tech kb:private",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    assert_eq!(
        body["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    body["client_id"].as_str().unwrap().to_owned()
}

fn approval_request(html: &str) -> String {
    let prefix = "name=\"request\" value=\"";
    let start = html.find(prefix).unwrap() + prefix.len();
    html[start..].split('"').next().unwrap().to_owned()
}

fn authorization_code(location: &str) -> String {
    location
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .find_map(|part| part.strip_prefix("code="))
        .unwrap()
        .to_owned()
}

async fn authorize(app: Router, client_id: &str, requested_scope: &str) -> String {
    let verifier = PKCE_VERIFIER;
    let query = form(&[
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("scope", requested_scope),
        ("state", "state-1"),
        ("resource", RESOURCE),
        ("code_challenge", &code_challenge(verifier)),
        ("code_challenge_method", "S256"),
    ]);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/authorize?{query}"))
                .header(header::HOST, "engram.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let request = approval_request(&text_body(response).await);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/authorize")
                .header(header::HOST, "engram.test")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&[
                    ("request", &request),
                    ("owner_secret", OWNER_SECRET),
                    ("decision", "approve"),
                    ("scope", requested_scope),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    let redirect = Url::parse(location).unwrap();
    assert_eq!(
        redirect
            .query_pairs()
            .find_map(|(key, value)| (key == "iss").then_some(value.into_owned())),
        Some(ISSUER.into())
    );
    authorization_code(location)
}

async fn exchange_code(
    app: Router,
    client_id: &str,
    code: &str,
    verifier: &str,
) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header(header::HOST, "engram.test")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", verifier),
                ("resource", RESOURCE),
            ])))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn exchange_refresh_token(
    app: Router,
    client_id: &str,
    refresh_token: &str,
    scope: Option<&str>,
) -> axum::response::Response {
    let mut fields = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
        ("resource", RESOURCE),
    ];
    if let Some(scope) = scope {
        fields.push(("scope", scope));
    }

    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header(header::HOST, "engram.test")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form(&fields)))
            .unwrap(),
    )
    .await
    .unwrap()
}

fn mcp_request(api_key: Option<&str>, bearer: Option<&str>, id: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "engram.test")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "fetch");
    if let Some(api_key) = api_key {
        builder = builder.header("x-api-key", api_key);
    }
    if let Some(bearer) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    builder
        .body(Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "fetch",
                    "arguments": {"id": id},
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": {"name": "oauth-test", "version": "1.0"},
                        "io.modelcontextprotocol/clientCapabilities": {},
                    },
                },
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn oauth_metadata_endpoints_advertise_mcp_oauth_contract() {
    let (_root, app) = app(60);
    let protected_resource = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource")
                .header(header::HOST, "engram.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(protected_resource.status(), StatusCode::OK);
    let protected_resource = json_body(protected_resource).await;
    assert_eq!(protected_resource["resource"], RESOURCE);
    assert_eq!(protected_resource["authorization_servers"][0], ISSUER);
    assert_eq!(
        protected_resource["scopes_supported"],
        json!(["kb:tech", "kb:private"])
    );

    let authorization_server = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .header(header::HOST, "engram.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorization_server.status(), StatusCode::OK);
    let authorization_server = json_body(authorization_server).await;
    assert_eq!(authorization_server["issuer"], ISSUER);
    assert_eq!(
        authorization_server["authorization_endpoint"],
        format!("{ISSUER}/oauth/authorize")
    );
    assert_eq!(
        authorization_server["token_endpoint"],
        format!("{ISSUER}/oauth/token")
    );
    assert_eq!(
        authorization_server["registration_endpoint"],
        format!("{ISSUER}/oauth/register")
    );
    assert_eq!(
        authorization_server["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(
        authorization_server["code_challenge_methods_supported"],
        json!(["S256"])
    );
}

#[tokio::test]
async fn oauth_endpoints_enforce_the_same_request_body_limit_as_mcp() {
    let (_root, app) = app(60);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header(header::HOST, "engram.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b'x'; 32 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn pkce_rejects_a_wrong_verifier() {
    let (_root, app) = app(60);
    let client_id = register_public_client(app.clone()).await;
    let code = authorize(app.clone(), &client_id, "kb:tech").await;
    let response = exchange_code(app, &client_id, &code, "wrong-pkce-verifier").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "invalid_grant");
}

#[tokio::test]
async fn kb_tech_bearer_token_hides_private_documents_and_api_keys_still_work() {
    let (_root, app) = app(60);
    let client_id = register_public_client(app.clone()).await;
    let code = authorize(app.clone(), &client_id, "kb:tech").await;
    let token = json_body(exchange_code(app.clone(), &client_id, &code, PKCE_VERIFIER).await).await;
    let access_token = token["access_token"].as_str().unwrap();
    assert_eq!(token["scope"], "kb:tech");

    let bearer_response = app
        .clone()
        .oneshot(mcp_request(
            None,
            Some(access_token),
            "90_private/secret.md",
        ))
        .await
        .unwrap();
    assert_eq!(bearer_response.status(), StatusCode::OK);
    let bearer_body = json_body(bearer_response).await;
    assert_eq!(bearer_body["result"]["isError"], true);
    assert_eq!(
        bearer_body["result"]["structuredContent"]["error"],
        "not_found"
    );

    let api_key_response = app
        .oneshot(mcp_request(
            Some("tech-secret"),
            None,
            "10_tech/rust/needle.md",
        ))
        .await
        .unwrap();
    assert_eq!(api_key_response.status(), StatusCode::OK);
    assert_eq!(
        json_body(api_key_response).await["result"]["structuredContent"]["title"],
        "Public needle"
    );
}

#[tokio::test]
async fn expired_or_tampered_bearer_token_is_unauthorized_with_metadata_challenge() {
    let (_root, app) = app(0);
    let client_id = register_public_client(app.clone()).await;
    let code = authorize(app.clone(), &client_id, "kb:tech").await;
    let token = json_body(exchange_code(app.clone(), &client_id, &code, PKCE_VERIFIER).await).await;
    let expired = token["access_token"].as_str().unwrap();

    for bearer in [expired.to_owned(), format!("{expired}tampered")] {
        let response = app
            .clone()
            .oneshot(mcp_request(None, Some(&bearer), "10_tech/rust/needle.md"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(challenge.contains("Bearer"));
        assert!(challenge.contains("oauth-protected-resource"));
        assert!(challenge.contains("kb:tech"));
        assert!(challenge.contains("kb:private"));
    }
}

#[tokio::test]
async fn refresh_grant_issues_a_new_access_and_refresh_token() {
    let (_root, app) = app(60);
    let client_id = register_public_client(app.clone()).await;
    let code = authorize(app.clone(), &client_id, "kb:tech").await;
    let initial =
        json_body(exchange_code(app.clone(), &client_id, &code, PKCE_VERIFIER).await).await;
    let original_access = initial["access_token"].as_str().unwrap().to_owned();
    let original_refresh = initial["refresh_token"].as_str().unwrap().to_owned();

    let response = exchange_refresh_token(app, &client_id, &original_refresh, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed = json_body(response).await;
    assert_eq!(refreshed["scope"], "kb:tech");
    assert_ne!(refreshed["access_token"], original_access);
    assert_ne!(refreshed["refresh_token"], original_refresh);
}

#[tokio::test]
async fn refresh_token_reuse_revokes_its_entire_family() {
    let (_root, app) = app(60);
    let client_id = register_public_client(app.clone()).await;
    let code = authorize(app.clone(), &client_id, "kb:tech").await;
    let initial =
        json_body(exchange_code(app.clone(), &client_id, &code, PKCE_VERIFIER).await).await;
    let original_refresh = initial["refresh_token"].as_str().unwrap().to_owned();

    let rotated =
        json_body(exchange_refresh_token(app.clone(), &client_id, &original_refresh, None).await)
            .await;
    let rotated_refresh = rotated["refresh_token"].as_str().unwrap().to_owned();
    let rotated_access = rotated["access_token"].as_str().unwrap().to_owned();

    let reused = exchange_refresh_token(app.clone(), &client_id, &original_refresh, None).await;
    assert_eq!(reused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(reused).await["error"], "invalid_grant");

    let family_revoked =
        exchange_refresh_token(app.clone(), &client_id, &rotated_refresh, None).await;
    assert_eq!(family_revoked.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(family_revoked).await["error"], "invalid_grant");

    let revoked_access = app
        .oneshot(mcp_request(
            None,
            Some(&rotated_access),
            "10_tech/rust/needle.md",
        ))
        .await
        .unwrap();
    assert_eq!(revoked_access.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_grant_allows_scope_narrowing() {
    let (_root, app) = app(60);
    let client_id = register_public_client(app.clone()).await;
    let code = authorize(app.clone(), &client_id, "kb:tech kb:private").await;
    let initial =
        json_body(exchange_code(app.clone(), &client_id, &code, PKCE_VERIFIER).await).await;
    let refresh = initial["refresh_token"].as_str().unwrap().to_owned();

    let response = exchange_refresh_token(app.clone(), &client_id, &refresh, Some("kb:tech")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let narrowed = json_body(response).await;
    assert_eq!(narrowed["scope"], "kb:tech");
    let private_fetch = app
        .oneshot(mcp_request(
            None,
            narrowed["access_token"].as_str(),
            "90_private/secret.md",
        ))
        .await
        .unwrap();
    assert_eq!(private_fetch.status(), StatusCode::OK);
    assert_eq!(json_body(private_fetch).await["result"]["isError"], true);
}

#[tokio::test]
async fn expired_refresh_token_is_rejected_as_invalid_grant() {
    let (_root, app) = app_with_ttls(60, 0);
    let client_id = register_public_client(app.clone()).await;
    let code = authorize(app.clone(), &client_id, "kb:tech").await;
    let initial =
        json_body(exchange_code(app.clone(), &client_id, &code, PKCE_VERIFIER).await).await;
    let refresh = initial["refresh_token"].as_str().unwrap().to_owned();

    let response = exchange_refresh_token(app, &client_id, &refresh, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "invalid_grant");
}

#[tokio::test]
async fn signed_access_tokens_and_refresh_rotation_survive_router_restart() {
    let root = TempDir::new().unwrap();
    prepare_kb(&root);
    let config = test_config(&root, 60, 60);
    let first_router = http::router(&config).unwrap();
    let client_id = register_public_client(first_router.clone()).await;
    let code = authorize(first_router.clone(), &client_id, "kb:tech").await;
    let initial =
        json_body(exchange_code(first_router, &client_id, &code, PKCE_VERIFIER).await).await;
    let access_token = initial["access_token"].as_str().unwrap().to_owned();
    let refresh_token = initial["refresh_token"].as_str().unwrap().to_owned();

    let persisted = std::fs::read_to_string(
        config
            .oauth
            .refresh_state_dir
            .join("refresh-token-families-v1.json"),
    )
    .unwrap();
    assert!(!persisted.contains(&access_token));
    assert!(!persisted.contains(&refresh_token));

    let restarted_router = http::router(&config).unwrap();
    let access_response = restarted_router
        .clone()
        .oneshot(mcp_request(
            None,
            Some(&access_token),
            "10_tech/rust/needle.md",
        ))
        .await
        .unwrap();
    assert_eq!(access_response.status(), StatusCode::OK);

    let refreshed =
        exchange_refresh_token(restarted_router, &client_id, &refresh_token, None).await;
    assert_eq!(refreshed.status(), StatusCode::OK);
}
