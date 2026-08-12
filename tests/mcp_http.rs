use std::{collections::BTreeSet, net::SocketAddr};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use engram_mcp::{
    config::{Config, OAuthConfig, ScopeDirectories},
    http,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

fn app(rate_limit_burst: u32) -> (TempDir, Router) {
    let root = TempDir::new().unwrap();
    std::fs::create_dir_all(root.path().join("10_tech/rust")).unwrap();
    std::fs::create_dir_all(root.path().join("90_private")).unwrap();
    std::fs::write(root.path().join("INDEX.md"), "# Engram\n").unwrap();
    std::fs::write(
        root.path().join("10_tech/rust/needle.md"),
        "---\ntitle: Public needle\ndescription: Public search result\n---\nneedle body\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("90_private/secret.md"),
        "---\ntitle: Private note\n---\nprivate-only-term\n",
    )
    .unwrap();

    let config = Config {
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
        rate_limit_burst,
        oauth: OAuthConfig {
            issuer: "https://engram.test".into(),
            resource: "https://engram.test/mcp".into(),
            owner_secret: "owner-secret-for-mcp-http-test".into(),
            signing_key: "signing-key-for-mcp-http-test-with-sufficient-length".into(),
            access_token_ttl_seconds: 60,
            authorization_code_ttl_seconds: 60,
            refresh_state_dir: root.path().join("oauth-state"),
            refresh_token_ttl_seconds: 60,
        },
    };
    (root, http::router(&config).unwrap())
}

fn request(method: &str, params: Value, api_key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "engram.test")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", method);
    if method == "tools/call" {
        let name = params["name"].as_str().unwrap();
        builder = builder.header("Mcp-Name", name);
    }
    if let Some(api_key) = api_key {
        builder = builder.header("x-api-key", api_key);
    }
    builder
        .body(Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            })
            .to_string(),
        ))
        .unwrap()
}

fn request_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn health_is_private_and_missing_key_is_unauthorized() {
    let (_root, app) = app(10);
    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::NO_CONTENT);

    let response = app
        .oneshot(request(
            "tools/list",
            json!({"_meta": request_meta()}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn lists_only_search_then_fetch_with_read_only_annotations() {
    let (_root, app) = app(10);
    let response = app
        .oneshot(request(
            "tools/list",
            json!({"_meta": request_meta()}),
            Some("tech-secret"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let tools = body["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "search");
    assert_eq!(tools[1]["name"], "fetch");
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
        assert_eq!(tool["annotations"]["destructiveHint"], false);
        assert_eq!(tool["annotations"]["openWorldHint"], false);
    }
}

#[tokio::test]
async fn search_and_fetch_enforce_scope_without_private_leakage() {
    let (_root, app) = app(20);
    let public_search = app
        .clone()
        .oneshot(request(
            "tools/call",
            json!({
                "name": "search",
                "arguments": {"query": "needle"},
                "_meta": request_meta(),
            }),
            Some("tech-secret"),
        ))
        .await
        .unwrap();
    let public_search = json_body(public_search).await;
    assert_eq!(
        public_search["result"]["structuredContent"]["results"][0]["id"],
        "10_tech/rust/needle.md"
    );

    let hidden_search = app
        .clone()
        .oneshot(request(
            "tools/call",
            json!({
                "name": "search",
                "arguments": {"query": "private-only-term"},
                "_meta": request_meta(),
            }),
            Some("tech-secret"),
        ))
        .await
        .unwrap();
    let hidden_search = json_body(hidden_search).await;
    assert!(
        hidden_search["result"]["structuredContent"]["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let hidden_fetch = app
        .clone()
        .oneshot(request(
            "tools/call",
            json!({
                "name": "fetch",
                "arguments": {"id": "90_private/secret.md"},
                "_meta": request_meta(),
            }),
            Some("tech-secret"),
        ))
        .await
        .unwrap();
    let hidden_fetch = json_body(hidden_fetch).await;
    assert_eq!(hidden_fetch["result"]["isError"], true);
    assert_eq!(
        hidden_fetch["result"]["structuredContent"]["error"],
        "not_found"
    );

    let private_fetch = app
        .oneshot(request(
            "tools/call",
            json!({
                "name": "fetch",
                "arguments": {"id": "90_private/secret.md"},
                "_meta": request_meta(),
            }),
            Some("private-secret"),
        ))
        .await
        .unwrap();
    let private_fetch = json_body(private_fetch).await;
    assert_eq!(
        private_fetch["result"]["structuredContent"]["title"],
        "Private note"
    );
}

#[tokio::test]
async fn blocks_invalid_origin_and_path_traversal() {
    let (_root, app) = app(10);
    let mut origin_request = request(
        "tools/list",
        json!({"_meta": request_meta()}),
        Some("tech-secret"),
    );
    origin_request
        .headers_mut()
        .insert(header::ORIGIN, "https://evil.test".parse().unwrap());
    let origin_response = app.clone().oneshot(origin_request).await.unwrap();
    assert_eq!(origin_response.status(), StatusCode::FORBIDDEN);

    let traversal_response = app
        .oneshot(request(
            "tools/call",
            json!({
                "name": "fetch",
                "arguments": {"id": "../../etc/passwd"},
                "_meta": request_meta(),
            }),
            Some("tech-secret"),
        ))
        .await
        .unwrap();
    let traversal = json_body(traversal_response).await;
    assert_eq!(traversal["error"]["code"], -32602);
    assert_eq!(traversal["error"]["message"], "invalid document id");
}

#[tokio::test]
async fn rate_limit_is_per_credential() {
    let (_root, app) = app(1);
    let first = app
        .clone()
        .oneshot(request(
            "tools/list",
            json!({"_meta": request_meta()}),
            Some("tech-secret"),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = app
        .oneshot(request(
            "tools/list",
            json!({"_meta": request_meta()}),
            Some("tech-secret"),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}
