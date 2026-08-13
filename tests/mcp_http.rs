use std::{collections::BTreeSet, net::SocketAddr, path::Path};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use engram_mcp::{
    config::{Config, InboxConfig, OAuthConfig, ScopeDirectories},
    http,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const INBOX: &str = "99_inbox";

fn config(root: &TempDir, rate_limit_burst: u32) -> Config {
    std::fs::create_dir_all(root.path().join("10_tech/rust")).unwrap();
    std::fs::create_dir_all(root.path().join("90_private")).unwrap();
    std::fs::create_dir_all(root.path().join(INBOX)).unwrap();
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
        // The inbox lives inside the knowledge base here exactly as it does in
        // production, so the "written notes stay invisible to search and fetch"
        // tests are meaningful rather than an artifact of the fixture.
        inbox: Some(InboxConfig {
            root: root.path().join(INBOX),
            writes_per_hour: 10,
            max_note_bytes: 32_768,
            max_total_bytes: 8_388_608,
        }),
    }
}

fn app(rate_limit_burst: u32) -> (TempDir, Router) {
    app_with(rate_limit_burst, |_| {})
}

fn app_with(rate_limit_burst: u32, adjust: impl FnOnce(&mut Config)) -> (TempDir, Router) {
    let root = TempDir::new().unwrap();
    let mut config = config(&root, rate_limit_burst);
    adjust(&mut config);
    (root, http::router(&config).unwrap())
}

fn inbox_files(root: &Path) -> Vec<String> {
    let mut names = std::fs::read_dir(root.join(INBOX))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn append(title: &str, body: &str, api_key: &str) -> Request<Body> {
    request(
        "tools/call",
        json!({
            "name": "append_note",
            "arguments": {"title": title, "body": body},
            "_meta": request_meta(),
        }),
        Some(api_key),
    )
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
async fn tech_scope_lists_only_search_then_fetch_with_read_only_annotations() {
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
async fn only_the_private_scope_is_offered_append_note() {
    let (_root, app) = app(10);
    let private = json_body(
        app.oneshot(request(
            "tools/list",
            json!({"_meta": request_meta()}),
            Some("private-secret"),
        ))
        .await
        .unwrap(),
    )
    .await;
    let tools = private["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 3);
    assert_eq!(tools[2]["name"], "append_note");
    assert_eq!(tools[2]["annotations"]["readOnlyHint"], false);
    assert_eq!(tools[2]["annotations"]["destructiveHint"], false);
    assert_eq!(tools[2]["annotations"]["idempotentHint"], false);
    assert_eq!(tools[2]["annotations"]["openWorldHint"], false);
    // The client supplies content, never a location.
    let properties = &tools[2]["inputSchema"]["properties"];
    assert!(properties["title"].is_object());
    assert!(properties["body"].is_object());
    assert!(properties["occurred"].is_object());
    assert_eq!(properties.as_object().unwrap().len(), 3);
}

#[tokio::test]
async fn tech_scope_cannot_call_append_note_or_learn_that_it_exists() {
    let (root, app) = app(10);
    let denied = json_body(
        app.clone()
            .oneshot(append("Tech note", "body", "tech-secret"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(denied["error"]["code"], -32602);
    assert_eq!(denied["error"]["message"], "tool not found");

    // Schema validation must not reveal a hidden tool.
    let malformed = json_body(
        app.clone()
            .oneshot(request(
                "tools/call",
                json!({
                    "name": "append_note",
                    "arguments": {"unexpected": 1},
                    "_meta": request_meta(),
                }),
                Some("tech-secret"),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(malformed["error"]["message"], "tool not found");

    let absent = json_body(
        app.oneshot(request(
            "tools/call",
            json!({"name": "write_file", "arguments": {}, "_meta": request_meta()}),
            Some("tech-secret"),
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(absent["error"], denied["error"]);
    assert!(inbox_files(root.path()).is_empty());
}

#[tokio::test]
async fn append_note_stores_a_server_named_markdown_file() {
    let (root, app) = app(10);
    let body = json_body(
        app.oneshot(append(
            "Rust Ownership Notes",
            "unique-inbox-term in the body",
            "private-secret",
        ))
        .await
        .unwrap(),
    )
    .await;
    let result = &body["result"]["structuredContent"];
    let id = result["id"].as_str().unwrap();
    assert!(id.starts_with("99_inbox/"));
    assert!(id.ends_with("-rust-ownership-notes.md"));

    let names = inbox_files(root.path());
    assert_eq!(names.len(), 1);
    assert_eq!(format!("99_inbox/{}", names[0]), id);

    let stored = std::fs::read_to_string(root.path().join(INBOX).join(&names[0])).unwrap();
    assert!(stored.starts_with("---\ntitle: Rust Ownership Notes\n"));
    assert!(stored.contains("source: mcp:append_note"));
    assert!(stored.contains(&format!("created: {}", result["created"].as_str().unwrap())));
    assert!(stored.ends_with("unique-inbox-term in the body\n"));
    assert_eq!(result["bytes"].as_u64().unwrap(), stored.len() as u64);
}

#[tokio::test]
async fn an_appended_note_stays_out_of_search_and_fetch() {
    let (_root, app) = app(20);
    let created = json_body(
        app.clone()
            .oneshot(append("Hidden Note", "unique-inbox-term", "private-secret"))
            .await
            .unwrap(),
    )
    .await;
    let id = created["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let searched = json_body(
        app.clone()
            .oneshot(request(
                "tools/call",
                json!({
                    "name": "search",
                    "arguments": {"query": "unique-inbox-term"},
                    "_meta": request_meta(),
                }),
                Some("private-secret"),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        searched["result"]["structuredContent"]["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let fetched = json_body(
        app.oneshot(request(
            "tools/call",
            json!({"name": "fetch", "arguments": {"id": id}, "_meta": request_meta()}),
            Some("private-secret"),
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(fetched["result"]["isError"], true);
    assert_eq!(fetched["result"]["structuredContent"]["error"], "not_found");
}

#[tokio::test]
async fn unavailable_inbox_costs_only_the_write_tool() {
    for adjust in [
        |config: &mut Config| config.inbox = None,
        |config: &mut Config| {
            config.inbox.as_mut().unwrap().root = config.kb_root.join("absent-inbox");
        },
    ] {
        let (_root, app) = app_with(20, adjust);
        let listed = json_body(
            app.clone()
                .oneshot(request(
                    "tools/list",
                    json!({"_meta": request_meta()}),
                    Some("private-secret"),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 2);

        let denied = json_body(
            app.clone()
                .oneshot(append("Note", "body", "private-secret"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(denied["error"]["message"], "tool not found");

        let fetched = json_body(
            app.oneshot(request(
                "tools/call",
                json!({
                    "name": "fetch",
                    "arguments": {"id": "10_tech/rust/needle.md"},
                    "_meta": request_meta(),
                }),
                Some("private-secret"),
            ))
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(
            fetched["result"]["structuredContent"]["title"],
            "Public needle"
        );
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
