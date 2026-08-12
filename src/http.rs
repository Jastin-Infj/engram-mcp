use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use axum::{
    Json, Router,
    extract::{Form, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post, post_service},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
};
use thiserror::Error;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    audit::{self, AuditContext},
    auth::{Authenticator, RateLimiter},
    config::Config,
    document::{DocumentStore, StoreError},
    oauth::{
        ApprovalForm, AuthorizationQuery, AuthorizationRedirect, OAuthError, OAuthService,
        RegistrationRequest, SCOPE_PRIVATE, SCOPE_TECH, TokenRequest,
    },
    server::KnowledgeBaseServer,
};

const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024;
const MAX_CONCURRENT_REQUESTS: usize = 16;

#[derive(Clone)]
struct AppState {
    authenticator: Authenticator,
    rate_limiter: RateLimiter,
    request_counter: Arc<AtomicU64>,
    oauth: OAuthService,
}

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("knowledge-base initialization failed")]
    Store(#[from] StoreError),
    #[error("OAuth initialization failed")]
    OAuth(#[from] OAuthError),
}

pub fn router(config: &Config) -> Result<Router, RouterError> {
    let store = DocumentStore::new(
        &config.kb_root,
        config.max_read_bytes,
        config.max_search_file_bytes,
        config.scope_directories.clone(),
    )?;
    let server = KnowledgeBaseServer::new(store, config.max_search_response_bytes);
    let transport_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(config.allowed_hosts.iter().cloned())
        .with_allowed_origins(config.allowed_origins.iter().cloned())
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(MAX_REQUEST_BODY_BYTES)
        // Pre-2026-07-28 clients (Claude.ai negotiates 2025-11-25) do not send
        // the per-POST Mcp-* metadata headers, so they must not be required.
        .with_stateless_protocol_metadata_required(false);
    let mcp_service = StreamableHttpService::new(
        move || Ok(server.clone()),
        NeverSessionManager::default().into(),
        transport_config,
    );
    let oauth = OAuthService::new(&config.oauth)?;
    let state = AppState {
        authenticator: Authenticator::with_oauth(
            &config.key_a,
            &config.key_b,
            oauth.bearer_authenticator(),
        ),
        rate_limiter: RateLimiter::new(config.rate_limit_per_minute, config.rate_limit_burst),
        request_counter: Arc::new(AtomicU64::new(0)),
        oauth,
    };

    let protected = Router::new()
        .route_service("/mcp", post_service(mcp_service))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authenticate_mcp_request,
        ));

    let oauth_routes = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/oauth/authorize",
            get(begin_authorization).post(complete_authorization),
        )
        .route("/oauth/token", post(exchange_token))
        .route("/oauth/register", post(register_client))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .with_state(state);

    Ok(oauth_routes
        .route("/healthz", get(healthz))
        .merge(protected)
        .fallback(not_found))
}

async fn healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

async fn protected_resource_metadata(State(state): State<AppState>) -> Response {
    oauth_response(StatusCode::OK, state.oauth.protected_resource_metadata())
}

async fn authorization_server_metadata(State(state): State<AppState>) -> Response {
    oauth_response(StatusCode::OK, state.oauth.authorization_server_metadata())
}

async fn begin_authorization(
    State(state): State<AppState>,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    match state.oauth.begin_authorization(query) {
        Ok(page) => secured(Html(page).into_response()),
        Err(error) => oauth_error_response(error),
    }
}

async fn complete_authorization(
    State(state): State<AppState>,
    Form(form): Form<ApprovalForm>,
) -> Response {
    match state.oauth.complete_authorization(form) {
        Ok(AuthorizationRedirect::Approved(location))
        | Ok(AuthorizationRedirect::Denied(location)) => {
            let mut response = StatusCode::SEE_OTHER.into_response();
            let location = match HeaderValue::from_str(&location) {
                Ok(value) => value,
                Err(_) => return oauth_error_response(OAuthError::InvalidAuthorizationRequest),
            };
            response.headers_mut().insert(header::LOCATION, location);
            secured(response)
        }
        Err(error) => oauth_error_response(error),
    }
}

async fn exchange_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Response {
    match state.oauth.exchange_token(
        request,
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
    ) {
        Ok(token) => oauth_response(StatusCode::OK, token),
        Err(error) => oauth_error_response(error),
    }
}

async fn register_client(
    State(state): State<AppState>,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    match state.oauth.register_client(request) {
        Ok(client) => oauth_response(StatusCode::CREATED, client),
        Err(error) => oauth_error_response(error),
    }
}

fn oauth_response<T: serde::Serialize>(status: StatusCode, body: T) -> Response {
    secured((status, Json(body)).into_response())
}

fn oauth_error_response(error: OAuthError) -> Response {
    let status = match error {
        OAuthError::InvalidClient => StatusCode::UNAUTHORIZED,
        OAuthError::InvalidConfiguration | OAuthError::Entropy | OAuthError::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::BAD_REQUEST,
    };
    oauth_response(status, serde_json::json!({"error": error.error_code()}))
}

async fn authenticate_mcp_request(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let started = Instant::now();
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let request_id = state.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
    let subject = match state.authenticator.authenticate_headers(request.headers()) {
        Ok(subject) => subject,
        Err(_) => {
            audit::rejected(
                request_id,
                &method,
                &path,
                StatusCode::UNAUTHORIZED.as_u16(),
                "unauthorized",
                started.elapsed(),
            );
            return unauthorized_mcp_response(&state);
        }
    };
    let context = AuditContext {
        request_id,
        credential_fingerprint: state.authenticator.fingerprint(subject.credential_id),
        scope: subject.scope,
    };
    if state.rate_limiter.check(subject).is_err() {
        audit::rejected(
            request_id,
            &method,
            &path,
            StatusCode::TOO_MANY_REQUESTS.as_u16(),
            "rate_limited",
            started.elapsed(),
        );
        return secured(StatusCode::TOO_MANY_REQUESTS.into_response());
    }
    request.extensions_mut().insert(subject.scope);
    request.extensions_mut().insert(context.clone());
    let response = secured(next.run(request).await);
    let bytes = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    audit::completed(
        &context,
        &method,
        &path,
        response.status().as_u16(),
        bytes,
        started.elapsed(),
    );
    response
}

fn unauthorized_mcp_response(state: &AppState) -> Response {
    let mut response = secured(StatusCode::UNAUTHORIZED.into_response());
    let challenge = format!(
        "Bearer resource_metadata=\"{}\", scope=\"{SCOPE_TECH} {SCOPE_PRIVATE}\"",
        state.oauth.protected_resource_metadata_url()
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn secured(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
