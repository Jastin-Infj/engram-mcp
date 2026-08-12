use std::borrow::Cow;

use axum::http::request::Parts;
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, ContentBlock, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ResultType,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    audit::{self, AuditContext},
    auth::AccessScope,
    document::{DocumentId, DocumentStore, FetchedDocument, StoreError},
};

const SEARCH_RESPONSE_WRAPPER_BYTES: usize = 1_024;

#[derive(Clone, Debug)]
pub struct KnowledgeBaseServer {
    store: DocumentStore,
    max_search_response_bytes: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SearchArguments {
    /// Literal, case-insensitive search terms (1 to 256 non-whitespace characters).
    query: String,
    /// Maximum results to return (1 to 20; default 10).
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FetchArguments {
    /// A relative Markdown path returned by search.
    id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct FetchResponse {
    id: DocumentId,
    title: String,
    text: String,
    metadata: FetchMetadata,
    truncated: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
struct FetchMetadata {
    path: String,
    description: String,
    updated: Option<String>,
}

impl KnowledgeBaseServer {
    pub fn new(store: DocumentStore, max_search_response_bytes: usize) -> Self {
        Self {
            store,
            max_search_response_bytes,
        }
    }
}

#[tool_router]
impl KnowledgeBaseServer {
    #[tool(
        name = "search",
        description = "Search readable Markdown documents. Use a returned id with fetch to read the full document.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn search(
        &self,
        Parameters(arguments): Parameters<SearchArguments>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let (scope, audit_context) = request_context(&context)?;
        match self.store.search(
            scope,
            &arguments.query,
            arguments.limit,
            self.max_search_response_bytes
                .saturating_sub(SEARCH_RESPONSE_WRAPPER_BYTES),
        ) {
            Ok(response) => {
                audit::tool(&audit_context, "search", "ok", None);
                structured(response)
            }
            Err(StoreError::InvalidQuery) => {
                audit::tool(&audit_context, "search", "invalid_query", None);
                Err(ErrorData::invalid_params("invalid search query", None))
            }
            Err(_) => {
                audit::tool(&audit_context, "search", "internal_error", None);
                Ok(internal_error(audit_context))
            }
        }
    }

    #[tool(
        name = "fetch",
        description = "Fetch one readable Markdown document by an id returned from search.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn fetch(
        &self,
        Parameters(arguments): Parameters<FetchArguments>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let (scope, audit_context) = request_context(&context)?;
        let id = DocumentId::parse(&arguments.id)
            .map_err(|_| ErrorData::invalid_params("invalid document id", None))?;

        match self.store.read(scope, &id) {
            Ok(document) => {
                audit::tool(&audit_context, "fetch", "ok", Some(id.as_str()));
                structured(fetch_response(document))
            }
            Err(StoreError::NotFound) => {
                audit::tool(&audit_context, "fetch", "not_found", Some(id.as_str()));
                Ok(CallToolResult::structured_error(
                    json!({ "error": "not_found" }),
                ))
            }
            Err(_) => {
                audit::tool(&audit_context, "fetch", "internal_error", Some(id.as_str()));
                Ok(internal_error(audit_context))
            }
        }
    }
}

#[tool_handler(
    name = "engram-mcp",
    instructions = "Use search first, then pass a returned id to fetch. Documents outside your access scope behave as not found. This server is read-only."
)]
impl ServerHandler for KnowledgeBaseServer {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        // Claude.ai negotiates 2025-11-25 and ChatGPT may negotiate older
        // versions; the tool contract is identical across all of them.
        Cow::Owned(vec![
            ProtocolVersion::V_2026_07_28,
            ProtocolVersion::V_2025_11_25,
            ProtocolVersion::V_2025_06_18,
            ProtocolVersion::V_2025_03_26,
        ])
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let router = Self::tool_router();
        let tools = ["search", "fetch"]
            .into_iter()
            .filter_map(|name| router.get(name).cloned())
            .collect();
        let supports_cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28);

        Ok(ListToolsResult {
            result_type: Some(ResultType::COMPLETE),
            tools,
            meta: None,
            next_cursor: None,
            ttl_ms: supports_cache_hints.then_some(0),
            cache_scope: supports_cache_hints.then_some(rmcp::model::CacheScope::Public),
        })
    }
}

fn request_context(
    context: &RequestContext<RoleServer>,
) -> Result<(AccessScope, AuditContext), ErrorData> {
    let parts = context
        .extensions
        .get::<Parts>()
        .ok_or_else(|| ErrorData::internal_error("request context unavailable", None))?;
    let scope = *parts
        .extensions
        .get::<AccessScope>()
        .ok_or_else(|| ErrorData::internal_error("authorization context unavailable", None))?;
    let audit_context = parts
        .extensions
        .get::<AuditContext>()
        .cloned()
        .ok_or_else(|| ErrorData::internal_error("audit context unavailable", None))?;
    Ok((scope, audit_context))
}

fn fetch_response(document: FetchedDocument) -> FetchResponse {
    FetchResponse {
        id: document.id.clone(),
        title: document.metadata.title,
        text: document.text,
        metadata: FetchMetadata {
            path: document.id.to_string(),
            description: document.metadata.description,
            updated: document.metadata.updated,
        },
        truncated: document.truncated,
    }
}

fn structured<T: Serialize>(value: T) -> Result<CallToolResult, ErrorData> {
    let value = serde_json::to_value(value)
        .map_err(|_| ErrorData::internal_error("failed to serialize tool result", None))?;
    // Chat clients (claude.ai, ChatGPT) surface only the text content blocks
    // to the model; structuredContent alone renders as an opaque placeholder.
    // The serialized JSON therefore goes into both. The duplication roughly
    // doubles the response, which stays within the transport body limits
    // because MAX_READ_BYTES and MAX_SEARCH_RESPONSE_BYTES cap the payload
    // well below them.
    let text = serde_json::to_string(&value)
        .map_err(|_| ErrorData::internal_error("failed to serialize tool result", None))?;
    let mut result = CallToolResult::structured(value);
    result.content = vec![ContentBlock::text(text)];
    Ok(result)
}

fn internal_error(context: AuditContext) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": "internal_error",
        "request_id": context.request_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_exactly_two_read_only_tools() {
        let router = KnowledgeBaseServer::tool_router();
        let search = router.get("search").unwrap();
        let fetch = router.get("fetch").unwrap();
        assert_eq!(router.list_all().len(), 2);
        assert_eq!(
            search.annotations.as_ref().unwrap().read_only_hint,
            Some(true)
        );
        assert_eq!(
            fetch.annotations.as_ref().unwrap().destructive_hint,
            Some(false)
        );
        assert!(router.get("read").is_none());
    }

    #[test]
    fn fetch_response_has_the_public_contract_shape() {
        let id = DocumentId::parse("10_tech/rust/example.md").unwrap();
        let response = fetch_response(FetchedDocument {
            id,
            text: "body".into(),
            metadata: crate::document::DocumentMetadata {
                title: "Example".into(),
                description: "Description".into(),
                updated: Some("2026-08-12".into()),
            },
            truncated: false,
        });
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["title"], "Example");
        assert_eq!(value["metadata"]["path"], "10_tech/rust/example.md");
    }
}
