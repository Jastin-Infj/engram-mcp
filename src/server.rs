use std::{borrow::Cow, time::SystemTime};

use axum::http::request::Parts;
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{tool::ToolCallContext, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ResultType,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    audit::{self, AuditContext},
    auth::{AccessScope, WriteRateLimiter},
    document::{DocumentId, DocumentStore, FetchedDocument, StoreError},
    inbox::{CreatedNote, InboxError, InboxStore},
};

const SEARCH_RESPONSE_WRAPPER_BYTES: usize = 1_024;
const APPEND_NOTE: &str = "append_note";

#[derive(Clone, Debug)]
pub struct KnowledgeBaseServer {
    store: DocumentStore,
    max_search_response_bytes: usize,
    /// `None` when no inbox is configured or the configured one is not usable.
    /// The read tools do not consult this, so losing the write surface never
    /// costs the server its ability to serve documents.
    inbox: Option<InboxSupport>,
}

#[derive(Clone, Debug)]
struct InboxSupport {
    store: InboxStore,
    limiter: WriteRateLimiter,
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

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AppendNoteArguments {
    /// A short subject line for the note (1 to 200 characters, no line breaks).
    title: String,
    /// The note itself, stored verbatim as Markdown.
    body: String,
    /// The date (YYYY-MM-DD) the conversation or event described by the note
    /// happened. Always provide it: the server records only the filing time,
    /// so without this an old topic looks current when the note is sorted.
    occurred: Option<String>,
}

impl KnowledgeBaseServer {
    pub fn new(
        store: DocumentStore,
        max_search_response_bytes: usize,
        inbox: Option<(InboxStore, WriteRateLimiter)>,
    ) -> Self {
        Self {
            store,
            max_search_response_bytes,
            inbox: inbox.map(|(store, limiter)| InboxSupport { store, limiter }),
        }
    }

    /// `append_note` exists only for callers that hold the private scope and
    /// only when there is somewhere to write. Everyone else is served a server
    /// that has never heard of it — the same treatment `90_private` documents
    /// get from the tech scope.
    fn append_note_is_visible(&self, scope: Option<AccessScope>) -> bool {
        self.inbox.is_some() && scope.is_some_and(AccessScope::allows_private)
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

    #[tool(
        name = "append_note",
        description = "File a new note in the knowledge base inbox for the owner to sort later. Always set occurred to the date (YYYY-MM-DD) the conversation or event happened, and mention it in the body too — the server only records the filing time, so an undated note about an old topic would be mistaken for current information. The server assigns the file name and adds the front matter; the note cannot be edited, replaced, or read back through search or fetch, and no existing document can be changed.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn append_note(
        &self,
        Parameters(arguments): Parameters<AppendNoteArguments>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let (scope, audit_context) = request_context(&context)?;
        // `call_tool` already refused callers that must not see this tool; the
        // check is repeated here so the guarantee does not depend on one caller.
        let Some(inbox) = self.inbox.as_ref().filter(|_| scope.allows_private()) else {
            return Err(tool_not_found());
        };
        let attempted = arguments.body.len() as u64;

        if inbox.limiter.check().is_err() {
            audit::tool_write(&audit_context, APPEND_NOTE, "rate_limited", None, attempted);
            return Ok(CallToolResult::structured_error(
                json!({ "error": "rate_limited" }),
            ));
        }

        let error = match inbox.store.create_note(
            &arguments.title,
            &arguments.body,
            arguments.occurred.as_deref(),
            audit_context.credential_fingerprint.as_ref(),
            SystemTime::now(),
        ) {
            Ok(note) => {
                audit::tool_write(
                    &audit_context,
                    APPEND_NOTE,
                    "ok",
                    Some(&note.id),
                    note.bytes,
                );
                return structured(append_note_response(note));
            }
            Err(error) => error,
        };

        // A refusal names the reason and nothing else: no path, no usage figure,
        // no remaining budget. Storage failures in particular must not let a
        // caller map the mount by reading the error text.
        let (outcome, response) = match error {
            InboxError::InvalidTitle => (
                "invalid_title",
                Err(ErrorData::invalid_params("invalid note title", None)),
            ),
            InboxError::InvalidBody => (
                "invalid_body",
                Err(ErrorData::invalid_params("invalid note body", None)),
            ),
            InboxError::InvalidOccurred => (
                "invalid_occurred",
                Err(ErrorData::invalid_params(
                    "invalid occurred date; use YYYY-MM-DD",
                    None,
                )),
            ),
            InboxError::NoteTooLarge => (
                "note_too_large",
                Ok(CallToolResult::structured_error(json!({
                    "error": "note_too_large",
                    "max_bytes": inbox.store.max_note_bytes(),
                }))),
            ),
            InboxError::QuotaExceeded => (
                "quota_exceeded",
                Ok(CallToolResult::structured_error(
                    json!({ "error": "quota_exceeded" }),
                )),
            ),
            _ => ("internal_error", Ok(internal_error(audit_context.clone()))),
        };
        audit::tool_write(&audit_context, APPEND_NOTE, outcome, None, attempted);
        response
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct AppendNoteResponse {
    /// Knowledge-base-relative path of the stored note. It is deliberately not
    /// a valid `fetch` id.
    id: String,
    created: String,
    bytes: u64,
}

fn append_note_response(note: CreatedNote) -> AppendNoteResponse {
    AppendNoteResponse {
        id: note.id,
        created: note.created,
        bytes: note.bytes,
    }
}

/// Byte-for-byte what `rmcp`'s tool router returns for a name it does not have,
/// so a caller cannot tell "you may not" from "there is no such tool".
fn tool_not_found() -> ErrorData {
    ErrorData::invalid_params("tool not found", None)
}

// The instructions are the same for every caller, so they describe append_note
// conditionally: a tech-scope client is never shown the tool and must not be
// told it exists.
#[tool_handler(
    name = "engram-mcp",
    instructions = "Use search first, then pass a returned id to fetch. Documents outside your access scope behave as not found. Existing documents can never be changed through this server. If append_note is listed, it files one new note in the owner's inbox for later sorting; the note cannot be read back with search or fetch."
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
        let mut names = vec!["search", "fetch"];
        if self.append_note_is_visible(request_scope(&context)) {
            names.push(APPEND_NOTE);
        }
        let tools = names
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

    /// Replaces the dispatcher `#[tool_handler]` would generate, so the scope
    /// check runs *before* the arguments are parsed. Otherwise a caller without
    /// the private scope could tell the tool exists by sending bad arguments and
    /// reading the validation error instead of "tool not found".
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name == APPEND_NOTE && !self.append_note_is_visible(request_scope(&context)) {
            return Err(tool_not_found());
        }
        Self::tool_router()
            .call(ToolCallContext::new(self, request, context))
            .await
    }
}

/// The scope the HTTP middleware authenticated, or `None` when the request did
/// not arrive through it. Absence is treated as "no private access".
fn request_scope(context: &RequestContext<RoleServer>) -> Option<AccessScope> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<AccessScope>())
        .copied()
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
    fn registers_two_read_only_tools_and_one_append_only_tool() {
        let router = KnowledgeBaseServer::tool_router();
        let search = router.get("search").unwrap();
        let fetch = router.get("fetch").unwrap();
        let append = router.get(APPEND_NOTE).unwrap();
        assert_eq!(router.list_all().len(), 3);
        assert_eq!(
            search.annotations.as_ref().unwrap().read_only_hint,
            Some(true)
        );
        assert_eq!(
            fetch.annotations.as_ref().unwrap().destructive_hint,
            Some(false)
        );
        let annotations = append.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only_hint, Some(false));
        // Appending never replaces or removes anything, so the tool is not
        // destructive even though it is not read-only.
        assert_eq!(annotations.destructive_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(false));
        assert_eq!(annotations.open_world_hint, Some(false));
        assert!(router.get("read").is_none());
        assert!(router.get("delete_note").is_none());
    }

    #[test]
    fn append_note_needs_both_a_private_scope_and_an_inbox() {
        let root = tempfile::TempDir::new().unwrap();
        let inbox = root.path().join(crate::inbox::INBOX_ID_PREFIX);
        std::fs::create_dir_all(&inbox).unwrap();
        let store = DocumentStore::new(
            root.path(),
            1_024,
            1_024,
            crate::config::ScopeDirectories::default(),
        )
        .unwrap();

        let without_inbox = KnowledgeBaseServer::new(store.clone(), 24_576, None);
        assert!(!without_inbox.append_note_is_visible(Some(AccessScope::Private)));

        let with_inbox = KnowledgeBaseServer::new(
            store,
            24_576,
            Some((
                crate::inbox::InboxStore::open(&inbox, root.path(), 32_768, 1_048_576).unwrap(),
                crate::auth::WriteRateLimiter::new(10),
            )),
        );
        assert!(with_inbox.append_note_is_visible(Some(AccessScope::Private)));
        assert!(!with_inbox.append_note_is_visible(Some(AccessScope::Tech)));
        assert!(!with_inbox.append_note_is_visible(None));
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
