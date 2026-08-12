use std::{sync::Arc, time::Duration};

use crate::auth::AccessScope;

/// Request metadata safe to expose to internal audit logging and tool handlers.
/// It deliberately excludes the API key and query text.
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub request_id: u64,
    pub credential_fingerprint: Arc<str>,
    pub scope: AccessScope,
}

impl AuditContext {
    fn scope_label(&self) -> &'static str {
        match self.scope {
            AccessScope::Tech => "tech",
            AccessScope::Private => "private",
        }
    }
}

pub fn rejected(
    request_id: u64,
    method: &str,
    path: &str,
    status: u16,
    outcome: &'static str,
    duration: Duration,
) {
    tracing::warn!(
        event = "mcp_request_rejected",
        request_id,
        method,
        path,
        status,
        outcome,
        duration_ms = duration.as_millis() as u64,
        "rejected MCP request"
    );
}

pub fn completed(
    context: &AuditContext,
    method: &str,
    path: &str,
    status: u16,
    bytes: u64,
    duration: Duration,
) {
    tracing::info!(
        event = "mcp_request",
        request_id = context.request_id,
        credential_fingerprint = context.credential_fingerprint.as_ref(),
        scope = context.scope_label(),
        client_type = "api_key",
        operation = "http",
        method,
        path,
        status,
        bytes,
        duration_ms = duration.as_millis() as u64,
        "completed MCP request"
    );
}

pub fn tool(
    context: &AuditContext,
    operation: &'static str,
    outcome: &'static str,
    document_id: Option<&str>,
) {
    tracing::info!(
        event = "mcp_tool",
        request_id = context.request_id,
        credential_fingerprint = context.credential_fingerprint.as_ref(),
        scope = context.scope_label(),
        client_type = "api_key",
        operation,
        outcome,
        document_id = document_id.unwrap_or(""),
        "completed MCP tool request"
    );
}

/// The read tools' record plus the byte count, for the one tool that changes
/// the knowledge base. `document_id` is the generated note path on success and
/// empty on refusal; `bytes` is what was written, or what was attempted when
/// the write was refused. The note's title and body are never recorded, for the
/// same reason `search` never records its query.
pub fn tool_write(
    context: &AuditContext,
    operation: &'static str,
    outcome: &'static str,
    document_id: Option<&str>,
    bytes: u64,
) {
    tracing::info!(
        event = "mcp_tool",
        request_id = context.request_id,
        credential_fingerprint = context.credential_fingerprint.as_ref(),
        scope = context.scope_label(),
        client_type = "api_key",
        operation,
        outcome,
        document_id = document_id.unwrap_or(""),
        bytes,
        "completed MCP tool request"
    );
}
