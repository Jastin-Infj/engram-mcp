use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    auth::AccessScope,
    document::{DocumentId, DocumentStore, StoreError},
};

const MAX_LIMIT: usize = 20;
const DEFAULT_LIMIT: usize = 10;
const MAX_SNIPPET_CHARS: usize = 600;

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SearchResult {
    pub id: DocumentId,
    pub title: String,
    pub snippet: String,
    pub metadata: SearchMetadata,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SearchMetadata {
    pub path: String,
    pub description: String,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone)]
struct ScoredResult {
    score: u32,
    result: SearchResult,
}

impl DocumentStore {
    pub fn search(
        &self,
        scope: AccessScope,
        query: &str,
        limit: Option<usize>,
        max_response_bytes: usize,
    ) -> Result<SearchResponse, StoreError> {
        let terms = parse_terms(query)?;
        let limit = limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(StoreError::InvalidQuery);
        }

        let mut scored = self
            .candidate_ids(scope)?
            .into_iter()
            .filter_map(|id| match self.read_for_search(scope, &id) {
                Ok(document) => score_document(&terms, document),
                Err(StoreError::NotFound) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        scored.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.result.id.cmp(&right.result.id))
        });

        let available = scored.len();
        let mut results = Vec::new();
        let mut truncated = available > limit;
        for scored_result in scored.into_iter().take(limit) {
            results.push(scored_result.result);
            let candidate = SearchResponse {
                results: results.clone(),
                truncated,
            };
            if serde_json::to_vec(&candidate)
                .map_err(|_| StoreError::InvalidQuery)?
                .len()
                > max_response_bytes
            {
                results.pop();
                truncated = true;
                break;
            }
        }

        Ok(SearchResponse { results, truncated })
    }
}

fn parse_terms(query: &str) -> Result<Vec<String>, StoreError> {
    if query.len() > 256 {
        return Err(StoreError::InvalidQuery);
    }
    let terms = query
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return Err(StoreError::InvalidQuery);
    }
    Ok(terms)
}

fn score_document(
    terms: &[String],
    document: crate::document::FetchedDocument,
) -> Option<Result<ScoredResult, StoreError>> {
    let path = document.id.as_str().to_lowercase();
    let title = document.metadata.title.to_lowercase();
    let description = document.metadata.description.to_lowercase();
    let text = document.text.to_lowercase();
    if !terms.iter().all(|term| {
        path.contains(term)
            || title.contains(term)
            || description.contains(term)
            || text.contains(term)
    }) {
        return None;
    }

    let score = terms.iter().fold(0, |score, term| {
        score
            + u32::from(path.contains(term)) * 100
            + u32::from(title.contains(term)) * 80
            + u32::from(description.contains(term)) * 50
            + u32::from(text.contains(term)) * 10
    });
    let (snippet, line_start, line_end) = snippet(&document.text, &terms[0]);
    Some(Ok(ScoredResult {
        score,
        result: SearchResult {
            id: document.id.clone(),
            title: document.metadata.title,
            snippet,
            metadata: SearchMetadata {
                path: document.id.to_string(),
                description: document.metadata.description,
                line_start,
                line_end,
            },
        },
    }))
}

fn snippet(text: &str, first_term: &str) -> (String, usize, usize) {
    let lines = text.lines().collect::<Vec<_>>();
    let match_index = lines
        .iter()
        .position(|line| line.to_lowercase().contains(first_term))
        .unwrap_or(0);
    let start = match_index.saturating_sub(2);
    let end = (match_index + 3).min(lines.len());
    let mut snippet = lines[start..end].join("\n");
    if snippet.chars().count() > MAX_SNIPPET_CHARS {
        snippet = snippet.chars().take(MAX_SNIPPET_CHARS).collect::<String>();
        snippet.push('…');
    }
    (snippet, start + 1, end)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use crate::{auth::AccessScope, config::ScopeDirectories, document::DocumentStore};

    #[test]
    fn search_is_scoped_and_sorted() {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("10_tech/rust")).unwrap();
        fs::create_dir_all(root.path().join("20_projects/demo")).unwrap();
        fs::create_dir_all(root.path().join("90_private")).unwrap();
        fs::write(
            root.path().join("10_tech/rust/ownership.md"),
            "# Ownership\nRust ownership rules\n",
        )
        .unwrap();
        fs::write(
            root.path().join("20_projects/demo/notes.md"),
            "# Demo\nOwnership in a project note\n",
        )
        .unwrap();
        fs::write(
            root.path().join("90_private/secret.md"),
            "ownership secret\n",
        )
        .unwrap();
        let store =
            DocumentStore::new(root.path(), 65_536, 1_024, ScopeDirectories::default()).unwrap();

        let response = store
            .search(AccessScope::Tech, "ownership", None, 24_576)
            .unwrap();
        let ids = response
            .results
            .iter()
            .map(|result| result.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec!["10_tech/rust/ownership.md", "20_projects/demo/notes.md"]
        );
    }

    #[test]
    fn search_never_exposes_private_matches_to_tech_scope() {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("90_private")).unwrap();
        fs::write(
            root.path().join("90_private/secret.md"),
            "sensitive-only-term\n",
        )
        .unwrap();
        let store =
            DocumentStore::new(root.path(), 65_536, 1_024, ScopeDirectories::default()).unwrap();

        let response = store
            .search(AccessScope::Tech, "sensitive-only-term", None, 24_576)
            .unwrap();
        assert!(response.results.is_empty());
    }

    #[test]
    fn rejects_empty_and_oversized_queries() {
        let root = TempDir::new().unwrap();
        let store =
            DocumentStore::new(root.path(), 65_536, 1_024, ScopeDirectories::default()).unwrap();
        assert!(store.search(AccessScope::Tech, "  ", None, 24_576).is_err());
        assert!(
            store
                .search(AccessScope::Tech, &"a".repeat(257), None, 24_576)
                .is_err()
        );
    }

    #[test]
    fn honors_response_size_cap() {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("10_tech")).unwrap();
        fs::write(
            root.path().join("10_tech/long.md"),
            format!("needle {}\n", "x".repeat(300)).repeat(3),
        )
        .unwrap();
        let store =
            DocumentStore::new(root.path(), 65_536, 65_536, ScopeDirectories::default()).unwrap();
        let response = store
            .search(AccessScope::Tech, "needle", None, 200)
            .unwrap();
        assert!(response.truncated);
        assert!(response.results.is_empty());
    }
}
