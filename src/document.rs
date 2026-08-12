use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(target_os = "linux")]
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

use crate::{auth::AccessScope, config::ScopeDirectories};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct DocumentId(String);

impl DocumentId {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, StoreError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > 512 || value.contains('\0') {
            return Err(StoreError::InvalidDocumentId);
        }
        if value.starts_with('/') || value.starts_with('\\') || value.contains('\\') {
            return Err(StoreError::InvalidDocumentId);
        }
        let bytes = value.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(StoreError::InvalidDocumentId);
        }

        let path = Path::new(value);
        if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
            return Err(StoreError::InvalidDocumentId);
        }
        for component in path.components() {
            match component {
                Component::Normal(segment) => {
                    let segment = segment.to_str().ok_or(StoreError::InvalidDocumentId)?;
                    if segment.starts_with('.') {
                        return Err(StoreError::InvalidDocumentId);
                    }
                }
                _ => return Err(StoreError::InvalidDocumentId),
            }
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn path(&self) -> &Path {
        Path::new(&self.0)
    }

    pub fn top_level(&self) -> Option<&str> {
        self.path()
            .components()
            .next()
            .and_then(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
    }
}

impl std::fmt::Display for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
pub struct DocumentMetadata {
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct FetchedDocument {
    pub id: DocumentId,
    pub text: String,
    pub metadata: DocumentMetadata,
    pub truncated: bool,
}

#[derive(Clone)]
pub struct DocumentStore {
    root: Arc<PathBuf>,
    root_fd: Arc<fs::File>,
    scope_directories: Arc<ScopeDirectories>,
    max_read_bytes: usize,
    max_search_file_bytes: usize,
}

impl std::fmt::Debug for DocumentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentStore")
            .field("root", &self.root)
            .field("scope_directories", &self.scope_directories)
            .field("max_read_bytes", &self.max_read_bytes)
            .field("max_search_file_bytes", &self.max_search_file_bytes)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("document was not found")]
    NotFound,
    #[error("document id is invalid")]
    InvalidDocumentId,
    #[error("document is not valid UTF-8")]
    InvalidUtf8,
    #[error("query is invalid")]
    InvalidQuery,
    #[error("safe file access is unavailable on this platform")]
    SafeOpenUnavailable,
    #[error("failed to access knowledge base")]
    Io(#[source] std::io::Error),
}

impl DocumentStore {
    pub fn new(
        root: impl AsRef<Path>,
        max_read_bytes: usize,
        max_search_file_bytes: usize,
        scope_directories: ScopeDirectories,
    ) -> Result<Self, StoreError> {
        let root = root.as_ref();
        let metadata = fs::metadata(root).map_err(StoreError::Io)?;
        if !metadata.is_dir() {
            return Err(StoreError::NotFound);
        }
        let canonical_root = fs::canonicalize(root).map_err(StoreError::Io)?;
        let root_fd = fs::File::open(&canonical_root).map_err(StoreError::Io)?;
        Ok(Self {
            root: Arc::new(canonical_root),
            root_fd: Arc::new(root_fd),
            scope_directories: Arc::new(scope_directories),
            max_read_bytes,
            max_search_file_bytes,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn max_search_file_bytes(&self) -> usize {
        self.max_search_file_bytes
    }

    pub fn is_allowed(&self, scope: AccessScope, id: &DocumentId) -> bool {
        match id.as_str() {
            "INDEX.md" => true,
            _ => match id.top_level() {
                Some(directory) if self.scope_directories.allows_public(directory) => true,
                Some(directory)
                    if scope.allows_private()
                        && self.scope_directories.allows_private(directory) =>
                {
                    true
                }
                _ => false,
            },
        }
    }

    pub fn read(&self, scope: AccessScope, id: &DocumentId) -> Result<FetchedDocument, StoreError> {
        self.read_limited(scope, id, self.max_read_bytes)
    }

    pub fn read_for_search(
        &self,
        scope: AccessScope,
        id: &DocumentId,
    ) -> Result<FetchedDocument, StoreError> {
        self.read_limited(scope, id, self.max_search_file_bytes)
    }

    pub fn candidate_ids(&self, scope: AccessScope) -> Result<Vec<DocumentId>, StoreError> {
        let mut ids = Vec::new();
        let root_index = self.root.join("INDEX.md");
        if root_index.is_file() {
            ids.push(DocumentId::parse("INDEX.md")?);
        }

        let mut roots = self
            .scope_directories
            .public_directories()
            .collect::<Vec<_>>();
        if scope.allows_private() {
            roots.extend(self.scope_directories.private_directories());
        }

        for top_level in roots {
            let directory = self.root.join(top_level);
            if !directory.exists() {
                continue;
            }
            let walker = ignore::WalkBuilder::new(&directory)
                .hidden(true)
                .follow_links(false)
                .git_global(false)
                .git_ignore(true)
                .git_exclude(true)
                .build();
            for entry in walker {
                let entry = entry.map_err(|error| StoreError::Io(io_error(error)))?;
                if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                    continue;
                }
                if entry.path().extension().and_then(|value| value.to_str()) != Some("md") {
                    continue;
                }
                let relative = entry
                    .path()
                    .strip_prefix(&*self.root)
                    .map_err(|_| StoreError::NotFound)?;
                let path = relative
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                ids.push(DocumentId::parse(path)?);
            }
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    fn read_limited(
        &self,
        scope: AccessScope,
        id: &DocumentId,
        max_bytes: usize,
    ) -> Result<FetchedDocument, StoreError> {
        if !self.is_allowed(scope, id) {
            return Err(StoreError::NotFound);
        }
        let file = self.open_regular_file(id)?;
        let (text, truncated) = read_utf8_limited(file, max_bytes)?;
        Ok(FetchedDocument {
            id: id.clone(),
            metadata: parse_metadata(&text, id),
            text,
            truncated,
        })
    }

    fn open_regular_file(&self, id: &DocumentId) -> Result<fs::File, StoreError> {
        #[cfg(target_os = "linux")]
        {
            let fd = openat2(
                self.root_fd.as_ref(),
                id.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(map_open_error)?;
            let file = fs::File::from(fd);
            if !file.metadata().map_err(StoreError::Io)?.is_file() {
                return Err(StoreError::NotFound);
            }
            Ok(file)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = id;
            Err(StoreError::SafeOpenUnavailable)
        }
    }
}

#[cfg(target_os = "linux")]
fn map_open_error(error: rustix::io::Errno) -> StoreError {
    if matches!(
        error,
        rustix::io::Errno::NOENT
            | rustix::io::Errno::NOTDIR
            | rustix::io::Errno::LOOP
            | rustix::io::Errno::XDEV
    ) {
        StoreError::NotFound
    } else {
        StoreError::Io(error.into())
    }
}

fn io_error(error: ignore::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn read_utf8_limited(file: fs::File, max_bytes: usize) -> Result<(String, bool), StoreError> {
    let mut bytes = Vec::with_capacity(max_bytes.saturating_add(1));
    file.take(u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(StoreError::Io)?;
    let truncated = bytes.len() > max_bytes;
    if truncated {
        bytes.truncate(max_bytes);
        while !bytes.is_empty() && std::str::from_utf8(&bytes).is_err() {
            bytes.pop();
        }
    }
    let text = String::from_utf8(bytes).map_err(|_| StoreError::InvalidUtf8)?;
    Ok((text, truncated))
}

#[derive(Debug, Deserialize)]
struct FrontMatter {
    title: Option<String>,
    description: Option<String>,
    updated: Option<String>,
}

fn parse_metadata(text: &str, id: &DocumentId) -> DocumentMetadata {
    let fallback_title = id
        .path()
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("Untitled")
        .to_owned();
    let Some(rest) = text.strip_prefix("---\n") else {
        return DocumentMetadata {
            title: fallback_title,
            ..Default::default()
        };
    };
    let Some(end) = rest.find("\n---\n") else {
        return DocumentMetadata {
            title: fallback_title,
            ..Default::default()
        };
    };
    match serde_yaml::from_str::<FrontMatter>(&rest[..end]) {
        Ok(front_matter) => DocumentMetadata {
            title: front_matter.title.unwrap_or(fallback_title),
            description: front_matter.description.unwrap_or_default(),
            updated: front_matter.updated,
        },
        Err(error) => {
            tracing::warn!(document_id = %id, error = %error, "invalid YAML front matter");
            DocumentMetadata {
                title: fallback_title,
                ..Default::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn store() -> (TempDir, DocumentStore) {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("10_tech/rust")).unwrap();
        fs::create_dir_all(root.path().join("90_private")).unwrap();
        fs::write(root.path().join("INDEX.md"), "# KB Index\n").unwrap();
        fs::write(
            root.path().join("10_tech/rust/ownership.md"),
            "---\ntitle: Ownership\ndescription: Rust ownership note\nupdated: 2026-08-12\n---\n\nOwned data.\n",
        )
        .unwrap();
        fs::write(root.path().join("90_private/diary.md"), "Private note\n").unwrap();
        let store =
            DocumentStore::new(root.path(), 1_024, 1_024, ScopeDirectories::default()).unwrap();
        (root, store)
    }

    #[test]
    fn rejects_path_traversal_and_non_markdown_ids() {
        for invalid in [
            "../etc/passwd",
            "/etc/passwd",
            "C:\\secret.md",
            "note.txt",
            ".hidden.md",
        ] {
            assert!(matches!(
                DocumentId::parse(invalid),
                Err(StoreError::InvalidDocumentId)
            ));
        }
    }

    #[test]
    fn allows_only_scope_roots() {
        let (_root, store) = store();
        let tech = DocumentId::parse("10_tech/rust/ownership.md").unwrap();
        let private = DocumentId::parse("90_private/diary.md").unwrap();
        assert!(store.is_allowed(AccessScope::Tech, &tech));
        assert!(!store.is_allowed(AccessScope::Tech, &private));
        assert!(store.is_allowed(AccessScope::Private, &private));
    }

    #[test]
    fn hides_private_documents_from_tech_scope() {
        let (_root, store) = store();
        let private = DocumentId::parse("90_private/diary.md").unwrap();
        assert!(matches!(
            store.read(AccessScope::Tech, &private),
            Err(StoreError::NotFound)
        ));
    }

    #[test]
    fn reads_front_matter_metadata() {
        let (_root, store) = store();
        let id = DocumentId::parse("10_tech/rust/ownership.md").unwrap();
        let document = store.read(AccessScope::Tech, &id).unwrap();
        assert_eq!(document.metadata.title, "Ownership");
        assert_eq!(document.metadata.description, "Rust ownership note");
        assert_eq!(document.metadata.updated.as_deref(), Some("2026-08-12"));
    }

    #[test]
    fn truncates_without_breaking_utf8() {
        let (root, _) = store();
        fs::write(
            root.path().join("10_tech/rust/utf8.md"),
            format!("{}😀xyz", "a".repeat(62)),
        )
        .unwrap();
        let store =
            DocumentStore::new(root.path(), 64, 1_024, ScopeDirectories::default()).unwrap();
        let id = DocumentId::parse("10_tech/rust/utf8.md").unwrap();
        let document = store.read(AccessScope::Tech, &id).unwrap();
        assert!(document.truncated);
        assert_eq!(document.text, "a".repeat(62));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let (root, store) = store();
        symlink("/etc/passwd", root.path().join("10_tech/rust/link.md")).unwrap();
        let id = DocumentId::parse("10_tech/rust/link.md").unwrap();
        assert!(matches!(
            store.read(AccessScope::Tech, &id),
            Err(StoreError::NotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_without_blocking() {
        use rustix::fs::{Mode, mkfifoat};

        let (root, store) = store();
        let directory = fs::File::open(root.path().join("10_tech/rust")).unwrap();
        mkfifoat(&directory, "stream.md", Mode::RUSR | Mode::WUSR).unwrap();
        let id = DocumentId::parse("10_tech/rust/stream.md").unwrap();
        assert!(matches!(
            store.read(AccessScope::Tech, &id),
            Err(StoreError::NotFound)
        ));
    }

    #[test]
    fn uses_configured_scope_directories_for_read_and_search_candidates() {
        use std::collections::BTreeSet;

        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("docs/rust")).unwrap();
        fs::create_dir_all(root.path().join("personal")).unwrap();
        fs::write(root.path().join("docs/rust/note.md"), "public needle\n").unwrap();
        fs::write(root.path().join("personal/note.md"), "private needle\n").unwrap();
        let directories = ScopeDirectories::new(
            BTreeSet::from(["docs".to_owned()]),
            BTreeSet::from(["personal".to_owned()]),
        )
        .unwrap();
        let store = DocumentStore::new(root.path(), 1_024, 1_024, directories).unwrap();
        let public_id = DocumentId::parse("docs/rust/note.md").unwrap();
        let private_id = DocumentId::parse("personal/note.md").unwrap();

        assert!(store.is_allowed(AccessScope::Tech, &public_id));
        assert!(!store.is_allowed(AccessScope::Tech, &private_id));
        assert!(store.is_allowed(AccessScope::Private, &private_id));
        assert_eq!(
            store
                .candidate_ids(AccessScope::Tech)
                .unwrap()
                .into_iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
            vec!["docs/rust/note.md"]
        );
    }
}
