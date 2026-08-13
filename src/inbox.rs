//! The only writable surface of this server.
//!
//! Notes are appended as new files under a single directory (`99_inbox/` of the
//! knowledge base) and nowhere else. The client never names a file: it supplies
//! a title and a body, and the server derives the file name from the current
//! time plus a slug. Creation uses `O_EXCL` under an `openat2` resolution that
//! cannot leave the inbox directory, so no request can overwrite, replace, or
//! reach an existing document — the canonical knowledge base stays read-only by
//! construction rather than by validation.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use thiserror::Error;

#[cfg(target_os = "linux")]
use rustix::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags, StatVfsMountFlags, openat2, statat,
};

/// Knowledge-base-relative directory the notes are reported under. The layout
/// is fixed by the KB design, so this is a constant rather than a setting;
/// `INBOX_ROOT` only says where that directory is mounted in this process.
pub const INBOX_ID_PREFIX: &str = "99_inbox";

const MAX_TITLE_CHARS: usize = 200;
const MAX_SLUG_CHARS: usize = 40;
const FALLBACK_SLUG: &str = "note";
/// Distinct file names tried before giving up. Only reached when many notes
/// share one second and one slug.
const MAX_NAME_ATTEMPTS: u32 = 64;
const NOTE_SOURCE: &str = "mcp:append_note";

#[derive(Debug, Error)]
pub enum InboxError {
    #[error("note title is invalid")]
    InvalidTitle,
    #[error("note body is invalid")]
    InvalidBody,
    #[error("occurred date is invalid; use YYYY-MM-DD")]
    InvalidOccurred,
    #[error("note is larger than the per-note limit")]
    NoteTooLarge,
    #[error("inbox storage quota is exhausted")]
    QuotaExceeded,
    #[error("no free note file name was available")]
    NameExhausted,
    #[error("inbox is unavailable")]
    Unavailable,
    #[error("generated file name is not a single safe component")]
    InvalidFileName,
    #[error("failed to write the note")]
    Io(#[source] std::io::Error),
}

/// What the caller is told after a successful append. `id` is the
/// knowledge-base-relative path, never a host or container path.
#[derive(Debug, Clone, Serialize)]
pub struct CreatedNote {
    pub id: String,
    pub bytes: u64,
    pub created: String,
}

#[derive(Clone)]
pub struct InboxStore {
    root: Arc<PathBuf>,
    root_fd: Arc<fs::File>,
    max_note_bytes: usize,
    max_total_bytes: u64,
}

impl std::fmt::Debug for InboxStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxStore")
            .field("root", &self.root)
            .field("max_note_bytes", &self.max_note_bytes)
            .field("max_total_bytes", &self.max_total_bytes)
            .finish()
    }
}

impl InboxStore {
    /// Opens the inbox directory and keeps a directory descriptor for every
    /// later write. Fails — rather than degrading silently — when the directory
    /// is missing, is not a directory, is not writable by this process, or
    /// would let a write escape into the knowledge base itself. Callers treat
    /// the failure as "no write tool", never as a startup error, so an
    /// unwritable inbox cannot take reading down with it.
    pub fn open(
        root: impl AsRef<Path>,
        kb_root: impl AsRef<Path>,
        max_note_bytes: usize,
        max_total_bytes: u64,
    ) -> Result<Self, InboxError> {
        let root = fs::canonicalize(root.as_ref()).map_err(InboxError::Io)?;
        if !fs::metadata(&root).map_err(InboxError::Io)?.is_dir() {
            return Err(InboxError::Unavailable);
        }
        // The inbox may live inside the knowledge base, but must never be the
        // knowledge base or contain it: that would put canonical documents
        // within reach of the writable descriptor.
        if let Ok(kb_root) = fs::canonicalize(kb_root.as_ref())
            && kb_root.starts_with(&root)
        {
            return Err(InboxError::Unavailable);
        }
        if !is_writable_directory(&root) {
            return Err(InboxError::Unavailable);
        }
        let root_fd = fs::File::open(&root).map_err(InboxError::Io)?;
        Ok(Self {
            root: Arc::new(root),
            root_fd: Arc::new(root_fd),
            max_note_bytes,
            max_total_bytes,
        })
    }

    pub fn max_note_bytes(&self) -> usize {
        self.max_note_bytes
    }

    /// Writes one note and returns what was created. `fingerprint` is the audit
    /// fingerprint of the credential that asked for the write; it is recorded
    /// in the note so a later reader can tie the file back to an audit record
    /// without the server keeping a separate ledger.
    pub fn create_note(
        &self,
        title: &str,
        body: &str,
        occurred: Option<&str>,
        fingerprint: &str,
        now: SystemTime,
    ) -> Result<CreatedNote, InboxError> {
        let title = normalize_title(title)?;
        validate_body(body, self.max_note_bytes)?;
        let occurred = occurred.map(validate_occurred).transpose()?;

        let seconds = unix_seconds(now);
        let created = rfc3339_utc(seconds);
        let contents = render_note(&title, &created, occurred, fingerprint, body)?;
        let size = contents.len() as u64;

        let used = self.used_bytes()?;
        if used.saturating_add(size) > self.max_total_bytes {
            return Err(InboxError::QuotaExceeded);
        }

        let slug = slug(&title);
        for attempt in 0..MAX_NAME_ATTEMPTS {
            let name = note_file_name(seconds, &slug, attempt);
            let Some(mut file) = self.create_exclusive(&name)? else {
                continue;
            };
            file.write_all(contents.as_bytes())
                .map_err(InboxError::Io)?;
            file.sync_all().map_err(InboxError::Io)?;
            return Ok(CreatedNote {
                id: format!("{INBOX_ID_PREFIX}/{name}"),
                bytes: size,
                created,
            });
        }
        // Only reachable with this many notes sharing one second and one slug.
        // Reported as an internal failure rather than a quota, because nothing
        // the caller can do about their own quota would help.
        Err(InboxError::NameExhausted)
    }

    /// Sum of the regular files directly in the inbox. Notes are always flat,
    /// so this bounds exactly what this server can add. Two concurrent writes
    /// can both observe the pre-write total; the write rate limit keeps that
    /// overshoot to one note.
    fn used_bytes(&self) -> Result<u64, InboxError> {
        #[cfg(target_os = "linux")]
        {
            let dir = Dir::read_from(self.root_fd.as_ref())
                .map_err(|error| InboxError::Io(error.into()))?;
            let mut total: u64 = 0;
            for entry in dir {
                let entry = entry.map_err(|error| InboxError::Io(error.into()))?;
                let name = entry.file_name();
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                let stat = statat(self.root_fd.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|error| InboxError::Io(error.into()))?;
                if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
                    total = total.saturating_add(u64::try_from(stat.st_size).unwrap_or(0));
                }
            }
            Ok(total)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(InboxError::Unavailable)
        }
    }

    /// `Ok(None)` means the name was taken, which is the caller's cue to try
    /// the next one. `O_EXCL` plus `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`
    /// means a pre-planted file, symlink, or mount cannot turn a create into a
    /// write to somewhere else: it can only cost the note a suffix.
    #[cfg(target_os = "linux")]
    fn create_exclusive(&self, name: &str) -> Result<Option<fs::File>, InboxError> {
        if !is_safe_file_name(name) {
            return Err(InboxError::InvalidFileName);
        }
        match openat2(
            self.root_fd.as_ref(),
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) {
            Ok(fd) => Ok(Some(fs::File::from(fd))),
            Err(rustix::io::Errno::EXIST) => Ok(None),
            Err(error) => Err(InboxError::Io(error.into())),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn create_exclusive(&self, name: &str) -> Result<Option<fs::File>, InboxError> {
        let _ = name;
        Err(InboxError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn is_writable_directory(root: &Path) -> bool {
    // `EACCESS` asks about the effective ids, which are the ones the later
    // `openat2` will be checked against. A read-only mount can still answer
    // "writable" on some filesystems, so the mount flags are consulted too.
    let writable = rustix::fs::accessat(
        rustix::fs::CWD,
        root,
        rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
        AtFlags::EACCESS,
    )
    .is_ok();
    let read_only_mount =
        rustix::fs::statvfs(root).is_ok_and(|stat| stat.f_flag.contains(StatVfsMountFlags::RDONLY));
    writable && !read_only_mount
}

#[cfg(not(target_os = "linux"))]
fn is_writable_directory(root: &Path) -> bool {
    let _ = root;
    false
}

/// Only names this module generates are ever passed to `openat2`; this is the
/// last check that the generator has not produced a path.
fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && name.ends_with(".md")
}

fn normalize_title(title: &str) -> Result<String, InboxError> {
    let title = title.trim();
    if title.is_empty() || title.chars().count() > MAX_TITLE_CHARS {
        return Err(InboxError::InvalidTitle);
    }
    // Control characters are rejected rather than escaped so the generated
    // front matter can never gain a line the client wrote.
    if title.chars().any(char::is_control) {
        return Err(InboxError::InvalidTitle);
    }
    Ok(title.to_owned())
}

/// `YYYY-MM-DD` only. A malformed date is rejected rather than stored, so the
/// field can be trusted by whatever sorts the inbox later.
fn validate_occurred(value: &str) -> Result<&str, InboxError> {
    let bytes = value.as_bytes();
    let well_formed = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|&i| bytes[i].is_ascii_digit());
    if !well_formed {
        return Err(InboxError::InvalidOccurred);
    }
    let month = value[5..7].parse::<u32>().unwrap_or(0);
    let day = value[8..10].parse::<u32>().unwrap_or(0);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(InboxError::InvalidOccurred);
    }
    Ok(value)
}

fn validate_body(body: &str, max_note_bytes: usize) -> Result<(), InboxError> {
    if body.trim().is_empty() || body.contains('\0') {
        return Err(InboxError::InvalidBody);
    }
    if body.len() > max_note_bytes {
        return Err(InboxError::NoteTooLarge);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct NoteFrontMatter<'a> {
    title: &'a str,
    created: &'a str,
    /// The date the conversation or event happened, as told by the caller.
    /// Distinct from `created`: a note filed today can describe last month.
    #[serde(skip_serializing_if = "Option::is_none")]
    occurred: Option<&'a str>,
    source: &'a str,
    fingerprint: &'a str,
}

/// Builds the stored file. The front matter is serialized by `serde_yaml`, so a
/// title containing `---`, quotes, or a colon is escaped rather than able to
/// start a second block; the body follows the closing delimiter untouched,
/// which is what makes a body that itself starts with `---` ordinary text.
fn render_note(
    title: &str,
    created: &str,
    occurred: Option<&str>,
    fingerprint: &str,
    body: &str,
) -> Result<String, InboxError> {
    let front_matter = serde_yaml::to_string(&NoteFrontMatter {
        title,
        created,
        occurred,
        source: NOTE_SOURCE,
        fingerprint,
    })
    .map_err(|_| InboxError::InvalidTitle)?;
    let front_matter = front_matter
        .strip_prefix("---\n")
        .unwrap_or(&front_matter)
        .trim_end_matches('\n');
    if front_matter.contains("\n---") {
        return Err(InboxError::InvalidTitle);
    }

    let mut note = String::with_capacity(front_matter.len() + body.len() + 16);
    note.push_str("---\n");
    note.push_str(front_matter);
    note.push_str("\n---\n\n");
    note.push_str(body);
    if !note.ends_with('\n') {
        note.push('\n');
    }
    Ok(note)
}

fn slug(title: &str) -> String {
    let mut slug = String::with_capacity(MAX_SLUG_CHARS);
    let mut separator = false;
    for character in title.chars() {
        let character = character.to_ascii_lowercase();
        if matches!(character, 'a'..='z' | '0'..='9') {
            if slug.len() >= MAX_SLUG_CHARS {
                break;
            }
            if separator && !slug.is_empty() {
                slug.push('-');
            }
            separator = false;
            if slug.len() >= MAX_SLUG_CHARS {
                break;
            }
            slug.push(character);
        } else {
            separator = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        FALLBACK_SLUG.to_owned()
    } else {
        slug
    }
}

fn note_file_name(seconds: i64, slug: &str, attempt: u32) -> String {
    let (year, month, day, hour, minute, second) = utc_parts(seconds);
    let suffix = if attempt == 0 {
        String::new()
    } else {
        format!("-{}", attempt + 1)
    };
    format!("{year:04}-{month:02}-{day:02}-{hour:02}{minute:02}{second:02}-{slug}{suffix}.md")
}

fn rfc3339_utc(seconds: i64) -> String {
    let (year, month, day, hour, minute, second) = utc_parts(seconds);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn unix_seconds(now: SystemTime) -> i64 {
    match now.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

fn utc_parts(seconds: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    (
        year,
        month,
        day,
        (time_of_day / 3_600) as u32,
        ((time_of_day / 60) % 60) as u32,
        (time_of_day % 60) as u32,
    )
}

/// Howard Hinnant's `civil_from_days`. Written out here rather than pulled in
/// as a date dependency: it is a fixed, testable formula, and the note file
/// name is the only place this server needs a calendar.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;

    const FINGERPRINT: &str = "0123456789abcdef";

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// 2026-08-13T03:45:00Z
    const SAMPLE_TIME: u64 = 1_786_592_700;

    fn store() -> (TempDir, InboxStore) {
        let kb = TempDir::new().unwrap();
        let inbox = kb.path().join(INBOX_ID_PREFIX);
        fs::create_dir_all(&inbox).unwrap();
        let store = InboxStore::open(&inbox, kb.path(), 32_768, 1_048_576).unwrap();
        (kb, store)
    }

    #[test]
    fn converts_days_to_calendar_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(utc_parts(951_782_400).0, 2000);
        assert_eq!(utc_parts(951_782_400).1, 2);
        assert_eq!(utc_parts(951_782_400).2, 29);
        // 2100 is not a leap year: 2100-02-28 + 1 day is 2100-03-01.
        assert_eq!(civil_from_days(47_540), (2100, 2, 28));
        assert_eq!(civil_from_days(47_541), (2100, 3, 1));
        assert_eq!(rfc3339_utc(SAMPLE_TIME as i64), "2026-08-13T03:45:00Z");
    }

    #[test]
    fn builds_slugs_from_titles_the_client_controls() {
        assert_eq!(slug("Rust Ownership Notes"), "rust-ownership-notes");
        assert_eq!(slug("  ../../etc/passwd  "), "etc-passwd");
        assert_eq!(slug("a__b--c"), "a-b-c");
        // A title with no ASCII alphanumerics still yields a usable name.
        assert_eq!(slug("所有権のメモ"), FALLBACK_SLUG);
        assert_eq!(slug("---"), FALLBACK_SLUG);
        let long = slug(&"ab".repeat(60));
        assert_eq!(long.len(), MAX_SLUG_CHARS);
        assert!(!long.ends_with('-'));
    }

    #[test]
    fn file_names_are_generated_and_never_client_paths() {
        let name = note_file_name(SAMPLE_TIME as i64, "rust-notes", 0);
        assert_eq!(name, "2026-08-13-034500-rust-notes.md");
        assert_eq!(
            note_file_name(SAMPLE_TIME as i64, "rust-notes", 1),
            "2026-08-13-034500-rust-notes-2.md"
        );
        assert!(is_safe_file_name(&name));
        assert!(!is_safe_file_name("../escape.md"));
        assert!(!is_safe_file_name("nested/note.md"));
        assert!(!is_safe_file_name(".hidden.md"));
        assert!(!is_safe_file_name("note.txt"));
    }

    #[test]
    fn front_matter_is_server_generated_and_escapes_hostile_titles() {
        let title = "---\ntitle: forged"; // rejected before rendering
        assert!(matches!(
            normalize_title(title),
            Err(InboxError::InvalidTitle)
        ));

        let title = "a: b --- \"quoted\" #hash 所有権";
        let note = render_note(title, "2026-08-13T03:45:00Z", None, FINGERPRINT, "body\n").unwrap();
        let rest = note.strip_prefix("---\n").unwrap();
        let end = rest.find("\n---\n").unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&rest[..end]).unwrap();
        assert_eq!(parsed["title"].as_str().unwrap(), title);
        assert_eq!(parsed["source"].as_str().unwrap(), NOTE_SOURCE);
        assert_eq!(parsed["fingerprint"].as_str().unwrap(), FINGERPRINT);
        assert_eq!(&rest[end..], "\n---\n\nbody\n");
    }

    #[test]
    fn a_body_that_starts_with_front_matter_stays_body() {
        let body = "---\ntitle: Forged\nsource: trusted\n---\n\nreal body\n";
        let note = render_note("Real", "2026-08-13T03:45:00Z", None, FINGERPRINT, body).unwrap();
        let rest = note.strip_prefix("---\n").unwrap();
        let end = rest.find("\n---\n").unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&rest[..end]).unwrap();
        assert_eq!(parsed["title"].as_str().unwrap(), "Real");
        assert_eq!(parsed["source"].as_str().unwrap(), NOTE_SOURCE);
        assert!(note.ends_with(body));
    }

    #[test]
    fn writes_a_note_with_a_generated_name() {
        let (_kb, store) = store();
        let note = store
            .create_note(
                "Rust Notes",
                "body text",
                None,
                FINGERPRINT,
                at(SAMPLE_TIME),
            )
            .unwrap();
        assert_eq!(note.id, "99_inbox/2026-08-13-034500-rust-notes.md");
        assert_eq!(note.created, "2026-08-13T03:45:00Z");

        let contents =
            fs::read_to_string(store.root.join("2026-08-13-034500-rust-notes.md")).unwrap();
        assert!(contents.starts_with("---\ntitle: Rust Notes\n"));
        assert!(contents.contains("source: mcp:append_note"));
        assert!(contents.ends_with("body text\n"));
        assert_eq!(note.bytes, contents.len() as u64);
    }

    #[test]
    fn a_name_collision_never_overwrites() {
        let (_kb, store) = store();
        let first = store
            .create_note("Same Title", "first", None, FINGERPRINT, at(SAMPLE_TIME))
            .unwrap();
        let second = store
            .create_note("Same Title", "second", None, FINGERPRINT, at(SAMPLE_TIME))
            .unwrap();
        assert_eq!(first.id, "99_inbox/2026-08-13-034500-same-title.md");
        assert_eq!(second.id, "99_inbox/2026-08-13-034500-same-title-2.md");
        assert!(
            fs::read_to_string(store.root.join("2026-08-13-034500-same-title.md"))
                .unwrap()
                .ends_with("first\n")
        );
    }

    #[test]
    fn gives_up_rather_than_reusing_a_name_when_every_suffix_is_taken() {
        let (_kb, store) = store();
        let slug = slug("Same Title");
        for attempt in 0..MAX_NAME_ATTEMPTS {
            let name = note_file_name(SAMPLE_TIME as i64, &slug, attempt);
            fs::write(store.root.join(&name), "existing").unwrap();
        }
        assert!(matches!(
            store.create_note("Same Title", "body", None, FINGERPRINT, at(SAMPLE_TIME)),
            Err(InboxError::NameExhausted)
        ));
        // Every pre-existing file is still exactly as it was.
        for attempt in 0..MAX_NAME_ATTEMPTS {
            let name = note_file_name(SAMPLE_TIME as i64, &slug, attempt);
            assert_eq!(
                fs::read_to_string(store.root.join(&name)).unwrap(),
                "existing"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_cannot_capture_the_write() {
        use std::os::unix::fs::symlink;

        let (kb, store) = store();
        let target = kb.path().join("captured.md");
        symlink(&target, store.root.join("2026-08-13-034500-same-title.md")).unwrap();
        let note = store
            .create_note("Same Title", "body", None, FINGERPRINT, at(SAMPLE_TIME))
            .unwrap();
        assert_eq!(note.id, "99_inbox/2026-08-13-034500-same-title-2.md");
        assert!(!target.exists());
    }

    #[test]
    fn rejects_titles_and_bodies_it_will_not_store() {
        let (_kb, store) = store();
        for title in ["", "   ", "line\nbreak", &"x".repeat(201)] {
            assert!(matches!(
                store.create_note(title, "body", None, FINGERPRINT, at(SAMPLE_TIME)),
                Err(InboxError::InvalidTitle)
            ));
        }
        for body in ["", "  \n ", "nul\0byte"] {
            assert!(matches!(
                store.create_note("Title", body, None, FINGERPRINT, at(SAMPLE_TIME)),
                Err(InboxError::InvalidBody)
            ));
        }
    }

    #[test]
    fn rejects_a_body_over_the_per_note_limit() {
        let kb = TempDir::new().unwrap();
        let inbox = kb.path().join(INBOX_ID_PREFIX);
        fs::create_dir_all(&inbox).unwrap();
        let store = InboxStore::open(&inbox, kb.path(), 64, 1_048_576).unwrap();
        assert!(matches!(
            store.create_note("Title", &"x".repeat(65), None, FINGERPRINT, at(SAMPLE_TIME)),
            Err(InboxError::NoteTooLarge)
        ));
        assert!(
            store
                .create_note("Title", &"x".repeat(64), None, FINGERPRINT, at(SAMPLE_TIME))
                .is_ok()
        );
    }

    #[test]
    fn rejects_writes_once_the_directory_quota_is_reached() {
        let kb = TempDir::new().unwrap();
        let inbox = kb.path().join(INBOX_ID_PREFIX);
        fs::create_dir_all(&inbox).unwrap();
        let store = InboxStore::open(&inbox, kb.path(), 32_768, 400).unwrap();
        assert!(
            store
                .create_note("First", "body", None, FINGERPRINT, at(SAMPLE_TIME))
                .is_ok()
        );
        fs::write(inbox.join("bulk.md"), "x".repeat(400)).unwrap();
        assert!(matches!(
            store.create_note("Second", "body", None, FINGERPRINT, at(SAMPLE_TIME)),
            Err(InboxError::QuotaExceeded)
        ));
    }

    #[test]
    fn refuses_an_inbox_that_would_expose_the_knowledge_base() {
        let kb = TempDir::new().unwrap();
        fs::create_dir_all(kb.path().join("10_tech")).unwrap();
        assert!(matches!(
            InboxStore::open(kb.path(), kb.path(), 32_768, 1_048_576),
            Err(InboxError::Unavailable)
        ));
        assert!(matches!(
            InboxStore::open(kb.path(), kb.path().join("10_tech"), 32_768, 1_048_576),
            Err(InboxError::Unavailable)
        ));
    }

    #[test]
    fn refuses_a_missing_or_unwritable_inbox() {
        let kb = TempDir::new().unwrap();
        assert!(InboxStore::open(kb.path().join("absent"), kb.path(), 32_768, 1_048_576).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let inbox = kb.path().join(INBOX_ID_PREFIX);
            fs::create_dir_all(&inbox).unwrap();
            fs::set_permissions(&inbox, fs::Permissions::from_mode(0o500)).unwrap();
            let opened = InboxStore::open(&inbox, kb.path(), 32_768, 1_048_576);
            // Running as root defeats the permission bits, so only assert the
            // rejection where the bits are actually enforced.
            let bits_enforced = fs::File::create(inbox.join("probe")).is_err();
            fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700)).unwrap();
            if bits_enforced {
                assert!(matches!(opened, Err(InboxError::Unavailable)));
            }
        }
    }
}
