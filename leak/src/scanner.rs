/// File and git-history secret scanner.
///
/// Walks directories, reads files, and scans content against all registered
/// secret patterns. Supports git commit history scanning, entropy gating,
/// binary file exclusion, and test-fixture severity reduction.
use crate::models::SecretMatch;
use crate::patterns::{entropy, is_low_quality_match, validate_jwt, PATTERNS};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// File extensions considered binary and skipped during scanning.
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg",
    "woff", "woff2", "ttf", "eot", "otf",
    "zip", "gz", "bz2", "xz", "tar", "rar", "7z",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "mp3", "mp4", "avi", "mkv", "mov", "wmv", "flv",
    "exe", "dll", "so", "dylib", "bin", "obj", "o",
    "ttf", "otf",
    "pyc", "class", "jar", "war",
];

/// Directory names that are always skipped during scans.
const SKIP_DIRS: &[&str] = &[
    ".git", ".svn", ".hg", "node_modules", "vendor",
    ".venv", "venv", "__pycache__", ".cache",
    "target", "build", "dist", ".gradle",
    ".DS_Store",
];

/// File extensions that are candidates for text scanning.
const SCAN_EXTS: &[&str] = &[
    "rs", "go", "py", "js", "ts", "tsx", "jsx", "java", "kt", "scala",
    "rb", "php", "pl", "pm", "c", "h", "cpp", "hpp", "cs", "swift",
    "sh", "bash", "zsh", "fish", "ps1", "bat", "cmd",
    "yml", "yaml", "toml", "json", "xml", "ini", "cfg", "conf",
    "env", "envrc", "dockerfile", "makefile",
    "tf", "tfvars", "hcl",
    "sql", "db", "sqlite",
    "html", "htm", "css", "scss", "less",
    "md", "rst", "txt",
    "pem", "key", "cert", "crt", "csr",
    "log",
    "gradle", "props", "properties",
];

/// Lock files that are skipped due to noise.
const LOCK_FILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "Gemfile.lock",
    "pnpm-lock.yaml",
];

/// File suffixes to skip (minified / compiled artifacts).
const SKIP_FILE_SUFFIXES: &[&str] = &[
    ".lock",
    ".sum",
    ".sig",
    ".min.js",
    ".map",
];

/// Maximum number of matches to report per file (prevents noise flooding).
const MAX_MATCHES_PER_FILE: usize = 50;

/// Check if a directory name is in the skip list.
fn is_skip_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name)
}

/// Check if a filename is a known lock file.
fn is_lock_file(name: &str) -> bool {
    LOCK_FILES.contains(&name)
}

/// Check if a filename has a skip suffix.
fn has_skip_suffix(name: &str) -> bool {
    SKIP_FILE_SUFFIXES.iter().any(|&s| name.ends_with(s))
}

/// Check if a path belongs to a test or fixture directory.
fn is_test_fixture_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("/test/")
        || path_str.contains("/tests/")
        || path_str.contains("/fixture/")
        || path_str.contains("/fixtures/")
        || path_str.contains("/example/")
        || path_str.contains("/examples/")
}

/// Reduce a severity level by one step (for test fixtures).
fn reduce_severity(sev: &str) -> &str {
    match sev {
        "critical" => "high",
        "high" => "medium",
        "medium" => "low",
        _ => "low",
    }
}

/// Determine whether a file entry should be scanned at all.
fn should_scan(entry: &walkdir::DirEntry) -> bool {
    // Check: skip directories
    if entry.file_type().is_dir() {
        return false;
    }

    let fname = entry.file_name().to_string_lossy();
    // Check: skip lock files
    if is_lock_file(&fname) {
        return false;
    }
    // Check: skip files with skip suffixes
    if has_skip_suffix(&fname) {
        return false;
    }

    // Check: only scan whitelisted text extensions
    if let Some(ext) = entry.path().extension() {
        let ext = ext.to_str().unwrap_or("").to_lowercase();
        if BINARY_EXTENSIONS.contains(&ext.as_str()) {
            return false;
        }
        return SCAN_EXTS.contains(&ext.as_str());
    }
    // Note: files without extensions are scanned (e.g., Dockerfile)
    true
}

/// Recursively scan a directory for secrets.
pub fn scan_dir(
    path: &Path,
    max_size: u64,
    enable_low: bool,
    no_low_entropy: bool,
) -> (Vec<SecretMatch>, u32) {
    let mut matches = Vec::new();
    let mut files_scanned = 0;

    // Loop: walk the directory tree
    for entry in WalkDir::new(path).into_iter().filter_entry(|e| {
        if e.file_type().is_dir() {
            if let Some(name) = e.file_name().to_str() {
                return !is_skip_dir(name);
            }
        }
        true
    }) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Check: only process regular files
        if !entry.file_type().is_file() {
            continue;
        }

        // Check: skip un-scannable files
        if !should_scan(&entry) {
            continue;
        }

        // Check: skip files exceeding max size
        if let Ok(meta) = entry.metadata() {
            if meta.len() > max_size {
                continue;
            }
        }

        files_scanned += 1;
        // Step: read file content
        let content = match fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Step: scan file content for secrets
        let file_matches = scan_content(&content, entry.path(), enable_low, no_low_entropy);
        matches.extend(file_matches);
    }

    (matches, files_scanned)
}

/// Scan a single file for secrets.
pub fn scan_file(
    path: &Path,
    max_size: u64,
    enable_low: bool,
    no_low_entropy: bool,
) -> (Vec<SecretMatch>, u32) {
    // Check: path must be a file
    if !path.is_file() {
        return (Vec::new(), 0);
    }

    // Check: skip files exceeding max size
    if let Ok(meta) = path.metadata() {
        if meta.len() > max_size {
            return (Vec::new(), 0);
        }
    }

    // Step: read file content
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (Vec::new(), 0),
    };

    // Step: scan content for secrets
    let matches = scan_content(&content, path, enable_low, no_low_entropy);
    (matches, 1)
}

/// Scan a string of content against all secret patterns.
fn scan_content(
    content: &str,
    filepath: &Path,
    enable_low: bool,
    no_low_entropy: bool,
) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    let mut file_match_count = 0;
    let filepath_str = filepath.to_string_lossy();
    let is_test = is_test_fixture_path(filepath);

    // Loop: check each pattern against the content
    for pattern in PATTERNS.iter() {
        // Check: skip low-severity patterns if disabled
        if !enable_low && pattern.severity == "low" {
            continue;
        }

        // Loop: find all matches for this pattern
        for cap in pattern.regex.find_iter(content) {
            // Check: enforce per-file match cap
            if file_match_count >= MAX_MATCHES_PER_FILE {
                break;
            }

            let matched_text = cap.as_str();
            // Step: calculate line number
            let line_num = content[..cap.start()].matches('\n').count() as u32 + 1;

            // Step: extract the full line containing the match
            let line_start = content[..cap.start()]
                .rfind('\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            let line_end = content[cap.end()..]
                .find('\n')
                .map(|i| cap.end() + i)
                .unwrap_or(content.len());
            let line = &content[line_start..line_end];

            // Branch: apply quality filters if entropy gating is enabled
            if no_low_entropy {
                // Check: skip low-quality matches (test data, placeholders)
                if is_low_quality_match(matched_text, line) {
                    continue;
                }
                // Check: validate JWT structure
                if pattern.name == "JWT Token" && !validate_jwt(matched_text) {
                    continue;
                }
                // Check: skip low-entropy low-severity matches
                if pattern.severity == "low" && entropy(matched_text) < 0.4 {
                    continue;
                }
            }

            // Step: build context snippet (truncate long lines)
            let context = if line.len() > 120 {
                format!("{}...", &line[..120])
            } else {
                line.to_string()
            };

            // Check: deduplicate identical matches on the same file/line/pattern
            if matches
                .iter()
                .any(|m: &SecretMatch| {
                    m.file == filepath_str && m.line == line_num && m.pattern == pattern.name
                })
            {
                continue;
            }

            // Branch: reduce severity for test/fixture files
            let severity = if is_test {
                reduce_severity(pattern.severity)
            } else {
                pattern.severity
            };

            // Handle: record the match
            matches.push(SecretMatch {
                file: filepath_str.to_string(),
                line: line_num,
                pattern: pattern.name.to_string(),
                severity: severity.to_string(),
                context,
            });

            file_match_count += 1;
        }

        // Check: stop early if per-file cap reached
        if file_match_count >= MAX_MATCHES_PER_FILE {
            break;
        }
    }

    matches
}

/// Scan git commit history for secrets using `git log -p --all --full-history`.
pub fn scan_git(path: &Path, enable_low: bool, no_low_entropy: bool) -> (Vec<SecretMatch>, u32) {
    let git_dir = path.join(".git");
    // Check: no .git directory found
    if !git_dir.is_dir() {
        return (Vec::new(), 0);
    }

    // Step: spawn git log command
    let output = match std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("log")
        .arg("-p")
        .arg("--all")
        .arg("--full-history")
        .output()
    {
        Ok(o) => o,
        Err(_) => return (Vec::new(), 0),
    };

    let content = String::from_utf8_lossy(&output.stdout);
    let mut matches = Vec::new();
    let mut current_commit = String::new();

    // Loop: iterate through git log lines
    for line in content.lines() {
        // Check: commit header line
        if line.starts_with("commit ") {
            current_commit = line
                .strip_prefix("commit ")
                .unwrap_or("")
                .chars()
                .take(8)
                .collect();
        }
        // Check: added lines (diff content, not file headers)
        if line.starts_with('+') && !line.starts_with("+++") {
            let clean = line[1..].to_string();
            let fake_path = format!("[git {}]", current_commit);

            // Loop: test each pattern against the diff line
            for pattern in PATTERNS.iter() {
                // Check: skip low-severity if disabled
                if !enable_low && pattern.severity == "low" {
                    continue;
                }
                // Check: test pattern match
                if let Some(cap) = pattern.regex.find(&clean) {
                    // Branch: apply quality filters
                    if no_low_entropy {
                        if is_low_quality_match(cap.as_str(), &clean) {
                            continue;
                        }
                        if pattern.name == "JWT Token" && !validate_jwt(cap.as_str()) {
                            continue;
                        }
                        if pattern.severity == "low" && entropy(cap.as_str()) < 0.4 {
                            continue;
                        }
                    }

                    // Step: calculate line number within the commit diff
                    let line_num = clean[..cap.start()].matches('\n').count() as u32 + 1;
                    // Step: truncate long context
                    let context = if clean.len() > 120 {
                        format!("{}...", &clean[..120])
                    } else {
                        clean.clone()
                    };

                    // Handle: record the git match
                    matches.push(SecretMatch {
                        file: fake_path.clone(),
                        line: line_num,
                        pattern: pattern.name.to_string(),
                        severity: pattern.severity.to_string(),
                        context,
                    });
                }
            }
        }
    }

    (matches, 1)
}
