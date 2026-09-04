/// Data models for the STALK identity-mapping and OSINT framework.
use serde::Serialize;

/// Top-level result of a STALK investigation against a single target.
#[derive(Debug, Default, Serialize, Clone)]
pub struct StalkResult {
    pub target: String,
    pub target_type: String,
    pub sites: Vec<SiteResult>,
    pub github: Option<GitHubProfile>,
    pub breaches: Vec<BreachResult>,
    pub dorks: Vec<String>,
    pub error: Option<String>,
}

/// Result of checking a single online platform for a given username.
#[derive(Debug, Serialize, Clone)]
pub struct SiteResult {
    pub name: String,
    pub url: String,
    pub exists: bool,
    pub status_code: u16,
}

/// Public GitHub profile data including repository list.
#[derive(Debug, Serialize, Clone)]
pub struct GitHubProfile {
    pub login: String,
    pub name: Option<String>,
    pub bio: Option<String>,
    pub public_repos: u32,
    pub followers: u32,
    pub following: u32,
    pub created_at: String,
    pub location: Option<String>,
    pub email: Option<String>,
    pub blog: Option<String>,
    pub repos: Vec<RepoInfo>,
}

/// Metadata for a single GitHub repository.
#[derive(Debug, Serialize, Clone)]
pub struct RepoInfo {
    pub name: String,
    pub description: Option<String>,
    pub language: Option<String>,
    pub stars: u32,
    pub forks: u32,
}

/// A single data-breach entry returned by HIBP.
#[derive(Debug, Serialize, Clone)]
pub struct BreachResult {
    pub name: String,
    pub domain: String,
    pub breach_date: String,
    pub pwn_count: u32,
    pub data_classes: Vec<String>,
}
