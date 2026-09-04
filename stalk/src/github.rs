/// GitHub profile OSINT — fetches public profile data and repository listing.
use crate::models::{GitHubProfile, RepoInfo};
use crate::stealth;

/// Fetch a GitHub user's public profile and repository list.
///
/// Calls the GitHub Users API and the user's `repos_url` endpoint,
/// assembling a [`GitHubProfile`] with up-to-date stats, bio, and
/// repository metadata. Returns `None` on any failure.
pub async fn lookup(username: &str) -> Option<GitHubProfile> {
    // Step: Build stealth HTTP client
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(stealth::random_ua())
        .build()
        .ok()?;

    // Step: Call GitHub Users API
    let url = format!("https://api.github.com/users/{}", username);
    let resp = client.get(&url).send().await.ok()?;
    // Check: Non-success status means user not found
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;

    // Step: Fetch repository list
    let repos_url = body["repos_url"].as_str().unwrap_or("").to_string();
    let mut repo_infos = Vec::new();
    // Check: repos_url present
    if !repos_url.is_empty() {
        if let Ok(repos_resp) = client.get(&repos_url).send().await {
            if let Ok(repos) = repos_resp.json::<Vec<serde_json::Value>>().await {
                // Loop: Map each repo JSON entry to RepoInfo struct
                repo_infos = repos.iter().map(|r| RepoInfo {
                    name: r["name"].as_str().unwrap_or("?").to_string(),
                    description: r["description"].as_str().map(|s| s.to_string()),
                    language: r["language"].as_str().map(|s| s.to_string()),
                    stars: r["stargazers_count"].as_u64().unwrap_or(0) as u32,
                    forks: r["forks_count"].as_u64().unwrap_or(0) as u32,
                }).collect();
            }
        }
    }

    // Return: Assemble full GitHubProfile
    Some(GitHubProfile {
        login: body["login"].as_str().unwrap_or(username).to_string(),
        name: body["name"].as_str().map(|s| s.to_string()),
        bio: body["bio"].as_str().map(|s| s.to_string()),
        public_repos: body["public_repos"].as_u64().unwrap_or(0) as u32,
        followers: body["followers"].as_u64().unwrap_or(0) as u32,
        following: body["following"].as_u64().unwrap_or(0) as u32,
        created_at: body["created_at"].as_str().unwrap_or("?").to_string(),
        location: body["location"].as_str().map(|s| s.to_string()),
        email: body["email"].as_str().map(|s| s.to_string()),
        blog: body["blog"].as_str().map(|s| s.to_string()),
        repos: repo_infos,
    })
}
