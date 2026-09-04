/// Google dork generation for username and email OSINT.
///
/// Produces search-engine query strings designed to surface personal
/// information, profiles, credentials leaks, and file disclosures.

/// Generate Google dork queries targeting a specific username.
///
/// Produces 14 dorks covering social media, code forges, paste sites,
/// stack exchange, and file-type leaks.
pub fn dorks_for_username(username: &str) -> Vec<String> {
    vec![
        format!("inurl:\"{}\" intitle:\"profile\"", username),
        format!("site:github.com \"{}\" inurl:commits", username),
        format!("site:linkedin.com/in \"{}\"", username),
        format!("site:twitter.com \"{}\"", username),
        format!("site:reddit.com/user/\"{}\"", username),
        format!("site:medium.com \"{}\"", username),
        format!("site:dev.to \"{}\"", username),
        format!("site:keybase.io \"{}\"", username),
        format!("\"{}\" \"email\" \"contact\"", username),
        format!("\"{}\" filetype:pdf OR filetype:docx", username),
        format!("\"{}\" \"password\" OR \"credentials\"", username),
        format!("\"{}\" site:pastebin.com", username),
        format!("\"{}\" site:gist.github.com", username),
        format!("\"{}\" site:stackoverflow.com", username),
    ]
}

/// Generate Google dork queries targeting a specific email domain.
///
/// Produces 8 dorks covering social media, paste sites, spreadsheets,
/// password disclosures, and Gist content associated with the domain.
pub fn dorks_for_email(domain: &str) -> Vec<String> {
    vec![
        format!("site:linkedin.com \"@{}", domain),
        format!("site:github.com \"@{}", domain),
        format!("site:twitter.com \"@{}", domain),
        format!("site:pastebin.com \"@{}", domain),
        format!("\"@{}\" filetype:xls OR filetype:xlsx", domain),
        format!("\"@{}\" \"password\"", domain),
        format!("\"@{}\" site:gist.github.com", domain),
        format!("site:docs.google.com \"@{}\"", domain),
    ]
}
