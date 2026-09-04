/// Cross-platform username enumeration across 77+ online services.
use crate::models::SiteResult;
use reqwest::Client;

/// A single platform definition with URL pattern and not-found patterns.
struct Site {
    name: &'static str,
    url: &'static str,
    not_found_patterns: &'static [&'static str],
}

/// Built-in registry of 77 online platforms to probe for username existence.
const SITES: &[Site] = &[
    Site { name: "GitHub", url: "https://github.com/{username}", not_found_patterns: &["Not Found", "this organization"] },
    Site { name: "Twitter/X", url: "https://twitter.com/{username}", not_found_patterns: &["this account doesn", "page doesn't exist", "not found", "no results"] },
    Site { name: "Reddit", url: "https://www.reddit.com/user/{username}", not_found_patterns: &["sorry, nobody on reddit", "page not found"] },
    Site { name: "Instagram", url: "https://www.instagram.com/{username}", not_found_patterns: &["page not found", "sorry, this page", "the link you followed may be broken"] },
    Site { name: "LinkedIn", url: "https://www.linkedin.com/in/{username}", not_found_patterns: &["page not found", "this page doesn", "profile not found"] },
    Site { name: "YouTube", url: "https://www.youtube.com/@{username}", not_found_patterns: &["not found", "this channel", "no results"] },
    Site { name: "Twitch", url: "https://www.twitch.tv/{username}", not_found_patterns: &["page not found", "not found", "sorry"] },
    Site { name: "TikTok", url: "https://www.tiktok.com/@{username}", not_found_patterns: &["couldn't find this account", "this account doesn", "no results"] },
    Site { name: "Facebook", url: "https://www.facebook.com/{username}", not_found_patterns: &["this content isn't available", "page not found", "this page isn't available"] },
    Site { name: "Medium", url: "https://medium.com/@{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Dev.to", url: "https://dev.to/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "HackerNews", url: "https://news.ycombinator.com/user?id={username}", not_found_patterns: &["no such user"] },
    Site { name: "StackOverflow", url: "https://stackoverflow.com/users/{username}", not_found_patterns: &["page not found", "user not found"] },
    Site { name: "Keybase", url: "https://keybase.io/{username}", not_found_patterns: &["not found", "couldn't find that user"] },
    Site { name: "BitBucket", url: "https://bitbucket.org/{username}", not_found_patterns: &["this page could not be found", "not found"] },
    Site { name: "GitLab", url: "https://gitlab.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "Patreon", url: "https://www.patreon.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "ProductHunt", url: "https://www.producthunt.com/@{username}", not_found_patterns: &["not found"] },
    Site { name: "Behance", url: "https://www.behance.net/{username}", not_found_patterns: &["page not found"] },
    Site { name: "Dribbble", url: "https://dribbble.com/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Flickr", url: "https://www.flickr.com/people/{username}", not_found_patterns: &["page not found", "not found", "no such user"] },
    Site { name: "Pinterest", url: "https://www.pinterest.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "Spotify", url: "https://open.spotify.com/user/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "SoundCloud", url: "https://soundcloud.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "Bandcamp", url: "https://bandcamp.com/{username}", not_found_patterns: &["not found"] },
    Site { name: "Mixcloud", url: "https://www.mixcloud.com/{username}", not_found_patterns: &["not found"] },
    Site { name: "Vimeo", url: "https://vimeo.com/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Steam", url: "https://steamcommunity.com/id/{username}", not_found_patterns: &["the specified profile could not be found"] },
    Site { name: "Chess.com", url: "https://www.chess.com/member/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "CodeWars", url: "https://www.codewars.com/users/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "Replit", url: "https://replit.com/@{username}", not_found_patterns: &["not found"] },
    Site { name: "Glitch", url: "https://glitch.com/@{username}", not_found_patterns: &["not found"] },
    Site { name: "Codepen", url: "https://codepen.io/{username}", not_found_patterns: &["not found"] },
    Site { name: "HackerRank", url: "https://www.hackerrank.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "LeetCode", url: "https://leetcode.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "TryHackMe", url: "https://tryhackme.com/p/{username}", not_found_patterns: &["page not found"] },
    Site { name: "HackTheBox", url: "https://app.hackthebox.com/profile/{username}", not_found_patterns: &["not found"] },
    Site { name: "Bugcrowd", url: "https://bugcrowd.com/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "HackerOne", url: "https://hackerone.com/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Upwork", url: "https://www.upwork.com/freelancers/~{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Fiverr", url: "https://www.fiverr.com/{username}", not_found_patterns: &["page not found"] },
    Site { name: "Freelancer", url: "https://www.freelancer.com/u/{username}", not_found_patterns: &["page not found"] },
    Site { name: "AngelList", url: "https://angel.co/u/{username}", not_found_patterns: &["not found"] },
    Site { name: "Kaggle", url: "https://www.kaggle.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "Wattpad", url: "https://www.wattpad.com/user/{username}", not_found_patterns: &["page not found"] },
    Site { name: "Scribd", url: "https://www.scribd.com/{username}", not_found_patterns: &["not found"] },
    Site { name: "SlideShare", url: "https://www.slideshare.net/{username}", not_found_patterns: &["not found"] },
    Site { name: "Gravatar", url: "https://en.gravatar.com/{username}", not_found_patterns: &["user not found", "page not found"] },
    Site { name: "Last.fm", url: "https://www.last.fm/user/{username}", not_found_patterns: &["user not found", "not found"] },
    Site { name: "Goodreads", url: "https://www.goodreads.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "Letterboxd", url: "https://letterboxd.com/{username}", not_found_patterns: &["not found"] },
    Site { name: "Telegram", url: "https://t.me/{username}", not_found_patterns: &["sorry, this page", "not found"] },
    Site { name: "Snapchat", url: "https://www.snapchat.com/add/{username}", not_found_patterns: &["not found"] },
    Site { name: "Pastebin", url: "https://pastebin.com/u/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "NPM", url: "https://www.npmjs.com/~{username}", not_found_patterns: &["not found"] },
    Site { name: "PyPI", url: "https://pypi.org/user/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "RubyGems", url: "https://rubygems.org/profiles/{username}", not_found_patterns: &["not found"] },
    Site { name: "Crates.io", url: "https://crates.io/users/{username}", not_found_patterns: &["not found"] },
    Site { name: "About.me", url: "https://about.me/{username}", not_found_patterns: &["not found"] },
    Site { name: "Linktree", url: "https://linktr.ee/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Bento", url: "https://bento.me/{username}", not_found_patterns: &["not found"] },
    Site { name: "Discord", url: "https://discord.com/users/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Mastodon.social", url: "https://mastodon.social/@{username}", not_found_patterns: &["not found", "no results"] },
    Site { name: "Buy Me a Coffee", url: "https://buymeacoffee.com/{username}", not_found_patterns: &["not found"] },
    Site { name: "Ko-fi", url: "https://ko-fi.com/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Venmo", url: "https://venmo.com/{username}", not_found_patterns: &["not found"] },
    Site { name: "Cash App", url: "https://cash.app/${username}", not_found_patterns: &["not found"] },
    Site { name: "Imgur", url: "https://imgur.com/user/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Giphy", url: "https://giphy.com/{username}", not_found_patterns: &["not found"] },
    Site { name: "VSCO", url: "https://vsco.co/{username}", not_found_patterns: &["not found"] },
    Site { name: "Issuu", url: "https://issuu.com/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Behance", url: "https://www.behance.net/{username}", not_found_patterns: &["page not found"] },
    Site { name: "500px", url: "https://500px.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "Redbubble", url: "https://www.redbubble.com/people/{username}", not_found_patterns: &["page not found"] },
    Site { name: "DeviantArt", url: "https://www.deviantart.com/{username}", not_found_patterns: &["page not found", "not found"] },
    Site { name: "Pexels", url: "https://www.pexels.com/@{username}", not_found_patterns: &["not found"] },
    Site { name: "Unsplash", url: "https://unsplash.com/@{username}", not_found_patterns: &["not found"] },
    Site { name: "Trello", url: "https://trello.com/{username}", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Notion", url: "https://notion.so/{username}", not_found_patterns: &["not found"] },
    Site { name: "Figma", url: "https://www.figma.com/@{username}", not_found_patterns: &["not found"] },
    Site { name: "Canva", url: "https://www.canva.com/{username}", not_found_patterns: &["page not found"] },
    Site { name: "StackShare", url: "https://stackshare.io/{username}", not_found_patterns: &["not found"] },
    Site { name: "G2", url: "https://www.g2.com/profile/{username}", not_found_patterns: &["not found"] },
    Site { name: "Couchsurfing", url: "https://www.couchsurfing.com/people/{username}", not_found_patterns: &["not found"] },
    Site { name: "Wix", url: "https://www.wix.com/{username}", not_found_patterns: &["page not found"] },
    Site { name: "Weebly", url: "https://{username}.weebly.com", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Tumblr", url: "https://{username}.tumblr.com", not_found_patterns: &["there's nothing here", "not found"] },
    Site { name: "Substack", url: "https://{username}.substack.com", not_found_patterns: &["not found", "page not found"] },
    Site { name: "Hashnode", url: "https://hashnode.com/@{username}", not_found_patterns: &["not found"] },
    Site { name: "DigitalOcean", url: "https://{username}.digitalocean.com", not_found_patterns: &["not found"] },
];

/// Enumerate a username across all 77 platforms in the site registry.
///
/// Applies request jitter between probes and returns a vector of
/// [`SiteResult`] indicating whether the account exists on each platform.
pub async fn enumerate(username: &str, client: &Client, jitter_ms: u64) -> Vec<SiteResult> {
    let mut results = Vec::new();
    // Loop: Iterate over every registered platform
    for site in SITES {
        // Step: Apply jitter delay before each request
        crate::stealth::jitter(jitter_ms).await;
        let url = site.url.replace("{username}", username);
        let result = check_site(client, site, username, &url).await;
        results.push(result);
    }
    results
}

/// Check a single platform for username existence via HTTP.
///
/// Analyses status code, redirect chains, response body patterns, and
/// rate-limit headers to conservatively determine account existence.
async fn check_site(client: &Client, site: &Site, username: &str, url: &str) -> SiteResult {
    // Step: Send HTTP GET request
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => {
            return SiteResult {
                name: site.name.to_string(),
                url: url.to_string(),
                exists: false,
                status_code: 0,
            };
        }
    };

    let headers = resp.headers();
    let status = resp.status().as_u16();
    let final_url = resp.url().as_str();

    // Check: Rate-limit / WAF detection — return unknown, not "exists"
    if is_rate_limited(headers) || status == 429 {
        return SiteResult {
            name: site.name.to_string(),
            url: url.to_string(),
            exists: false,
            status_code: status,
        };
    }

    // Check: Platform redirected away from profile page entirely
    let redirected_away = final_url != url
        && !final_url.to_lowercase().contains(&username.to_lowercase());

    // Branch: 404 is clear not-found
    if status == 404 {
        return SiteResult {
            name: site.name.to_string(),
            url: url.to_string(),
            exists: false,
            status_code: status,
        };
    }

    // Branch: 410 Gone = account removed
    if status == 410 {
        return SiteResult {
            name: site.name.to_string(),
            url: url.to_string(),
            exists: false,
            status_code: status,
        };
    }

    // Branch: 403 often means exists but blocked (protected account)
    if status == 403 {
        return SiteResult {
            name: site.name.to_string(),
            url: url.to_string(),
            exists: true,
            status_code: status,
        };
    }

    // Branch: 401 means exists but needs auth
    if status == 401 {
        return SiteResult {
            name: site.name.to_string(),
            url: url.to_string(),
            exists: true,
            status_code: status,
        };
    }

    // Branch: 3xx redirect — follow and check body
    if resp.status().is_redirection() {
        let redirect_url = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(url);
        // Handle: Follow the redirect manually
        if let Ok(final_resp) = client.get(redirect_url).send().await {
            let final_status = final_resp.status().as_u16();
            if let Ok(body) = final_resp.text().await {
                let body_lower = body.to_lowercase();
                let has_not_found = site.not_found_patterns.iter()
                    .any(|pat| body_lower.contains(&pat.to_lowercase()));
                // Check: Redirect lands on not-found page
                return SiteResult {
                    name: site.name.to_string(),
                    url: url.to_string(),
                    exists: !has_not_found,
                    status_code: final_status,
                };
            }
        }
        // Fallback: Could not determine — be conservative
        return SiteResult {
            name: site.name.to_string(),
            url: url.to_string(),
            exists: false,
            status_code: status,
        };
    }

    // Branch: 200/2xx responses — check body for "not found" patterns
    if status >= 200 && status < 300 {
        if let Ok(body) = resp.text().await {
            let body_lower = body.to_lowercase();
            let has_not_found = site.not_found_patterns.iter()
                .any(|pat| body_lower.contains(&pat.to_lowercase()));
            let exists = !has_not_found
                // Check: Redirected away from profile page
                && !redirected_away;
            return SiteResult {
                name: site.name.to_string(),
                url: url.to_string(),
                exists,
                status_code: status,
            };
        }
        // Fallback: Could not read body — be conservative
        return SiteResult {
            name: site.name.to_string(),
            url: url.to_string(),
            exists: false,
            status_code: status,
        };
    }

    // Fallback: Anything else (429, 503, etc.) — be conservative
    SiteResult {
        name: site.name.to_string(),
        url: url.to_string(),
        exists: false,
        status_code: status,
    }
}

/// Heuristic detection of rate-limiting via response headers.
fn is_rate_limited(headers: &reqwest::header::HeaderMap) -> bool {
    // Check: Retry-After header present
    if headers.get("retry-after").is_some() {
        return true;
    }
    // Check: X-RateLimit-Remaining is zero
    if let Some(val) = headers.get("x-ratelimit-remaining") {
        if let Ok(s) = val.to_str() {
            if let Ok(n) = s.parse::<u32>() {
                if n == 0 { return true; }
            }
        }
    }
    false
}
