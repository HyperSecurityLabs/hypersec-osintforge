/// Data models for the PRY reconnaissance framework.
use serde::Serialize;

/// Top-level result of a domain/IP intelligence lookup.
#[derive(Debug, Default, Serialize, Clone)]
pub struct LookupResult {
    /// The original target string.
    pub target: String,
    pub registrar: Option<String>,
    pub registrar_url: Option<String>,
    pub registrar_iana_id: Option<String>,
    pub domain_id: Option<String>,
    pub domain_registry_id: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub name_servers: Vec<String>,
    pub registrant_name: Option<String>,
    pub registrant_org: Option<String>,
    pub registrant_email: Option<String>,
    pub registrant_phone: Option<String>,
    pub registrant_street: Option<String>,
    pub registrant_city: Option<String>,
    pub registrant_state: Option<String>,
    pub registrant_country: Option<String>,
    pub registrant_zip: Option<String>,
    pub admin_org: Option<String>,
    pub admin_email: Option<String>,
    pub admin_phone: Option<String>,
    pub tech_name: Option<String>,
    pub tech_org: Option<String>,
    pub tech_street: Option<String>,
    pub tech_city: Option<String>,
    pub tech_state: Option<String>,
    pub tech_zip: Option<String>,
    pub tech_country: Option<String>,
    pub tech_email: Option<String>,
    pub tech_phone: Option<String>,
    pub abuse_email: Option<String>,
    pub dnssec: Option<String>,
    pub domain_status: Vec<String>,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    /// Data source identifier (rdap, whois, dns, etc.).
    pub source: String,
    /// Raw WHOIS response text.
    pub raw_whois: String,
    /// Error message if the lookup failed.
    pub error: Option<String>,
    /// Raw WHOIS referral response text.
    pub raw_referral: String,
}

impl LookupResult {
    /// Create a new LookupResult with just the target set.
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            ..Default::default()
        }
    }

    /// Check whether an Option<String> is both present and non-empty.
    fn non_empty(v: &Option<String>) -> bool {
        v.as_ref().is_some_and(|s| !s.is_empty())
    }

    /// Merge another LookupResult into this one, filling missing fields.
    pub fn merge(&mut self, other: &LookupResult) {
        macro_rules! merge_field {
            ($field:ident) => {
                if Self::non_empty(&other.$field) && self.$field.is_none() {
                    self.$field.clone_from(&other.$field);
                }
            };
        }
        merge_field!(registrar);
        merge_field!(registrar_url);
        merge_field!(registrar_iana_id);
        merge_field!(domain_id);
        merge_field!(domain_registry_id);
        merge_field!(creation_date);
        merge_field!(expiration_date);
        merge_field!(updated_date);
        merge_field!(registrant_name);
        merge_field!(registrant_org);
        merge_field!(registrant_email);
        merge_field!(registrant_phone);
        merge_field!(registrant_street);
        merge_field!(registrant_city);
        merge_field!(registrant_state);
        merge_field!(registrant_country);
        merge_field!(registrant_zip);
        merge_field!(admin_org);
        merge_field!(admin_email);
        merge_field!(admin_phone);
        merge_field!(tech_name);
        merge_field!(tech_org);
        merge_field!(tech_street);
        merge_field!(tech_city);
        merge_field!(tech_state);
        merge_field!(tech_zip);
        merge_field!(tech_country);
        merge_field!(tech_email);
        merge_field!(tech_phone);
        merge_field!(abuse_email);
        merge_field!(dnssec);
        // Loop: merge name servers (deduplicated)
        for ns in &other.name_servers {
            if !ns.is_empty() && !self.name_servers.contains(ns) {
                self.name_servers.push(ns.clone());
            }
        }
        // Loop: merge domain statuses (deduplicated)
        for st in &other.domain_status {
            if !st.is_empty() && !self.domain_status.contains(st) {
                self.domain_status.push(st.clone());
            }
        }
        // Loop: merge A records (deduplicated)
        for a in &other.a_records {
            if !self.a_records.contains(a) {
                self.a_records.push(a.clone());
            }
        }
        // Loop: merge AAAA records (deduplicated)
        for a in &other.aaaa_records {
            if !self.aaaa_records.contains(a) {
                self.aaaa_records.push(a.clone());
            }
        }
        // Handle: merge raw WHOIS data
        if !other.raw_whois.is_empty() && self.raw_whois.is_empty() {
            self.raw_whois = other.raw_whois.clone();
        }
        if !other.raw_referral.is_empty() && self.raw_referral.is_empty() {
            self.raw_referral = other.raw_referral.clone();
        }
    }

    /// Returns true if the result contains meaningful data.
    pub fn has_data(&self) -> bool {
        Self::non_empty(&self.registrar)
            || Self::non_empty(&self.creation_date)
            || Self::non_empty(&self.expiration_date)
            || Self::non_empty(&self.registrant_org)
            || Self::non_empty(&self.registrant_name)
            || !self.name_servers.is_empty()
            || !self.a_records.is_empty()
            || !self.aaaa_records.is_empty()
    }
}
