/// X.509 certificate parser — extracts all fields from DER-encoded certificates.
use crate::models::CertResult;
use sha2::{Digest, Sha256};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

/// Parse a DER-encoded X.509 certificate into a structured `CertResult`.
pub fn parse(der: &[u8]) -> Result<CertResult, String> {
    // Step: parse the DER certificate
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("Failed to parse certificate: {}", e))?;

    let mut r = CertResult::default();

    // Step: compute SHA-256 fingerprint
    let mut hasher = Sha256::new();
    hasher.update(der);
    let hash = hasher.finalize();
    r.sha256_fingerprint = Some(
        hash.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":"),
    );

    // Loop: extract subject fields from certificate attributes
    for attr in cert.subject().iter_attributes() {
        let oid = attr.attr_type().to_string();
        if let Ok(val) = attr.as_str() {
            // Dispatch: map OID to subject field
            match oid.as_str() {
                "2.5.4.3" => r.subject_cn = Some(val.to_string()),
                "2.5.4.10" => r.subject_o = Some(val.to_string()),
                "2.5.4.11" => r.subject_ou = Some(val.to_string()),
                "2.5.4.7" => r.subject_l = Some(val.to_string()),
                "2.5.4.8" => r.subject_st = Some(val.to_string()),
                "2.5.4.6" => r.subject_c = Some(val.to_string()),
                _ => {}
            }
        }
    }

    // Loop: extract issuer fields from certificate attributes
    for attr in cert.issuer().iter_attributes() {
        let oid = attr.attr_type().to_string();
        if let Ok(val) = attr.as_str() {
            // Dispatch: map OID to issuer field
            match oid.as_str() {
                "2.5.4.3" => r.issuer_cn = Some(val.to_string()),
                "2.5.4.10" => r.issuer_o = Some(val.to_string()),
                "2.5.4.11" => r.issuer_ou = Some(val.to_string()),
                "2.5.4.6" => r.issuer_c = Some(val.to_string()),
                _ => {}
            }
        }
    }

    // Step: extract validity period
    let validity = cert.validity();
    r.not_before = Some(validity.not_before.to_string());
    r.not_after = Some(validity.not_after.to_string());

    // Step: compute days remaining until expiry
    let now = chrono::Utc::now().naive_utc();
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(
        &validity.not_after.to_string(),
        "%b %d %H:%M:%S %Y %Z",
    ) {
        let dur = ndt - now;
        r.days_remaining = Some(dur.num_days());
    } else if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(
        &validity.not_after.to_string(),
        "%Y-%m-%d %H:%M:%S %Z",
    ) {
        let dur = ndt - now;
        r.days_remaining = Some(dur.num_days());
    }

    // Step: extract serial number
    let raw_bytes = cert.raw_serial();
    r.serial = Some(
        raw_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(""),
    );

    // Step: extract public key algorithm
    let pki = cert.public_key();
    let algo_oid = pki.algorithm.algorithm.to_string();
    r.pub_key_algo = Some(
        // Dispatch: map OID to human-readable algorithm name
        match algo_oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA",
            "1.2.840.10045.2.1" => "ECDSA",
            "1.3.101.112" => "Ed25519",
            "1.3.101.113" => "Ed448",
            o => o,
        }
        .to_string(),
    );

    // Step: extract public key size
    if let Ok(pk) = pki.parsed() {
        let ks = pk.key_size();
        if ks > 0 {
            r.pub_key_size = Some(ks as u32);
        }
    }

    // Step: extract Subject Alternative Names
    if let Ok(Some(sans)) = cert.subject_alternative_name() {
        for san in &sans.value.general_names {
            if let GeneralName::DNSName(n) = san {
                let s = n.to_string();
                if !r.san_dns.contains(&s) {
                    r.san_dns.push(s);
                }
            }
        }
    }

    // Step: extract Key Usage extension
    if let Ok(Some(ku)) = cert.key_usage() {
        if ku.value.digital_signature() {
            r.key_usage.push("digitalSignature".into());
        }
        if ku.value.non_repudiation() {
            r.key_usage.push("nonRepudiation".into());
        }
        if ku.value.key_encipherment() {
            r.key_usage.push("keyEncipherment".into());
        }
        if ku.value.data_encipherment() {
            r.key_usage.push("dataEncipherment".into());
        }
        if ku.value.key_agreement() {
            r.key_usage.push("keyAgreement".into());
        }
        if ku.value.key_cert_sign() {
            r.key_usage.push("keyCertSign".into());
        }
        if ku.value.crl_sign() {
            r.key_usage.push("crlSign".into());
        }
        if ku.value.encipher_only() {
            r.key_usage.push("encipherOnly".into());
        }
        if ku.value.decipher_only() {
            r.key_usage.push("decipherOnly".into());
        }
    }

    // Step: extract Extended Key Usage extension
    if let Ok(Some(eku)) = cert.extended_key_usage() {
        if eku.value.server_auth {
            r.ext_key_usage.push("serverAuth".into());
        }
        if eku.value.client_auth {
            r.ext_key_usage.push("clientAuth".into());
        }
        if eku.value.code_signing {
            r.ext_key_usage.push("codeSigning".into());
        }
        if eku.value.email_protection {
            r.ext_key_usage.push("emailProtection".into());
        }
        if eku.value.time_stamping {
            r.ext_key_usage.push("timeStamping".into());
        }
        if eku.value.ocsp_signing {
            r.ext_key_usage.push("ocspSigning".into());
        }
        for oid in &eku.value.other {
            r.ext_key_usage.push(oid.to_string());
        }
    }

    // Step: check if certificate is a CA
    r.is_ca = cert.is_ca();

    // Loop: iterate over all extensions for CRL and OCSP URLs
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::CRLDistributionPoints(crls) => {
                for dp in crls.iter() {
                    if let Some(x509_parser::extensions::DistributionPointName::FullName(names)) =
                        &dp.distribution_point
                    {
                        for name in names {
                            if let GeneralName::URI(uri) = name {
                                r.crl_urls.push(uri.to_string());
                            }
                        }
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for desc in &aia.accessdescs {
                    // Check: OCSP responder OID (1.3.6.1.5.5.7.48.1)
                    if desc.access_method.to_string() == "1.3.6.1.5.5.7.48.1" {
                        if let GeneralName::URI(uri) = &desc.access_location {
                            r.ocsp_url = Some(uri.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(r)
}
