/// TLS connection handler — connects to targets with a permissive verifier and extracts certificate info.
use crate::models::CertResult;
use rustls::pki_types::ServerName;
use rustls::client::danger::ServerCertVerifier;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// A permissive certificate verifier that accepts all certificates.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        // Always accept — no verification
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Connect to a TLS server and extract certificate information.
pub async fn connect(host: &str, port: u16) -> CertResult {
    let mut r = CertResult {
        target: host.to_string(),
        port,
        ..Default::default()
    };
    let addr = format!("{}:{}", host, port);

    // Step: build permissive TLS client config
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // Step: TCP connect with 10-second timeout
    let stream = match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            r.error = Some(format!("TCP connect failed: {}", e));
            return r;
        }
        Err(_) => {
            r.error = Some(format!("TCP connect to {} timed out (10s)", addr));
            return r;
        }
    };

    // Step: construct server name
    let server_name = match ServerName::try_from(host) {
        Ok(n) => n.to_owned(),
        Err(_) => {
            r.error = Some("Invalid hostname".into());
            return r;
        }
    };

    // Step: perform TLS handshake
    let conn = match connector.connect(server_name, stream).await {
        Ok(c) => c,
        Err(e) => {
            r.error = Some(format!("TLS handshake failed: {}", e));
            return r;
        }
    };

    let (_, session) = conn.get_ref();

    // Step: extract negotiated cipher suite and TLS version
    if let Some(cs) = session.negotiated_cipher_suite() {
        r.cipher_suite = Some(format!("{:?}", cs.suite()));
        r.tls_version = Some(format!("{:?}", cs.version().version));
    }

    // Step: extract peer certificate chain
    let peer_certs = session.peer_certificates().unwrap_or_default();
    // Check: no certificates
    if peer_certs.is_empty() {
        return r;
    }
    // Check: sanity limit on chain length
    if peer_certs.len() > 20 {
        return r;
    }
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = peer_certs.to_vec();
    r.chain_length = certs.len();
    r.chain_der = certs.iter().map(|c| c.to_vec()).collect();

    // Step: parse the leaf certificate
    if let Some(leaf_der) = certs.first() {
        // Check: validate leaf certificate size
        if leaf_der.is_empty() || leaf_der.len() > 65536 {
            return r;
        }
        r.cert_der = leaf_der.to_vec();
        if let Ok(mut parsed) = crate::parser::parse(leaf_der) {
            parsed.chain_length = r.chain_length;
            parsed.cert_der = leaf_der.to_vec();
            parsed.chain_der = r.chain_der.clone();
            parsed.target = host.to_string();
            parsed.port = port;
            r = parsed;
        }
    }

    r
}
