use std::{path::PathBuf, io, sync::Arc, net::Ipv4Addr};
use anyhow::{Result, ensure};
use clap::Parser;
use rcgen::{
    Certificate,
    CertificateParams,
    KeyPair,
    PKCS_ED25519,
    IsCa,
    BasicConstraints,
};
use once_cell::sync::Lazy;
use tokio::{fs, net::TcpStream};
use tokio_rustls::TlsConnector;
use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer};
use rustls::{
    RootCertStore,
    ClientConfig,
    ServerConfig,
    pki_types::{
        CertificateDer,
        PrivateKeyDer,
        PrivatePkcs8KeyDer,
        ServerName,
    },
};

static CONTEXT_DIR: Lazy<PathBuf> = Lazy::new(|| PathBuf::from("pki_context"));
static CA_KEY_DER_PATH: Lazy<PathBuf> = Lazy::new(|| CONTEXT_DIR.join("ca_key.der"));
static CA_CERT_DER_PATH: Lazy<PathBuf> = Lazy::new(|| CONTEXT_DIR.join("ca_cert.der"));
static SERVER_KEY_DER_PATH: Lazy<PathBuf> = Lazy::new(|| CONTEXT_DIR.join("server_key.der"));
static SERVER_CERT_DER_PATH: Lazy<PathBuf> = Lazy::new(|| CONTEXT_DIR.join("server_cert.der"));

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
struct Opt {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
enum Cmd {
    NewServerCert(NewServerCertOpt),
    Server, 
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
struct NewServerCertOpt {
    #[clap(short, long, default_value = "test.local")]
    dns_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let opt = Opt::parse();
    match opt.cmd {
        Cmd::NewServerCert(new_server_cert_opt) => new_server_cert(new_server_cert_opt.dns_name).await?,
        Cmd::Server => server().await?,
        Cmd::Client => client().await?,
    };
    Ok(())
}

async fn server() -> Result<()> {
    // server that uses the generated certificate and key
    ensure!(fs::metadata(&*SERVER_CERT_DER_PATH).await.is_ok(), "Server certificate is not found: {}", SERVER_CERT_DER_PATH.display());
    ensure!(fs::metadata(&*SERVER_KEY_DER_PATH).await.is_ok(), "Server key is not found: {}", SERVER_KEY_DER_PATH.display());

    let cert_der = fs::read(&*SERVER_CERT_DER_PATH).await?;
    let cert = CertificateDer::from(cert_der);
    let key_der = fs::read(&*SERVER_KEY_DER_PATH).await?;
    let key = PrivatePkcs8KeyDer::from(key_der);
    let key = PrivateKeyDer::Pkcs8(key);

    let server_tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    HttpServer::new(|| { App::new().route("/", web::get().to(index)) })
        .workers(1)
        .bind_rustls_0_22("test.local:8443", server_tls_config)?
        .run()
        .await?;
    Ok(())
}

async fn index(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().body("Hello world"))
}

async fn client() -> Result<()> {
    let ca_cert_der = fs::read(&*CA_CERT_DER_PATH).await?;
    let ca_cert = CertificateDer::from(ca_cert_der);

    let mut root_cert_store = RootCertStore::empty();    
    root_cert_store.add(ca_cert)?;

    use ed25519_dalek::Verifier;
    use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
    use webpki::alg_id;

    #[derive(Debug)]
    struct Ed25519Verify;

    impl SignatureVerificationAlgorithm for Ed25519Verify {
        fn public_key_alg_id(&self) -> AlgorithmIdentifier {
            alg_id::ED25519
        }

        fn signature_alg_id(&self) -> AlgorithmIdentifier {
            alg_id::ED25519
        }

        fn verify_signature(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), InvalidSignature> {
            let public_key = public_key.try_into().map_err(|_| InvalidSignature)?;
            let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
            ed25519_dalek::VerifyingKey::from_bytes(public_key)
                .map_err(|_| InvalidSignature)?
                .verify(message, &signature)
                .map_err(|_| InvalidSignature)
        }
    }

    let cert_der = fs::read(&*SERVER_CERT_DER_PATH).await?;
    let cert = CertificateDer::from(cert_der);
    let cert_parsed = rustls::server::ParsedCertificate::try_from(&cert)?;
    rustls::client::verify_server_cert_signed_by_trust_anchor(&cert_parsed, &root_cert_store, &[], rustls::pki_types::UnixTime::now(), &[&Ed25519Verify])?;

    log::debug!("Default providers: {:?}", rustls::crypto::ring::default_provider());

    let host = "test.local";
    let addr = Ipv4Addr::new(127, 0, 0, 1);
    log::debug!("Looked up host");    

    let dnsname = ServerName::try_from(host.to_string())?; // connector wants static lifetime    
    let stream = TcpStream::connect((addr, 8443)).await?;
    log::debug!("Connected tcp");    

    let config = ClientConfig::builder_with_protocol_versions(&rustls::ALL_VERSIONS)
        .with_root_certificates(root_cert_store)    
        .with_no_client_auth();
    log::debug!("Set up root cert");    

    let connector = TlsConnector::from(Arc::new(config));    
    let stream = connector.connect(dnsname, stream).await?;    
    log::debug!("Connected tls");    

    Ok(())
}

async fn new_server_cert(dns_name: String) -> Result<()> {
    fs::create_dir_all(&*CONTEXT_DIR).await?;
    let ca_key = match fs::read(&*CA_KEY_DER_PATH).await {
        Ok(ca_der) => KeyPair::from_der(&ca_der)?,
        Err(err) => match err.kind() {
            io::ErrorKind::NotFound => {
                let ca_key = KeyPair::generate(&PKCS_ED25519)?;
                log::trace!("Generated a new CA key with algorithm: {:?}", ca_key.algorithm());
                let ca_der = ca_key.serialize_der();
                fs::write(&*CA_KEY_DER_PATH, &ca_der).await?;
                ca_key
            },
            _ => return Err(err.into()),
        }
    };

    let ca_cert = match fs::read(&*CA_CERT_DER_PATH).await {
        Ok(ca_der) => {
            let ca_params = CertificateParams::from_ca_cert_der(&ca_der, ca_key)?;
            log::trace!("Loaded a CA certificate with algorithm: {:?}", ca_params.alg);
            Certificate::from_params(ca_params)?
        },
        Err(err) => match err.kind() {
            io::ErrorKind::NotFound => {
                let mut cert_params = CertificateParams::new(vec!["localhost".to_string()]);
                cert_params.alg = &PKCS_ED25519;
                log::trace!("Generated a new CA certificate with algorithm: {:?}", cert_params.alg);
                cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                cert_params.key_pair = Some(ca_key);
                let ca_cert = Certificate::from_params(cert_params)?;
                let ca_der = ca_cert.serialize_der()?;
                fs::write(&*CA_CERT_DER_PATH, &ca_der).await?;
                ca_cert
            },
            _ => return Err(err.into()),
        }
    };

    let key = KeyPair::generate(&PKCS_ED25519)?;
    log::trace!("Generated a new server key with algorithm: {:?}", key.algorithm());
    let mut cert_params = CertificateParams::new(vec![dns_name]);
    cert_params.alg = &PKCS_ED25519;
    log::trace!("Generated a new server certificate with algorithm: {:?}", cert_params.alg);
    let cert = Certificate::from_params(cert_params)?;
    let cert_der = cert.serialize_der_with_signer(&ca_cert)?;
    let key_der = key.serialize_der();
    fs::write(&*SERVER_KEY_DER_PATH, &key_der).await?;
    fs::write(&*SERVER_CERT_DER_PATH, &cert_der).await?;

    log::info!("Server certificate and key are generated: key={}, cert={}", SERVER_KEY_DER_PATH.display(), SERVER_CERT_DER_PATH.display());
    Ok(())
}
