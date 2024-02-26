use std::{path::PathBuf, io};
use anyhow::Result;
use clap::Parser;
use rcgen::{
    Certificate,
    CertificateParams,
    KeyPair,
    PKCS_ECDSA_P256_SHA256,
    IsCa,
    BasicConstraints,
};
use once_cell::sync::Lazy;
use tokio::fs;

static CONTEXT_DIR: Lazy<PathBuf> = Lazy::new(|| PathBuf::from("pki_context"));
static CA_KEY_PEM_PATH: Lazy<PathBuf> = Lazy::new(|| CONTEXT_DIR.join("ca_key.pem"));
static CA_CERT_PEM_PATH: Lazy<PathBuf> = Lazy::new(|| CONTEXT_DIR.join("ca_cert.pem"));
static SERVER_KEY_PEM_PATH: Lazy<PathBuf> = Lazy::new(|| CONTEXT_DIR.join("server_key.pem"));
static SERVER_CERT_PEM_PATH: Lazy<PathBuf> = Lazy::new(|| CONTEXT_DIR.join("server_cert.pem"));

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
struct Opt {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
enum Cmd {
    NewServerCert(NewServerCertOpt),
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
    };
    Ok(())
}

async fn new_server_cert(dns_name: String) -> Result<()> {
    fs::create_dir_all(&*CONTEXT_DIR).await?;
    let ca_key = match fs::read_to_string(&*CA_KEY_PEM_PATH).await {
        Ok(ca_pem) => KeyPair::from_pem(&ca_pem)?,
        Err(err) => match err.kind() {
            io::ErrorKind::NotFound => {
                let ca_key = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
                let ca_pem = ca_key.serialize_pem();
                fs::write(&*CA_KEY_PEM_PATH, &ca_pem).await?;
                ca_key
            },
            _ => return Err(err.into()),
        }
    };

    let ca_cert = match fs::read_to_string(&*CA_CERT_PEM_PATH).await {
        Ok(ca_pem) => {
            let ca_params = CertificateParams::from_ca_cert_pem(&ca_pem, ca_key)?;
            Certificate::from_params(ca_params)?
        },
        Err(err) => match err.kind() {
            io::ErrorKind::NotFound => {
                let mut cert_params = CertificateParams::new(vec!["localhost".to_string()]);
                cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                cert_params.key_pair = Some(ca_key);
                let ca_cert = Certificate::from_params(cert_params)?;
                let ca_pem = ca_cert.serialize_pem()?;
                fs::write(&*CA_CERT_PEM_PATH, &ca_pem).await?;
                ca_cert
            },
            _ => return Err(err.into()),
        }
    };

    let key = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
    let cert_params = CertificateParams::new(vec![dns_name]);
    let cert = Certificate::from_params(cert_params)?;
    let cert_pem = cert.serialize_pem_with_signer(&ca_cert)?;
    let key_pem = key.serialize_pem();
    fs::write(&*SERVER_KEY_PEM_PATH, &key_pem).await?;
    fs::write(&*SERVER_CERT_PEM_PATH, &cert_pem).await?;

    log::info!("Server certificate and key are generated: key={}, cert={}", SERVER_KEY_PEM_PATH.display(), SERVER_CERT_PEM_PATH.display());
    Ok(())
}
