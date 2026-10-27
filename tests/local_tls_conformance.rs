#![cfg(all(feature = "http1", feature = "ring"))]

use std::{sync::Arc, time::Duration};

use hyper::{Body, Client, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use rustls::{
    pki_types::CertificateDer, pki_types::PrivatePkcs8KeyDer, ClientConfig, RootCertStore,
    ServerConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

// A fully local HTTPS integration boundary: no external endpoints or
// production credentials, and no bypass of verification policies.
async fn request_test_server(
    trust_certificate: bool,
    hostname: &str,
) -> Result<StatusCode, hyper::Error> {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("generate ephemeral test cert");
    let cert = CertificateDer::from(
        issued
            .serialize_der()
            .expect("cert DER"),
    );
    let key = PrivatePkcs8KeyDer::from(issued.serialize_private_key_der());

    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .expect("TLS test server config");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local socket");
    let port = listener
        .local_addr()
        .expect("bound socket")
        .port();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let server_task = tokio::spawn(async move {
        let (socket, _) = listener
            .accept()
            .await
            .expect("test accept");
        if let Ok(mut stream) = acceptor.accept(socket).await {
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await;
            let _ = stream.flush().await;
        }
    });
    let mut roots = RootCertStore::empty();
    if trust_certificate {
        roots
            .add(cert)
            .expect("trusted test cert");
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Body> = Client::builder().build(connector);
    let url: Uri = format!("https://{hostname}:{port}/")
        .parse()
        .expect("HTTPS URI");
    let response = tokio::time::timeout(Duration::from_secs(5), client.get(url))
        .await
        .expect("bounded test request");
    server_task.abort();
    response.map(|r| r.status())
}

#[tokio::test]
async fn accepts_trusted_local_certificate() {
    assert_eq!(
        request_test_server(true, "localhost")
            .await
            .unwrap(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn rejects_untrusted_certificate() {
    assert!(request_test_server(false, "localhost")
        .await
        .is_err());
}

#[tokio::test]
async fn rejects_wrong_hostname() {
    assert!(request_test_server(true, "127.0.0.1")
        .await
        .is_err());
}
