// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod, SslVerifyMode},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, SubjectAlternativeName},
    },
};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Challenge {
    None,
    Token,
    Html,
    Retry,
}

struct Gateway {
    url: String,
    fingerprint: String,
    files: tempfile::TempDir,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Gateway {
    fn new(challenge: Challenge, client_certificate: bool) -> Self {
        let files = tempfile::tempdir().unwrap();
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Ghaf test gateway")
            .unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        let serial = openssl::bn::BigNum::from_u32(1)
            .unwrap()
            .to_asn1_integer()
            .unwrap();
        cert.set_serial_number(&serial).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert.append_extension(
            SubjectAlternativeName::new()
                .ip("127.0.0.1")
                .build(&cert.x509v3_context(None, None))
                .unwrap(),
        )
        .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert.build();
        std::fs::write(files.path().join("cert.pem"), cert.to_pem().unwrap()).unwrap();
        std::fs::write(
            files.path().join("key.pem"),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        let fingerprint = cert
            .digest(MessageDigest::sha256())
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        if client_certificate {
            acceptor.cert_store_mut().add_cert(cert).unwrap();
            acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "https://{}/remote/login?realm=Staff%20%26%20VPN",
            listener.local_addr().unwrap()
        );
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let captured = requests.clone();
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut posts = 0;
            while !stopped.load(Ordering::SeqCst) {
                let Ok((stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let Ok(stream) = acceptor.accept(stream) else {
                    continue;
                };
                let mut reader = BufReader::new(stream);
                let mut request = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                    request.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                assert!(length < 65536);
                let mut body = vec![0; length];
                if reader.read_exact(&mut body).is_err() {
                    continue;
                }
                request.push_str(&String::from_utf8(body).unwrap());
                let post = request.starts_with("POST ");
                captured.lock().unwrap().push(request);
                let mut cookie = "";
                let mut status = "200 OK";
                let body = if post {
                    posts += 1;
                    match (challenge, posts) {
                        (Challenge::Token, 1) => {
                            "ret=1,tokeninfo=otp,reqid=1,polid=1,grp=1,portal=test,peer=test,magic=abc"
                        }
                        (Challenge::Html, 1) => {
                            status = "401 Unauthorized";
                            "<html><form id='_login' method='post' action='/remote/logincheck'><input type='hidden' name='username' value='test-user'><input type='password' name='credential'></form></html>"
                        }
                        (Challenge::Retry, 1) => {
                            status = "405 Method Not Allowed";
                            "Invalid credentials"
                        }
                        _ => {
                            cookie = "Set-Cookie: SVPNCOOKIE=test-session; Path=/\r\n";
                            "ok"
                        }
                    }
                } else {
                    "<html>Login</html>"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/html\r\n{}Connection: close\r\n\r\n{}",
                    body.len(),
                    cookie,
                    body
                );
                let _ = reader.get_mut().write_all(response.as_bytes());
            }
        });
        Self {
            url,
            fingerprint,
            files,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn config(&self) -> Value {
        json!({"gateway":self.url,"username":"test-user","password":"test-password",
            "fingerprint":self.fingerprint,"certificate":"","key":"","ca":""})
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn authenticate(config: Value, answer: Option<&str>) -> (bool, Vec<Value>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ghaf-fortivpn-service"))
        .arg("--authenticate-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{config}").unwrap();
    let stdout = child.stdout.take().unwrap();
    let answer = answer.map(str::to_owned);
    let reader = std::thread::spawn(move || {
        let mut events = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let event: Value = serde_json::from_str(&line.unwrap()).unwrap();
            if event["event"] == "Prompt" {
                if let Some(answer) = &answer {
                    writeln!(stdin, "{}", json!(answer)).unwrap();
                } else {
                    break;
                }
            }
            events.push(event);
        }
        events
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("authentication worker timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    (status.success(), reader.join().unwrap())
}

#[test]
fn password_and_realm_produce_a_fresh_cookie() {
    let gateway = Gateway::new(Challenge::None, false);
    for _ in 0..2 {
        let (success, events) = authenticate(gateway.config(), None);
        assert!(success);
        assert_eq!(events[0]["secrets"]["cookie"], "SVPNCOOKIE=test-session");
        assert!(
            events[0]["secrets"]["gwcert"]
                .as_str()
                .unwrap()
                .starts_with("pin-sha256:")
        );
    }
    let requests = gateway.requests.lock().unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        2
    );
    assert!(requests.iter().any(|r| r.contains("username=test-user")
        && r.contains("credential=test-password")
        && r.contains("realm=Staff%20%26%20VPN")));
}

#[test]
fn mfa_prompts_for_code_without_reusing_password() {
    let gateway = Gateway::new(Challenge::Token, false);
    let (success, events) = authenticate(gateway.config(), Some("123456"));
    assert!(success);
    assert_eq!(events[0]["event"], "Prompt");
    assert_eq!(events[0]["secret"], true);
    let requests = gateway.requests.lock().unwrap();
    assert!(requests.last().unwrap().contains("code=123456"));
    assert!(!requests.last().unwrap().contains("test-password"));
}

#[test]
fn rejects_untrusted_gateway_and_accepts_configured_ca() {
    let gateway = Gateway::new(Challenge::None, false);
    let mut config = gateway.config();
    config["fingerprint"] = json!("00".repeat(32));
    assert!(!authenticate(config.clone(), None).0);
    assert!(gateway.requests.lock().unwrap().is_empty());
    config["ca"] = json!(gateway.files.path().join("cert.pem"));
    assert!(authenticate(config, None).0);
}

#[test]
fn uses_private_client_certificate_for_password_and_certificate_only_modes() {
    let gateway = Gateway::new(Challenge::None, true);
    let mut config = gateway.config();
    config["certificate"] = json!(gateway.files.path().join("cert.pem"));
    config["key"] = json!(gateway.files.path().join("key.pem"));
    assert!(authenticate(config.clone(), None).0);
    config["password"] = json!("");
    assert!(authenticate(config, None).0);
}

#[test]
fn cancelling_mfa_does_not_return_a_cookie() {
    let gateway = Gateway::new(Challenge::Token, false);
    let (success, events) = authenticate(gateway.config(), None);
    assert!(!success);
    assert!(events.iter().all(|event| event["event"] != "Complete"));
}

#[test]
fn html_mfa_does_not_replace_the_saved_login_password() {
    let gateway = Gateway::new(Challenge::Html, false);
    let (success, events) = authenticate(gateway.config(), Some("654321"));
    assert!(success);
    assert_eq!(events[0]["event"], "Prompt");
    assert!(events.last().unwrap()["password"].is_null());
    let requests = gateway.requests.lock().unwrap();
    assert!(requests.last().unwrap().contains("credential=654321"));
    assert!(!requests.last().unwrap().contains("test-password"));
}

#[test]
fn corrected_password_is_returned_to_the_backend_only_after_success() {
    let gateway = Gateway::new(Challenge::Retry, false);
    let (success, events) = authenticate(gateway.config(), Some("corrected-password"));
    assert!(success);
    assert_eq!(events[0]["event"], "Prompt");
    assert!(
        events[0]["label"]
            .as_str()
            .unwrap()
            .contains("Invalid credentials")
    );
    assert_eq!(events.last().unwrap()["password"], "corrected-password");
}
