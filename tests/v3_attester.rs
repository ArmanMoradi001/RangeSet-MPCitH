//! Attester service tests: CLI prove→verify round-trip and the real HTTP
//! layer over loopback sockets (ephemeral ports, no external processes
//! except the crate's own binaries). Fast insecure preset only.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;

use range_set_mpcith::attester::serve_n;
use range_set_mpcith::v3::envelope::ProofEnvelopeV1;

fn prove_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rsp-prove"))
}

fn verify_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rsp-verify"))
}

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rsp-attester-test-{}-{}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const CONTEXT_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn prove_envelope(dir: &std::path::Path) -> (PathBuf, String) {
    let out = dir.join("proof.env");
    let status = Command::new(prove_bin())
        .args([
            "--value",
            "20",
            "--lo",
            "10",
            "--hi",
            "40",
            "--members",
            "10,20,30,40",
            "--member-index",
            "1",
            "--context",
            CONTEXT_HEX,
            "--params",
            "fast-insecure-test",
            "--seed",
            "4242",
            "--out",
        ])
        .arg(&out)
        .output()
        .expect("run rsp-prove");
    assert!(
        status.status.success(),
        "rsp-prove failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let summary = String::from_utf8(status.stdout).unwrap();
    assert!(summary.contains("\"envelope_hash\""), "summary: {summary}");
    let env_bytes = std::fs::read(&out).unwrap();
    let env = ProofEnvelopeV1::from_bytes(&env_bytes).unwrap();
    let root_hex = hex::encode(env.set_root);
    (out, root_hex)
}

fn verify_cli(env_file: &std::path::Path, root_hex: &str, tamper_root: bool) -> (bool, String) {
    let root = if tamper_root {
        "ff".to_string() + &root_hex[2..]
    } else {
        root_hex.to_string()
    };
    let output = Command::new(verify_bin())
        .args([
            "--envelope",
            &env_file.to_string_lossy(),
            "--lo",
            "10",
            "--hi",
            "40",
            "--set-root",
            &root,
            "--num-members",
            "4",
            "--depth",
            "2",
            "--context",
            CONTEXT_HEX,
            "--allowed-params",
            "fast-insecure-test",
        ])
        .output()
        .expect("run rsp-verify");
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
    )
}

#[test]
fn cli_prove_then_verify_roundtrip() {
    let dir = workdir("cli");
    let (env_file, root_hex) = prove_envelope(&dir);
    let (ok, stdout) = verify_cli(&env_file, &root_hex, false);
    assert!(ok, "rsp-verify rejected honest envelope: {stdout}");
    assert!(stdout.contains("\"ok\":true"), "stdout: {stdout}");
    let (ok, stdout) = verify_cli(&env_file, &root_hex, true);
    assert!(!ok, "rsp-verify accepted wrong root: {stdout}");
    assert!(
        stdout.contains("statement_mismatch"),
        "stdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn http_post(addr: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (String, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let mut req = format!("POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8(resp).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (head.to_string(), body.to_string())
}

fn http_get(addr: &str, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8(resp).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (head.to_string(), body.to_string())
}

#[test]
fn service_verify_over_http() {
    let dir = workdir("http");
    let (env_file, root_hex) = prove_envelope(&dir);
    let env_bytes = std::fs::read(&env_file).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    // healthz + honest verify + wrong-root verify.
    let server = std::thread::spawn(move || serve_n(listener, 3));

    let (head, body) = http_get(&addr, "/healthz");
    assert!(head.contains("200 OK"), "health head: {head}");
    assert!(body.contains("\"status\":\"ok\""), "health body: {body}");

    let hdrs = [
        ("X-Expected-Range-Lo", "10"),
        ("X-Expected-Range-Hi", "40"),
        ("X-Expected-Set-Root", root_hex.as_str()),
        ("X-Expected-Num-Members", "4"),
        ("X-Expected-Depth", "2"),
        ("X-Expected-Context", CONTEXT_HEX),
        ("X-Allowed-Params", "fast-insecure-test"),
    ];
    let (head, body) = http_post(&addr, "/verify", &hdrs, &env_bytes);
    assert!(head.contains("200 OK"), "verify head: {head}");
    assert!(body.contains("\"ok\":true"), "verify body: {body}");
    assert!(body.contains("\"proof_bytes\":"), "verify body: {body}");

    let bad_root = "ff".to_string() + &root_hex[2..];
    let mut bad_hdrs = hdrs.to_vec();
    bad_hdrs[2] = ("X-Expected-Set-Root", bad_root.as_str());
    let (head, body) = http_post(&addr, "/verify", &bad_hdrs, &env_bytes);
    assert!(head.contains("200 OK"), "reject head: {head}");
    assert!(body.contains("\"ok\":false"), "reject body: {body}");
    assert!(body.contains("statement_mismatch"), "reject body: {body}");

    server.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn service_rejects_garbage_and_unknown_routes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || serve_n(listener, 2));

    let mut stream = TcpStream::connect(&addr).unwrap();
    // Malformed header line (no colon): must fail closed with 400.
    stream
        .write_all(b"GET /x HTTP/1.1\r\nNoColon\r\n\r\n")
        .unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8(resp).unwrap();
    assert!(text.contains("400"), "malformed head: {text}");

    let (head, _) = http_get(&addr, "/nope");
    assert!(head.contains("404"), "route head: {head}");

    server.join().unwrap();
}
