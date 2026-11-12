//! `rsp-attester`: minimal std-only HTTP service wrapping [`handle_verify`].
//!
//! Routes: `GET /healthz` → service JSON; `POST /verify` → JSON verdict
//! (always HTTP 200 for a well-formed HTTP request; 400 only for HTTP
//! framing errors). Request/response shapes are defined in
//! [`range_set_mpcith::attester`].
//!
//! Usage: `rsp-attester --listen 127.0.0.1:8080`
//! Binds the loopback interface by default; binding a public interface is a
//! deployment decision documented in `docs/fabric-integration.md`.

use std::net::TcpListener;

use range_set_mpcith::attester::serve_forever;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let listen = args
        .windows(2)
        .find(|w| w[0] == "--listen")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("bind {listen} failed: {e}");
        std::process::exit(1);
    });
    eprintln!("rsp-attester listening on {listen}");
    serve_forever(listener);
}
