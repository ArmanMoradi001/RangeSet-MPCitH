//! Off-chain attester service logic (integration layer, not protocol).
//!
//! This module contains the pure, socket-free core of the `rsp-attester`
//! HTTP service: parsing a minimal HTTP/1.0-1.1 request, mapping headers to
//! ledger-held expectations, running [`verify_envelope`], and rendering a
//! fixed-shape JSON verdict. The binary (`src/bin/rsp-attester.rs`) only
//! moves bytes between TCP and these functions, so all behavior below is
//! unit-testable without a network.
//!
//! Request contract (`POST /verify`):
//! - Headers `X-Expected-Range-Lo`, `X-Expected-Range-Hi`,
//!   `X-Expected-Set-Root` (64 hex chars), `X-Expected-Num-Members`,
//!   `X-Expected-Depth`, `X-Expected-Context` (64 hex chars),
//!   `X-Allowed-Params` (comma-separated preset ids from [`named_params`]).
//! - Body: raw [`ProofEnvelopeV1`] bytes (cap [`MAX_BODY_BYTES`]).
//!
//! Response contract: always HTTP 200 with a fixed-shape JSON body,
//! `{"ok":true,"envelope_hash":"…","proof_bytes":N}` or
//! `{"ok":false,"error":"…","reason":"…"}`. Transport success is never
//! confused with verification success. No security claim attaches to this
//! API; it reports what the (experimental, unreviewed) verifier computed.

use crate::v3::envelope::{
    named_params, verify_envelope, EnvelopeReject, ExpectedStatement, ProofEnvelopeV1,
    MAX_ENVELOPE_PROOF_BYTES,
};
use crate::v3::params::V3Params;

/// Service identity string in `/healthz` and error prefixes.
pub const SERVICE_NAME: &str = "rsp-attester";

/// Envelope format version served by this binary.
pub const SERVICE_ENVELOPE_VERSION: u16 = 1;

/// Fail-closed cap on the HTTP body (envelope + framing headroom).
pub const MAX_BODY_BYTES: usize = MAX_ENVELOPE_PROOF_BYTES + 4096;

/// A parsed verify request: who the ledger expects, what is allowed, and
/// the opaque envelope bytes to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyRequest {
    pub expected: ExpectedStatement,
    pub allowed: Vec<V3Params>,
    pub envelope_bytes: Vec<u8>,
}

/// The verdict rendered as JSON. `ok` mirrors HTTP 200 in every case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub ok: bool,
    /// Hex envelope hash on success, empty string otherwise.
    pub envelope_hash: String,
    /// Carried proof length on success, 0 otherwise.
    pub proof_bytes: usize,
    /// Machine-readable reason (`ok`, or the [`EnvelopeReject`] path).
    pub error: String,
    /// Human-readable detail (verifier message); empty on success.
    pub reason: String,
}

/// Request parsing failures (transport/API layer, before verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// Not a parseable HTTP request (bad method/path/version/headers).
    BadRequest(String),
    /// Body exceeds [`MAX_BODY_BYTES`] or `Content-Length` is missing/bad.
    BodyRejected(String),
    /// A required `X-Expected-*` / `X-Allowed-Params` header is missing or
    /// malformed (names the header).
    BadHeader { header: &'static str, detail: String },
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::BadRequest(d) => write!(f, "bad request: {d}"),
            ApiError::BodyRejected(d) => write!(f, "body rejected: {d}"),
            ApiError::BadHeader { header, detail } => {
                write!(f, "bad header {header}: {detail}")
            }
        }
    }
}

impl std::error::Error for ApiError {}

fn parse_u32_header(headers: &[(&str, &str)], name: &'static str) -> Result<u32, ApiError> {
    let raw = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .ok_or(ApiError::BadHeader {
            header: name,
            detail: "missing".into(),
        })?;
    raw.parse::<u32>().map_err(|_| ApiError::BadHeader {
        header: name,
        detail: format!("not a u32: {raw:?}"),
    })
}

fn parse_hex32_header(headers: &[(&str, &str)], name: &'static str) -> Result<[u8; 32], ApiError> {
    let raw = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .ok_or(ApiError::BadHeader {
            header: name,
            detail: "missing".into(),
        })?;
    let bytes = hex::decode(raw).map_err(|_| ApiError::BadHeader {
        header: name,
        detail: "not hex".into(),
    })?;
    if bytes.len() != 32 {
        return Err(ApiError::BadHeader {
            header: name,
            detail: format!("need 64 hex chars, got {} chars", raw.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Split a raw HTTP request into method, path, headers, and body.
/// Only the head is interpreted as UTF-8; the body stays opaque bytes
/// (envelope payloads are binary). Returns the body slice range so the
/// caller avoids copying twice.
pub fn split_http_request(
    buf: &[u8],
) -> Result<(&str, &str, Vec<(&str, &str)>, usize, usize), ApiError> {
    // Header terminator search on raw bytes: the body is binary and must
    // never go through UTF-8 validation.
    let term = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ApiError::BadRequest("no header terminator".into()))?;
    let head = std::str::from_utf8(&buf[..term])
        .map_err(|_| ApiError::BadRequest("head is not UTF-8".into()))?;
    let body_off = term + 4;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ApiError::BadRequest("empty request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ApiError::BadRequest("no method".into()))?;
    let path = parts
        .next()
        .ok_or_else(|| ApiError::BadRequest("no path".into()))?;
    let mut headers = Vec::new();
    for line in lines {
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| ApiError::BadRequest(format!("bad header line {line:?}")))?;
        headers.push((k.trim(), v.trim()));
    }
    // Body end: honor Content-Length when present, else take all received.
    let body_end = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| {
            v.trim().parse::<usize>().map_err(|_| {
                ApiError::BodyRejected(format!("bad Content-Length {v:?}"))
            })
        })
        .transpose()?
        .map(|len| body_off.saturating_add(len))
        .unwrap_or(buf.len());
    if body_end > buf.len() {
        return Err(ApiError::BodyRejected("body shorter than Content-Length".into()));
    }
    Ok((method, path, headers, body_off, body_end))
}

/// Build a [`VerifyRequest`] from parsed headers + body.
pub fn verify_request_from_parts(
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<VerifyRequest, ApiError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ApiError::BodyRejected(format!(
            "body {} bytes exceeds cap {MAX_BODY_BYTES}",
            body.len()
        )));
    }
    let expected = ExpectedStatement {
        range_lo: parse_u32_header(headers, "X-Expected-Range-Lo")?,
        range_hi: parse_u32_header(headers, "X-Expected-Range-Hi")?,
        set_root: parse_hex32_header(headers, "X-Expected-Set-Root")?,
        num_members: parse_u32_header(headers, "X-Expected-Num-Members")?,
        depth: parse_u32_header(headers, "X-Expected-Depth")?,
        context: parse_hex32_header(headers, "X-Expected-Context")?,
    };
    let allowed_raw = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-Allowed-Params"))
        .map(|(_, v)| *v)
        .ok_or(ApiError::BadHeader {
            header: "X-Allowed-Params",
            detail: "missing".into(),
        })?;
    let mut allowed = Vec::new();
    for id in allowed_raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match named_params(id) {
            Some(p) => {
                if !allowed.contains(&p) {
                    allowed.push(p);
                }
            }
            None => {
                return Err(ApiError::BadHeader {
                    header: "X-Allowed-Params",
                    detail: format!("unknown preset {id:?}"),
                })
            }
        }
    }
    if allowed.is_empty() {
        return Err(ApiError::BadHeader {
            header: "X-Allowed-Params",
            detail: "empty allowlist".into(),
        });
    }
    Ok(VerifyRequest {
        expected,
        allowed,
        envelope_bytes: body.to_vec(),
    })
}

/// Map an [`EnvelopeReject`] to a stable machine-readable error token.
pub fn reject_token(reject: &EnvelopeReject) -> &'static str {
    match reject {
        EnvelopeReject::ParamsInvalid(_) => "params_invalid",
        EnvelopeReject::ParamsNotAllowed => "params_not_allowed",
        EnvelopeReject::StatementMismatch { .. } => "statement_mismatch",
        EnvelopeReject::ProofTooLarge { .. } => "proof_too_large",
        EnvelopeReject::ProofParse(_) => "proof_parse",
        EnvelopeReject::HeaderMismatch { .. } => "header_mismatch",
        EnvelopeReject::StatementInvalid(_) => "statement_invalid",
        EnvelopeReject::VerificationFailed(_) => "verification_failed",
        EnvelopeReject::Codec(_) => "envelope_codec",
    }
}

/// Run verification for a parsed request. Never panics on adversary input:
/// oversized or malformed envelopes surface as [`Attestation`] with
/// `ok == false`.
pub fn handle_verify(req: &VerifyRequest) -> Attestation {
    if req.envelope_bytes.len() > MAX_BODY_BYTES {
        return Attestation {
            ok: false,
            envelope_hash: String::new(),
            proof_bytes: 0,
            error: "body_too_large".into(),
            reason: format!(
                "envelope {} bytes exceeds cap {MAX_BODY_BYTES}",
                req.envelope_bytes.len()
            ),
        };
    }
    let env = match ProofEnvelopeV1::from_bytes(&req.envelope_bytes) {
        Ok(env) => env,
        Err(e) => {
            return Attestation {
                ok: false,
                envelope_hash: String::new(),
                proof_bytes: 0,
                error: reject_token(&EnvelopeReject::Codec(String::new())).into(),
                reason: format!("{e}"),
            }
        }
    };
    match verify_envelope(&env, &req.expected, &req.allowed) {
        Ok(()) => Attestation {
            ok: true,
            envelope_hash: env.envelope_hash_hex().unwrap_or_default(),
            proof_bytes: env.proof_bytes.len(),
            error: "ok".into(),
            reason: String::new(),
        },
        Err(e) => Attestation {
            ok: false,
            envelope_hash: String::new(),
            proof_bytes: 0,
            error: reject_token(&e).into(),
            reason: format!("{e}"),
        },
    }
}

/// Escape a string for embedding in the fixed-shape JSON we emit.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render an [`Attestation`] as the fixed-shape JSON body.
pub fn attestation_json(a: &Attestation) -> String {
    format!(
        "{{\"ok\":{},\"envelope_hash\":\"{}\",\"proof_bytes\":{},\"error\":\"{}\",\"reason\":\"{}\"}}",
        a.ok,
        a.envelope_hash,
        a.proof_bytes,
        json_escape(&a.error),
        json_escape(&a.reason),
    )
}

/// Render the `/healthz` body.
pub fn health_json() -> String {
    format!(
        "{{\"status\":\"ok\",\"service\":\"{SERVICE_NAME}\",\"envelope_version\":{SERVICE_ENVELOPE_VERSION}}}"
    )
}

/// Render an [`ApiError`] as a JSON error body (transport-level failure).
pub fn api_error_json(e: &ApiError) -> String {
    let (error, reason) = match e {
        ApiError::BadRequest(d) => ("bad_request", d.clone()),
        ApiError::BodyRejected(d) => ("body_rejected", d.clone()),
        ApiError::BadHeader { header, detail } => (
            "bad_header",
            format!("{header}: {detail}"),
        ),
    };
    format!(
        "{{\"ok\":false,\"envelope_hash\":\"\",\"proof_bytes\":0,\"error\":\"{}\",\"reason\":\"{}\"}}",
        json_escape(error),
        json_escape(&reason),
    )
}

// ---------------------------------------------------------------------------
// Socket serving (shared by the `rsp-attester` binary and socket-level
// tests). Pure HTTP framing around the functions above; no verification
// logic lives here.
// ---------------------------------------------------------------------------

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn respond(stream: &TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = stream;
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

/// Serve one already-accepted connection (blocking).
pub fn handle_connection(mut stream: TcpStream) {
    if stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .is_err()
    {
        return;
    }
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        match stream.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > MAX_BODY_BYTES + 8192 {
                    respond(
                        &stream,
                        "400 Bad Request",
                        &api_error_json(&ApiError::BodyRejected("headers exceed cap".into())),
                    );
                    return;
                }
                if let Some(i) = find_double_crlf(&buf) {
                    break i;
                }
            }
            Err(_) => return,
        }
    };
    let content_len = header_value(&buf[..head_end], "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_len > MAX_BODY_BYTES {
        respond(
            &stream,
            "400 Bad Request",
            &api_error_json(&ApiError::BodyRejected(format!(
                "Content-Length {content_len} exceeds cap {MAX_BODY_BYTES}"
            ))),
        );
        return;
    }
    while buf.len() < head_end + content_len {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return,
        }
        if buf.len() > MAX_BODY_BYTES + 8192 {
            respond(
                &stream,
                "400 Bad Request",
                &api_error_json(&ApiError::BodyRejected("body exceeds cap".into())),
            );
            return;
        }
    }
    let total = head_end + content_len.min(buf.len().saturating_sub(head_end));
    let req_bytes = &buf[..total];
    let (method, path, headers, body_off, body_end) = match split_http_request(req_bytes) {
        Ok(parts) => parts,
        Err(e) => {
            respond(&stream, "400 Bad Request", &api_error_json(&e));
            return;
        }
    };
    match (method, path) {
        ("GET", "/healthz") => respond(&stream, "200 OK", &health_json()),
        ("POST", "/verify") => {
            let body = &req_bytes[body_off..body_end];
            match verify_request_from_parts(&headers, body) {
                Ok(req) => respond(&stream, "200 OK", &attestation_json(&handle_verify(&req))),
                Err(e) => respond(&stream, "200 OK", &api_error_json(&e)),
            }
        }
        _ => respond(
            &stream,
            "404 Not Found",
            &api_error_json(&ApiError::BadRequest("unknown route".into())),
        ),
    }
}

/// Serve exactly `n` connections sequentially, then return. Used by
/// socket-level tests for a deterministic shutdown.
pub fn serve_n(listener: TcpListener, n: usize) {
    for stream in listener.incoming().take(n) {
        match stream {
            Ok(stream) => handle_connection(stream),
            Err(_) => return,
        }
    }
}

/// Serve forever with one thread per connection. Used by `rsp-attester`.
pub fn serve_forever(listener: TcpListener) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || handle_connection(stream));
            }
            Err(e) => eprintln!("{SERVICE_NAME}: accept failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(String, String)]) -> Vec<(&str, &str)> {
        pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    #[test]
    fn split_request_parses_method_path_headers_body() {
        let raw = b"POST /verify HTTP/1.1\r\nContent-Length: 3\r\nX-A: b\r\n\r\nabc";
        let (method, path, hdrs, off, end) = split_http_request(raw).unwrap();
        assert_eq!((method, path), ("POST", "/verify"));
        assert!(hdrs.contains(&("X-A", "b")));
        assert_eq!(&raw[off..end], b"abc");
    }

    #[test]
    fn split_request_rejects_garbage() {
        assert!(split_http_request(b"garbage").is_err());
        assert!(split_http_request(b"GET /x HTTP/1.1\r\nNoColon\r\n\r\n").is_err());
    }

    #[test]
    fn header_parsers_name_the_header() {
        let owned = [("X-Expected-Range-Lo".to_string(), "abc".to_string())];
        let hdrs = headers(&owned);
        assert_eq!(
            parse_u32_header(&hdrs, "X-Expected-Range-Lo"),
            Err(ApiError::BadHeader {
                header: "X-Expected-Range-Lo",
                detail: "not a u32: \"abc\"".into(),
            })
        );
        let missing: Vec<(&str, &str)> = vec![];
        assert!(matches!(
            parse_hex32_header(&missing, "X-Expected-Set-Root"),
            Err(ApiError::BadHeader { .. })
        ));
    }

    #[test]
    fn allowlist_rejects_unknown_preset() {
        let owned = [
            ("X-Expected-Range-Lo".to_string(), "10".to_string()),
            ("X-Expected-Range-Hi".to_string(), "40".to_string()),
            ("X-Expected-Set-Root".to_string(), "ab".repeat(32)),
            ("X-Expected-Num-Members".to_string(), "4".to_string()),
            ("X-Expected-Depth".to_string(), "2".to_string()),
            ("X-Expected-Context".to_string(), "07".repeat(32)),
            ("X-Allowed-Params".to_string(), "no-such-preset".to_string()),
        ];
        let hdrs = headers(&owned);
        assert!(matches!(
            verify_request_from_parts(&hdrs, b"bytes"),
            Err(ApiError::BadHeader { .. })
        ));
    }

    #[test]
    fn oversize_body_rejected_before_verify() {
        let req = VerifyRequest {
            expected: ExpectedStatement {
                range_lo: 0,
                range_hi: 0,
                set_root: [0u8; 32],
                num_members: 0,
                depth: 0,
                context: [0u8; 32],
            },
            allowed: vec![],
            envelope_bytes: vec![0u8; MAX_BODY_BYTES + 1],
        };
        let a = handle_verify(&req);
        assert!(!a.ok);
        assert_eq!(a.error, "body_too_large");
    }

    #[test]
    fn json_shapes_are_fixed() {
        let a = Attestation {
            ok: true,
            envelope_hash: "ab".into(),
            proof_bytes: 7,
            error: "ok".into(),
            reason: String::new(),
        };
        assert_eq!(
            attestation_json(&a),
            r#"{"ok":true,"envelope_hash":"ab","proof_bytes":7,"error":"ok","reason":""}"#
        );
        assert!(health_json().contains(SERVICE_NAME));
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn reject_tokens_cover_every_variant() {
        let cases = [
            (
                EnvelopeReject::ParamsInvalid("x".into()),
                "params_invalid",
            ),
            (EnvelopeReject::ParamsNotAllowed, "params_not_allowed"),
            (
                EnvelopeReject::StatementMismatch { field: "depth" },
                "statement_mismatch",
            ),
            (
                EnvelopeReject::ProofTooLarge { len: 1 },
                "proof_too_large",
            ),
            (EnvelopeReject::ProofParse("x".into()), "proof_parse"),
            (
                EnvelopeReject::HeaderMismatch { field: "depth" },
                "header_mismatch",
            ),
            (
                EnvelopeReject::StatementInvalid("x".into()),
                "statement_invalid",
            ),
            (
                EnvelopeReject::VerificationFailed("x".into()),
                "verification_failed",
            ),
            (EnvelopeReject::Codec("x".into()), "envelope_codec"),
        ];
        for (reject, token) in cases {
            assert_eq!(reject_token(&reject), token);
        }
    }
}
