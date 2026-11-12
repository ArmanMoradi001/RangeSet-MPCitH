//! `rsp-verify`: verify a proof envelope file against caller-supplied
//! (ledger-held) expectations. The machine-readable twin of the attester
//! service's `POST /verify`, for scripts and the Fabric bring-up runbook.
//!
//! Usage:
//! ```sh
//! rsp-verify --envelope proof.env --lo 10 --hi 40 --set-root <64 hex> \
//!   --num-members 4 --depth 2 --context <64 hex> \
//!   --allowed-params fast-insecure-test
//! ```
//! Prints the fixed-shape JSON verdict. Exit 0 iff the proof verifies,
//! 1 if it is rejected or invalid, 2 on usage error.

use std::process::ExitCode;

use range_set_mpcith::attester::{
    attestation_json, handle_verify, verify_request_from_parts,
};

fn usage() -> ! {
    eprintln!(
        "usage: rsp-verify --envelope FILE --lo LO --hi HI --set-root HEX64 \
--num-members N --depth D --context HEX64 --allowed-params A[,B...]"
    );
    std::process::exit(2);
}

fn arg(args: &[String], name: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| {
            eprintln!("missing {name}");
            usage();
        })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let path = arg(&args, "--envelope");
    let body = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("read {path} failed: {e}");
        std::process::exit(1);
    });
    let headers = [
        ("X-Expected-Range-Lo", arg(&args, "--lo")),
        ("X-Expected-Range-Hi", arg(&args, "--hi")),
        ("X-Expected-Set-Root", arg(&args, "--set-root")),
        ("X-Expected-Num-Members", arg(&args, "--num-members")),
        ("X-Expected-Depth", arg(&args, "--depth")),
        ("X-Expected-Context", arg(&args, "--context")),
        ("X-Allowed-Params", arg(&args, "--allowed-params")),
    ];
    let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let req = match verify_request_from_parts(&refs, &body) {
        Ok(req) => req,
        Err(e) => {
            println!(
                "{{\"ok\":false,\"envelope_hash\":\"\",\"proof_bytes\":0,\"error\":\"bad_header\",\"reason\":\"{e}\"}}"
            );
            return ExitCode::from(1);
        }
    };
    let attestation = handle_verify(&req);
    println!("{}", attestation_json(&attestation));
    if attestation.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
