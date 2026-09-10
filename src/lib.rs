// Copyright 2026 Salesforce, Inc. All rights reserved.
mod classifier;
mod generated;

use crate::classifier::{classify, ClassifierConfig, Verdict};
use crate::generated::config::Config;
use anyhow::{anyhow, Result};
use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;
use std::collections::HashSet;

const MARKER_HEADER: &str = "x-p4a-bot-detection";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Audit,
    Block,
}

struct ResolvedConfig {
    mode: Mode,
    allowlist: Vec<String>,
    denylist: Vec<String>,
    required_browser_headers: Vec<String>,
    header_signature_threshold: usize,
    fail_open: bool,
    block_status_code: i64,
    block_body: String,
}

impl From<&Config> for ResolvedConfig {
    fn from(c: &Config) -> Self {
        let default_denylist = [
            "curl",
            "wget",
            "python-requests",
            "Go-http-client",
            "PostmanRuntime",
            "java",
            "libwww-perl",
            "okhttp",
            "aiohttp",
            "node-fetch",
        ];
        let default_required = ["Accept", "Accept-Language", "Sec-Fetch-Mode", "sec-ch-ua"];
        ResolvedConfig {
            mode: match c.mode.as_deref() {
                Some("block") => Mode::Block,
                _ => Mode::Audit,
            },
            allowlist: c.user_agent_allowlist.clone().unwrap_or_default(),
            denylist: c
                .user_agent_denylist
                .clone()
                .unwrap_or_else(|| default_denylist.iter().map(|s| s.to_string()).collect()),
            required_browser_headers: c
                .required_browser_headers
                .clone()
                .unwrap_or_else(|| default_required.iter().map(|s| s.to_string()).collect()),
            header_signature_threshold: c.header_signature_threshold.unwrap_or(2).max(0) as usize,
            fail_open: c.fail_open.unwrap_or(true),
            block_status_code: c.block_status_code.unwrap_or(403),
            block_body: c
                .block_body
                .clone()
                .unwrap_or_else(|| "Request blocked: automated client detected.".to_string()),
        }
    }
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    violations: PolicyViolations,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("Failed to parse configuration: {e}"))?;
    let resolved = ResolvedConfig::from(&config);
    let filter = on_request(|rs| request_filter(rs, &resolved, &violations));
    launcher.launch(filter).await?;
    Ok(())
}

async fn request_filter(
    request_state: RequestState,
    cfg: &ResolvedConfig,
    violations: &PolicyViolations,
) -> Flow<()> {
    let headers_state = request_state.into_headers_state().await;
    let handler = headers_state.handler();

    let user_agent = handler.header("user-agent");
    let present: HashSet<String> = cfg
        .required_browser_headers
        .iter()
        .filter(|h| {
            handler
                .header(&h.to_lowercase())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .map(|h| h.to_lowercase())
        .collect();

    let classifier_cfg = ClassifierConfig {
        allowlist: &cfg.allowlist,
        denylist: &cfg.denylist,
        required_browser_headers: &cfg.required_browser_headers,
        header_signature_threshold: cfg.header_signature_threshold,
    };

    match classify(user_agent.as_deref(), &present, &classifier_cfg) {
        Verdict::Human => Flow::Continue(()),
        Verdict::Bot { reasons } => {
            violations.generate_policy_violation();
            let reason_str = reasons.join(",");
            match cfg.mode {
                Mode::Block => {
                    if !(100..=599).contains(&cfg.block_status_code) {
                        logger::error!(
                            "Invalid blockStatusCode {}; failOpen={}",
                            cfg.block_status_code,
                            cfg.fail_open
                        );
                        return if cfg.fail_open {
                            Flow::Continue(())
                        } else {
                            Flow::Break(Response::new(500))
                        };
                    }
                    logger::warn!("Bot blocked [{}]: {}", cfg.block_status_code, reason_str);
                    Flow::Break(
                        Response::new(cfg.block_status_code as u32)
                            .with_body(cfg.block_body.clone().into_bytes()),
                    )
                }
                Mode::Audit => {
                    logger::warn!("Bot flagged (audit): {}", reason_str);
                    handler.add_header(MARKER_HEADER, "flagged");
                    Flow::Continue(())
                }
            }
        }
    }
}

#[cfg(test)]
mod filter_tests {
    use pdk_unit::{UnitTestBuilder, UnitHttpRequest, UnitHttpResponse, UnitHttpMessage, TraceBackend};
    use std::rc::Rc;

    const SCRIPTED_UA: &str = "python-requests/2.31.0";
    const BROWSER_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";

    fn browser_request() -> UnitHttpRequest {
        UnitHttpRequest::get()
            .with_path("/api/resource")
            .with_header("user-agent", BROWSER_UA)
            .with_header("accept", "text/html")
            .with_header("accept-language", "en-US")
            .with_header("sec-fetch-mode", "navigate")
            .with_header("sec-ch-ua", "\"Chromium\";v=\"120\"")
    }

    #[test]
    fn audit_mode_passes_scripted_request_and_injects_marker() {
        let backend = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(r#"{"mode":"audit"}"#)
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(crate::configure);

        let resp = tester.request(UnitHttpRequest::get().with_path("/x").with_header("user-agent", SCRIPTED_UA));
        assert_eq!(resp.status_code(), 200);
        let upstream = backend.next().unwrap();
        assert_eq!(upstream.header("x-p4a-bot-detection").as_deref(), Some("flagged"));
    }

    #[test]
    fn block_mode_rejects_scripted_request() {
        let mut tester = UnitTestBuilder::default()
            .with_config(r#"{"mode":"block","blockBody":"nope"}"#)
            .with_entrypoint(crate::configure);
        let resp = tester.request(UnitHttpRequest::get().with_path("/x").with_header("user-agent", SCRIPTED_UA));
        assert_eq!(resp.status_code(), 403);
        assert_eq!(std::str::from_utf8(resp.body()).unwrap(), "nope");
    }

    #[test]
    fn human_request_passes_untouched_in_block_mode() {
        let backend = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(r#"{"mode":"block"}"#)
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(crate::configure);
        let resp = tester.request(browser_request());
        assert_eq!(resp.status_code(), 200);
        let upstream = backend.next().unwrap();
        assert!(upstream.header("x-p4a-bot-detection").is_none());
    }

    #[test]
    fn fail_open_governs_invalid_block_status_code() {
        let backend = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
        // invalid blockStatusCode + failOpen true -> request continues
        let mut open = UnitTestBuilder::default()
            .with_config(r#"{"mode":"block","blockStatusCode":999,"failOpen":true}"#)
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(crate::configure);
        assert_eq!(open.request(UnitHttpRequest::get().with_path("/x").with_header("user-agent", SCRIPTED_UA)).status_code(), 200);

        // failOpen false -> 500
        let mut closed = UnitTestBuilder::default()
            .with_config(r#"{"mode":"block","blockStatusCode":999,"failOpen":false}"#)
            .with_entrypoint(crate::configure);
        assert_eq!(closed.request(UnitHttpRequest::get().with_path("/x").with_header("user-agent", SCRIPTED_UA)).status_code(), 500);
    }
}

#[cfg(test)]
mod config_tests {
    use crate::generated::config::Config;

    #[test]
    fn parses_partial_config_with_camelcase_aliases() {
        let json = r#"{"mode":"block","headerSignatureThreshold":3}"#;
        let cfg: Config = serde_json::from_slice(json.as_bytes()).unwrap();
        assert_eq!(cfg.mode.as_deref(), Some("block"));
        assert_eq!(cfg.header_signature_threshold, Some(3));
        assert!(cfg.user_agent_denylist.is_none());
    }
}
