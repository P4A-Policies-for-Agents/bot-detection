use std::collections::HashSet;

#[derive(Debug)]
pub enum Verdict {
    Human,
    Bot { reasons: Vec<String> },
}

pub struct ClassifierConfig<'a> {
    pub allowlist: &'a [String],
    pub denylist: &'a [String],
    pub required_browser_headers: &'a [String],
    pub header_signature_threshold: usize,
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Classify a request. `present_headers` holds lowercased names of headers
/// present with a non-empty value. Pure: no PDK / IO dependencies.
pub fn classify(
    user_agent: Option<&str>,
    present_headers: &HashSet<String>,
    cfg: &ClassifierConfig,
) -> Verdict {
    let ua = user_agent.map(str::trim).filter(|s| !s.is_empty());

    // 1. Allowlist short-circuit.
    if let Some(ua) = ua {
        if cfg.allowlist.iter().any(|p| contains_ci(ua, p)) {
            return Verdict::Human;
        }
    }

    let mut reasons = Vec::new();

    // 2a. User-Agent signal.
    match ua {
        None => reasons.push("ua_missing".to_string()),
        Some(ua) => {
            if let Some(pat) = cfg.denylist.iter().find(|p| contains_ci(ua, p)) {
                reasons.push(format!("ua_denylisted:{pat}"));
            }
        }
    }

    // 2b. Header-signature signal.
    let missing = cfg
        .required_browser_headers
        .iter()
        .filter(|h| !present_headers.contains(&h.to_lowercase()))
        .count();
    if cfg.header_signature_threshold > 0 && missing >= cfg.header_signature_threshold {
        reasons.push(format!("missing_headers:{missing}"));
    }

    if reasons.is_empty() {
        Verdict::Human
    } else {
        Verdict::Bot { reasons }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn cfg<'a>(allow: &'a [String], deny: &'a [String], req: &'a [String], t: usize) -> ClassifierConfig<'a> {
        ClassifierConfig { allowlist: allow, denylist: deny, required_browser_headers: req, header_signature_threshold: t }
    }
    fn present(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| n.to_lowercase()).collect()
    }
    fn s(v: &[&str]) -> Vec<String> { v.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn allowlist_wins_over_denylist_and_missing_headers() {
        let allow = s(&["mycorp-monitor"]);
        let deny = s(&["curl"]);
        let req = s(&["Accept", "sec-ch-ua"]);
        let v = classify(Some("curl/8.4 mycorp-monitor"), &present(&[]), &cfg(&allow, &deny, &req, 1));
        assert!(matches!(v, Verdict::Human));
    }

    #[test]
    fn denylisted_user_agent_is_bot_with_reason() {
        let deny = s(&["python-requests"]);
        let req = s(&["Accept"]);
        let v = classify(Some("python-requests/2.31"), &present(&["Accept"]), &cfg(&[], &deny, &req, 5));
        match v {
            Verdict::Bot { reasons } => assert!(reasons.iter().any(|r| r.starts_with("ua_denylisted:"))),
            _ => panic!("expected Bot"),
        }
    }

    #[test]
    fn missing_user_agent_is_bot() {
        let req = s(&["Accept"]);
        let v = classify(None, &present(&["Accept"]), &cfg(&[], &[], &req, 5));
        match v {
            Verdict::Bot { reasons } => assert!(reasons.iter().any(|r| r == "ua_missing")),
            _ => panic!("expected Bot"),
        }
    }

    #[test]
    fn header_signature_threshold_boundary() {
        let req = s(&["Accept", "Accept-Language", "Sec-Fetch-Mode", "sec-ch-ua"]);
        let deny = s(&["curl"]);
        // browser-like UA, 2 of 4 required headers missing, threshold 2 -> Bot
        let at = classify(Some("Mozilla/5.0"), &present(&["Accept", "Accept-Language"]), &cfg(&[], &deny, &req, 2));
        assert!(matches!(at, Verdict::Bot { .. }));
        // 1 missing, threshold 2 -> Human
        let below = classify(Some("Mozilla/5.0"), &present(&["Accept", "Accept-Language", "Sec-Fetch-Mode"]), &cfg(&[], &deny, &req, 2));
        assert!(matches!(below, Verdict::Human));
    }

    #[test]
    fn clean_browser_request_is_human() {
        let req = s(&["Accept", "Accept-Language", "Sec-Fetch-Mode", "sec-ch-ua"]);
        let deny = s(&["curl", "python-requests"]);
        let v = classify(Some("Mozilla/5.0 (Macintosh)"), &present(&["Accept", "Accept-Language", "Sec-Fetch-Mode", "sec-ch-ua"]), &cfg(&[], &deny, &req, 2));
        assert!(matches!(v, Verdict::Human));
    }

    #[test]
    fn user_agent_matching_is_case_insensitive() {
        let deny = s(&["CURL"]);
        let req = s(&["Accept"]);
        let v = classify(Some("curl/8.4"), &present(&["Accept"]), &cfg(&[], &deny, &req, 5));
        assert!(matches!(v, Verdict::Bot { .. }));
    }
}
