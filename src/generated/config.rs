use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "blockBody")]
    pub block_body: Option<String>,
    #[serde(alias = "blockStatusCode")]
    pub block_status_code: Option<i64>,
    #[serde(alias = "failOpen")]
    pub fail_open: Option<bool>,
    #[serde(alias = "headerSignatureThreshold")]
    pub header_signature_threshold: Option<i64>,
    #[serde(alias = "mode")]
    pub mode: Option<String>,
    #[serde(alias = "requiredBrowserHeaders")]
    pub required_browser_headers: Option<Vec<String>>,
    #[serde(alias = "userAgentAllowlist")]
    pub user_agent_allowlist: Option<Vec<String>>,
    #[serde(alias = "userAgentDenylist")]
    pub user_agent_denylist: Option<Vec<String>>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
