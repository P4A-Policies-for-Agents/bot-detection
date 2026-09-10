// Copyright 2026 Salesforce, Inc. All rights reserved.

mod common;

use httpmock::MockServer;
use pdk_test::{pdk_test, TestComposite};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use common::*;

const FLEX_PORT: Port = 8081;

async fn composite(policy_json: serde_json::Value) -> anyhow::Result<TestComposite> {
    let httpmock_config = HttpMockConfig::builder().port(80).version("latest").hostname("backend").build();
    let policy_config = PolicyConfig::builder().name(POLICY_NAME).configuration(policy_json).build();
    let api_config = ApiConfig::builder()
        .name("ingress-http").upstream(&httpmock_config).path("/").port(FLEX_PORT).policies([policy_config]).build();
    let flex_config = FlexConfig::builder()
        .version("1.13.0").hostname("local-flex")
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .with_api(api_config).build();
    Ok(TestComposite::builder().with_service(flex_config).with_service(httpmock_config).build().await?)
}

#[pdk_test]
async fn block_mode_rejects_curl() -> anyhow::Result<()> {
    let composite = composite(serde_json::json!({"mode":"block","blockBody":"blocked"})).await?;
    let flex: Flex = composite.service()?;
    let url = flex.external_url(FLEX_PORT).unwrap();
    let httpmock: HttpMock = composite.service()?;
    let mock = MockServer::connect_async(httpmock.socket()).await;
    mock.mock_async(|when, then| { when.path_contains("/"); then.status(200).body("upstream"); }).await;

    let resp = reqwest::Client::new().get(format!("{url}/api")).header("user-agent", "curl/8.4.0").send().await?;
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.text().await?, "blocked");
    Ok(())
}

#[pdk_test]
async fn audit_mode_injects_marker_upstream() -> anyhow::Result<()> {
    let composite = composite(serde_json::json!({"mode":"audit"})).await?;
    let flex: Flex = composite.service()?;
    let url = flex.external_url(FLEX_PORT).unwrap();
    let httpmock: HttpMock = composite.service()?;
    let mock = MockServer::connect_async(httpmock.socket()).await;
    let hit = mock.mock_async(|when, then| {
        when.path_contains("/").header_exists("x-p4a-bot-detection");
        then.status(200).body("ok");
    }).await;

    let resp = reqwest::Client::new().get(format!("{url}/api")).header("user-agent", "curl/8.4.0").send().await?;
    assert_eq!(resp.status(), 200);
    hit.assert();
    Ok(())
}

#[pdk_test]
async fn human_request_passes() -> anyhow::Result<()> {
    let composite = composite(serde_json::json!({"mode":"block"})).await?;
    let flex: Flex = composite.service()?;
    let url = flex.external_url(FLEX_PORT).unwrap();
    let httpmock: HttpMock = composite.service()?;
    let mock = MockServer::connect_async(httpmock.socket()).await;
    mock.mock_async(|when, then| { when.path_contains("/"); then.status(200).body("ok"); }).await;

    let resp = reqwest::Client::new().get(format!("{url}/api"))
        .header("user-agent", "Mozilla/5.0 (Macintosh)")
        .header("accept", "text/html").header("accept-language", "en-US")
        .header("sec-fetch-mode", "navigate").header("sec-ch-ua", "\"Chromium\";v=\"120\"")
        .send().await?;
    assert_eq!(resp.status(), 200);
    Ok(())
}
