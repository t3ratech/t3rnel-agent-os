use std::sync::Arc;

mod audit;
mod auth;
mod client;
mod tools;

use tools::T3rnelMcpServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("t3rnel_mcp=debug".parse()?)
                .add_directive("rmcp=info".parse()?),
        )
        .with_writer(std::io::stderr)
        .init();

    let daemon_url =
        std::env::var("T3RNEL_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());

    let api_key = std::env::var("T3RNEL_API_KEY").ok();

    let capability_tier =
        std::env::var("T3RNEL_MCP_TIER").unwrap_or_else(|_| "observe".to_string());

    let is_inventor = std::env::var("T3RNEL_INVENTOR_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    tracing::info!(
        daemon_url = %daemon_url,
        tier = %capability_tier,
        inventor_mode = is_inventor,
        "starting t3rnel MCP server"
    );

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let server = Arc::new(T3rnelMcpServer::new(
        http_client,
        daemon_url,
        api_key,
        capability_tier,
        is_inventor,
    )?);

    let service = rmcp::serve_server(server, rmcp::transport::stdio()).await?;

    tracing::info!("MCP server running on stdio; waiting for shutdown");
    service.waiting().await?;
    tracing::info!("MCP server shutting down");

    Ok(())
}
