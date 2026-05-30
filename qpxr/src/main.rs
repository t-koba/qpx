use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    qpxr::run().await
}
