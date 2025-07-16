use sigmars::SigmaCollection;
use tracing::info;

// Load Sigma rules from directory
pub fn load_sigma_rules() -> anyhow::Result<SigmaCollection> {
    let rule_dir = std::env::var("SIGMA_RULE_PATH").expect("SIGMA_RULE_PATH not set");

    info!("Using Sigma rule path: {}", rule_dir);

    let collection = SigmaCollection::new_from_dir(&rule_dir)
        .map_err(|e| anyhow::anyhow!("Failed to load rules: {}", e))?;

    info!("Loaded {} Sigma rules", collection.len());
    Ok(collection)
}
