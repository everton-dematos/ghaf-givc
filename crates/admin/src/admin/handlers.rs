use sigmars::rule::SigmaRule;
use std::collections::HashMap;
use tracing::info;

pub fn handle_response_for_match(rule: &SigmaRule, level: &str, source_vm: &str, message: &str) {
    // Check tags for category-based response logic
    if let Some(tags) = &rule.tags {
        if tags
            .iter()
            .any(|tag| tag == "attack.defense_evasion" || tag == "attack.impact")
        {
            respond_ssh_stop(source_vm, message);
            return;
        }
    }

    // Fallback: use severity level
    match level {
        "critical" => respond_critical_level(source_vm, message),
        _ => {}
    }
}

fn respond_ssh_stop(source_vm: &str, message: &str) {
    if source_vm == "ghaf-host" || source_vm == "admin-vm" {
        info!(
            "[RESPONSE] SSH stop detected on critical VM ({}), no reboot action taken.",
            source_vm
        );
        return;
    }

    info!(
        "[RESPONSE] SSH stop detected on {}, triggering reboot. MSG: {}",
        source_vm, message
    );

    // TODO: Add logic here
}

fn respond_critical_level(source_vm: &str, message: &str) {
    info!(
        "[RESPONSE] High severity log received from {} | MSG: {}",
        source_vm, message
    );
    // TODO: Add logic here
}
