use axum::{body::Bytes, http::StatusCode, response::IntoResponse};
use chrono::{DateTime, NaiveDateTime, Utc};
use prost::Message;
use prost_types::Timestamp;
use serde_json::json;
use sigmars::{SigmaCollection, event::Event as SigmaEvent, event::LogSource};
use snap::raw::Decoder;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};

use crate::admin::handlers::handle_response_for_match;

#[derive(prost::Message)]
pub struct PushRequest {
    #[prost(message, repeated, tag = "1")]
    pub streams: Vec<LogStream>,
}

#[derive(prost::Message)]
pub struct LogStream {
    #[prost(string, tag = "1")]
    pub labels: String,
    #[prost(message, repeated, tag = "2")]
    pub entries: Vec<LogEntry>,
}

#[derive(prost::Message)]
pub struct LogEntry {
    #[prost(bytes, tag = "1")]
    pub timestamp: Vec<u8>,
    #[prost(string, tag = "2")]
    pub line: String,
}

/// Parses Loki label string into a map.
pub fn parse_labels(labels: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let trimmed = labels.trim_matches(|c| c == '{' || c == '}');
    for pair in trimmed.split(',') {
        if let Some((key, value)) = pair.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim_matches('"').to_string();
            map.insert(key, value);
        }
    }
    map
}

pub async fn handle_logs(body: Bytes, sigma_rules: Arc<SigmaCollection>) -> impl IntoResponse {
    // Process incoming log POST request

    let mut decoder = Decoder::new();

    match decoder.decompress_vec(&body) {
        Ok(decompressed) => match PushRequest::decode(&*decompressed) {
            Ok(decoded) => {
                for stream in decoded.streams {
                    let labels_map = parse_labels(&stream.labels);

                    // Extract source VM from labels
                    let source_vm = labels_map
                        .get("__journal__hostname")
                        .or_else(|| labels_map.get("nodename"))
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");

                    for entry in stream.entries {
                        let ts = match Timestamp::decode(&*entry.timestamp) {
                            Ok(t) => NaiveDateTime::from_timestamp_opt(t.seconds, t.nanos as u32)
                                .map(|ndt| {
                                    DateTime::<Utc>::from_utc(ndt, Utc)
                                        .format("%b %d %H:%M:%S")
                                        .to_string()
                                })
                                .unwrap_or_else(|| "<invalid timestamp>".to_string()),
                            Err(_) => "<invalid timestamp>".to_string(),
                        };

                        // Normalize line format
                        let line = entry.line.replace('\n', "␤").replace('\r', "␍");
                        // info!("[{} | source: {}] {}", ts, source_vm, line);

                        // Build structured log object
                        let json_log = json!({
                            "timestamp": Utc::now().to_rfc3339(),
                            "hostname": source_vm,
                            "message": line
                        });

                        // Add metadata to event
                        let mut metadata = HashMap::new();
                        metadata.insert("source_vm".to_string(), json!(source_vm));
                        metadata.insert("raw_line".to_string(), json!(line));

                        // info!("{}", json_log.to_string());

                        // Create Sigma event
                        let event = SigmaEvent::new(json_log)
                            .logsource(
                                LogSource::default()
                                    .product("linux")
                                    .service("systemd-journal"),
                            )
                            .metadata(metadata);

                        // info!("EVENT MESSAGE FIELD: {:?}", event.data.get("message"));
                        // info!("DEBUG EVENT LOGSOURCE: {:?}", event.logsource);
                        // info!("DEBUG EVENT METADATA: {:?}", event.metadata);

                        // Run detection logic
                        //let matches = sigma_rules.get_detection_matches_unfiltered(&event);
                        let matches: Vec<String> =
                            sigma_rules.get_detection_matches_unfiltered(&event);

                        // Process all matched rules - it can be more than one
                        for id in matches {
                            let rule = sigma_rules
                                .get(&id)
                                .expect("Matched rule ID not found in collection");

                            let level = rule.level.as_deref().unwrap_or("unknown");
                            info!(
                                "MATCHED RULE: {} | LEVEL: {} | SOURCE VM: {} | LOG: {}",
                                id, level, source_vm, line
                            );

                            // Trigger appropriate respons
                            handle_response_for_match(rule, level, source_vm, &line);
                        }
                    }
                }
            }
            Err(e) => error!("Failed to decode protobuf payload: {}", e),
        },
        Err(e) => error!("Failed to decompress snappy body: {}", e),
    }

    StatusCode::OK
}
