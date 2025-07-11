use std::collections::HashMap;
use tracing::info;

fn redact(key: &str, value: &str) -> String {
    let lower = key.to_ascii_lowercase();
    if lower.contains("authorization") || lower.contains("api-key") || lower.contains("apikey") || lower.contains("token") {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

fn pick_first<'a>(map: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        if let Some(v) = map.get(*k) {
            return Some(v.as_str());
        }
    }
    None
}

/// Best-effort debug logging for OpenAI requests when `OPENAI_DEBUG_BODIES` is set.
/// Truncates body preview and redacts likely secrets.
pub fn log_openai_debug(descriptor_map: &HashMap<String, String>, hits_addend: Option<u64>) {
    if std::env::var("OPENAI_DEBUG_BODIES").is_err() {
        return;
    }

    let path_keys = [":path", "req.path", "http.path", "request.path", "path"];
    let body_keys = [
        "http.request.body",
        "req.body",
        "body",
        "messages",
        "prompt",
        "input",
    ];

    let Some(path) = pick_first(descriptor_map, &path_keys) else { return; };
    let is_openai = path.contains("/v1/completions") || path.contains("/v1/chat/completions");
    if !is_openai {
        return;
    }

    let body_raw = pick_first(descriptor_map, &body_keys).unwrap_or("");
    let mut preview = body_raw.to_string();
    let max_len: usize = std::env::var("OPENAI_DEBUG_MAX_LEN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2048);
    if preview.len() > max_len {
        preview.truncate(max_len);
        preview.push_str("...[truncated]");
    }

    // Also include a small selection of non-sensitive fields if present
    let model = descriptor_map.get("model").map(|v| redact("model", v)).unwrap_or_default();
    let org = descriptor_map
        .get("openai-organization")
        .map(|v| redact("openai-organization", v))
        .unwrap_or_default();

    info!(
        path = path,
        tokens = hits_addend.unwrap_or(0),
        model = %model,
        org = %org,
        body_preview = %preview,
        body_len = body_raw.len(),
        "OpenAI request detected"
    );
}

