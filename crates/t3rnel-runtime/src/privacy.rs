//! Privacy tag stripping for persistence boundaries.
//!
//! `<private>...</private>` marks content that may be useful within a live turn
//! but must not be persisted to memory, audit logs, A2A messages, or saved
//! sessions.

use t3rnel_types::message::{ContentBlock, Message, MessageContent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyStripResult {
    pub text: String,
    pub stripped_segments: usize,
}

/// Strip `<private>...</private>` segments from text. Tags are matched
/// case-insensitively, and an unterminated private segment strips to EOF.
pub fn strip_private_tags(input: &str) -> PrivacyStripResult {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    let mut stripped_segments = 0;

    while let Some((start, start_end)) = find_private_start(input, cursor) {
        output.push_str(&input[cursor..start]);
        stripped_segments += 1;
        if let Some((end, end_end)) = find_case_insensitive(input, "</private>", start_end) {
            let _ = end;
            cursor = end_end;
        } else {
            cursor = input.len();
            break;
        }
    }

    if cursor < input.len() {
        output.push_str(&input[cursor..]);
    }

    PrivacyStripResult {
        text: output,
        stripped_segments,
    }
}

/// Sanitize a message before persistence.
pub fn sanitize_message(message: &Message) -> Message {
    Message {
        role: message.role,
        content: sanitize_message_content(&message.content),
        // Preserve when the message was written.
        //
        // This ran over the whole session on every turn, so discarding the
        // timestamp here erased it from every message already stored — not just
        // the one being sanitised. The chat then showed a dash for every time,
        // and each turn re-saved the session with the field gone.
        //
        // A timestamp is not private data: it records when something was said,
        // not what. Redaction belongs in the content, which is what
        // sanitize_message_content handles.
        at: message.at,
        // Preserve server- and provider-assigned message identity: the
        // sanitized copy is the same message, not a new one.
        msg_id: message.msg_id.clone(),
        provider_msg_id: message.provider_msg_id.clone(),
    }
}

pub fn sanitize_message_content(content: &MessageContent) -> MessageContent {
    match content {
        MessageContent::Text(text) => MessageContent::Text(strip_private_tags(text).text),
        MessageContent::Unknown(value) => MessageContent::Unknown(sanitize_json_value(value)),
        MessageContent::Blocks(blocks) => MessageContent::Blocks(sanitize_blocks(blocks)),
    }
}

pub fn sanitize_blocks(blocks: &[ContentBlock]) -> Vec<ContentBlock> {
    blocks
        .iter()
        .map(|block| match block {
            ContentBlock::Text {
                text,
                provider_metadata,
            } => ContentBlock::Text {
                text: strip_private_tags(text).text,
                provider_metadata: provider_metadata.as_ref().map(sanitize_json_value),
            },
            ContentBlock::ToolUse {
                id,
                name,
                input,
                provider_metadata,
            } => ContentBlock::ToolUse {
                id: id.clone(),
                name: name.clone(),
                input: sanitize_json_value(input),
                provider_metadata: provider_metadata.as_ref().map(sanitize_json_value),
            },
            ContentBlock::ToolResult {
                tool_use_id,
                tool_name,
                content,
                is_error,
            } => ContentBlock::ToolResult {
                tool_use_id: tool_use_id.clone(),
                tool_name: tool_name.clone(),
                content: strip_private_tags(content).text,
                is_error: *is_error,
            },
            ContentBlock::Thinking {
                thinking,
                signature,
                provider_metadata,
            } => ContentBlock::Thinking {
                thinking: strip_private_tags(thinking).text,
                signature: signature.clone(),
                provider_metadata: provider_metadata.as_ref().map(sanitize_json_value),
            },
            ContentBlock::Image { media_type, data } => ContentBlock::Image {
                media_type: media_type.clone(),
                data: data.clone(),
            },
            // Opaque provider-generated blob — must be echoed back verbatim
            // or the API rejects the history. It is not user text, so there
            // is nothing to strip.
            ContentBlock::RedactedThinking { data } => {
                ContentBlock::RedactedThinking { data: data.clone() }
            }
            ContentBlock::Unknown => ContentBlock::Unknown,
        })
        .collect()
}

pub fn sanitize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => serde_json::Value::String(strip_private_tags(text).text),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(sanitize_json_value).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), sanitize_json_value(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn find_private_start(input: &str, from: usize) -> Option<(usize, usize)> {
    let (start, _) = find_case_insensitive(input, "<private", from)?;
    let tag_tail = &input[start..];
    let close_rel = tag_tail.find('>')?;
    Some((start, start + close_rel + 1))
}

fn find_case_insensitive(input: &str, needle: &str, from: usize) -> Option<(usize, usize)> {
    if from >= input.len() {
        return None;
    }
    let haystack = input[from..].to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let rel = haystack.find(&needle)?;
    let start = from + rel;
    Some((start, start + needle.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_private_segments_case_insensitively() {
        let result = strip_private_tags("keep <PRIVATE>secret</private> visible");
        assert_eq!(result.text, "keep  visible");
        assert_eq!(result.stripped_segments, 1);
    }

    #[test]
    fn strips_unterminated_private_segment_to_eof() {
        let result = strip_private_tags("keep <private>secret forever");
        assert_eq!(result.text, "keep ");
        assert_eq!(result.stripped_segments, 1);
    }

    #[test]
    fn sanitizes_nested_json_strings() {
        let value = serde_json::json!({
            "cmd": "echo <private>token</private>",
            "args": ["safe", "<private>x</private>y"]
        });
        let sanitized = sanitize_json_value(&value);
        assert_eq!(sanitized["cmd"], "echo ");
        assert_eq!(sanitized["args"][1], "y");
    }
}

#[cfg(test)]
mod timestamp_preservation_tests {
    use super::*;
    use t3rnel_types::message::Role;

    #[test]
    fn sanitising_keeps_the_time_a_message_was_written() {
        // The sanitiser runs across the entire session every turn, so dropping
        // the timestamp erased it from all stored history rather than from one
        // message. A timestamp records when something was said, not what, so it
        // is not redacted.
        let original = Message::user("my email is someone@example.com");
        assert!(original.at.is_some());

        let sanitised = sanitize_message(&original);
        assert_eq!(
            sanitised.at, original.at,
            "sanitising must not erase when the message was written"
        );
    }

    #[test]
    fn an_unstamped_message_stays_unstamped() {
        // Absence is preserved as absence; the sanitiser never invents a time,
        // which would date replayed history to the moment it was sanitised.
        let unstamped = Message {
            role: Role::User,
            content: MessageContent::Text("x".into()),
            ..Default::default()
        };
        assert!(sanitize_message(&unstamped).at.is_none());
    }
}
