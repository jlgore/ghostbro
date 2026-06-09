//! Dependency-free HTML-to-markdown normalizer.
//!
//! This is deliberately not a full HTML parser. The relay's goal (per the PRD)
//! is "stripped-down web content": readable text with the dominant structural
//! markers preserved, the scripting/styling boilerplate removed, and HTML
//! entities decoded. A hand-written tokenizer keeps the dependency surface of
//! this security-sensitive binary minimal and the output deterministic.

/// Convert an HTML document into a markdown-ish plain-text rendering.
pub fn html_to_markdown(html: &str) -> String {
    let stripped = strip_noise_blocks(html);
    let rendered = render_tokens(&stripped);
    collapse_whitespace(&rendered)
}

/// Remove `<script>`, `<style>`, `<head>`, and comment blocks wholesale, since
/// their text content is never useful in the rendered output.
fn strip_noise_blocks(input: &str) -> String {
    let mut output = strip_comments(input);
    for tag in ["script", "style", "head", "noscript", "svg"] {
        output = strip_element(&output, tag);
    }
    output
}

fn strip_comments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("<!--") {
        output.push_str(&rest[..start]);
        match rest[start..].find("-->") {
            Some(end) => rest = &rest[start + end + 3..],
            None => {
                rest = "";
                break;
            }
        }
    }
    output.push_str(rest);
    output
}

/// Remove a `<tag ...> ... </tag>` element (case-insensitive), including nested
/// occurrences, by repeatedly excising the first open/close pair.
fn strip_element(input: &str, tag: &str) -> String {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let lowered = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut idx = 0;
    while idx < input.len() {
        match lowered[idx..].find(&open) {
            Some(rel) => {
                let open_at = idx + rel;
                // Confirm this is a tag boundary, not a prefix (e.g. <styled>).
                let after = lowered.as_bytes().get(open_at + open.len()).copied();
                let is_boundary = matches!(after, Some(b'>') | Some(b' ') | Some(b'/') | Some(b'\t') | Some(b'\n') | Some(b'\r') | None);
                if !is_boundary {
                    output.push_str(&input[idx..open_at + open.len()]);
                    idx = open_at + open.len();
                    continue;
                }
                output.push_str(&input[idx..open_at]);
                match lowered[open_at..].find(&close) {
                    Some(crel) => idx = open_at + crel + close.len(),
                    None => {
                        idx = input.len();
                    }
                }
            }
            None => {
                output.push_str(&input[idx..]);
                break;
            }
        }
    }
    output
}

/// Walk the remaining markup, emitting markdown for the structural tags we care
/// about and dropping everything else.
fn render_tokens(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();
    // Pending anchor href, set when we open `<a href=...>` and consumed at `</a>`.
    let mut anchor_href: Option<String> = None;

    while let Some((idx, ch)) = chars.next() {
        if ch != '<' {
            // Accumulate a run of text up to the next tag, then decode entities.
            let start = idx;
            let mut end = start + ch.len_utf8();
            while let Some(&(next_idx, next_ch)) = chars.peek() {
                if next_ch == '<' {
                    break;
                }
                end = next_idx + next_ch.len_utf8();
                chars.next();
            }
            output.push_str(&decode_entities(&input[start..end]));
            continue;
        }

        // Consume the tag body up to '>'.
        let tag_start = idx + 1;
        let mut tag_end = tag_start;
        for (next_idx, next_ch) in chars.by_ref() {
            if next_ch == '>' {
                tag_end = next_idx;
                break;
            }
            tag_end = next_idx + next_ch.len_utf8();
        }
        let raw_tag = &input[tag_start..tag_end];
        let (name, closing) = tag_name(raw_tag);

        // Headings: emit the marker on the opening tag, just a block break on
        // the closing tag so following content starts on a fresh line.
        if let Some(level) = heading_level(&name) {
            if closing {
                output.push_str("\n\n");
            } else {
                output.push_str("\n\n");
                for _ in 0..level {
                    output.push('#');
                }
                output.push(' ');
            }
            continue;
        }

        match name.as_str() {
            "li" if !closing => output.push_str("\n- "),
            "br" => output.push('\n'),
            "p" | "div" | "section" | "article" | "tr" | "ul" | "ol" | "table" | "header"
            | "footer" | "blockquote" | "pre" => output.push_str("\n\n"),
            "a" => {
                if closing {
                    if let Some(href) = anchor_href.take() {
                        if !href.is_empty() {
                            output.push_str(&format!("]({href})"));
                            continue;
                        }
                    }
                } else {
                    let href = attr_value(raw_tag, "href").unwrap_or_default();
                    anchor_href = Some(href.clone());
                    if !href.is_empty() {
                        output.push('[');
                    }
                }
            }
            _ => {}
        }
    }
    output
}

/// Return the heading level (1-6) for `h1`..`h6`, else `None`.
fn heading_level(name: &str) -> Option<usize> {
    let level = name.strip_prefix('h')?;
    match level {
        "1" => Some(1),
        "2" => Some(2),
        "3" => Some(3),
        "4" => Some(4),
        "5" => Some(5),
        "6" => Some(6),
        _ => None,
    }
}

/// Extract the lowercased tag name and whether it is a closing tag.
fn tag_name(raw_tag: &str) -> (String, bool) {
    let trimmed = raw_tag.trim();
    let (closing, rest) = match trimmed.strip_prefix('/') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };
    let name: String = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect();
    (name, closing)
}

/// Pull an attribute value out of a raw tag body (quoted or bare).
fn attr_value(raw_tag: &str, attr: &str) -> Option<String> {
    let lowered = raw_tag.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lowered[search_from..].find(attr) {
        let at = search_from + rel;
        let before_ok = at == 0
            || lowered.as_bytes()[at - 1].is_ascii_whitespace();
        let after = lowered[at + attr.len()..].trim_start();
        if before_ok && after.starts_with('=') {
            let after_eq = lowered[at + attr.len()..]
                .trim_start()
                .strip_prefix('=')?
                .trim_start();
            // Map the position in `lowered` back to the original `raw_tag`.
            let value_offset = raw_tag.len() - after_eq.len();
            let value_region = &raw_tag[value_offset..];
            return Some(parse_attr_value(value_region));
        }
        search_from = at + attr.len();
    }
    None
}

fn parse_attr_value(region: &str) -> String {
    let region = region.trim_start();
    if let Some(rest) = region.strip_prefix('"') {
        return decode_entities(rest.split('"').next().unwrap_or_default());
    }
    if let Some(rest) = region.strip_prefix('\'') {
        return decode_entities(rest.split('\'').next().unwrap_or_default());
    }
    decode_entities(
        region
            .split(|ch: char| ch.is_ascii_whitespace() || ch == '>')
            .next()
            .unwrap_or_default(),
    )
}

/// Decode the common named entities plus numeric (`&#NN;` / `&#xNN;`) escapes.
fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_owned();
    }
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        output.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        match tail.find(';') {
            Some(semi) if semi <= 10 => {
                let entity = &tail[1..semi];
                if let Some(decoded) = decode_entity(entity) {
                    output.push(decoded);
                } else {
                    output.push_str(&tail[..=semi]);
                }
                rest = &tail[semi + 1..];
            }
            _ => {
                output.push('&');
                rest = &tail[1..];
            }
        }
    }
    output.push_str(rest);
    output
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" | "#39" => Some('\''),
        "nbsp" => Some(' '),
        "mdash" => Some('\u{2014}'),
        "ndash" => Some('\u{2013}'),
        "hellip" => Some('\u{2026}'),
        "copy" => Some('\u{00A9}'),
        _ => {
            let code = if let Some(hex) = entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                entity.strip_prefix('#')?.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

/// Trim each line, drop runs of blank lines down to at most one, and trim the
/// document ends.
fn collapse_whitespace(input: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut blank_run = 0;
    for raw_line in input.lines() {
        let collapsed = collapse_inline_spaces(raw_line);
        if collapsed.is_empty() {
            blank_run += 1;
            if blank_run <= 1 && !lines.is_empty() {
                lines.push(String::new());
            }
        } else {
            blank_run = 0;
            lines.push(collapsed);
        }
    }
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

fn collapse_inline_spaces(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut last_space = false;
    for ch in line.chars() {
        if ch.is_whitespace() {
            if !last_space {
                output.push(' ');
            }
            last_space = true;
        } else {
            output.push(ch);
            last_space = false;
        }
    }
    output.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_scripts_and_styles() {
        let html = "<p>keep</p><script>var x = 1 < 2;</script><style>.a{}</style>";
        let md = html_to_markdown(html);
        assert!(md.contains("keep"));
        assert!(!md.contains("var x"));
        assert!(!md.contains(".a{}"));
    }

    #[test]
    fn renders_headings_and_links() {
        let html = "<h1>Title</h1><p>Hello <a href=\"https://example.com/x\">world</a></p>";
        let md = html_to_markdown(html);
        assert!(md.starts_with("# Title"));
        assert!(md.contains("[world](https://example.com/x)"));
    }

    #[test]
    fn heading_close_tag_does_not_duplicate_marker() {
        // A full HTML doc like the smoke fixture must render to exactly "# msg".
        let html = "<!DOCTYPE html><html><head><style>.x{}</style></head>\
                    <body><h1>hello relay</h1></body></html>";
        assert_eq!("# hello relay", html_to_markdown(html));
    }

    #[test]
    fn decodes_entities() {
        let html = "<p>a &amp; b &lt;tag&gt; &#39;q&#39; &#x41;</p>";
        let md = html_to_markdown(html);
        assert_eq!("a & b <tag> 'q' A", md);
    }

    #[test]
    fn collapses_blank_lines_and_spaces() {
        let html = "<p>one</p>\n\n\n<p>two    spaced</p>";
        let md = html_to_markdown(html);
        assert_eq!("one\n\ntwo spaced", md);
    }

    #[test]
    fn handles_unclosed_script() {
        let html = "<p>before</p><script>dangling";
        let md = html_to_markdown(html);
        assert_eq!("before", md);
    }

    #[test]
    fn bare_attribute_value_parsed() {
        let html = "<a href=https://example.com>link</a>";
        let md = html_to_markdown(html);
        assert!(md.contains("[link](https://example.com)"));
    }
}
