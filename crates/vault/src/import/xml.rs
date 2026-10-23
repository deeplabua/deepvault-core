//! Just enough XML for an export: nested elements and their text, with entities and CDATA.
//! Attributes, comments, processing instructions and the DOCTYPE are skipped. The tree keeps
//! only where text is in the file; text is decoded on demand into a buffer of its exact size.

use zeroize::Zeroizing;

/// Deeper than any export nests; a bound so a hostile file cannot make the tree unbounded.
const MAX_DEPTH: usize = 64;

pub(super) struct Element {
    pub name: String,
    pub children: Vec<Element>,
    text: Vec<Span>,
}

#[derive(Clone, Copy)]
enum Span {
    /// Character data with entities still in it.
    Raw(usize, usize),
    /// A CDATA section's contents, as they are.
    Cdata(usize, usize),
}

impl Element {
    fn new(name: String) -> Self {
        Self { name, children: Vec::new(), text: Vec::new() }
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    /// Every element named `name` below this one, in document order (not below a match).
    pub fn find_all<'a>(&'a self, name: &str, found: &mut Vec<&'a Element>) {
        for child in &self.children {
            if child.name == name {
                found.push(child);
            } else {
                child.find_all(name, found);
            }
        }
    }

    /// The element's own text, entities decoded. Decoding only shrinks text, so the buffer
    /// is allocated once at the raw length and never grows.
    pub fn text(&self, bytes: &[u8]) -> Zeroizing<Vec<u8>> {
        let size = self.text.iter().map(|span| match *span {
            Span::Raw(start, end) | Span::Cdata(start, end) => end - start,
        });
        let mut out = Zeroizing::new(Vec::with_capacity(size.sum()));
        for span in &self.text {
            match *span {
                Span::Cdata(start, end) => out.extend_from_slice(&bytes[start..end]),
                Span::Raw(start, end) => decode(&bytes[start..end], &mut out),
            }
        }
        out
    }
}

/// `&amp;` `&lt;` `&gt;` `&quot;` `&apos;` `&#NN;` `&#xHH;`; anything else is kept as written.
fn decode(raw: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'&' {
            if let Some(length) = raw[i..].iter().take(12).position(|byte| *byte == b';') {
                let name = &raw[i + 1..i + length];
                let character = match name {
                    b"amp" => Some('&'),
                    b"lt" => Some('<'),
                    b"gt" => Some('>'),
                    b"quot" => Some('"'),
                    b"apos" => Some('\''),
                    [b'#', b'x' | b'X', hex @ ..] => number(hex, 16),
                    [b'#', decimal @ ..] => number(decimal, 10),
                    _ => None,
                };
                if let Some(character) = character {
                    let mut buffer = [0; 4];
                    out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                    i += length + 1;
                    continue;
                }
            }
        }
        out.push(raw[i]);
        i += 1;
    }
}

fn number(digits: &[u8], radix: u32) -> Option<char> {
    let text = std::str::from_utf8(digits).ok()?;
    char::from_u32(u32::from_str_radix(text, radix).ok()?)
}

/// The document as a nameless root holding its top-level elements; `None` when it is not
/// well formed (an unclosed or mismatched tag, an unterminated comment, too deep).
pub(super) fn parse(bytes: &[u8]) -> Option<Element> {
    let mut stack = vec![Element::new(String::new())];
    let mut i = 0;
    while i < bytes.len() {
        let Some(offset) = bytes[i..].iter().position(|byte| *byte == b'<') else {
            stack.last_mut()?.text.push(Span::Raw(i, bytes.len()));
            break;
        };
        if offset > 0 {
            stack.last_mut()?.text.push(Span::Raw(i, i + offset));
        }
        i += offset;
        let rest = &bytes[i..];
        if rest.starts_with(b"<!--") {
            i += find(rest, b"-->")? + 3;
        } else if rest.starts_with(b"<![CDATA[") {
            let end = find(rest, b"]]>")?;
            stack.last_mut()?.text.push(Span::Cdata(i + 9, i + end));
            i += end + 3;
        } else if rest.starts_with(b"<?") {
            i += find(rest, b"?>")? + 2;
        } else if rest.starts_with(b"<!") {
            i += find(rest, b">")? + 1;
        } else if rest.starts_with(b"</") {
            let end = find(rest, b">")?;
            let name = std::str::from_utf8(&rest[2..end]).ok()?.trim();
            let element = stack.pop()?;
            if stack.is_empty() || element.name != name {
                return None;
            }
            stack.last_mut()?.children.push(element);
            i += end + 1;
        } else {
            let end = tag_end(rest)?;
            let tag = &rest[1..end];
            let self_closing = tag.last() == Some(&b'/');
            let name_end =
                tag.iter().position(|byte| byte.is_ascii_whitespace() || *byte == b'/').unwrap_or(tag.len());
            let name = std::str::from_utf8(&tag[..name_end]).ok()?.to_owned();
            if name.is_empty() {
                return None;
            }
            if self_closing {
                stack.last_mut()?.children.push(Element::new(name));
            } else {
                if stack.len() > MAX_DEPTH {
                    return None;
                }
                stack.push(Element::new(name));
            }
            i += end + 1;
        }
    }
    (stack.len() == 1).then(|| stack.pop()).flatten()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// The `>` that ends a start tag, past any `>` inside quoted attribute values.
fn tag_end(tag: &[u8]) -> Option<usize> {
    let mut quote = None;
    for (i, byte) in tag.iter().enumerate() {
        match (quote, byte) {
            (None, b'"' | b'\'') => quote = Some(*byte),
            (Some(open), _) if open == *byte => quote = None,
            (None, b'>') => return Some(i),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_text_entities_and_cdata() {
        let xml = br#"<?xml version="1.0"?><!-- c --><a x="1>2"><b>r&amp;d &lt;&#65;&#x42;&bogus; x>y</b><c/><b><![CDATA[<raw>&amp;]]></b></a>"#;
        let root = parse(xml).unwrap();
        let a = root.child("a").unwrap();
        let texts: Vec<_> =
            a.children_named("b").map(|b| String::from_utf8(b.text(xml).to_vec()).unwrap()).collect();
        assert_eq!(texts, ["r&d <AB&bogus; x>y", "<raw>&amp;"]);
        assert!(a.child("c").is_some());
    }

    #[test]
    fn rejects_broken_documents() {
        assert!(parse(b"<a><b></a>").is_none());
        assert!(parse(b"<a>").is_none());
        assert!(parse(b"</a>").is_none());
        assert!(parse(b"<a><!-- open</a>").is_none());
        assert!(parse("<a>".repeat(100).as_bytes()).is_none());
    }
}
