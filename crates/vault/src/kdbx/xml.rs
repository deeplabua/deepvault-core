//! The XML inside a KDBX file: entries read out of it, in document order (protected values are
//! XORed with one stream in that order — the history's and the recycle bin's too), and a
//! vault's entries written into it.

use std::io::Read;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use zeroize::Zeroizing;

use super::crypto::InnerStream;
use crate::entropy::Entropy;
use crate::error::{Result, VaultError};
use crate::ssh::{base64_decode, base64_encode};

/// A string field of an entry. No `Debug`: the value may be a password.
pub(super) struct StringField {
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
    pub protected: bool,
}

impl StringField {
    pub fn new(key: &str, value: &[u8], protected: bool) -> Self {
        StringField { key: key.into(), value: Zeroizing::new(value.to_vec()), protected }
    }
}

/// An entry as KDBX has it.
pub(super) struct Entry {
    pub strings: Vec<StringField>,
    pub tags: Vec<String>,
    /// Its group's path below the root, `Work/Servers`.
    pub group: Option<String>,
    /// Its files: name and content (read).
    pub files: Vec<(String, Zeroizing<Vec<u8>>)>,
    /// Its files: name and index among the binaries (written).
    pub refs: Vec<(String, usize)>,
    pub created: u64,
    pub modified: u64,
}

pub(super) struct Parsed {
    pub entries: Vec<Entry>,
    /// Entries in the recycle bin.
    pub skipped: usize,
}

struct Group {
    name: String,
    uuid: String,
}

/// The entries of `xml`; protected values decrypted with `stream`; files from `binaries`
/// (KDBX 4's inner header) or the XML's own (KDBX 3.1).
pub(super) fn read(xml: &[u8], mut stream: InnerStream, binaries: Vec<Zeroizing<Vec<u8>>>) -> Result<Parsed> {
    let text = std::str::from_utf8(xml).map_err(|_| VaultError::Corrupted)?;
    let mut reader = Reader::from_str(text);
    let mut path: Vec<String> = Vec::new();
    let mut groups: Vec<Group> = Vec::new();
    let mut buffer = Zeroizing::new(String::new());
    let (mut recycle_bin, mut in_recycle_bin) = (String::new(), 0usize);
    let mut meta_binaries: Vec<(String, bool, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut meta_binary: Option<(String, bool)> = None;
    let mut current: Option<Entry> = None;
    let mut refs: Vec<(String, String)> = Vec::new();
    let (mut key, mut value, mut protected, mut value_ref) =
        (String::new(), Zeroizing::new(Vec::new()), false, None::<String>);
    let mut parsed = Parsed { entries: Vec::new(), skipped: 0 };

    let attribute = |e: &BytesStart, name: &str| -> Option<String> {
        e.try_get_attribute(name)
            .ok()
            .flatten()
            .and_then(|a| a.normalized_value(quick_xml::XmlVersion::Implicit1_0).ok().map(|v| v.into_owned()))
    };

    loop {
        let event = reader.read_event().map_err(|_| VaultError::Corrupted)?;
        let (start, empty) = match &event {
            Event::Start(e) => (Some(e.clone()), false),
            Event::Empty(e) => (Some(e.clone()), true),
            _ => (None, false),
        };
        if let Some(e) = start {
            let name = e.local_name().into_inner().to_owned();
            let parent = path.last().map(String::as_str).unwrap_or("");
            buffer.clear();
            match name.as_str() {
                "Group" => groups.push(Group { name: String::new(), uuid: String::new() }),
                "Entry" if parent == "Group" => {
                    current = Some(Entry {
                        strings: Vec::new(),
                        tags: Vec::new(),
                        group: None,
                        files: Vec::new(),
                        refs: Vec::new(),
                        created: 0,
                        modified: 0,
                    });
                    refs.clear();
                }
                "Value" => {
                    protected = attribute(&e, "Protected").is_some_and(|v| v.eq_ignore_ascii_case("true"));
                    value_ref = attribute(&e, "Ref");
                }
                "Binary" if parent == "Binaries" => {
                    let compressed =
                        attribute(&e, "Compressed").is_some_and(|v| v.eq_ignore_ascii_case("true"));
                    meta_binary = Some((attribute(&e, "ID").unwrap_or_default(), compressed));
                }
                _ => {}
            }
            path.push(name);
            if !empty {
                continue;
            }
        }
        let end = match &event {
            Event::End(_) | Event::Empty(_) => true,
            Event::Text(t) => {
                buffer.push_str(t);
                false
            }
            Event::CData(t) => {
                buffer.push_str(t);
                false
            }
            Event::GeneralRef(r) => {
                match r.resolve_char_ref().ok().flatten() {
                    Some(c) => buffer.push(c),
                    None => buffer.push_str(match &**r {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => "",
                    }),
                }
                false
            }
            Event::Eof => break,
            _ => false,
        };
        if !end {
            continue;
        }
        let name = path.pop().unwrap_or_default();
        let parent = path.last().map(String::as_str).unwrap_or("");
        let in_history = path.iter().any(|p| p == "History");
        match (name.as_str(), parent) {
            ("Key", "String") | ("Key", "Binary") => key = buffer.trim().to_owned(),
            ("Value", "String") => {
                value = if protected {
                    let compact: String = buffer.chars().filter(|c| !c.is_whitespace()).collect();
                    let mut bytes = Zeroizing::new(base64_decode(&compact).ok_or(VaultError::Corrupted)?);
                    // Every protected value moves the stream, kept or not.
                    stream.apply(&mut bytes);
                    bytes
                } else {
                    Zeroizing::new(buffer.as_bytes().to_vec())
                };
            }
            ("Value", "Binary") => {}
            ("String", "Entry") if !in_history => {
                if let Some(entry) = current.as_mut() {
                    entry.strings.push(StringField {
                        key: std::mem::take(&mut key),
                        value: std::mem::take(&mut value),
                        protected,
                    });
                }
            }
            ("Binary", "Entry") if !in_history => {
                if let Some(id) = value_ref.take() {
                    refs.push((std::mem::take(&mut key), id));
                }
            }
            ("Tags", "Entry") if !in_history => {
                if let Some(entry) = current.as_mut() {
                    entry.tags = buffer
                        .split([';', ','])
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
            }
            ("UUID", "Group") => {
                if let Some(group) = groups.last_mut() {
                    group.uuid = buffer.trim().to_owned();
                    if !recycle_bin.is_empty() && group.uuid == recycle_bin {
                        in_recycle_bin += 1;
                    }
                }
            }
            ("Name", "Group") => {
                if let Some(group) = groups.last_mut() {
                    group.name = buffer.trim().to_owned();
                }
            }
            ("RecycleBinUUID", "Meta") => recycle_bin = buffer.trim().to_owned(),
            ("Binary", "Binaries") => {
                if let Some((id, compressed)) = meta_binary.take() {
                    let compact: String = buffer.chars().filter(|c| !c.is_whitespace()).collect();
                    let mut data = Zeroizing::new(base64_decode(&compact).ok_or(VaultError::Corrupted)?);
                    if compressed {
                        let mut out = Zeroizing::new(Vec::new());
                        flate2::read::GzDecoder::new(&data[..])
                            .read_to_end(&mut out)
                            .map_err(|_| VaultError::Corrupted)?;
                        data = out;
                    }
                    meta_binaries.push((id, false, data));
                }
            }
            ("Entry", "Group") => {
                if let Some(mut entry) = current.take() {
                    if in_recycle_bin > 0 {
                        parsed.skipped += 1;
                        continue;
                    }
                    let names: Vec<&str> =
                        groups.iter().skip(1).map(|g| g.name.as_str()).filter(|n| !n.is_empty()).collect();
                    entry.group = (!names.is_empty()).then(|| names.join("/"));
                    for (name, id) in refs.drain(..) {
                        let content =
                            id.parse::<usize>().ok().and_then(|i| binaries.get(i)).cloned().or_else(|| {
                                meta_binaries
                                    .iter()
                                    .find(|(m, _, _)| *m == id)
                                    .map(|(_, _, data)| data.clone())
                            });
                        if let Some(content) = content {
                            entry.files.push((name, content));
                        }
                    }
                    parsed.entries.push(entry);
                }
            }
            ("Group", _) => {
                if let Some(group) = groups.pop() {
                    if !recycle_bin.is_empty() && group.uuid == recycle_bin {
                        in_recycle_bin = in_recycle_bin.saturating_sub(1);
                    }
                }
            }
            _ => {}
        }
        buffer.clear();
    }
    if groups.is_empty() && parsed.entries.is_empty() && !text.contains("<KeePassFile") {
        return Err(VaultError::InvalidImport);
    }
    Ok(parsed)
}

/// `entries` as KDBX 4 XML, in one group; protected values XORed with `stream` in order.
pub(super) fn write(
    entries: &[Entry],
    stream: &mut InnerStream,
    entropy: &mut dyn Entropy,
) -> Zeroizing<Vec<u8>> {
    let now = time(entropy.now());
    let mut out = Zeroizing::new(String::with_capacity(4096));
    out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile><Meta>");
    out.push_str("<Generator>DeepVault</Generator><DatabaseName>DeepVault</DatabaseName>");
    out.push_str(
        "<MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectUserName>False</ProtectUserName>",
    );
    out.push_str("<ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>False</ProtectNotes>");
    out.push_str("</MemoryProtection><RecycleBinEnabled>False</RecycleBinEnabled></Meta><Root><Group>");
    out.push_str(&format!("<UUID>{}</UUID><Name>DeepVault</Name>", uuid(entropy)));
    out.push_str(&format!("<Times>{}</Times><IsExpanded>True</IsExpanded>", times(&now, &now)));
    for entry in entries {
        out.push_str(&format!("<Entry><UUID>{}</UUID>", uuid(entropy)));
        out.push_str(&format!("<Times>{}</Times>", times(&time(entry.created), &time(entry.modified))));
        if !entry.tags.is_empty() {
            out.push_str("<Tags>");
            escape(&mut out, &entry.tags.join(";"));
            out.push_str("</Tags>");
        }
        for string in &entry.strings {
            out.push_str("<String><Key>");
            escape(&mut out, &string.key);
            out.push_str("</Key>");
            if string.protected {
                let mut hidden = Zeroizing::new(string.value.to_vec());
                stream.apply(&mut hidden);
                out.push_str(&format!("<Value Protected=\"True\">{}</Value>", base64_encode(&hidden)));
            } else {
                out.push_str("<Value>");
                escape(&mut out, &String::from_utf8_lossy(&string.value));
                out.push_str("</Value>");
            }
            out.push_str("</String>");
        }
        for (name, index) in &entry.refs {
            out.push_str("<Binary><Key>");
            escape(&mut out, name);
            out.push_str(&format!("</Key><Value Ref=\"{index}\"/></Binary>"));
        }
        out.push_str("</Entry>");
    }
    out.push_str("</Group><DeletedObjects/></Root></KeePassFile>\n");
    Zeroizing::new(out.as_bytes().to_vec())
}

fn uuid(entropy: &mut dyn Entropy) -> String {
    let mut bytes = [0u8; 16];
    entropy.fill(&mut bytes);
    base64_encode(&bytes)
}

/// KDBX 4's time: seconds since 0001-01-01 as a little-endian i64, base64.
fn time(unix: u64) -> String {
    base64_encode(&(unix as i64 + 62_135_596_800).to_le_bytes())
}

fn times(created: &str, modified: &str) -> String {
    format!(
        "<CreationTime>{created}</CreationTime><LastModificationTime>{modified}</LastModificationTime>\
         <LastAccessTime>{modified}</LastAccessTime><ExpiryTime>{created}</ExpiryTime><Expires>False</Expires>\
         <UsageCount>0</UsageCount><LocationChanged>{created}</LocationChanged>"
    )
}

/// XML text: the five escapes, and control characters XML 1.0 does not allow left out.
fn escape(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
}
