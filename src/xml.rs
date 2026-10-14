//! Minimal XML support: a tiny DOM parser for the few request documents S3 accepts, and a
//! string builder for responses.

use crate::util::xml_escape;

#[derive(Debug, Default)]
pub struct Node {
    pub name: String,
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }
}

fn decode_entities(s: &str, out: &mut String) -> Option<()> {
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let end = rest[i..].find(';')? + i;
        let ent = &rest[i + 1..end];
        match ent {
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "amp" => out.push('&'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let code = if let Some(h) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                    u32::from_str_radix(h, 16).ok()?
                } else {
                    ent.strip_prefix('#')?.parse().ok()?
                };
                out.push(char::from_u32(code)?);
            }
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(())
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Parse a document and return its root element.
pub fn parse(input: &str) -> Option<Node> {
    let mut stack: Vec<Node> = vec![Node::default()];
    let mut s = input.trim_start_matches('\u{feff}');
    while !s.is_empty() {
        let Some(lt) = s.find('<') else {
            if !s.trim().is_empty() {
                decode_entities(s, &mut stack.last_mut()?.text)?;
            }
            break;
        };
        if lt > 0 {
            decode_entities(&s[..lt], &mut stack.last_mut()?.text)?;
        }
        s = &s[lt..];
        if let Some(r) = s.strip_prefix("<?") {
            s = &r[r.find("?>")? + 2..];
        } else if let Some(r) = s.strip_prefix("<!--") {
            s = &r[r.find("-->")? + 3..];
        } else if let Some(r) = s.strip_prefix("<![CDATA[") {
            let end = r.find("]]>")?;
            stack.last_mut()?.text.push_str(&r[..end]);
            s = &r[end + 3..];
        } else if let Some(r) = s.strip_prefix("<!") {
            s = &r[r.find('>')? + 1..];
        } else if let Some(r) = s.strip_prefix("</") {
            let end = r.find('>')?;
            let name = local(r[..end].trim());
            let node = stack.pop()?;
            if node.name != name || stack.is_empty() {
                return None;
            }
            stack.last_mut()?.children.push(node);
            s = &r[end + 1..];
        } else {
            // Start tag; find its end while respecting quoted attribute values.
            let b = s.as_bytes();
            let mut i = 1;
            let mut quote = 0u8;
            while i < b.len() {
                match b[i] {
                    q @ (b'"' | b'\'') if quote == 0 => quote = q,
                    q if q == quote => quote = 0,
                    b'>' if quote == 0 => break,
                    _ => {}
                }
                i += 1;
            }
            if i >= b.len() {
                return None;
            }
            let inner = &s[1..i];
            let self_closing = inner.ends_with('/');
            let inner = inner.trim_end_matches('/');
            let name = local(inner.split(|c: char| c.is_whitespace()).next()?);
            if name.is_empty() {
                return None;
            }
            let node = Node { name: name.to_string(), ..Default::default() };
            if self_closing {
                stack.last_mut()?.children.push(node);
            } else {
                stack.push(node);
            }
            s = &s[i + 1..];
        }
    }
    if stack.len() != 1 {
        return None;
    }
    let mut doc = stack.pop()?;
    if doc.children.len() != 1 {
        return None;
    }
    let mut root = doc.children.pop()?;
    trim_all(&mut root);
    Some(root)
}

fn trim_all(n: &mut Node) {
    if !n.children.is_empty() {
        n.text.clear();
    }
    for c in &mut n.children {
        trim_all(c);
    }
}

/// Builds XML response documents.
pub struct Xml(pub String);

pub const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

impl Xml {
    pub fn new(root: &str) -> Self {
        let mut s = String::with_capacity(512);
        s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<");
        s.push_str(root);
        s.push_str(" xmlns=\"");
        s.push_str(NS);
        s.push_str("\">");
        Xml(s)
    }
    pub fn open(&mut self, tag: &str) -> &mut Self {
        self.0.push('<');
        self.0.push_str(tag);
        self.0.push('>');
        self
    }
    pub fn close(&mut self, tag: &str) -> &mut Self {
        self.0.push_str("</");
        self.0.push_str(tag);
        self.0.push('>');
        self
    }
    pub fn elem(&mut self, tag: &str, text: impl AsRef<str>) -> &mut Self {
        self.open(tag);
        xml_escape(text.as_ref(), &mut self.0);
        self.close(tag)
    }
    pub fn opt(&mut self, tag: &str, text: Option<impl AsRef<str>>) -> &mut Self {
        if let Some(t) = text {
            self.elem(tag, t);
        }
        self
    }
    pub fn owner(&mut self, tag: &str) -> &mut Self {
        self.open(tag).elem("ID", crate::OWNER_ID).elem("DisplayName", crate::OWNER_ID).close(tag)
    }
    pub fn finish(mut self, root: &str) -> String {
        self.close(root);
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_complete() {
        let doc = r#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <!-- comment -->
  <Part><PartNumber>1</PartNumber><ETag>"a&amp;b"</ETag></Part>
  <Part><PartNumber>2</PartNumber><ETag>&quot;c&quot;</ETag><ChecksumCRC32/></Part>
</CompleteMultipartUpload>"#;
        let root = parse(doc).unwrap();
        assert_eq!(root.name, "CompleteMultipartUpload");
        let parts: Vec<_> = root.children_named("Part").collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].child_text("ETag"), Some("\"a&b\""));
        assert_eq!(parts[1].child_text("ETag"), Some("\"c\""));
    }

    #[test]
    fn parse_keys_with_whitespace_and_cdata() {
        let doc = "<Delete><Object><Key> spaced key </Key></Object><Object><Key><![CDATA[a<b]]></Key></Object><Quiet>true</Quiet></Delete>";
        let root = parse(doc).unwrap();
        let keys: Vec<_> = root.children_named("Object").map(|o| o.child_text("Key").unwrap()).collect();
        assert_eq!(keys, vec![" spaced key ", "a<b"]);
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse("<a><b></a>").is_none());
        assert!(parse("<a>").is_none());
    }
}
