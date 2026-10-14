//! Static website hosting: bucket website configuration (index / error documents, redirects,
//! routing rules) and the HTML pages the website endpoint answers with.

use crate::error::{S3Result, err};
use crate::util::{uri_encode, xml_escape};
use crate::xml::Node;

const MAX_RULES: usize = 50;

#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Appended to requests for `/` or `.../` (required unless every request is redirected).
    pub index: Option<String>,
    /// Object served (with the original error status) when a request fails.
    pub error_document: Option<String>,
    pub redirect_all: Option<RedirectAll>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct RedirectAll {
    pub host: String,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub prefix: Option<String>,
    pub error_code: Option<u16>,
    pub redirect: Redirect,
}

#[derive(Debug, Clone)]
pub struct Redirect {
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub replace_prefix: Option<String>,
    pub replace_key: Option<String>,
    pub code: u16,
}

fn text(n: &Node, name: &str) -> Option<String> {
    n.child_text(name).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn protocol(n: &Node) -> S3Result<Option<String>> {
    match text(n, "Protocol") {
        None => Ok(None),
        Some(p) if p == "http" || p == "https" => Ok(Some(p)),
        Some(_) => Err(err::InvalidArgument().with_message("Invalid protocol, protocol can be http or https.")),
    }
}

impl Config {
    pub fn parse(doc: &Node) -> S3Result<Config> {
        if doc.name != "WebsiteConfiguration" {
            return Err(err::MalformedXML());
        }
        let mut c = Config::default();
        if let Some(all) = doc.child("RedirectAllRequestsTo") {
            let host = text(all, "HostName").ok_or_else(err::MalformedXML)?;
            c.redirect_all = Some(RedirectAll { host, protocol: protocol(all)? });
            if doc.child("IndexDocument").is_some() || doc.child("ErrorDocument").is_some() || doc.child("RoutingRules").is_some()
            {
                return Err(err::InvalidArgument()
                    .with_message("RedirectAllRequestsTo cannot be provided in conjunction with other Routing Rules."));
            }
            return Ok(c);
        }
        let suffix = doc
            .child("IndexDocument")
            .and_then(|i| text(i, "Suffix"))
            .ok_or_else(|| err::InvalidArgument().with_message("A value for IndexDocument Suffix must be provided"))?;
        if suffix.contains('/') {
            return Err(err::InvalidArgument().with_message("The IndexDocument Suffix is not well formed"));
        }
        c.index = Some(suffix);
        c.error_document = doc.child("ErrorDocument").and_then(|e| text(e, "Key"));
        if let Some(rules) = doc.child("RoutingRules") {
            for r in rules.children_named("RoutingRule") {
                let cond = r.child("Condition");
                let prefix = cond.and_then(|c| c.child_text("KeyPrefixEquals")).map(str::to_string);
                let error_code = match cond.and_then(|c| text(c, "HttpErrorCodeReturnedEquals")) {
                    Some(code) => Some(
                        code.parse::<u16>()
                            .ok()
                            .filter(|c| (400..600).contains(c))
                            .ok_or_else(|| err::InvalidArgument().with_message("The provided HTTP error code is not valid"))?,
                    ),
                    None => None,
                };
                let rd = r.child("Redirect").ok_or_else(err::MalformedXML)?;
                let redirect =
                    Redirect {
                        protocol: protocol(rd)?,
                        host: text(rd, "HostName"),
                        replace_prefix: rd.child_text("ReplaceKeyPrefixWith").map(str::to_string),
                        replace_key: rd.child_text("ReplaceKeyWith").map(str::to_string),
                        code: match text(rd, "HttpRedirectCode") {
                            None => 301,
                            Some(c) => c.parse::<u16>().ok().filter(|c| (300..400).contains(c)).ok_or_else(|| {
                                err::InvalidArgument().with_message("The provided HTTP redirect code is not valid")
                            })?,
                        },
                    };
                if redirect.replace_prefix.is_some() && redirect.replace_key.is_some() {
                    return Err(
                        err::InvalidArgument().with_message("You can only define ReplaceKeyPrefix or ReplaceKey but not both.")
                    );
                }
                c.rules.push(Rule { prefix, error_code, redirect });
            }
            if c.rules.is_empty() || c.rules.len() > MAX_RULES {
                return Err(err::InvalidArgument().with_message("RoutingRules must contain between 1 and 50 rules"));
            }
        }
        Ok(c)
    }

    /// First routing rule that applies to `key`, before the object is fetched (`error` None)
    /// or after the request failed with `error`.
    pub fn rule_for(&self, key: &str, error: Option<u16>) -> Option<&Rule> {
        self.rules.iter().find(|r| r.error_code == error && r.prefix.as_deref().is_none_or(|p| key.starts_with(p)))
    }
}

impl Rule {
    /// `Location` for a request for `key` that this rule redirects.
    pub fn location(&self, key: &str, req_proto: &str, req_host: &str) -> String {
        let rd = &self.redirect;
        let new_key = match (&rd.replace_key, &rd.replace_prefix) {
            (Some(k), _) => k.clone(),
            (None, Some(p)) => format!("{p}{}", &key[self.prefix.as_deref().unwrap_or("").len()..]),
            (None, None) => key.to_string(),
        };
        format!(
            "{}://{}/{}",
            rd.protocol.as_deref().unwrap_or(req_proto),
            rd.host.as_deref().unwrap_or(req_host),
            uri_encode(&new_key, true)
        )
    }
}

/// The default HTML error page of the website endpoint.
pub fn error_page(status: u16, reason: &str, code: &str, message: &str, rid: &str) -> String {
    let mut s = String::with_capacity(512);
    s.push_str("<html>\n<head><title>");
    s.push_str(&format!("{status} {reason}"));
    s.push_str("</title></head>\n<body>\n<h1>");
    s.push_str(&format!("{status} {reason}"));
    s.push_str("</h1>\n<ul>\n<li>Code: ");
    xml_escape(code, &mut s);
    s.push_str("</li>\n<li>Message: ");
    xml_escape(message, &mut s);
    s.push_str("</li>\n<li>RequestId: ");
    xml_escape(rid, &mut s);
    s.push_str("</li>\n</ul>\n<hr/>\n</body>\n</html>\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml;

    fn parse(s: &str) -> S3Result<Config> {
        Config::parse(&xml::parse(s).unwrap())
    }

    #[test]
    fn parses_and_routes() {
        let c = parse(
            "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument>\
             <ErrorDocument><Key>404.html</Key></ErrorDocument><RoutingRules>\
             <RoutingRule><Condition><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition>\
             <Redirect><ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith></Redirect></RoutingRule>\
             <RoutingRule><Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition>\
             <Redirect><HostName>example.com</HostName><Protocol>https</Protocol><HttpRedirectCode>302</HttpRedirectCode></Redirect></RoutingRule>\
             </RoutingRules></WebsiteConfiguration>",
        )
        .unwrap();
        assert_eq!(c.index.as_deref(), Some("index.html"));
        assert_eq!(c.error_document.as_deref(), Some("404.html"));
        let r = c.rule_for("docs/a b.html", None).unwrap();
        assert_eq!(r.location("docs/a b.html", "http", "h"), "http://h/documents/a%20b.html");
        assert!(c.rule_for("other", None).is_none());
        let r = c.rule_for("missing", Some(404)).unwrap();
        assert_eq!((r.location("missing", "http", "h"), r.redirect.code), ("https://example.com/missing".into(), 302));
        assert!(c.rule_for("missing", Some(403)).is_none());
    }

    #[test]
    fn validation() {
        assert!(parse("<WebsiteConfiguration></WebsiteConfiguration>").is_err());
        assert!(
            parse("<WebsiteConfiguration><IndexDocument><Suffix>a/b</Suffix></IndexDocument></WebsiteConfiguration>").is_err()
        );
        let all = parse("<WebsiteConfiguration><RedirectAllRequestsTo><HostName>x.com</HostName></RedirectAllRequestsTo></WebsiteConfiguration>").unwrap();
        assert_eq!(all.redirect_all.unwrap().host, "x.com");
        assert!(parse("<WebsiteConfiguration><RedirectAllRequestsTo><HostName>x.com</HostName></RedirectAllRequestsTo><IndexDocument><Suffix>i</Suffix></IndexDocument></WebsiteConfiguration>").is_err());
        assert!(parse("<WebsiteConfiguration><IndexDocument><Suffix>i</Suffix></IndexDocument><RoutingRules><RoutingRule><Redirect><ReplaceKeyWith>a</ReplaceKeyWith><ReplaceKeyPrefixWith>b</ReplaceKeyPrefixWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>").is_err());
    }
}
