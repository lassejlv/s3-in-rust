//! Built-in web console: static assets served at `/_console/`. The page is a small S3 client
//! that signs requests in the browser, so the server needs no session state or extra API.

use crate::util::xml_escape;

const INDEX: &str = include_str!("console/index.html");
const APP_JS: &str = include_str!("console/app.js");
const APP_CSS: &str = include_str!("console/app.css");

/// Content-Security-Policy for console pages: only same-origin scripts, styles and requests.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; \
                       connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

/// (content type, body) of a console asset; `path` is the request path.
pub fn asset(path: &str, region: &str) -> Option<(&'static str, String)> {
    match path {
        "/_console" | "/_console/" | "/_console/index.html" => {
            let mut r = String::new();
            xml_escape(region, &mut r);
            Some(("text/html; charset=utf-8", INDEX.replace("{{REGION}}", &r)))
        }
        "/_console/app.js" => Some(("text/javascript; charset=utf-8", APP_JS.to_string())),
        "/_console/app.css" => Some(("text/css; charset=utf-8", APP_CSS.to_string())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn assets() {
        let (ct, body) = super::asset("/_console/", "eu-<x>").unwrap();
        assert!(ct.starts_with("text/html"));
        assert!(body.contains("content=\"eu-&lt;x&gt;\""));
        assert!(super::asset("/_console/app.js", "r").is_some());
        assert!(super::asset("/_console/../etc/passwd", "r").is_none());
    }
}
