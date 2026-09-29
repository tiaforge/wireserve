//! The few pages a person sees while claiming a device (PLAN.md M38).
//!
//! Every value from outside — a node name, what the identity provider says
//! about someone — goes through [`escape`]. Every page is served with
//! [`html`], which forbids framing (the confirmation button must not be
//! clickable from someone else's page), scripts and referrers, and is never
//! cached.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Text made safe to place in HTML, in element content and in quoted
/// attribute values alike.
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;\
line-height:1.5;color:#1b1b1b;background:#fff}h1{font-size:1.4rem}code{background:#f2f2f2;padding:0 .25rem}\
button{font-size:1rem;padding:.5rem 1rem}.note{color:#555;font-size:.9rem}\
@media(prefers-color-scheme:dark){body{color:#e8e8e8;background:#161616}code{background:#2a2a2a}.note{color:#aaa}}";

/// A page with `title` and `body`, which must already be escaped HTML.
fn document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title><style>{STYLE}</style></head><body><h1>{}</h1>{body}</body></html>",
        escape(title),
        escape(title)
    )
}

/// An HTML answer with the headers every claim page carries, and
/// `set_cookie` if given.
#[must_use]
pub fn html(status: StatusCode, title: &str, body: &str, set_cookie: Option<String>) -> Response {
    let mut resp = (status, document(title, body)).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    if let Some(cookie) = set_cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        h.insert(header::SET_COOKIE, cookie);
    }
    resp
}

/// A page saying what went wrong, and nothing else.
#[must_use]
pub fn problem(status: StatusCode, message: &str) -> Response {
    html(status, "This link did not work", &format!("<p>{}</p>", escape(message)), None)
}

/// "Sign in `node` as `who`?", with everything that helps a person notice
/// a link that is not what they were told: the node's tags and whoever owns
/// it now. `token` goes back with the answer.
#[must_use]
pub fn confirm(node: &str, tags: &[String], current: Option<&str>, who: &str, groups: &[String], token: &str) -> String {
    let mut body = format!(
        "<p>Make <strong>{}</strong> your device, signed in as <strong>{}</strong>?</p>",
        escape(node),
        escape(who)
    );
    body.push_str("<p>It will then reach what your groups are granted");
    if groups.is_empty() {
        body.push_str(" — you are in no groups right now.</p>");
    } else {
        body.push_str(": ");
        body.push_str(&groups.iter().map(|g| format!("<code>{}</code>", escape(g))).collect::<Vec<_>>().join(", "));
        body.push_str(".</p>");
    }
    if !tags.is_empty() {
        body.push_str(&format!(
            "<p class=\"note\">Tagged: {}</p>",
            tags.iter().map(|t| escape(t)).collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(current) = current {
        body.push_str(&format!("<p class=\"note\">It belongs to <strong>{}</strong> now; this replaces them.</p>", escape(current)));
    }
    body.push_str(&format!(
        "<form method=\"post\" action=\"confirm\"><input type=\"hidden\" name=\"token\" value=\"{}\">\
         <button type=\"submit\">Yes, this is my device</button></form>\
         <p class=\"note\">If nobody asked you to set up <strong>{}</strong> just now, close this page: \
         whoever sent you this link would get your access.</p>",
        escape(token),
        escape(node)
    ));
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_from_outside_is_escaped() {
        assert_eq!(escape("<a href=\"x\">'&'</a>\u{7}"), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
        let page = confirm("n<1>", &["t\"x".into()], Some("mallory<script>"), "a@b", &["g&h".into()], "tok\"en");
        assert!(!page.contains("<script>") && !page.contains("n<1>") && !page.contains("tok\"en"), "{page}");
        assert!(page.contains("value=\"tok&quot;en\""));
    }

    #[test]
    fn pages_cannot_be_framed_or_cached() {
        let resp = html(StatusCode::OK, "t", "", Some("c=1; Path=/".into()));
        let h = resp.headers();
        assert_eq!(h["x-frame-options"], "DENY");
        assert!(h["content-security-policy"].to_str().unwrap().contains("frame-ancestors 'none'"));
        assert_eq!(h["cache-control"], "no-store");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["set-cookie"], "c=1; Path=/");
    }
}
