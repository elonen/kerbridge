//! The webhook body: one template, rendered with every substituted value
//! JSON-string-escaped.
//!
//! Directory-derived text reaches this -- a display name, a group name, an error
//! quoting either -- and it can carry quotes, backslashes and newlines. So a
//! template is not a format string with values pasted into it: every value goes
//! through `serde_json`'s own string escaper, and nothing the IdP can name is
//! able to close the JSON string it lands in and extend the payload.
//!
//! The content type is fixed for the same reason. A configurable one would let a
//! template select an encoding this escaper does not implement, which is an
//! injection bug with a plausible excuse.
//!
//! Both failures a template can have are startup errors rather than a silent
//! empty field at three in the morning: an unknown `%PLACEHOLDER%`, and a
//! template that does not render as JSON at all.

use anyhow::{Result, bail};

/// What a `%PLACEHOLDER%` may name. `DESIGN.md` @ Operator notification is
/// authoritative for the set; adding one here without adding it there leaves an
/// operator reading a table that does not describe what ships.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Event,
    Severity,
    Component,
    Realm,
    Timestamp,
    Message,
    Detail,
    Icon,
}

impl Field {
    const ALL: [(&'static str, Self); 8] = [
        ("EVENT", Self::Event),
        ("SEVERITY", Self::Severity),
        ("COMPONENT", Self::Component),
        ("REALM", Self::Realm),
        ("TIMESTAMP", Self::Timestamp),
        ("MESSAGE", Self::Message),
        ("DETAIL", Self::Detail),
        ("ICON", Self::Icon),
    ];

    fn lookup(name: &str) -> Option<Self> {
        Self::ALL.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
    }

    fn known() -> String {
        Self::ALL.iter().map(|(n, _)| format!("%{n}%")).collect::<Vec<_>>().join(", ")
    }
}

/// One event's substitution set. Every field is a `&str` because every one of
/// them is escaped on the way out, so none needs a type of its own.
pub struct Values<'a> {
    pub event: &'a str,
    pub severity: &'a str,
    pub component: &'a str,
    pub realm: &'a str,
    pub timestamp: &'a str,
    pub message: &'a str,
    pub detail: &'a str,
    pub icon: &'a str,
}

impl Values<'_> {
    fn get(&self, field: Field) -> &str {
        match field {
            Field::Event => self.event,
            Field::Severity => self.severity,
            Field::Component => self.component,
            Field::Realm => self.realm,
            Field::Timestamp => self.timestamp,
            Field::Message => self.message,
            Field::Detail => self.detail,
            Field::Icon => self.icon,
        }
    }
}

#[derive(Debug)]
enum Part {
    Literal(String),
    Field(Field),
}

#[derive(Debug)]
pub struct Template(Vec<Part>);

impl Template {
    /// Parse and prove it. Beyond resolving the placeholders, this renders the
    /// template once with hostile sample values and parses the result as JSON --
    /// a missing brace is then a startup error rather than a receiver quietly
    /// rejecting every event the deployment ever sends.
    pub fn parse(raw: &str) -> Result<Self> {
        let template = Self(parts(raw)?);
        // Every character that has to survive escaping: the quote and backslash
        // that would close or extend the string, a newline, and a bare control
        // character, which JSON requires to be escaped even though nothing here
        // would notice it in a chat message.
        const HOSTILE: &str = "a\"b\\c\nd\u{7}e";
        let sample = template.render(&Values {
            event: HOSTILE,
            severity: HOSTILE,
            component: HOSTILE,
            realm: HOSTILE,
            timestamp: HOSTILE,
            message: HOSTILE,
            detail: HOSTILE,
            icon: HOSTILE,
        });
        if serde_json::from_str::<serde_json::Value>(&sample).is_err() {
            bail!(
                "the notification template does not render as JSON. The body is JSON and every \
                 substituted value is escaped as a JSON string, so each placeholder has to sit \
                 inside one -- `{{\"text\":\"%MESSAGE%\"}}`, not `{{\"text\":%MESSAGE%}}`"
            );
        }
        Ok(template)
    }

    pub fn render(&self, values: &Values) -> String {
        let mut out = String::new();
        for part in &self.0 {
            match part {
                Part::Literal(text) => out.push_str(text),
                Part::Field(field) => out.push_str(&escape(values.get(*field))),
            }
        }
        out
    }
}

/// Split a template into literals and placeholders.
///
/// `%` is only special when it opens a `%NAME%` whose name is upper-case,
/// digits and underscores -- so a percentage sign in prose stays a percentage
/// sign, and only something already shaped like a placeholder can be rejected
/// for not being one.
fn parts(raw: &str) -> Result<Vec<Part>> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut rest = raw;
    while let Some(at) = rest.find('%') {
        literal.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        match after.split_once('%') {
            Some((name, tail)) if is_placeholder(name) => {
                let Some(field) = Field::lookup(name) else {
                    bail!(
                        "the notification template names %{name}%, which is not a placeholder. \
                         Known: {}",
                        Field::known()
                    );
                };
                if !literal.is_empty() {
                    parts.push(Part::Literal(std::mem::take(&mut literal)));
                }
                parts.push(Part::Field(field));
                rest = tail;
            }
            // Not placeholder-shaped, so this `%` is just a `%`.
            _ => {
                literal.push('%');
                rest = after;
            }
        }
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        parts.push(Part::Literal(literal));
    }
    Ok(parts)
}

fn is_placeholder(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// A value as it appears *inside* a JSON string: `serde_json`'s own escaper,
/// with the quotes it adds taken back off.
///
/// Hand-rolling this is exactly the mistake the module exists to avoid -- the
/// hand-rolled version handles `"` and `\`, and then a display name with a
/// newline in it produces a body the receiver rejects, or worse, accepts.
fn escape(value: &str) -> String {
    let quoted = serde_json::to_string(value).expect("a string always serializes");
    quoted[1..quoted.len() - 1].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values<'a>(message: &'a str, detail: &'a str) -> Values<'a> {
        Values {
            event: "sync-credential-expiring",
            severity: "warning",
            component: "sync",
            realm: "EXAMPLE.SITE",
            timestamp: "2026-07-30T12:00:00Z",
            message,
            detail,
            icon: "\u{1f7e0}",
        }
    }

    #[test]
    fn substitutes_every_placeholder() {
        let t = Template::parse(
            r#"{"a":"%EVENT%","b":"%SEVERITY%","c":"%COMPONENT%","d":"%REALM%","e":"%TIMESTAMP%","f":"%MESSAGE%","g":"%DETAIL%","h":"%ICON%"}"#,
        )
        .unwrap();
        let body = t.render(&values("m", "d"));
        assert_eq!(
            body,
            r#"{"a":"sync-credential-expiring","b":"warning","c":"sync","d":"EXAMPLE.SITE","e":"2026-07-30T12:00:00Z","f":"m","g":"d","h":"🟠"}"#
        );
    }

    /// An emoji is multi-byte UTF-8 and must reach the receiver as itself: JSON
    /// escaping applies to the characters JSON reserves, and to nothing else.
    #[test]
    fn an_icon_survives_escaping() {
        let t = Template::parse(r#"{"text":"%ICON% %MESSAGE%"}"#).unwrap();
        let body = t.render(&values("m", "d"));
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["text"], "\u{1f7e0} m");
    }

    /// The whole point of the module. A display name is IdP-controlled text
    /// that reaches the body, and a quote in it must not be able to close the
    /// string it sits in -- the payload stays one JSON object with one `text`.
    #[test]
    fn a_hostile_value_cannot_break_out_of_its_string() {
        let t = Template::parse(r#"{"text":"%MESSAGE%"}"#).unwrap();
        let body = t.render(&values(r#"","admin":true,"x":"#, ""));
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed.get("admin").is_none(), "{body}");
        assert_eq!(parsed["text"], r#"","admin":true,"x":"#);
    }

    /// Backslashes, newlines and control characters are the rest of it: each one
    /// is either invalid raw inside a JSON string or means something else there.
    #[test]
    fn escapes_what_json_requires_escaped() {
        let t = Template::parse(r#"{"text":"%MESSAGE%"}"#).unwrap();
        let body = t.render(&values("back\\slash\nnewline\u{7}bell", ""));
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["text"], "back\\slash\nnewline\u{7}bell");
    }

    #[test]
    fn an_unknown_placeholder_is_refused_by_name() {
        let err = Template::parse(r#"{"text":"%HOSTNAME%"}"#).unwrap_err().to_string();
        assert!(err.contains("%HOSTNAME%"), "{err}");
        assert!(err.contains("%MESSAGE%"), "{err}");
    }

    /// A percentage sign is not a placeholder, and neither is a lower-case
    /// word between two of them: refusing those would make ordinary prose
    /// unwritable, which is how an operator ends up with no template at all.
    #[test]
    fn a_bare_percent_stays_literal() {
        for raw in [
            r#"{"text":"100% of cycles failed"}"#,
            r#"{"text":"%not a placeholder%"}"#,
            r#"{"text":"%%"}"#,
            r#"{"text":"50%"}"#,
        ] {
            let body = Template::parse(raw).unwrap().render(&values("m", "d"));
            assert_eq!(body, raw, "{raw}");
        }
    }

    /// A placeholder outside a string renders as bare text where JSON wants a
    /// value, so the receiver rejects every event. Caught at startup instead.
    #[test]
    fn a_template_that_does_not_render_as_json_is_refused() {
        for raw in [
            r#"{"text":%MESSAGE%}"#,  // placeholder outside a string
            r#"{"text":"%MESSAGE%""#, // truncated
            r#"text=%MESSAGE%"#,      // not JSON at all
        ] {
            let err = Template::parse(raw).unwrap_err().to_string();
            assert!(err.contains("does not render as JSON"), "{raw}: {err}");
        }
    }

    /// The default has to survive its own rule, and a template with no
    /// placeholders at all is still a valid one.
    #[test]
    fn a_constant_template_is_valid() {
        assert_eq!(
            Template::parse(r#"{"text":"something happened"}"#).unwrap().render(&values("m", "d")),
            r#"{"text":"something happened"}"#
        );
    }
}
