//! What the operator decided, read back out of a live file.
//!
//! An option that a `*.toml` sets is a configuration decision; every option it
//! leaves out follows its default. That rule is only readable because a
//! template comments out every option that has one -- see
//! `crates/kerbridge-config/GLOSSARY.md`. This module turns the rule into data,
//! which is what lets `kbconfig` say what a deployment chose without the
//! operator reading six files.
//!
//! It reads a document that has **not** been through [`super::Config::load`],
//! deliberately. A set holding a key this version dropped fails to load, and
//! that is the set most in need of being read: the answer has to survive the
//! failure it explains.

use serde_json::Value as Json;

use super::template::Table;

/// One option an operator set, and what the parser would have used instead.
#[derive(Debug, PartialEq)]
pub struct Decision {
    /// Dotted from the file's root: `min_severity` inside `[notify]` is
    /// `notify.min_severity`.
    pub path: String,
    /// As written in the file.
    pub value: toml::Value,
    pub instead: Instead,
}

/// What the parser would have used for an option the file did not set.
#[derive(Debug, PartialEq)]
pub enum Instead {
    /// Nothing: the option is required, and a file that omits it does not load.
    Nothing,
    /// This value.
    Default(Json),
    /// A value derived from another option, or no value at all. `realm.base_dn`
    /// and `notify.url_file` are the two shapes of this.
    Derived,
}

impl Decision {
    /// Whether the operator wrote the value the parser would have used anyway.
    ///
    /// Such a line decides nothing and costs something: it cannot be told apart
    /// from a real configuration decision, so it pins the deployment to today's
    /// default for as long as it is there.
    pub fn restates_the_default(&self) -> bool {
        match &self.instead {
            Instead::Default(value) => {
                serde_json::to_value(&self.value).is_ok_and(|written| written == *value)
            }
            _ => false,
        }
    }
}

/// What one live file holds, against the schema that describes it.
#[derive(Debug, Default)]
pub struct Read {
    pub decisions: Vec<Decision>,
    /// How many options the file leaves to their default.
    pub defaulted: usize,
    /// Keys the schema does not describe, dotted, with what the file says
    /// against them. [`super::Config::load`] refuses a file holding one; this
    /// names them instead, because a set that will not load is exactly the set
    /// someone is trying to understand -- and the value is what a rename would
    /// have to carry to the key's new name.
    pub unknown: Vec<(String, toml::Value)>,
}

/// Read one file's decisions.
///
/// `document` is the parsed `*.toml`; `schema` is that file's document from
/// [`super::schemas`], or the assembled one an adapter builds for a source
/// file. A table the document leaves out is still walked, with nothing in it,
/// so its keys count as defaulted rather than disappearing.
pub fn read(document: &toml::Table, schema: &Json) -> Result<Read, String> {
    let mut found = Read::default();
    walk(&Table::root("", schema)?, schema, document, "", &mut found)?;
    found.decisions.sort_by(|a, b| a.path.cmp(&b.path));
    found.unknown.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

fn walk(
    table: &Table,
    root: &Json,
    document: &toml::Table,
    prefix: &str,
    found: &mut Read,
) -> Result<(), String> {
    let empty = toml::Table::new();
    for (key, property) in &table.properties {
        let path = format!("{prefix}{key}");
        let stated = document.get(key);

        // A table descends whether or not the document opened it: its keys are
        // at their defaults either way, and they have to be counted.
        if let Ok(child) = table.child(key, root) {
            let inner = match stated {
                Some(toml::Value::Table(t)) => t,
                // Stated as something that is not a table. The parser is where
                // that is refused; here it is one unreadable key, not a reason
                // to stop reading the other five files.
                Some(value) => {
                    found.unknown.push((path, value.clone()));
                    continue;
                }
                None => &empty,
            };
            walk(&child, root, inner, &format!("{path}."), found)?;
            continue;
        }

        match stated {
            Some(value) => found.decisions.push(Decision {
                path,
                value: value.clone(),
                instead: instead(table, key, property),
            }),
            None => found.defaulted += 1,
        }
    }

    for (key, value) in document {
        if !table.properties.contains_key(key) {
            found.unknown.push((format!("{prefix}{key}"), value.clone()));
        }
    }
    Ok(())
}

fn instead(table: &Table, key: &str, property: &Json) -> Instead {
    if table.required.iter().any(|r| r == key) {
        return Instead::Nothing;
    }
    match property.get("default").filter(|d| !d.is_null()) {
        Some(value) => Instead::Default(value.clone()),
        None => Instead::Derived,
    }
}

/// Write decisions into a freshly rendered template.
///
/// Every option in a template holds its key exactly once, on one line, in one
/// of three forms -- `key = <example>`, `#key = <default>`, or a bare `#key =`.
/// A test in `config/template.rs` holds that, and it is what makes this a line
/// rewrite: the prose, the section banners and the commented defaults around
/// the line survive untouched, so an upgraded file reads as this version's
/// template with the operator's answers in it.
///
/// The second return is the decisions it could not place, being options this
/// version's template does not name. The caller reports them: dropping a line
/// an operator wrote is not something to do quietly.
pub fn apply(template: &str, decisions: &[(String, toml::Value)]) -> (String, Vec<String>) {
    let mut out = String::with_capacity(template.len());
    let mut placed: Vec<String> = Vec::new();
    let mut prefix = String::new();

    for line in template.lines() {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            prefix = format!("{name}.");
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let set = option_key(line).and_then(|key| {
            let path = format!("{prefix}{key}");
            let (_, value) = decisions.iter().find(|(p, _)| *p == path)?;
            Some((path, format!("{key} = {value}")))
        });
        match set {
            Some((path, written)) => {
                out.push_str(&written);
                out.push('\n');
                placed.push(path);
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }

    let missed = decisions
        .iter()
        .map(|(path, _)| path.clone())
        .filter(|path| !placed.contains(path))
        .collect();
    (out, missed)
}

/// Every option a document names, dotted, in the order the lines come.
///
/// It reads commented lines as well as set ones, because in a template and in a
/// live file alike a commented line still *names* the option. Two of those
/// lists subtracted is what an upgrade needs: an option this version's template
/// names and the old file never mentioned is one this version added.
pub fn options(document: &str) -> Vec<String> {
    lines(document).into_iter().map(|line| line.path).collect()
}

/// One option line, as the document writes it.
#[derive(Debug, PartialEq)]
pub struct Line {
    /// Dotted from the file's root, as [`Decision::path`] is.
    pub path: String,
    /// Whether the line states the option rather than commenting it out.
    ///
    /// In a *template* that is exactly "the parser requires this one":
    /// [`super::template::render`] states a required option and comments out
    /// every option that has a default, and a test in `config/template.rs`
    /// holds it. In a live file it means the operator set it.
    pub stated: bool,
    /// The value the option is shown with, which in a template is always one of
    /// three: the example a required option is written with, the default a
    /// commented one names, or -- where the line itself shows nothing, the bare
    /// `#key =` an option with neither has -- the `# Example:` line directly
    /// above it, which [`super::template::render`] writes for exactly that
    /// case.
    ///
    /// So every option a *template* names shows a value of its own type, and
    /// that is what a caller placing an answer into one has to read the type
    /// from. A live file the operator wrote need not, hence the `Option`.
    pub shown: Option<toml::Value>,
}

/// Every option a document names, with the shape of the line that names it.
///
/// The one walk behind [`options`] and behind anything that needs to know what
/// an option *is* rather than only that it exists -- whether the template
/// requires it, and what type it holds. Both answers come off the line itself
/// rather than out of the schema, because the line is what [`apply`] rewrites.
pub fn lines(document: &str) -> Vec<Line> {
    let mut found = Vec::new();
    let mut prefix = String::new();
    // An `# Example:` belongs to the option on the very next line and to no
    // other, so it survives exactly one line. `option_key` cannot mistake it
    // for an option itself -- prose is `# ` with a space, an option is not.
    let mut example: Option<toml::Value> = None;
    for line in document.lines() {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            prefix = format!("{name}.");
            example = None;
            continue;
        }
        if let Some(key) = option_key(line) {
            let shown = line.split_once('=').map(|(_, value)| value.trim()).unwrap_or_default();
            found.push(Line {
                path: format!("{prefix}{key}"),
                stated: !line.starts_with('#'),
                shown: shown.parse().ok().or_else(|| example.take()),
            });
        }
        example = line.strip_prefix("# Example: ").and_then(|shown| shown.trim().parse().ok());
    }
    found
}

/// The key an option line names, on a line that is one. A commented option is
/// `#key = ...` with no space after the `#`, and prose is `# ` with one, so the
/// two never read alike -- which is why `# Example: "DC=example,DC=site"` is
/// not mistaken for an option called `Example`.
fn option_key(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('#').unwrap_or(line);
    let key = rest.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next()?;
    let after = rest[key.len()..].trim_start_matches(' ');
    (!key.is_empty() && after.starts_with('=')).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schemas;

    fn schema_for(file: &str) -> Json {
        schemas().unwrap().into_iter().find(|(name, _)| *name == file).expect("a known file").1
    }

    fn read_file(file: &str, body: &str) -> Read {
        read(&toml::from_str(body).expect("the document parses"), &schema_for(file)).unwrap()
    }

    /// The whole point, on the file with the most keys: what is stated is a
    /// decision, and everything else is counted and not listed.
    #[test]
    fn a_stated_key_is_a_decision_and_the_rest_are_counted() {
        let found = read_file(
            "realm.toml",
            "realm = \"EXAMPLE.SITE\"\n\
             ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
             ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n\
             ticket_lifetime_seconds = 3600\n",
        );
        let paths: Vec<&str> = found.decisions.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(paths, ["ldap_ca_file", "ldap_url", "realm", "ticket_lifetime_seconds"]);
        // Eighteen keys in the file, `[provision]`'s three among them, four
        // stated.
        assert_eq!(found.defaulted, 14);
        assert!(found.unknown.is_empty(), "{:?}", found.unknown);

        let lifetime = &found.decisions[3];
        assert_eq!(lifetime.instead, Instead::Default(36000.into()));
        assert!(!lifetime.restates_the_default());
        assert_eq!(found.decisions[2].instead, Instead::Nothing);
    }

    /// A line that writes the default again decides nothing, and saying so is
    /// what keeps a file down to the decisions an upgrade must carry forward.
    #[test]
    fn a_line_that_writes_the_default_again_is_named_as_one() {
        let found = read_file("sync.toml", "dry_run = false\ninterval_seconds = 600\n");
        assert!(found.decisions[0].restates_the_default(), "dry_run = false is the default");
        assert!(!found.decisions[1].restates_the_default());
    }

    /// A key with no default is not a key with a default of nothing: the file
    /// has to say which, because "delete this line" is safe advice for one and
    /// wrong for the other.
    #[test]
    fn a_derived_key_is_told_apart_from_one_with_a_default() {
        let found = read_file(
            "realm.toml",
            "realm = \"EXAMPLE.SITE\"\n\
             ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
             ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n\
             base_dn = \"DC=example,DC=site\"\n",
        );
        let base_dn = found.decisions.iter().find(|d| d.path == "base_dn").unwrap();
        assert_eq!(base_dn.instead, Instead::Derived);
        assert!(!base_dn.restates_the_default());
    }

    /// `[notify]` is a struct of its own inside `main.toml`, and its keys are
    /// dotted so that two files' `timeout_seconds` never read alike.
    #[test]
    fn a_nested_table_is_walked_and_its_keys_are_dotted() {
        let stated = read_file("main.toml", "sources = []\n\n[notify]\nmin_severity = \"error\"\n");
        assert_eq!(stated.decisions[0].path, "notify.min_severity");
        assert_eq!(stated.decisions[1].path, "sources");

        // Left out entirely, its keys still count rather than vanish.
        let absent = read_file("main.toml", "sources = []\n");
        assert_eq!(absent.decisions.len(), 1);
        assert_eq!(absent.defaulted, stated.defaulted + 1);
    }

    /// The set that most needs reading is the one that no longer loads. An
    /// unknown key is named and the rest of the file is still read.
    #[test]
    fn an_unknown_key_is_named_and_does_not_stop_the_read() {
        let found = read_file("sync.toml", "dry_run = true\ndryrun = true\n\n[notify]\na = 1\n");
        let named: Vec<&str> = found.unknown.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(named, ["dryrun", "notify"]);
        assert_eq!(found.unknown[0].1, toml::Value::Boolean(true));
        assert_eq!(found.decisions.len(), 1);
        assert_eq!(found.decisions[0].path, "dry_run");
    }

    /// The three forms a template writes an option in, read back. What this
    /// says is that a template names the type of every option it holds --
    /// which is what lets `kbconfig init` put an answer in as the type the
    /// option has rather than as the type the text reads as.
    #[test]
    fn every_form_a_template_writes_names_its_type() {
        let found = lines(
            r#"# prose
realm = "EXAMPLE.SITE"
#ticket_lifetime_seconds = 36000
# Example: "DC=example,DC=site"
#base_dn =

[provision]
#dns_forwarder = "1.1.1.1"
"#,
        );
        let seen: Vec<(&str, bool, Option<&str>)> = found
            .iter()
            .map(|line| {
                (line.path.as_str(), line.stated, line.shown.as_ref().map(|v| v.type_str()))
            })
            .collect();
        assert_eq!(
            seen,
            [
                // Stated, so required, and its example says it is a string.
                ("realm", true, Some("string")),
                ("ticket_lifetime_seconds", false, Some("integer")),
                // Its own line shows nothing; the `# Example:` above it does.
                ("base_dn", false, Some("string")),
                ("provision.dns_forwarder", false, Some("string")),
            ]
        );
        assert_eq!(found[0].shown, Some(toml::Value::String("EXAMPLE.SITE".to_owned())));
    }
}
