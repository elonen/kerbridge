//! Every plain field of the config structs, as the dotted path `kbconfig get`
//! answers by.
//!
//! Generated rather than listed, because a list is a second spelling of the
//! structs and drifts from them: the paths come out of the parser's own
//! serialization, so a field the parser gained is a path this emits without an
//! edit here. What is *not* a field -- a derived value read back through an
//! accessor -- cannot come from here and is joined on by `kbconfig`, which is
//! also where a provider's own settings join.

use std::collections::BTreeMap;

use super::Config;

/// The loaded set as `path -> value`, one entry per field.
///
/// A nested struct dots: `[notify]` inside `main.toml` is `main.notify.*`, and
/// a source is `sources.<name>.*` under the name that file was listed by.
/// `kbmanage.*` is absent where the deployment has no `kbmanage.toml`, which is
/// every container: the paths do not exist rather than reading as empty.
pub fn field_paths(config: &Config) -> Result<BTreeMap<String, String>, String> {
    let mut table = BTreeMap::new();
    put(&mut table, "main", &config.main)?;
    put(&mut table, "realm", &config.realm)?;
    put(&mut table, "issuerd", &config.issuerd)?;
    put(&mut table, "broker", &config.broker)?;
    put(&mut table, "sync", &config.sync)?;
    if let Some(kbmanage) = &config.kbmanage {
        put(&mut table, "kbmanage", kbmanage)?;
    }
    for source in &config.sources {
        put(&mut table, &format!("sources.{}", source.name), source)?;
    }
    Ok(table)
}

fn put<T: serde::Serialize>(
    table: &mut BTreeMap<String, String>,
    prefix: &str,
    value: &T,
) -> Result<(), String> {
    let value = serde_json::to_value(value).map_err(|e| format!("{prefix}: {e}"))?;
    walk(table, prefix, &value);
    Ok(())
}

fn walk(table: &mut BTreeMap<String, String>, path: &str, value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                walk(table, &format!("{path}.{key}"), value);
            }
        }
        leaf => {
            table.insert(path.to_owned(), show(leaf));
        }
    }
}

/// How one value reaches stdout. Nothing here quotes or escapes: the output is
/// what a shell assigns to a variable, so a decoration would have to be
/// stripped by every caller.
///
/// An array is one element per line, so `for` over the output is a loop. An
/// unset optional is the empty string rather than a missing path: the path
/// exists and has no value, which is a different answer from a path nobody
/// spelled and has to stay distinguishable from it.
fn show(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items) => {
            items.iter().map(show).collect::<Vec<String>>().join("\n")
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_reaches_a_shell_undecorated() {
        let secret = "/etc/kerbridge.secrets/notify_url";
        assert_eq!(show(&serde_json::json!(secret)), secret);
        assert_eq!(show(&serde_json::json!(["a", "b"])), "a\nb");
        assert_eq!(show(&serde_json::json!([])), "");
        assert_eq!(show(&serde_json::json!(null)), "");
        assert_eq!(show(&serde_json::json!(36000)), "36000");
        assert_eq!(show(&serde_json::json!(true)), "true");
    }
}
