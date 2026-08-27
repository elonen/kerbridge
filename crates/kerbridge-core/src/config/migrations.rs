//! Every change to the shape of the config set, and what each one means for a
//! file written before it.
//!
//! **The list carries no version numbers, and nothing records which version
//! wrote a config set.** It is replayed from the top every time, and each entry
//! does nothing unless what it describes is actually in the file. A set that
//! has already moved past an entry does not match it, so replaying is safe; a
//! set that skipped four versions matches four entries in one pass. This is
//! what removes the version stamp, the reconstruction of historical defaults
//! and the three-way merge that a version-aware upgrade would need -- and each
//! of those is a thing that can be wrong about a deployment it has never seen.
//!
//! It is only this cheap because a template comments out every option that has
//! a default. A file therefore holds the operator's decisions and nothing else,
//! so an entry has a small, stated set of lines to look at.
//!
//! **A rename ships with its entry, in the same commit.** The entry is not
//! documentation of what happened; it is the only thing that turns
//! `unknown field` into an answer, and the only thing `kbconfig` can replay.
//!
//! **Most operators match no entry at all.** A set that never stated the option
//! a rename is about simply takes the new default.

use std::collections::BTreeMap;

/// One change to the shape of the config set.
///
/// Each is stated as a precondition and a consequence, never as a version
/// range: "if this file sets `sam_attribute`" rather than "if this set was
/// written before 0.4".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migration {
    /// The option kept its meaning and its file, and changed its name.
    Renamed { file: &'static str, from: &'static str, to: &'static str },
    /// The option kept its meaning and moved to another file, under this name
    /// there.
    Moved { file: &'static str, key: &'static str, to_file: &'static str, to: &'static str },
    /// The option is gone. `instead` says what to do now, in one sentence an
    /// operator can act on.
    Retired { file: &'static str, key: &'static str, instead: &'static str },
    /// The option kept its name, and one of the values it takes was renamed.
    /// The only entry that reads a value rather than a key.
    ValueRenamed { file: &'static str, key: &'static str, from: &'static str, to: &'static str },
}

/// Ordered, oldest first, and never reordered: a later entry may act on what an
/// earlier one produced.
pub const MIGRATIONS: &[Migration] = &[
    // No `sync.toml` entry on purpose: `[sync] audit_log_file` and this move of
    // the audit paths landed in the same unreleased cycle, so no config set was
    // ever written that could state the old sync path.
    Migration::ValueRenamed {
        file: "issuerd.toml",
        key: "audit_log_file",
        from: "/var/lib/kerbridge-audit/issuer.log",
        to: "/var/log/kerbridge/issuerd/audit.log",
    },
    Migration::ValueRenamed {
        file: "broker.toml",
        key: "audit_log_file",
        from: "/var/lib/kerbridge-audit/broker.log",
        to: "/var/log/kerbridge/broker/audit.log",
    },
    Migration::Renamed {
        file: "sync.toml",
        from: "cycle_deadline_seconds",
        to: "read_deadline_seconds",
    },
    // Both spellings resolve: the entry above rewrites the old name into this
    // one, and this entry then removes it.
    Migration::Retired {
        file: "sync.toml",
        key: "read_deadline_seconds",
        instead: "a read runs until it is done, and a stalled one is abandoned on its own",
    },
];

/// What a source file is called in an entry. A deployment names its own source
/// files -- `idp_entra.toml`, `idp_staff.toml` -- and an entry is about the
/// shape they share, so it names the shape.
pub const SOURCE_FILE: &str = "idp_<name>.toml";

impl Migration {
    /// The file this entry reads. For a `Moved` entry that is where the option
    /// was, not where it goes.
    pub fn file(&self) -> &'static str {
        match self {
            Self::Renamed { file, .. }
            | Self::Moved { file, .. }
            | Self::Retired { file, .. }
            | Self::ValueRenamed { file, .. } => file,
        }
    }

    /// The key this entry reads.
    pub fn key(&self) -> &'static str {
        match self {
            Self::Renamed { from, .. } => from,
            Self::Moved { key, .. }
            | Self::Retired { key, .. }
            | Self::ValueRenamed { key, .. } => key,
        }
    }

    /// Whether the entry has something to say about an option holding this.
    /// `None` is an option the file does not set. A `ValueRenamed` matches only
    /// where the value is the old one, which is why the check is not simply
    /// "the key is present".
    fn matches(&self, value: Option<&toml::Value>) -> bool {
        let Some(value) = value else { return false };
        match self {
            Self::ValueRenamed { from, .. } => value.as_str() == Some(from),
            _ => true,
        }
    }

    /// One line for an operator, in the imperative: what to do, not what
    /// happened.
    pub fn instruction(&self) -> String {
        match self {
            Self::Renamed { from, to, .. } => format!("rename `{from}` to `{to}`"),
            Self::Moved { key, to_file, to, .. } => {
                format!("move `{key}` to `{to}` in {to_file}")
            }
            Self::Retired { key, instead, .. } => format!("remove `{key}`: {instead}"),
            Self::ValueRenamed { key, from, to, .. } => {
                format!("`{key} = \"{from}\"` is now `{key} = \"{to}\"`")
            }
        }
    }
}

/// What to say about a file the parser refused, or nothing where the list knows
/// of no reason.
///
/// The caller has an error naming an option this version does not accept, which
/// on its own tells an operator only that they are wrong. This turns it into an
/// instruction where the list holds one.
pub fn explain(file: &str, text: &str) -> Vec<String> {
    explain_with(MIGRATIONS, file, text)
}

fn explain_with(list: &[Migration], file: &str, text: &str) -> Vec<String> {
    // A file too broken to parse says nothing about which options it sets, and
    // the syntax error the caller already holds is the better message anyway.
    let Ok(document) = text.parse::<toml::Table>() else { return Vec::new() };
    list.iter()
        .filter(|entry| entry.file() == shape_of(file))
        .filter(|entry| entry.matches(at(&document, entry.key())))
        .map(Migration::instruction)
        .collect()
}

/// What to do about one option, where the list knows.
///
/// `explain` answers for a whole file, which is what a parse failure has.
/// `kbconfig` has already read the file and reports line by line, so it asks
/// per option instead. Both read the same entries.
pub fn instruction(file: &str, key: &str, value: &toml::Value) -> Option<String> {
    MIGRATIONS
        .iter()
        .find(|entry| {
            entry.file() == shape_of(file) && entry.key() == key && entry.matches(Some(value))
        })
        .map(Migration::instruction)
}

/// Replay the whole list over a config set, oldest entry first.
///
/// `set` is keyed by the filename each document was read from, so an entry
/// naming [`SOURCE_FILE`] reaches every source file the deployment has. The
/// returned lines are what changed, in the order it changed, for the caller to
/// show. An empty return means the set was already current -- which is the
/// normal answer, and the reason replaying costs nothing.
pub fn replay(set: &mut BTreeMap<String, toml::Table>) -> Vec<String> {
    let mut changed = Vec::new();
    for entry in MIGRATIONS {
        let files: Vec<String> =
            set.keys().filter(|file| shape_of(file) == entry.file()).cloned().collect();
        for file in files {
            // A deployment that does not have the target file cannot be given
            // one here: an absent `kbmanage.toml` is a deliberate state, and
            // writing one would turn an upgrade into a change of what the
            // deployment is. Checked before the document is borrowed.
            if let Migration::Moved { key, to_file, .. } = entry
                && !set.contains_key(*to_file)
                && set[&file].contains_key(*key)
            {
                changed.push(format!(
                    "{file}: `{key}` belongs in {to_file}, which this deployment does not \
                     have -- it was left where it is"
                ));
                continue;
            }

            let document = set.get_mut(&file).expect("a key just taken from this map");
            if !entry.matches(at(document, entry.key())) {
                continue;
            }
            let mut moved = None;
            match entry {
                Migration::Renamed { from, to, .. } => {
                    let value = take(document, from).expect("matched, so it is there");
                    put(document, to, value);
                }
                Migration::Retired { key, .. } => {
                    take(document, key);
                }
                Migration::ValueRenamed { key, to, .. } => {
                    put(document, key, toml::Value::String((*to).to_owned()));
                }
                Migration::Moved { key, to_file, to, .. } => {
                    moved = take(document, key).map(|value| (value, *to_file, *to));
                }
            }
            if let Some((value, to_file, to)) = moved {
                put(set.get_mut(to_file).expect("checked above"), to, value);
            }
            changed.push(format!("{file}: {}", entry.instruction()));
        }
    }
    changed
}

/// Take a value out by dotted path, leaving the table that held it in place: a
/// `[notify]` header with nothing under it is still valid, and removing it
/// would move every line below.
fn take(document: &mut toml::Table, path: &str) -> Option<toml::Value> {
    let (table, key) = descend_mut(document, path)?;
    table.remove(key)
}

/// Put a value at a dotted path, making the table on the way if the file does
/// not have it yet.
fn put(document: &mut toml::Table, path: &str, value: toml::Value) {
    let mut table = document;
    let (prefix, key) = match path.rsplit_once('.') {
        None => ("", path),
        Some(split) => split,
    };
    for step in prefix.split('.').filter(|s| !s.is_empty()) {
        table = table
            .entry(step)
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("a table, or one just made");
    }
    table.insert(key.to_owned(), value);
}

fn descend_mut<'a>(
    document: &'a mut toml::Table,
    path: &'a str,
) -> Option<(&'a mut toml::Table, &'a str)> {
    let (prefix, key) = match path.rsplit_once('.') {
        None => return Some((document, path)),
        Some(split) => split,
    };
    let mut table = document;
    for step in prefix.split('.') {
        table = table.get_mut(step)?.as_table_mut()?;
    }
    Some((table, key))
}

/// A filename as an entry names it: every `idp_*.toml` is the one source-file
/// shape, and every other file is itself.
fn shape_of(file: &str) -> &str {
    if file.starts_with("idp_") && file.ends_with(".toml") { SOURCE_FILE } else { file }
}

/// A value by dotted path, so that an entry can name an option inside a table:
/// `notify.min_severity`.
fn at<'a>(document: &'a toml::Table, path: &str) -> Option<&'a toml::Value> {
    let (table, key) = match path.rsplit_once('.') {
        None => (document, path),
        Some((prefix, key)) => {
            let mut table = document;
            for step in prefix.split('.') {
                table = table.get(step)?.as_table()?;
            }
            (table, key)
        }
    };
    table.get(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not the shipping list -- these stand in for entries that do not exist
    /// yet, so that the replay is exercised before the first real rename
    /// depends on it.
    const SAMPLE: &[Migration] = &[
        Migration::Renamed { file: "sync.toml", from: "sam_attribute", to: "sam_source" },
        Migration::Moved {
            file: "sync.toml",
            key: "device_grant_days",
            to_file: "main.toml",
            to: "device_grant_days",
        },
        Migration::Retired {
            file: "broker.toml",
            key: "legacy_endpoint",
            instead: "the endpoint it enabled is always on",
        },
        Migration::ValueRenamed { file: SOURCE_FILE, key: "provider", from: "azure", to: "entra" },
    ];

    #[test]
    fn an_entry_speaks_only_for_its_own_file() {
        assert!(explain_with(SAMPLE, "main.toml", "sam_attribute = \"upn\"\n").is_empty());
        assert_eq!(
            explain_with(SAMPLE, "sync.toml", "sam_attribute = \"upn\"\n"),
            ["rename `sam_attribute` to `sam_source`"]
        );
    }

    /// The property that removes the version stamp: an entry is a no-op on a
    /// file that has already moved past it, so replaying the whole list on
    /// every load is safe.
    #[test]
    fn replaying_a_list_on_a_current_file_says_nothing() {
        assert!(
            explain_with(SAMPLE, "sync.toml", "sam_source = \"upn\"\ndry_run = true\n").is_empty()
        );
    }

    /// A set that skipped several versions matches several entries in the one
    /// pass, in the order they were made.
    #[test]
    fn one_pass_answers_a_file_that_is_several_versions_behind() {
        let found =
            explain_with(SAMPLE, "sync.toml", "sam_attribute = \"upn\"\ndevice_grant_days = 30\n");
        assert_eq!(
            found,
            [
                "rename `sam_attribute` to `sam_source`",
                "move `device_grant_days` to `device_grant_days` in main.toml"
            ]
        );
    }

    /// A renamed value is not a renamed key: the option is spelled the way this
    /// version spells it, and only the value it holds is out of date.
    #[test]
    fn a_renamed_value_matches_the_old_value_and_nothing_else() {
        let old = explain_with(SAMPLE, "idp_staff.toml", "provider = \"azure\"\n");
        assert_eq!(old, ["`provider = \"azure\"` is now `provider = \"entra\"`"]);
        assert!(explain_with(SAMPLE, "idp_staff.toml", "provider = \"entra\"\n").is_empty());
    }

    /// A deployment names its own source files, so an entry names the shape
    /// they share and reaches every one of them.
    #[test]
    fn a_source_entry_reaches_whatever_the_deployment_named_its_sources() {
        for file in ["idp_entra.toml", "idp_staff.toml", "idp_2.toml"] {
            assert_eq!(explain_with(SAMPLE, file, "provider = \"azure\"\n").len(), 1, "{file}");
        }
    }

    /// A file too broken to parse is the caller's syntax error to report, not
    /// this list's to guess at.
    #[test]
    fn an_unparsable_file_is_left_to_the_error_the_caller_already_has() {
        assert!(explain_with(SAMPLE, "sync.toml", "sam_attribute = \n").is_empty());
    }

    #[test]
    fn an_option_inside_a_table_is_reached_by_its_dotted_path() {
        const NESTED: &[Migration] =
            &[Migration::Renamed { file: "main.toml", from: "notify.url", to: "notify.url_file" }];
        assert_eq!(explain_with(NESTED, "main.toml", "[notify]\nurl = \"x\"\n").len(), 1);
        assert!(explain_with(NESTED, "main.toml", "url = \"x\"\n").is_empty());
    }

    /// The entries that ship, against the defaults they carry a set to. A
    /// `ValueRenamed` whose `to` is not what this version defaults to would
    /// rewrite a config set to a path no daemon reads -- and would do it
    /// silently, since the file would still parse.
    #[test]
    fn a_shipping_entry_moves_a_value_to_what_this_version_defaults_to() {
        let defaults = [
            ("issuerd.toml", super::super::default_issuer_audit()),
            ("broker.toml", super::super::default_broker_audit()),
        ];
        for entry in MIGRATIONS {
            let Migration::ValueRenamed { file, key: "audit_log_file", to, .. } = entry else {
                continue;
            };
            let (_, default) = defaults
                .iter()
                .find(|(name, _)| name == file)
                .unwrap_or_else(|| panic!("{file} has an audit entry and no default here"));
            assert_eq!(
                default.as_deref().map(|p| p.to_string_lossy().into_owned()).as_deref(),
                Some(*to),
                "{file}"
            );
        }
    }

    /// The ratchet. A key that was renamed away must not come back meaning
    /// something else: the list would then answer with the older of the two
    /// changes and send an operator the wrong way. Trivially true today, and
    /// the point is that it stays true without anyone remembering to look.
    #[test]
    fn no_key_is_retired_and_then_used_again() {
        let mut gone: Vec<(&str, &str)> = Vec::new();
        for entry in MIGRATIONS {
            let name = (entry.file(), entry.key());
            assert!(
                !gone.contains(&name),
                "{}: {} is used again after it was retired",
                name.0,
                name.1
            );
            if !matches!(entry, Migration::ValueRenamed { .. }) {
                gone.push(name);
            }
        }
    }
}
