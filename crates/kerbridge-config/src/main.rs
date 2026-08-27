//! `kbconfig` -- the configuration of a deployment that does not exist yet.
//!
//! It runs *before the realm does*, and its caller is the directory bootstrap,
//! which needs values out of the config set and needs to enumerate its sources
//! -- one OU, one service account and one ACE set each. Shell cannot read TOML,
//! which is why `get` and `sources` exist at all.
//!
//! **It links no LDAP client, and that absence is the privilege boundary.**
//! Directory reach is unavailable here rather than merely unexercised, which is
//! why this is a separate binary from `kbmanage` rather than a subcommand of it:
//! that tool finds its own configuration before it can run, and binds as an
//! account holding delete-child ACEs. A config tool inside it would have to be
//! configured before it could read the configuration, and would ship an
//! operator the directory-deleting binary as part of setup.
//!
//! The IdP is reach of a different kind and is allowed: its OIDC endpoints are
//! public, external, unprivileged, and they exist before, during and after
//! bootstrap, so probing them is not the circular dependency that asking whether
//! an OU exists would be. `check --online` does that, and nothing on a startup
//! or bootstrap path passes the flag -- a transient IdP outage must not be
//! turned into a local one.

#![forbid(unsafe_code)]

mod cli;
mod paths;

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use crate::cli::{Cli, Command};
use anyhow::{Context, Result, bail};
use clap::Parser;
use kerbridge_core::config::decisions::{Instead, Read, read};
use kerbridge_core::config::migrations;
use kerbridge_core::config::{Config, ISSUERD_FILE, TEMPLATE_SOURCES, schemas, templates};
use kerbridge_idp::{IdpSettings, Provider, Verdict};

/// Deadline on one probe request -- connect, TLS, headers and body. Generous
/// because an operator is at the console waiting for the answer, and because a
/// slow IdP is reported as a warning rather than something to give up on early.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

// `upgrade`'s exit code, and the whole of what it means. It answers one
// question -- is the set already this version's shape? -- asked after the
// command has done whatever it does, so a wet run answers yes because it just
// made it so. Two rather than one for no: one is spent on an error, and the
// diff/grep convention puts an informational state above the error code.
//
// A Debian maintainer script reads this, so it is a promised interface and is
// written down in the README beside `get`'s. There is deliberately no third
// code for an option this version cannot carry: that is the `dropped`
// accounting's to report in the operator's face, and a script must not branch
// on it when the instruction is identical either way -- read the dry run, then
// run it for real.
const ALREADY_THIS_SHAPE: u8 = 0;
const NOT_THIS_SHAPE: u8 = 2;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("kbconfig: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    let locate = || match &cli.config {
        Some(path) => Ok(path.clone()),
        None => kerbridge_core::config::discover(),
    };
    // Every verb but one has only ran-or-failed to report, and 1 is how it
    // reports failure -- `main` prints the error and exits with it.
    let ran = |result: Result<()>| result.map(|()| 0);
    match &cli.command {
        // The two verbs that write a directory rather than read one, so
        // neither locates a set: each is told where to write.
        Command::Init { dir, set, force } => {
            for line in init(dir, set, *force)? {
                println!("{line}");
            }
            Ok(0)
        }
        Command::Schema { dir, force } => ran(schema(dir, *force)),
        Command::Check { online } => ran(check(&locate()?, *online)),
        Command::Get { path } => ran(get(&locate()?, path)),
        Command::Sources => ran(sources(&locate()?)),
        Command::Decisions => ran(decisions(&locate()?)),
        Command::Upgrade { dry_run } => upgrade(&locate()?, *dry_run),
    }
}

/// Load the whole set, then say what held.
///
/// Each source's `[provider_config]` is parsed too. `kerbridge-core` hands that
/// table to the adapter without looking inside, so a typo in one is invisible
/// until the adapter is built -- which at startup is after the process has
/// committed to running.
fn check(dir: &Path, online: bool) -> Result<()> {
    let config = Config::load(dir)?;
    one_identity_stated_once(dir)?;
    let parent_ou = config.realm.idp_parent_ou();

    let mut sources = Vec::with_capacity(config.sources.len());
    for source in &config.sources {
        let file = format!("idp_{}.toml", source.name);
        let provider =
            Provider::from_name(&source.provider).with_context(|| format!("{file}: provider"))?;
        let settings = IdpSettings::parse(provider, &source.provider_config)
            .with_context(|| format!("in {file}"))?;
        sources.push((source, settings));
    }

    // The template set less the one optional file, plus it when the set has it.
    let files =
        TEMPLATE_SOURCES.len() - 1 + usize::from(config.kbmanage.is_some()) + config.sources.len();
    println!("config: {files} files under {} parse and cross-check", dir.display());
    println!(
        "realm: {} at {} over {}",
        config.realm.realm,
        config.realm.base_dn(),
        config.realm.ldap_url
    );
    println!(
        "broker: {}, issuer socket {}",
        config.broker.listen,
        config.broker.issuer_socket.display()
    );
    println!("sync: every {}s", config.sync.interval_seconds);
    if config.sources.is_empty() {
        println!("sources: none listed -- a realm mid-bootstrap, not a broken one");
    }
    for (source, _) in &sources {
        println!("source {}: {}, owns {}", source.name, source.provider, source.ou(&parent_ou));
    }
    for warning in &config.warnings {
        eprintln!("warning: {warning}");
    }

    if online {
        probe(&sources)?;
    }
    Ok(())
}

/// The two unix identities `issuerd.toml` spells twice over, each as a name and
/// as a number, in the order the name wins.
const ISSUERD_IDENTITIES: [(&str, &str); 2] =
    [("socket_group", "socket_gid"), ("broker_user", "broker_uid")];

/// Refuse a file that states both halves of one identity.
///
/// The name wins, so the number beside it would be read by nobody -- and a
/// silent disagreement about which unix identity reaches the issuer socket costs
/// every login while nothing reports it, which is the whole reason the contract
/// is written down anywhere.
///
/// It reads the document through `decisions` rather than the loaded [`Config`],
/// and that is the point rather than a shortcut: serde cannot tell a written
/// `10002` from an absent line, and a stated option against a defaulted one is
/// exactly the distinction this rests on.
///
/// The keys only. Whether the name exists on this host is `issuerd`'s question:
/// it is the one process that resolves, and this one runs on hosts where the
/// account is created after the file is written.
fn one_identity_stated_once(dir: &Path) -> Result<()> {
    let Some(document) = document(dir, ISSUERD_FILE)? else { return Ok(()) };
    let read = found(ISSUERD_FILE, &document, &schema_of(ISSUERD_FILE)?)?;
    let stated = |key: &str| read.decisions.iter().any(|decision| decision.path == key);
    for (name, number) in ISSUERD_IDENTITIES {
        if stated(name) && stated(number) {
            bail!(
                "{ISSUERD_FILE} states both `{name}` and `{number}`. They are one identity \
                 and the name is the one issuerd uses, so the number would be read by \
                 nobody -- delete whichever of the two you did not mean."
            );
        }
    }
    Ok(())
}

/// Ask each source's IdP the three questions only it can answer, and fail on the
/// verdicts that name the configuration.
///
/// A warning does not fail: it means nothing answered, which says nothing about
/// whether the file is right, and an operator who cannot reach the IdP from the
/// broker host still has to be able to finish validating the file.
fn probe(sources: &[(&kerbridge_core::config::SourceFile, IdpSettings)]) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the probe runtime")?;
    let mut failures = 0;
    for (source, settings) in sources {
        for probe in runtime.block_on(kerbridge_idp::probe(settings, PROBE_TIMEOUT)) {
            let mark = match probe.verdict {
                Verdict::Pass => "ok  ",
                Verdict::Warn => "warn",
                Verdict::Fail => "FAIL",
            };
            println!("{} {mark} {} -- {}", source.name, probe.check, probe.detail);
            failures += usize::from(probe.verdict == Verdict::Fail);
        }
    }
    if failures > 0 {
        bail!("{failures} probe(s) contradict the configuration");
    }
    Ok(())
}

fn get(dir: &Path, path: &str) -> Result<()> {
    let table = paths::flatten(&Config::load(dir)?)?;
    println!("{}", paths::resolve(&table, path)?);
    Ok(())
}

/// What the operator chose, file by file, and how much they left alone.
///
/// It reads the documents rather than a loaded [`Config`], and that is the
/// point rather than a shortcut: a set holding a key this version no longer
/// accepts does not load, and that is the set someone most needs read back to
/// them. Every failure here is therefore a line in the report, never a stop.
fn decisions(dir: &Path) -> Result<()> {
    let mut blocks: Vec<(String, Read)> = Vec::new();
    for (file, schema) in schemas().map_err(|e| anyhow::anyhow!("{e}"))? {
        if let Some(document) = document(dir, file)? {
            blocks.push((file.to_owned(), found(file, &document, &schema)?));
        }
    }
    for (file, document) in source_documents(dir)? {
        let named = document.get("provider").and_then(toml::Value::as_str).unwrap_or_default();
        let provider = Provider::from_name(named).with_context(|| format!("{file}: provider"))?;
        let schema = provider.source_schema().map_err(|e| anyhow::anyhow!("{e}"))?;
        let read = found(&file, &document, &schema)?;
        blocks.push((file, read));
    }

    let stated: usize = blocks.iter().map(|(_, r)| r.decisions.len()).sum();
    let defaulted: usize = blocks.iter().map(|(_, r)| r.defaulted).sum();
    println!("{}: {stated} options set, {defaulted} at their default.", dir.display());

    let mut required = 0;
    let mut restated = 0;
    let mut unknown = 0;
    for (file, read) in &blocks {
        let mut lines: Vec<(char, String, String)> = Vec::new();
        for decision in &read.decisions {
            let mut mark = ' ';
            let note = if decision.restates_the_default() {
                restated += 1;
                mark = '=';
                "same as the default".to_owned()
            } else {
                match &decision.instead {
                    // Nothing to report: the option has no default value, which
                    // is why the file has to set it. Leaving the note off is
                    // what keeps a screen of required identities from burying
                    // the two lines that changed something.
                    Instead::Nothing => {
                        required += 1;
                        String::new()
                    }
                    Instead::Default(value) => format!("default {value}"),
                    // Both shapes of "no default", kept apart from a default of
                    // nothing: the comment above the line says which.
                    Instead::Derived => "derived or unset".to_owned(),
                }
            };
            lines.push((mark, format!("{} = {}", decision.path, decision.value), note));
        }
        for (path, value) in &read.unknown {
            unknown += 1;
            // The list is the only place that knows an option was renamed
            // rather than invented, and an instruction beats a diagnosis.
            let note = migrations::instruction(file, path, value)
                .unwrap_or_else(|| "no such option in this version".to_owned());
            lines.push(('!', format!("{path} = {value}"), note));
        }
        if lines.is_empty() {
            continue;
        }
        println!("\n{file}");
        print_aligned(&lines);
    }

    // Last, not first. It explains marks the reader has already met, and a
    // reader who has met none of them has stopped before reaching it. Each line
    // is printed only where the report holds what it describes.
    println!("\nThe note on a line is the value KerBridge would use if you deleted that line.");
    if required > 0 {
        println!("A line with no note is an option you must set: it has no default value.");
    }
    if restated > 0 {
        println!("Comment out the lines marked `=`, so a new version can change the default.");
    }
    if unknown > 0 {
        println!("Correct the lines marked `!`, as the note against each one says.");
        println!("`kbconfig upgrade --dry-run` says what that command would correct for you.");
    }
    if restated + unknown > 0 {
        println!("\n{restated} line(s) marked `=`, {unknown} marked `!`.");
    }
    Ok(())
}

/// Carry a config set to this version.
///
/// Two steps, and they are separate on purpose. The migration list is replayed
/// first, over the whole set at once, because an option that moved to another
/// file has to leave one document and reach another before either is written.
/// Then every file is written again from this version's template with the
/// operator's answers put back into it -- so the prose, the newly added
/// options and the commented defaults all become this version's, and the
/// answers are the only thing carried over.
///
/// It never changes what an option evaluates to. A decision goes back as
/// written, including one that writes a value already the default: `decisions`
/// names those and it is the operator's call, not this command's.
fn upgrade(dir: &Path, dry_run: bool) -> Result<u8> {
    let mut set: BTreeMap<String, toml::Table> = BTreeMap::new();
    for (file, _) in schemas().map_err(|e| anyhow::anyhow!("{e}"))? {
        if let Some(document) = document(dir, file)? {
            set.insert(file.to_owned(), document);
        }
    }
    let providers: BTreeMap<String, Provider> = source_documents(dir)?
        .into_iter()
        .map(|(file, document)| {
            let named = document.get("provider").and_then(toml::Value::as_str).unwrap_or_default();
            let provider = Provider::from_name(named)
                .with_context(|| format!("{file}: provider"))
                .map(|provider| (file.clone(), provider));
            set.insert(file, document);
            provider
        })
        .collect::<Result<_>>()?;

    let mut report: Vec<String> = migrations::replay(&mut set);
    let mut written = 0;
    let mut dropped = 0;
    for (file, document) in &set {
        let (schema, template) = match providers.get(file) {
            Some(provider) => (
                provider.source_schema().map_err(|e| anyhow::anyhow!("{e}"))?,
                provider.source_template().map_err(|e| anyhow::anyhow!("{e}"))?,
            ),
            None => (schema_of(file)?, template_of(file)?),
        };
        let old = std::fs::read_to_string(dir.join(file)).unwrap_or_default();
        let read = found(file, document, &schema)?;
        let mut answers: Vec<(String, toml::Value)> =
            read.decisions.iter().map(|d| (d.path.clone(), d.value.clone())).collect();
        answers.extend(read.unknown.iter().cloned());

        let (body, missed) = kerbridge_core::config::decisions::apply(&template, &answers);
        for path in &missed {
            dropped += 1;
            let value = answers.iter().find(|(p, _)| p == path).map(|(_, v)| v);
            report.push(format!(
                "{file}: dropped `{path} = {}` -- this version has no such option",
                value.map(ToString::to_string).unwrap_or_default()
            ));
        }
        for option in new_options(&template, &old) {
            report.push(format!("{file}: this version adds `{option}`"));
        }

        if old == body {
            continue;
        }
        let path = dir.join(file);
        let backup = path.with_extension("toml.bak");
        written += 1;
        report.push(format!("{file}: written again from this version's template"));
        // The .bak is single-generation by design -- the rename below overwrites
        // it -- and it is the only surviving copy of any comment the operator
        // wrote by hand, so a second upgrade destroys one silently unless this
        // says so. Reported in both modes: a dry run is where an operator finds
        // out in time to copy it somewhere else.
        if backup.exists() {
            report.push(format!(
                "{file}: the earlier {file}.bak is overwritten -- there is only ever one"
            ));
        }
        if !dry_run {
            // Read before the rename, because after it this name belongs to the
            // .bak. Otherwise the replacement takes a fresh umask-derived mode
            // and the mode the admin (or a package) chose survives only on the
            // copy nobody reads -- Policy §10.7.3 wants local changes preserved
            // across an upgrade, and §10.10 is the section that says a file's
            // mode and owner are among them. The group matters in a Debian
            // deployment, where this runs as root against files group-owned by
            // _kerbridge.
            let kept = std::fs::metadata(&path)
                .with_context(|| format!("reading the mode and owner of {file}"))?;
            std::fs::rename(&path, &backup).with_context(|| format!("keeping the old {file}"))?;
            // The mode is asked for at creation and not only set afterwards.
            // open(2) subtracts the umask and never adds to what is asked, so
            // this can only land at or below the kept mode -- which means the
            // replacement is never briefly *wider* than the file it replaces.
            // `set_permissions` then puts back whatever the umask took.
            let mut new = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(kept.permissions().mode())
                .open(&path)
                .with_context(|| format!("writing {file}"))?;
            new.write_all(body.as_bytes()).with_context(|| format!("writing {file}"))?;
            std::fs::set_permissions(&path, kept.permissions())
                .with_context(|| format!("restoring the mode of {file}"))?;
            std::os::unix::fs::chown(&path, Some(kept.uid()), Some(kept.gid()))
                .with_context(|| format!("restoring the owner of {file}"))?;
        }
    }

    for line in &report {
        println!("{line}");
    }
    if written == 0 {
        println!("{}: already this version's shape, nothing to do.", dir.display());
        return Ok(ALREADY_THIS_SHAPE);
    }
    if dry_run {
        println!("\n{written} file(s) would change. Nothing was written.");
        println!("Run `kbconfig upgrade` without --dry-run to write them.");
        return Ok(NOT_THIS_SHAPE);
    }
    println!("\n{written} file(s) written. The old ones are beside them, as *.toml.bak.");
    if dropped > 0 {
        println!("{dropped} line(s) were dropped. They are in the .bak files if you need them.");
    }
    println!("Any comment you added yourself is in the .bak files, not in the new ones.\n");
    check(dir, false)?;
    // The set is this version's shape because this run just made it so: same
    // predicate as the dry run, answered after the command did its work.
    Ok(ALREADY_THIS_SHAPE)
}

/// Options this version's template names that the old file did not mention at
/// all, set or commented. What an operator most wants out of an upgrade, and
/// the one thing a diff of two rendered templates would bury under prose.
fn new_options(template: &str, old: &str) -> Vec<String> {
    let had = kerbridge_core::config::decisions::options(old);
    kerbridge_core::config::decisions::options(template)
        .into_iter()
        .filter(|option| !had.contains(option))
        .collect()
}

fn schema_of(file: &str) -> Result<serde_json::Value> {
    schemas()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .into_iter()
        .find(|(name, _)| *name == file)
        .map(|(_, schema)| schema)
        .with_context(|| format!("{file}: this version has no such file"))
}

fn template_of(file: &str) -> Result<String> {
    templates()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .into_iter()
        .find(|(name, _)| *name == file)
        .map(|(_, body)| body)
        .with_context(|| format!("{file}: this version has no such file"))
}

/// Read one file, and say which file it was if the read fails.
fn found(file: &str, document: &toml::Table, schema: &serde_json::Value) -> Result<Read> {
    read(document, schema).map_err(|e| anyhow::anyhow!("{file}: {e}"))
}

/// The mark, the value column, and the note against it.
///
/// The mark is what a reader scans for: `=` is a line that writes the value
/// already in force, `!` is a line that stops the services from starting, and a
/// space is a line that is doing its job. It sits in column one so that the
/// two that need an answer are findable without reading any of the others.
///
/// The column is as wide as the widest *annotated* line, capped at
/// [`NOTE_COLUMN`]: a line with no note needs no room reserved beside it, and
/// most of the long lines are the required identities, which have none. A note
/// against a line wider than the column goes on the next row.
fn print_aligned(lines: &[(char, String, String)]) {
    let width = lines
        .iter()
        .filter(|(_, _, note)| !note.is_empty())
        .map(|(_, line, _)| line.len())
        .max()
        .unwrap_or(0)
        .min(NOTE_COLUMN);
    for (mark, line, note) in lines {
        if note.is_empty() {
            println!("{mark} {line}");
        } else if line.len() <= width {
            println!("{mark} {line:width$}  {note}");
        } else {
            println!("{mark} {line}\n  {:width$}  {note}", "");
        }
    }
}

/// How wide the value column may grow before a line takes its note on the next
/// row. Chosen so that the two together stay inside 80 columns.
const NOTE_COLUMN: usize = 52;

/// One file of the set, parsed but not validated. `None` where the file is not
/// there -- `kbmanage.toml` normally is not, and a set missing a required file
/// is `check`'s to refuse.
fn document(dir: &Path, file: &str) -> Result<Option<toml::Table>> {
    let path = dir.join(file);
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(None) };
    Ok(Some(toml::from_str(&text).with_context(|| format!("in {}", path.display()))?))
}

/// The source files `main.toml` lists, read the same way. The list comes out of
/// the document rather than out of a loaded `Config`, so a set that will not
/// load still reports every source it names.
fn source_documents(dir: &Path) -> Result<Vec<(String, toml::Table)>> {
    let Some(main) = document(dir, kerbridge_core::config::MAIN_FILE)? else {
        return Ok(Vec::new());
    };
    let names = main.get("sources").and_then(toml::Value::as_array).cloned().unwrap_or_default();
    let mut out = Vec::new();
    for name in names.iter().filter_map(toml::Value::as_str) {
        let file = format!("idp_{name}.toml");
        if let Some(document) = document(dir, &file)? {
            out.push((file, document));
        }
    }
    Ok(out)
}

fn sources(dir: &Path) -> Result<()> {
    for source in &Config::load(dir)?.sources {
        println!("{}", source.name);
    }
    Ok(())
}

/// A whole config set, written from this version's templates with the caller's
/// answers put into it.
///
/// The envelope templates come from `kerbridge-core` and each provider's block
/// from its own adapter, so a second adapter's file appears here with no edit to
/// this function.
///
/// **With no `--set` the bodies are the templates unchanged**, which is what the
/// committed `deploy/configs/*.toml.example` set holds, under the live names. A
/// test holds the equality.
///
/// This is the verb a Debian `postinst` calls with the debconf answers, and it
/// carries two rules of its own so that no maintainer script has to retype
/// either:
///
/// - **Write only if absent.** An existing file is refused unless `--force`,
///   because overwriting an edited config set is the one destructive thing this
///   binary can do.
/// - **Write nothing at all if a required answer is empty.** Not the file, not
///   the rest of the set. An empty answer cannot be told from a question nobody
///   answered, so an unattended install must end with no config set rather than
///   one naming a realm nobody chose. It says which answer it was and exits 0:
///   nothing malfunctioned and the install goes on, which is the whole reason
///   the rule lives here rather than in shell.
///
/// An empty answer for an option that is *not* required is dropped instead, and
/// reported. The template's commented default line then survives, which is what
/// an answer of "no opinion" means -- writing `key = ""` would state the empty
/// string as the deployment's choice.
fn init(dir: &Path, set: &[String], force: bool) -> Result<Vec<String>> {
    let mut files: Vec<(String, String)> = templates()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .into_iter()
        .map(|(name, body)| (name.to_owned(), body))
        .collect();
    for provider in Provider::ALL {
        let body = provider.source_template().map_err(|e| anyhow::anyhow!("{e}"))?;
        files.push((format!("idp_{}.toml", provider.name()), body));
    }

    let answers: Vec<Answer> =
        set.iter().map(|argument| Answer::parse(argument)).collect::<Result<_>>()?;
    // An answer naming a file this version does not write reaches no template,
    // so `apply` never sees it to report it -- it is named here instead.
    let mut unplaceable: Vec<String> = answers
        .iter()
        .filter(|answer| !files.iter().any(|(name, _)| *name == answer.file))
        .map(|answer| format!("{}: this version writes no {}", answer.named(), answer.file))
        .collect();
    let mut missing: Vec<String> = Vec::new();
    let mut defaulted: Vec<String> = Vec::new();
    let mut written: Vec<(String, String)> = Vec::with_capacity(files.len());

    for (file, template) in &files {
        let lines = kerbridge_core::config::decisions::lines(template);
        let mut answered: Vec<(String, toml::Value)> = Vec::new();
        for answer in answers.iter().filter(|answer| answer.file == *file) {
            let line = lines.iter().find(|line| line.path == answer.path);
            if answer.text.is_empty() {
                // In a template a stated line is exactly a required option.
                match line {
                    Some(line) if line.stated => missing.push(answer.named()),
                    _ => defaulted.push(answer.named()),
                }
                continue;
            }
            answered.push((
                answer.path.clone(),
                answer.value(line.and_then(|line| line.shown.as_ref()))?,
            ));
        }
        let (body, missed) = kerbridge_core::config::decisions::apply(template, &answered);
        unplaceable.extend(missed.into_iter().map(|path| {
            format!("{}.{path}: {file} has no such option in this version", stem(file))
        }));
        written.push((file.clone(), body));
    }

    let mut report: Vec<String> = Vec::new();
    for path in &defaulted {
        report.push(format!("{path}: answered empty and not required -- left at its default"));
    }
    for note in &unplaceable {
        report.push(format!("{note} -- your answer was not written"));
    }
    if !missing.is_empty() {
        report.push(format!(
            "{}: nothing written -- required and answered empty: {}",
            dir.display(),
            missing.join(", ")
        ));
        return Ok(report);
    }
    write_set(dir, &written, force)?;
    Ok(report)
}

/// One `--set <file>.<option>=<value>`, split up but not yet interpreted.
///
/// The text stays text until the template says what type the option holds,
/// because that is the only place the type is written down once.
#[derive(Debug)]
struct Answer {
    /// The file the option lives in -- `realm.toml`, `idp_entra.toml`.
    file: String,
    /// Dotted from that file's root, the form `kbconfig decisions` prints and
    /// [`kerbridge_core::config::decisions::apply`] places.
    path: String,
    /// The right-hand side, verbatim. Empty is the answer debconf gives for a
    /// question nobody answered, and this command's whole shape turns on it.
    text: String,
}

impl Answer {
    fn parse(argument: &str) -> Result<Self> {
        let (path, text) = argument
            .split_once('=')
            .with_context(|| format!("--set {argument}: an answer is <file>.<option>=<value>"))?;
        // The first dot, not the last: a path below a table keeps its own dots,
        // as in `idp_entra.provider_config.tenant_id`.
        let (stem, option) = path.split_once('.').with_context(|| {
            format!(
                "--set {argument}: {path:?} names no file. An answer is \
                 <file>.<option>=<value>, as in realm.realm=EXAMPLE.SITE"
            )
        })?;
        Ok(Self { file: format!("{stem}.toml"), path: option.to_owned(), text: text.to_owned() })
    }

    /// How the answer is named back to whoever wrote it: the `--set` path.
    fn named(&self) -> String {
        format!("{}.{}", stem(&self.file), self.path)
    }

    /// The TOML value this answer stands for, in the type the option holds.
    ///
    /// `shown` is the value this version's template displays for the option --
    /// its example, its default, or the `# Example:` above a line that shows
    /// neither -- and it is where the type comes from. So a string option takes
    /// its answer as written and never as the integer, the boolean or the date
    /// the text happens to read as: a `group_suffix` of `42` is the text `42`.
    ///
    /// A non-string option parses its answer as TOML, which is what makes
    /// `main.sources=["entra"]` a list. Text that will not parse is refused
    /// there rather than quietly written as a string the parser will reject.
    ///
    /// A template shows a value for every option it names, so the last arm is
    /// not reachable from one. It is there for a document that is not a
    /// template, and it guesses: text that parses as TOML is that value, and
    /// anything else is the string it reads as.
    fn value(&self, shown: Option<&toml::Value>) -> Result<toml::Value> {
        match shown {
            Some(toml::Value::String(_)) => Ok(toml::Value::String(self.text.clone())),
            Some(other) => self.text.parse().with_context(|| {
                format!(
                    "--set {}: this option holds {}, and {:?} is not one",
                    self.named(),
                    other.type_str(),
                    self.text
                )
            }),
            None => {
                Ok(self.text.parse().unwrap_or_else(|_| toml::Value::String(self.text.clone())))
            }
        }
    }
}

/// A config file's name without its extension, which is what a `--set` path
/// names it by.
fn stem(file: &str) -> &str {
    file.strip_suffix(".toml").unwrap_or(file)
}

/// The parser's description of itself, as JSON Schema: one document per config
/// file, plus the mapping that points an editor at them.
///
/// Written rather than printed because there is one document per file, and
/// because the caller that wants them is an editor, which wants them on disk.
/// The documents go in their own `schema/` subdirectory -- a config directory
/// is a place an operator edits, and a generated file they must not edit does
/// not belong in it. The mapping cannot join them there: taplo finds a
/// `.taplo.toml` by walking up from the file being edited, so it has to sit
/// beside the `*.toml` it describes.
///
/// A source file's document is named after its *provider*, not after a
/// deployment's source name: which keys the block has follows the adapter, and
/// one document serves every source using it.
fn schema(dir: &Path, force: bool) -> Result<()> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut described: Vec<String> = Vec::new();
    for (name, schema) in schemas().map_err(|e| anyhow::anyhow!("{e}"))? {
        files.push((schema_file(name), render_json(&schema)?));
        described.push(name.to_owned());
    }
    for provider in Provider::ALL {
        let schema = provider.source_schema().map_err(|e| anyhow::anyhow!("{e}"))?;
        let file = format!("idp_{}.toml", provider.name());
        files.push((schema_file(&file), render_json(&schema)?));
        described.push(file);
    }
    files.push((TAPLO_FILE.to_owned(), taplo_config(&described)));
    write_set(dir, &files, force)
}

/// Taplo's configuration file, which is how a schema reaches an editor. It sits
/// in the config directory itself, not in [`SCHEMA_DIR`], because taplo walks
/// up from the file being edited to find it.
const TAPLO_FILE: &str = ".taplo.toml";

/// Where the documents go, under the config directory. Their own subdirectory,
/// so that nothing an operator must not edit sits among the files they must.
const SCHEMA_DIR: &str = "schema";

/// Which document describes which file, for the one tool that reads such a
/// mapping: taplo, as the `taplo` command and as the language server Helix,
/// Neovim and the VS Code TOML extension all run. Nothing in KerBridge reads
/// it, and a deployment that wants no editor support can delete it.
///
/// Both relative paths here are resolved against this file's own directory --
/// `include` as well as `schema.path`, whatever taplo's own documentation says
/// about the first. So an `include` pattern is a bare name, a `**/` in front of
/// one would stop it matching, and a `schema.path` reaches into [`SCHEMA_DIR`]
/// from here.
///
/// The `.example` copy is named beside the live file because it is the one a
/// reader opens before a deployment exists.
fn taplo_config(config_files: &[String]) -> String {
    let mut out = String::from(
        "# Written by `kbconfig schema`, and read by taplo -- the `taplo` command, and\n\
         # the language server that Helix, Neovim and the VS Code TOML extension run.\n\
         # It says which schema describes which file, which is what gives an editor\n\
         # completion and validation while you edit. Nothing in KerBridge reads it.\n\
         #\n\
         # The documents themselves are in schema/ beside this file. Both are\n\
         # generated, and neither is yours to edit. Rewrite the set after an\n\
         # upgrade, from the config directory:\n\
         #\n\
         #   kbconfig schema . --force\n\
         #\n\
         # A source file is idp_<name>.toml for whatever name the deployment chose,\n\
         # and the rule below names the adapter's own. A source named anything else\n\
         # needs its file named in that rule's `include` too -- and `--force` writes\n\
         # this file again, so keep the edit somewhere you will not lose.\n",
    );
    for file in config_files {
        out.push_str(&format!(
            "\n[[rule]]\ninclude = [\"{file}\", \"{file}.example\"]\nschema = {{ path = \"{}\" }}\n",
            schema_file(file)
        ));
    }
    out
}

/// `main.toml` -> `schema/main.schema.json`, as a path under the config
/// directory. Nothing resolves this by name: it is one document per config
/// file, and the mapping says which describes which. One function, because the
/// document and the mapping entry naming it must not drift apart.
fn schema_file(config_file: &str) -> String {
    format!("{SCHEMA_DIR}/{}.schema.json", config_file.trim_end_matches(".toml"))
}

/// Pretty, and with a trailing newline. It is a file a person opens and a file
/// a diff is read on, which a single line would ruin for both.
fn render_json(schema: &serde_json::Value) -> Result<String> {
    let mut text = serde_json::to_string_pretty(schema).context("rendering the schema")?;
    text.push('\n');
    Ok(text)
}

/// Write a named set of files, or none of them.
///
/// Every name is tested before any is written: a half-written set is worse than
/// a refused one, because the files that did land look like a complete answer.
fn write_set(dir: &Path, files: &[(String, String)], force: bool) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    if !force {
        let present: Vec<&str> = files
            .iter()
            .map(|(name, _)| name.as_str())
            .filter(|name| dir.join(name).exists())
            .collect();
        if !present.is_empty() {
            bail!(
                "{} already holds {} -- pass --force to overwrite",
                dir.display(),
                present.join(", ")
            );
        }
    }

    for (name, body) in files {
        let path = dir.join(name);
        // A name may hold a directory of its own -- `schema/main.schema.json`.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A config set on disk: the emitted templates, plus the one decision no
    /// template can make for a deployment. The closest thing to a complete
    /// example this repository has, and one `kerbridge-core` and `kerbridge-idp`
    /// each hold current against their own parsers.
    pub struct Fixture(PathBuf);

    pub fn fixture(label: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("kbconfig-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in templates().expect("the sources render") {
            std::fs::write(dir.join(name), body).unwrap();
        }
        for provider in Provider::ALL {
            let name = format!("idp_{}.toml", provider.name());
            let body = provider.source_template().expect("the source template renders");
            std::fs::write(dir.join(name), body).unwrap();
        }
        Fixture(dir)
    }

    impl Fixture {
        pub fn dir(&self) -> &Path {
            &self.0
        }

        pub fn load(&self) -> Config {
            Config::load(&self.0).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The claim `SETUP.md` rests on: an operator who has copied the templates
    /// and named an admission group gets a pass, offline, with no realm and no
    /// network.
    #[test]
    fn the_template_set_checks_out_offline() {
        check(fixture("check").dir(), false).unwrap();
    }

    /// A set straight out of the templates has decided only what it had to: the
    /// required keys, plus the admission group the fixture picks. Nothing else
    /// is stated, which is the property the whole template convention exists
    /// for, measured here on a real directory rather than on one body of text.
    #[test]
    fn a_copied_template_set_decides_only_what_it_must() {
        let fixture = fixture("decisions");
        let dir = fixture.dir();
        decisions(dir).unwrap();

        let mut required = 0;
        for (file, schema) in schemas().unwrap() {
            let Some(document) = document(dir, file).unwrap() else { continue };
            let read = read(&document, &schema).unwrap();
            assert!(read.unknown.is_empty(), "{file}: {:?}", read.unknown);
            for decision in &read.decisions {
                assert_eq!(
                    decision.instead,
                    Instead::Nothing,
                    "{file}: {} is stated and does not have to be",
                    decision.path
                );
                required += 1;
            }
        }
        // sources; realm, ldap_url, ldap_ca_file; the broker's two; kbmanage's
        // two. A number rather than a shape, so that a key gaining or losing
        // its default is a failure here and not a silent change of what an
        // operator has to fill in.
        assert_eq!(required, 8);
    }

    /// Both halves of one identity, and the file parses either way -- serde
    /// cannot tell a written `10002` from an absent line, so nothing below this
    /// command would ever report the disagreement. It names the pair, because
    /// which of the two lines to delete is the operator's call and not this
    /// command's.
    ///
    /// Offline, on the plain `check` a daemon runs at startup: an identity that
    /// contradicts itself must not wait for a run that reaches the IdP.
    #[test]
    fn check_refuses_a_file_that_states_one_identity_twice() {
        let fixture = fixture("identity");
        let dir = fixture.dir();
        let path = dir.join("issuerd.toml");
        let template = std::fs::read_to_string(&path).unwrap();

        for (name, number) in ISSUERD_IDENTITIES {
            std::fs::write(&path, format!("{template}{name} = \"_kerbridge\"\n")).unwrap();
            check(dir, false).expect("a name alone is the whole of the identity");
            std::fs::write(&path, format!("{template}{number} = 4242\n")).unwrap();
            check(dir, false).expect("a number alone is what every Compose set states");

            std::fs::write(&path, format!("{template}{name} = \"_kerbridge\"\n{number} = 4242\n"))
                .unwrap();
            let err = format!("{:#}", check(dir, false).unwrap_err());
            assert!(err.contains(name) && err.contains(number), "{err}");
        }
    }

    /// A key that this version dropped has to survive being read: the set no
    /// longer loads, and naming the line is the whole of the help available.
    #[test]
    fn a_key_this_version_dropped_is_named_rather_than_refused() {
        let fixture = fixture("decisions-stale");
        let dir = fixture.dir();
        let path = dir.join("sync.toml");
        let body = std::fs::read_to_string(&path).unwrap() + "sam_attribute = \"upn\"\n";
        std::fs::write(&path, body).unwrap();

        assert!(Config::load(dir).is_err(), "the set must not load");
        decisions(dir).unwrap();
        let read =
            read(&document(dir, "sync.toml").unwrap().unwrap(), &schema_of("sync.toml")).unwrap();
        assert_eq!(read.unknown.len(), 1);
        assert_eq!(read.unknown[0].0, "sam_attribute");
    }

    fn schema_of(file: &str) -> serde_json::Value {
        schemas().unwrap().into_iter().find(|(name, _)| *name == file).unwrap().1
    }

    /// State these root-level lines in a set's `realm.toml`, above the first
    /// table header rather than at the end of the file: `realm.toml` closes
    /// with `[provision]`, and a key written after that header is that table's.
    fn realm_also_stating(dir: &Path, lines: &str) {
        let path = dir.join("realm.toml");
        let body = std::fs::read_to_string(&path).unwrap();
        let (root, table) = body.split_once("\n[").expect("realm.toml opens a table");
        std::fs::write(&path, format!("{root}\n{lines}\n[{table}")).unwrap();
    }

    /// The contract, and the reason an operator can run this without reading
    /// the diff: an upgrade changes the shape of the files and nothing about
    /// what any option evaluates to. Every answer goes back, including the one
    /// that writes a value already the default -- naming those is `decisions`'
    /// job, and acting on them is the operator's.
    #[test]
    fn an_upgrade_changes_no_effective_value() {
        let fixture = fixture("upgrade");
        let dir = fixture.dir();
        // One of each kind of answer: required, a default overridden, and an
        // option with no default at all.
        realm_also_stating(
            dir,
            "ticket_lifetime_seconds = 3600\nbase_dn = \"DC=example,DC=site\"\n",
        );

        let before = format!("{:?}", Config::load(dir).unwrap());
        upgrade(dir, false).unwrap();
        assert_eq!(before, format!("{:?}", Config::load(dir).unwrap()));
    }

    /// The promise a Debian maintainer script reads, in the numbers it reads it
    /// in rather than through the constants that spell them: one question --
    /// is the set already this version's shape? -- answered after the command
    /// has done whatever it does, so the wet run that just made it so says yes.
    #[test]
    fn the_exit_code_says_whether_the_set_is_this_versions_shape() {
        let fixture = fixture("upgrade-code");
        let dir = fixture.dir();
        realm_also_stating(dir, "ticket_lifetime_seconds = 3600\n");

        assert_eq!(upgrade(dir, true).unwrap(), 2, "a stale set, and nothing written");
        assert_eq!(upgrade(dir, false).unwrap(), 0, "the same predicate, after the writing");
        assert_eq!(upgrade(dir, true).unwrap(), 0, "and it stays answered");
    }

    /// A file's mode and owner are the admin's. Renaming the old one away and
    /// writing a fresh one would hand the replacement whatever the umask says,
    /// leaving the real answer on the `.bak` -- where nothing reads it and the
    /// next upgrade overwrites it.
    #[test]
    fn a_rewrite_keeps_the_mode_and_the_group_of_the_file_it_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture("upgrade-mode");
        let dir = fixture.dir();
        realm_also_stating(dir, "ticket_lifetime_seconds = 3600\n");
        let path = dir.join("realm.toml");
        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o640)).unwrap();
        // A group the replacement would not have been given on its own, so the
        // assertion is about the rewrite rather than about this process.
        let group = another_group(std::fs::metadata(&path).unwrap().gid());
        std::os::unix::fs::chown(&path, None, Some(group)).unwrap();

        upgrade(dir, false).unwrap();

        assert!(dir.join("realm.toml.bak").is_file(), "the file has to have been rewritten");
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.permissions().mode() & 0o7777, 0o640);
        assert_eq!(after.gid(), group);
    }

    /// A group this process may chown to that is not `gid`. Linux answers it
    /// without a libc dependency; where there is no `/proc` and where the
    /// process is in one group, `gid` is the answer and the assertion above
    /// weakens to "the rewrite left the group alone", which is still it.
    fn another_group(gid: u32) -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find_map(|line| line.strip_prefix("Groups:"))
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|group| group.parse().ok())
            .find(|group| *group != gid)
            .unwrap_or(gid)
    }

    /// `--dry-run` is what an operator runs first, so it has to be true that it
    /// writes nothing at all -- not the file, and not a `.bak` beside it.
    #[test]
    fn a_dry_run_writes_nothing() {
        let fixture = fixture("upgrade-dry");
        let dir = fixture.dir();
        let before: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), std::fs::read(e.path()).unwrap())
            })
            .collect();
        upgrade(dir, true).unwrap();
        let after: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), std::fs::read(e.path()).unwrap())
            })
            .collect();
        assert_eq!(before.len(), after.len());
        for entry in &before {
            assert!(after.contains(entry), "{:?} changed", entry.0);
        }
    }

    /// An option the operator set that this version has no migration for is
    /// dropped, because a file holding it does not load and an upgrade that
    /// left it would achieve nothing. It is named and it is in the `.bak`:
    /// dropping a line somebody wrote is not something to do quietly.
    #[test]
    fn an_option_with_no_migration_is_dropped_and_the_old_file_kept() {
        let fixture = fixture("upgrade-drop");
        let dir = fixture.dir();
        let path = dir.join("sync.toml");
        let body = std::fs::read_to_string(&path).unwrap() + "sam_attribute = \"upn\"\n";
        std::fs::write(&path, body).unwrap();

        upgrade(dir, false).unwrap();
        Config::load(dir).expect("the set loads once the line is gone");
        let kept = std::fs::read_to_string(dir.join("sync.toml.bak")).unwrap();
        assert!(kept.contains("sam_attribute"), "the old file keeps the line");
    }

    /// A second source, so a per-source rule is exercised against more than the
    /// one file every fixture already has.
    fn second_source(dir: &Path, name: &str) {
        let body = format!(
            "{}{}",
            kerbridge_core::config::source_envelope(name, Provider::Entra.name())
                .expect("the envelope renders"),
            Provider::Entra.template().expect("the block renders")
        );
        std::fs::write(dir.join(format!("idp_{name}.toml")), body).unwrap();
        let path = dir.join("main.toml");
        let body = std::fs::read_to_string(&path)
            .unwrap()
            .replace(r#"sources = ["entra"]"#, &format!(r#"sources = ["entra", "{name}"]"#));
        std::fs::write(&path, body).unwrap();
    }

    /// An option that was deployment-wide and is now per source reaches *every*
    /// source, and leaves the file it came from. Copying is the only lossless
    /// answer -- "which source gets it" has no other one -- so no account
    /// changes its name because of an upgrade.
    #[test]
    fn an_option_that_became_per_source_is_copied_into_every_source() {
        let fixture = fixture("upgrade-spread");
        let dir = fixture.dir();
        second_source(dir, "staff");
        let path = dir.join("sync.toml");
        let body = std::fs::read_to_string(&path).unwrap() + "sam_source = \"upn\"\n";
        std::fs::write(&path, body).unwrap();

        upgrade(dir, false).unwrap();

        let config = Config::load(dir).expect("the set loads once the option has moved");
        for source in &config.sources {
            let settings = IdpSettings::parse(Provider::Entra, &source.provider_config)
                .expect("the block parses");
            assert_eq!(
                settings.paths()["sam_source"],
                "upn",
                "source {} did not take what sync.toml held",
                source.name
            );
        }
        let sync = std::fs::read_to_string(dir.join("sync.toml")).unwrap();
        assert!(!sync.contains("\nsam_source"), "the old home still states it:\n{sync}");
    }

    /// What an operator most wants out of an upgrade, and the one thing a diff
    /// of two rendered templates buries under prose.
    #[test]
    fn an_option_this_version_added_is_named() {
        let old = "# prose\nrealm = \"EXAMPLE.SITE\"\n#ticket_lifetime_seconds = 36000\n";
        let new = "# prose\nrealm = \"EXAMPLE.SITE\"\n#ticket_lifetime_seconds = 36000\n\
                   \n# new in this version\n#renewal_grace_seconds = 60\n\n[notify]\n#url_file =\n";
        assert_eq!(new_options(new, old), ["renewal_grace_seconds", "notify.url_file"]);
        assert!(new_options(old, old).is_empty());
    }

    /// The path that does not exist has to name itself, because the operator who
    /// hits it is reading a script someone else wrote.
    #[test]
    fn an_unknown_path_names_itself_rather_than_printing_nothing() {
        let dir = fixture("get");
        let err = format!("{:#}", get(dir.dir(), "realm.tenant_id").unwrap_err());
        assert!(err.contains("realm.tenant_id"), "{err}");
    }

    /// The published schema, against documents the parser accepts.
    ///
    /// Nothing else closes this direction. `kerbridge-core`'s own tests hold
    /// every template to the *parser*, by deserializing it into the real
    /// structs -- stricter than any schema can be. What no test asks is whether
    /// the schema agrees, and the schema is the half that leaves this
    /// repository: an editor that marks a legal file wrong is a bug an operator
    /// meets and we never see. `provider_config` was exactly that, admitted by
    /// the parser and forbidden by the schema, until `Provider::source_schema`
    /// composed the two halves.
    ///
    /// Both shapes of the document, because they fail differently. As shipped
    /// it is the required keys and nothing else, which is what catches a schema
    /// that requires something the parser does not. With every key set it is
    /// the whole surface, which is what catches a type.
    #[test]
    fn the_schema_accepts_every_document_the_parser_does() {
        let mut cases: Vec<(String, String, serde_json::Value)> = Vec::new();
        for ((file, body), (described, schema)) in
            templates().unwrap().into_iter().zip(schemas().unwrap())
        {
            assert_eq!(file, described, "a template and a schema fell out of order");
            cases.push((file.to_owned(), body, schema));
        }
        for provider in Provider::ALL {
            cases.push((
                format!("idp_{}.toml", provider.name()),
                provider.source_template().unwrap(),
                provider.source_schema().unwrap(),
            ));
        }

        for (file, body, schema) in cases {
            let validator = jsonschema::validator_for(&schema)
                .unwrap_or_else(|e| panic!("{file}: the document is not a schema: {e}"));
            for (shape, document) in
                [("as shipped", body.clone()), ("with every key set", uncomment(&body))]
            {
                let parsed: toml::Value = toml::from_str(&document)
                    .unwrap_or_else(|e| panic!("{file}, {shape}: not TOML: {e}"));
                let instance = serde_json::to_value(&parsed).unwrap();
                let refused: Vec<String> = validator
                    .iter_errors(&instance)
                    .map(|e| format!("{} {e}", e.instance_path()))
                    .collect();
                assert!(refused.is_empty(), "{file}, {shape}: {}", refused.join("; "));
            }
        }
    }

    /// Drop the comment mark from every `#key = value` line, so that the
    /// document states the whole surface. A bare `#key =` is left alone: it has
    /// no value to state, and uncommenting it would not be TOML.
    ///
    /// A prose line is never one. The key must reach ` = ` with nothing but
    /// name characters before it, which is what keeps `main.toml`'s own worked
    /// example -- `#max_inflight = 8`, indented under a comment -- out.
    fn uncomment(template: &str) -> String {
        let mut out = String::with_capacity(template.len());
        for line in template.lines() {
            let shown = line.strip_prefix('#').filter(|rest| {
                rest.split_once(" = ").is_some_and(|(key, _)| {
                    !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
            });
            out.push_str(shown.unwrap_or(line));
            out.push('\n');
        }
        out
    }

    /// A document beside every config file an editor could open, source files
    /// included, and a mapping that names each of them.
    ///
    /// The mapping is the half that can drift silently: a renamed document
    /// leaves taplo pointed at a file that is not there, and an editor that
    /// simply stops validating looks the same as one that never started.
    #[test]
    fn the_schema_is_written_with_a_mapping_that_names_every_document() {
        let dir = fixture("schema");
        let into = dir.0.join("out");
        schema(&into, false).unwrap();

        let mut wanted: Vec<String> =
            TEMPLATE_SOURCES.iter().map(|(name, _)| (*name).to_owned()).collect();
        wanted.extend(Provider::ALL.iter().map(|p| format!("idp_{}.toml", p.name())));
        for file in &wanted {
            let path = into.join(schema_file(file));
            let text = std::fs::read_to_string(&path).expect("a document per file");
            serde_json::from_str::<serde_json::Value>(&text).expect("it is JSON");
        }

        let mapping: toml::Value =
            toml::from_str(&std::fs::read_to_string(into.join(TAPLO_FILE)).unwrap()).unwrap();
        let rules = mapping["rule"].as_array().expect("one rule per file");
        assert_eq!(rules.len(), wanted.len());
        for rule in rules {
            let named = rule["schema"]["path"].as_str().expect("a rule names a document");
            assert!(into.join(named).is_file(), "{named} is mapped and is not there");
            let include = rule["include"].as_array().expect("a rule names its files");
            assert!(include.iter().any(|f| wanted.iter().any(|w| f.as_str() == Some(w))));
        }

        let err = format!("{:#}", schema(&into, false).unwrap_err());
        assert!(err.contains("main.schema.json") && err.contains("--force"), "{err}");
    }

    /// Overwriting an edited config set is the one destructive thing this binary
    /// can do, so it is the one thing it refuses by default. It is also half of
    /// what a Debian `postinst` needs from `init`: write only if absent.
    #[test]
    fn init_refuses_to_overwrite_an_existing_file() {
        let dir = fixture("init-force");
        let into = dir.0.join("out");
        init(&into, &[], false).unwrap();
        let err = format!("{:#}", init(&into, &[], false).unwrap_err());
        assert!(err.contains("main.toml") && err.contains("--force"), "{err}");
        init(&into, &[], true).unwrap();
        // Every provider's file, not just core's six.
        for provider in Provider::ALL {
            assert!(into.join(format!("idp_{}.toml", provider.name())).exists());
        }
    }

    /// With nothing answered, the bodies are this version's templates byte for
    /// byte -- the same bytes `deploy/configs/*.toml.example` holds.
    #[test]
    fn init_with_no_answers_writes_the_templates_unchanged() {
        let dir = fixture("init-templates");
        let into = dir.0.join("out");
        assert!(init(&into, &[], false).unwrap().is_empty(), "nothing to report");

        let mut wanted: Vec<(String, String)> =
            templates().unwrap().into_iter().map(|(n, b)| (n.to_owned(), b)).collect();
        for provider in Provider::ALL {
            let name = format!("idp_{}.toml", provider.name());
            wanted.push((name, provider.source_template().unwrap()));
        }
        for (file, body) in &wanted {
            let written = std::fs::read_to_string(into.join(file)).expect("a live *.toml per file");
            assert!(written == *body, "{file} is not this version's template");
        }
        // The live names, not the reference copies: this set is meant to be read
        // by the daemons.
        assert!(!into.join("main.toml.example").exists());
    }

    /// The verb a `postinst` calls, driven the way it calls it: a debconf answer
    /// for every question the package asks, plus the values it supplies without
    /// asking. What lands has to be a set that loads, with the answers in it.
    #[test]
    fn init_writes_the_answers_into_a_set_that_loads() {
        let dir = fixture("init-answers");
        let into = dir.0.join("out");
        let answers = [
            "realm.realm=KERB.EXAMPLE.SITE",
            "realm.ldap_url=ldaps://dc1.kerb.example.site:636",
            "realm.ldap_ca_file=/etc/kerbridge/certs/realm-ca.pem",
            "main.sources=[\"entra\"]",
            "issuerd.socket_group=_kerbridge",
            "idp_entra.provider_config.tenant_id=aaaabbbb-0000-cccc-1111-dddd2222eeee",
            "idp_entra.provider_config.admission_group_id=77778888-bbbb-9999-cccc-0000dddd1111",
            // A suffix that reads as an integer, which is the case that says the
            // type comes from the option and not from the text.
            "idp_entra.group_suffix=42",
        ]
        .map(str::to_owned);
        assert!(init(&into, &answers, false).unwrap().is_empty(), "every answer places");

        let config = Config::load(&into).expect("the answered set loads");
        assert_eq!(config.realm.realm, "KERB.EXAMPLE.SITE");
        assert_eq!(config.realm.ldap_url, "ldaps://dc1.kerb.example.site:636");
        assert_eq!(config.realm.base_dn(), "DC=kerb,DC=example,DC=site");
        assert_eq!(config.sources.len(), 1, "main.sources arrived as a list, not a string");
        assert_eq!(config.issuerd.socket_group.as_deref(), Some("_kerbridge"));
        let entra = &config.sources[0].provider_config;
        assert_eq!(entra["tenant_id"].as_str(), Some("aaaabbbb-0000-cccc-1111-dddd2222eeee"));
        assert_eq!(
            entra["admission_group_id"].as_str(),
            Some("77778888-bbbb-9999-cccc-0000dddd1111")
        );
        assert_eq!(config.sources[0].group_suffix, "42");

        // The prose and the commented defaults are still the template's: this is
        // a line rewrite, and an operator opening the file has to find the file
        // they would have found by hand.
        let realm = std::fs::read_to_string(into.join("realm.toml")).unwrap();
        assert!(realm.contains("#ticket_lifetime_seconds = 36000"), "{realm}");
    }

    /// The rule that makes an unattended install safe: an empty answer cannot be
    /// told from a question nobody answered, and a set naming a realm nobody
    /// chose is worse than no set. Not this file, the whole set -- and it says
    /// which answer it was.
    #[test]
    fn init_writes_nothing_when_a_required_answer_is_empty() {
        let dir = fixture("init-empty");
        let into = dir.0.join("out");
        let answers = ["realm.realm=", "issuerd.socket_group=_kerbridge"].map(str::to_owned);
        let report = init(&into, &answers, false).unwrap().join("\n");

        assert!(report.contains("realm.realm"), "{report}");
        assert!(!into.join("issuerd.toml").exists(), "no file at all, not just realm.toml");
        assert!(!into.join("realm.toml").exists());
    }

    /// An empty answer for an option that has a default is "no opinion", and
    /// the template's commented line already says it better than
    /// `socket_gid = ""` would. Reported, because the caller asked for
    /// something and did not get it.
    #[test]
    fn an_empty_answer_for_an_optional_option_leaves_the_default_commented() {
        let dir = fixture("init-optional");
        let into = dir.0.join("out");
        let report = init(&into, &["issuerd.socket_gid=".to_owned()], false).unwrap().join("\n");

        assert!(report.contains("issuerd.socket_gid"), "{report}");
        let issuerd = std::fs::read_to_string(into.join("issuerd.toml")).unwrap();
        assert!(issuerd.contains("#socket_gid = 10002"), "{issuerd}");
        Config::load(&into).expect("the set still loads");
    }

    /// A preseed for a key this version dropped, and one for a file it never
    /// had. Both are named and the set is still written: a stale answer is the
    /// operator's to fix, and dropping one quietly is how a deployment comes to
    /// believe it configured something.
    #[test]
    fn init_names_an_answer_it_cannot_place() {
        let dir = fixture("init-unplaceable");
        let into = dir.0.join("out");
        let answers =
            ["realm.sam_attribute=upn", "idp_okta.provider_config.tenant_id=x"].map(str::to_owned);
        let report = init(&into, &answers, false).unwrap().join("\n");

        assert!(report.contains("realm.sam_attribute"), "{report}");
        assert!(report.contains("idp_okta.provider_config.tenant_id"), "{report}");
        Config::load(&into).expect("the rest of the set is written and loads");
    }

    /// An answer whose text will not become the type the option holds is a
    /// stop, not a string quietly written for the parser to reject later.
    #[test]
    fn an_answer_of_the_wrong_type_is_refused_by_name() {
        let dir = fixture("init-type");
        let into = dir.0.join("out");
        let err =
            format!("{:#}", init(&into, &["main.sources=entra".to_owned()], false).unwrap_err());
        assert!(err.contains("main.sources") && err.contains("array"), "{err}");
        assert!(!into.join("main.toml").exists(), "it stopped before writing");
    }

    /// The `--set` grammar, wrong in the two ways a shell gets it wrong.
    #[test]
    fn an_answer_that_is_not_file_option_value_says_so() {
        let missing_value = format!("{:#}", Answer::parse("realm.realm").unwrap_err());
        assert!(missing_value.contains("<file>.<option>=<value>"), "{missing_value}");
        let missing_file = format!("{:#}", Answer::parse("realm=EXAMPLE.SITE").unwrap_err());
        assert!(missing_file.contains("names no file"), "{missing_file}");
        // A DN is full of `=`, and only the first one separates.
        let answer = Answer::parse("broker.bind_dn=CN=svc,DC=example,DC=site").unwrap();
        assert_eq!((answer.file.as_str(), answer.path.as_str()), ("broker.toml", "bind_dn"));
        assert_eq!(answer.text, "CN=svc,DC=example,DC=site");
    }
}
