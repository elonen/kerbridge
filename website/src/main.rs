//! Renders the user help site, one page per language.
//!
//! The page quotes the agent's own labels constantly -- headlines, buttons,
//! blocker sentences -- and those already exist, reviewed, in eleven languages
//! in the client. So this links the client's string tables rather than restating
//! them: a translator writing `content/fi.toml` writes prose, never a label, and
//! the Finnish button names arrive already agreed with the shipped UI.
//!
//! It links them by including the module directly rather than depending on the
//! crate, because `kerbridge-client` has no Linux arm and a site that only
//! builds on macOS is a site nobody can publish from CI. The include needs one
//! thing from its host crate -- `crate::sys::ui_language`, and only inside
//! `tr()`, which nothing here calls -- so `sys` below is that whole seam. If
//! `strings/mod.rs` ever reaches for something else in the client, this stops
//! compiling and the answer is to promote `strings/` to its own crate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use minijinja::{Environment, context};

/// Stands in for the client's platform seam. `tr()` is the only caller and the
/// site never uses it: every page names its language explicitly.
mod sys {
    pub fn ui_language() -> String {
        String::new()
    }
}

// The site reads the tables and nothing else; `tr`, `fill`, `duration` and the
// rest exist for the agents that also compile this file.
#[allow(dead_code)]
#[path = "../../client/kerbridge-client/src/strings/mod.rs"]
mod strings;

use strings::Lang;

/// Both platforms live in one document and CSS shows one of them, so a reader
/// can switch without a reload and a deep link stays valid on either.
const PLATFORMS: [&str; 2] = ["win", "mac"];

/// Copied into the output rather than kept a second time here. `docs/` owns
/// them: `README.md` shows the same two screenshots.
const FROM_DOCS: [(&str, &str); 3] = [
    ("systray-windows.png", "systray-win.png"),
    ("systray-macos.png", "systray-mac.png"),
    ("kerbridge-logo.svg", "logo.svg"),
];

fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check = args.iter().any(|a| a == "--check");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = root.parent().ok_or("website/ has no parent")?.to_path_buf();

    let icons = load_icons(&root.join(".build/icons"))?;
    let mut env = Environment::new();
    env.set_trim_blocks(true);
    env.set_lstrip_blocks(true);
    let page_src = read(&root.join("templates/page.html.j2"))?;
    env.add_template("page", &page_src).map_err(|e| format!("templates/page.html.j2: {e}"))?;
    let index_src = read(&root.join("templates/index.html.j2"))?;
    env.add_template("index", &index_src).map_err(|e| format!("templates/index.html.j2: {e}"))?;

    // English is the source every other file is translated from, so its key set
    // is the contract: a missing key elsewhere is a hole in a page, and an extra
    // one is a key that was renamed in English and left behind here.
    let english = load_content(&root, "en")?;
    let lookups = lookup_fields(&page_src);
    let mut pages = Vec::new();
    let mut untranslated = Vec::new();
    for lang in Lang::ALL {
        let s = strings::pick(lang);
        // A language the agent speaks but the page has not been translated into
        // is a gap, not a failure: the site simply does not offer it, exactly as
        // `lang_for_tag` hands an untranslated desktop the English table. Said
        // out loud, because a silently short language list looks finished.
        let Ok(content) = load_content(&root, s.lang_tag) else {
            untranslated.push(s.lang_tag);
            continue;
        };
        check_keys(s.lang_tag, &english, &content)?;
        check_label_keys(s.lang_tag, &content, &lookups, &s.fields().collect())?;
        pages.push((s, content));
    }
    if !untranslated.is_empty() {
        println!("website: not translated yet, and so not published: {}", untranslated.join(" "));
    }

    let menu: Vec<_> =
        pages.iter().map(|(s, c)| (s.lang_tag, c["language_name"].clone())).collect();

    let out = root.join("dist");
    if !check {
        reset(&out)?;
    }
    for (s, content) in &pages {
        let html = env
            .get_template("page")
            .unwrap()
            .render(context! {
                s => s.fields().collect::<BTreeMap<_, _>>(),
                t => content,
                lang => s.lang_tag,
                langs => menu,
                icons => icons,
                platforms => PLATFORMS,
            })
            .map_err(|e| format!("rendering {}: {e:#}", s.lang_tag))?;
        if !check {
            write(&out.join(s.lang_tag).join("index.html"), &html)?;
        }
    }

    if check {
        println!("website: {} languages render, key sets agree with en", pages.len());
        return Ok(());
    }

    let redirect = env
        .get_template("index")
        .unwrap()
        .render(context! { langs => menu, tags => menu.iter().map(|l| l.0).collect::<Vec<_>>() })
        .map_err(|e| format!("rendering the language index: {e:#}"))?;
    write(&out.join("index.html"), &redirect)?;

    for entry in fs::read_dir(root.join("assets")).map_err(|e| format!("assets/: {e}"))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_file() {
            copy(&path, &out.join("assets").join(path.file_name().unwrap()))?;
        }
    }
    for (src, dst) in FROM_DOCS {
        copy(&repo.join("docs").join(src), &out.join("img").join(dst))?;
    }
    copy(&root.join("assets/fonts"), &out.join("assets/fonts"))?;

    // GitHub Pages serves the custom domain from this file, and runs Jekyll --
    // which drops paths beginning with an underscore -- unless told not to.
    write(&out.join("CNAME"), "help.kerbridge.org\n")?;
    write(&out.join(".nojekyll"), "")?;

    println!("website: wrote {} languages to {}", pages.len(), out.display());
    Ok(())
}

/// The five state icons for each platform, inlined into the page rather than
/// linked. An `<img>` is a separate document, where the `currentColor` these are
/// drawn in resolves to its own black instead of the page's ink -- inline, the
/// icon follows the theme the way the real tray icon follows the taskbar.
fn load_icons(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut icons = BTreeMap::new();
    for platform in ["windows", "macos"] {
        for condition in ["working", "not-started", "flaky", "will-stop", "stopped"] {
            let name = format!("{platform}-{condition}.svg");
            let svg = read(&dir.join(&name)).map_err(|e| {
                format!("{e}\n       run `make icons` first -- the icons are built, not committed")
            })?;
            // Sized and labelled at the point of use; the file is a bare square.
            let svg = svg.replacen("<svg ", "<svg class=\"trayicon\" aria-hidden=\"true\" ", 1);
            let key = format!("{}-{condition}", if platform == "windows" { "win" } else { "mac" });
            icons.insert(key, svg);
        }
    }
    Ok(icons)
}

fn load_content(root: &Path, tag: &str) -> Result<BTreeMap<String, toml::Value>, String> {
    let path = root.join("content").join(format!("{tag}.toml"));
    let text = read(&path)?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// A page renders a fixed set of keys, so a translation that is missing one
/// renders a hole and a translation carrying an extra one is holding a string
/// English has since renamed. Both are reported, both fail.
fn check_keys(
    tag: &str,
    english: &BTreeMap<String, toml::Value>,
    other: &BTreeMap<String, toml::Value>,
) -> Result<(), String> {
    let missing: Vec<_> = english.keys().filter(|k| !other.contains_key(*k)).collect();
    let extra: Vec<_> = other.keys().filter(|k| !english.contains_key(*k)).collect();
    if missing.is_empty() && extra.is_empty() {
        return Ok(());
    }
    let mut msg = format!("content/{tag}.toml does not match content/en.toml");
    if !missing.is_empty() {
        msg += &format!("\n       missing: {missing:?}");
    }
    if !extra.is_empty() {
        msg += &format!("\n       not in en.toml: {extra:?}");
    }
    Err(msg)
}

/// The content fields the template feeds to the string table, as `s[row.field]`.
///
/// Read out of the template rather than listed here, so a lookup added later is
/// covered without anyone remembering to.
fn lookup_fields(template: &str) -> BTreeSet<String> {
    template
        .match_indices("s[")
        .filter(|(i, _)| {
            // `icons[g.icon]` ends in `s[` too, so the match has to start a name.
            !template[..*i].ends_with(|c: char| c.is_alphanumeric() || c == '_')
        })
        .filter_map(|(i, _)| {
            let rest = &template[i + 2..];
            let expr = &rest[..rest.find(']')?];
            Some(expr.split_once('.')?.1.to_owned())
        })
        .collect()
}

/// Every content value that names a label must name one that exists.
///
/// minijinja resolves an unknown key to undefined and renders it as empty, so a
/// string renamed in the client leaves a blank button name on eleven pages with
/// nothing failing -- which is how `act_sign_out_entra` survived its own rename.
fn check_label_keys(
    tag: &str,
    content: &BTreeMap<String, toml::Value>,
    fields: &BTreeSet<String>,
    table: &BTreeMap<&str, &str>,
) -> Result<(), String> {
    fn walk(
        value: &toml::Value,
        fields: &BTreeSet<String>,
        table: &BTreeMap<&str, &str>,
        bad: &mut Vec<String>,
    ) {
        match value {
            toml::Value::Table(t) => {
                for (k, v) in t {
                    if let (true, Some(name)) = (fields.contains(k), v.as_str())
                        && !table.contains_key(name)
                    {
                        bad.push(format!("{k} = {name:?}"));
                    }
                    walk(v, fields, table, bad);
                }
            }
            toml::Value::Array(a) => a.iter().for_each(|v| walk(v, fields, table, bad)),
            _ => {}
        }
    }
    let mut bad = Vec::new();
    for value in content.values() {
        walk(value, fields, table, &mut bad);
    }
    if bad.is_empty() {
        return Ok(());
    }
    Err(format!(
        "content/{tag}.toml names {} label(s) the client's string table does not have: {}",
        bad.len(),
        bad.join(", ")
    ))
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn write(path: &Path, body: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn copy(src: &Path, dst: &Path) -> Result<(), String> {
    if src.is_dir() {
        for entry in fs::read_dir(src).map_err(|e| format!("{}: {e}", src.display()))? {
            let path = entry.map_err(|e| e.to_string())?.path();
            copy(&path, &dst.join(path.file_name().unwrap()))?;
        }
        return Ok(());
    }
    if let Some(dir) = dst.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    fs::copy(src, dst)
        .map(|_| ())
        .map_err(|e| format!("{} -> {}: {e}", src.display(), dst.display()))
}

fn reset(out: &Path) -> Result<(), String> {
    if out.exists() {
        fs::remove_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    }
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))
}
