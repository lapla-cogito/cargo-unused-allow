use anyhow::Context as _;

#[derive(clap::Parser)]
#[command(
    name = "cargo-unused-allow",
    bin_name = "cargo-unused-allow",
    version,
    about = "Detect unused #[allow(...)] attributes in Rust projects",
    override_usage = "cargo-unused-allow [OPTIONS] [-- <CLIPPY_ARGS>...]"
)]
struct Args {
    /// Check all targets (tests, examples, etc...)
    #[arg(long)]
    all_targets: bool,

    /// Automatically remove unused #[allow(...)] attributes from source files
    #[arg(long)]
    fix: bool,

    /// Lint names to exclude from detection (can be specified multiple times)
    #[arg(long = "exclude", value_name = "LINT")]
    excludes: Vec<String>,

    /// Extra arguments passed through to `cargo clippy` (specify after --)
    #[arg(last = true, value_name = "CLIPPY_ARGS", hide = false)]
    clippy_args: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct CargoMessage {
    reason: String,
    message: Option<DiagnosticMessage>,
}

#[derive(Debug, serde::Deserialize)]
struct DiagnosticMessage {
    code: Option<DiagnosticCode>,
    level: String,
    spans: Vec<DiagnosticSpan>,
    rendered: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DiagnosticCode {
    code: String,
}

#[derive(Debug, serde::Deserialize)]
struct DiagnosticSpan {
    file_name: String,
    line_start: usize,
    column_start: usize,
    is_primary: bool,
    text: Vec<SpanText>,
    /// Present when the span originates from a macro expansion.
    expansion: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct SpanText {
    text: String,
    highlight_start: usize,
    highlight_end: usize,
}

#[derive(Debug)]
struct UnusedAllow {
    file: String,
    line: usize,
    column: usize,
    lint_name: String,
    original_text: String,
}

struct FileGuard {
    originals: std::collections::HashMap<std::path::PathBuf, Vec<u8>>,
}

impl FileGuard {
    fn new() -> Self {
        Self {
            originals: std::collections::HashMap::new(),
        }
    }

    fn modify_file(&mut self, path: &std::path::Path, new_content: &[u8]) -> anyhow::Result<()> {
        if !self.originals.contains_key(path) {
            let original = std::fs::read(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            self.originals.insert(path.to_owned(), original);
        }
        std::fs::write(path, new_content)
            .with_context(|| format!("failed to write {}", path.display()))?;

        Ok(())
    }

    fn restore_all(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        for (path, content) in &self.originals {
            if let Err(e) = std::fs::write(path, content) {
                errors.push(format!("{}: {e}", path.display()));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("failed to restore some files:\n{}", errors.join("\n"));
        }
    }
}

impl Drop for FileGuard {
    fn drop(&mut self) {
        if let Err(e) = self.restore_all() {
            eprintln!("cargo-unused-allow: ERROR during file restoration: {e}");
        }
    }
}

fn find_project_root() -> anyhow::Result<std::path::PathBuf> {
    let mut dir = std::env::current_dir().context("failed to get current directory")?;
    loop {
        if dir.join("Cargo.toml").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            anyhow::bail!("could not find Cargo.toml in any parent directory");
        }
    }
}

fn is_excluded_dir(entry: &walkdir::DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();

    name.starts_with('.') || name == "target"
}

fn find_rs_files(root: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| e.file_type().is_file() || !is_excluded_dir(e))
    {
        let entry = entry?;
        if entry.file_type().is_file()
            && let Some(ext) = entry.path().extension()
            && ext == "rs"
        {
            files.push(entry.into_path());
        }
    }

    Ok(files)
}

fn replace_allow_with_expect(
    source: &str,
    re_bare: &regex::Regex,
    re_cfg: &regex::Regex,
) -> Option<String> {
    let has_bare = re_bare.is_match(source);
    let has_cfg = re_cfg.is_match(source);
    if !has_bare && !has_cfg {
        return None;
    }
    let replaced = re_bare.replace_all(source, "#${1}[expect(").to_string();
    let replaced = re_cfg.replace_all(&replaced, ", expect(").to_string();

    Some(replaced)
}

fn extract_lint_name(span: &DiagnosticSpan) -> String {
    if let Some(st) = span.text.first()
        && st.highlight_start > 0
        && st.highlight_end > 0
    {
        let chars: Vec<char> = st.text.chars().collect();
        let start = (st.highlight_start - 1).min(chars.len());
        let end = (st.highlight_end - 1).min(chars.len());
        if start < end {
            let highlighted: String = chars[start..end].iter().collect();
            // If the highlighted text contains `expect(LINT)` (e.g. from a
            // cfg_attr expansion), extract the lint name from inside it.
            if let Some(lint) = extract_lint_from_expect_text(&highlighted) {
                return lint;
            }
            let trimmed = highlighted
                .trim()
                .trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != ':');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    "unknown".to_string()
}

/// Try to extract a lint name from text that contains `expect(LINT_NAME)`.
/// This handles cases where the highlighted span covers a `cfg_attr` wrapper
/// or a full `expect(...)` token rather than just the bare lint name.
fn extract_lint_from_expect_text(text: &str) -> Option<String> {
    let idx = text.rfind("expect(")?;
    let after = &text[idx + "expect(".len()..];
    let lint = after.split(')').next()?;
    let lint = lint.trim();
    if lint.is_empty() {
        return None;
    }

    if lint
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == ':')
    {
        Some(lint.to_string())
    } else {
        None
    }
}

fn find_lint_position(display_text: &str, lint_name: &str) -> Option<usize> {
    let allow_pos = display_text.rfind("allow(")?;
    let search_start = allow_pos + "allow(".len();
    let pos_in_parens = display_text[search_start..].find(lint_name)?;

    Some(search_start + pos_in_parens)
}

fn print_finding(finding: &UnusedAllow, idx: usize) {
    let display_text = finding
        .original_text
        .replace("#[expect(", "#[allow(")
        .replace("#![expect(", "#![allow(")
        .replace(", expect(", ", allow(");
    println!(
        "  {idx}. {file}:{line}:{col}  [lint: {lint}]",
        file = finding.file,
        line = finding.line,
        col = finding.column,
        lint = finding.lint_name,
    );
    println!("     {display_text}");

    if let Some(pos) = find_lint_position(&display_text, &finding.lint_name) {
        let char_pos = display_text[..pos].chars().count();
        let char_len = finding.lint_name.chars().count();
        println!("     {}{}", " ".repeat(char_pos), "^".repeat(char_len));
    }
}

// `#[allow(...)]` or `#[cfg_attr(condition, allow(...))]`.
enum AttrMatch {
    Bare {
        start: usize,
        end: usize,
        bang: String,
        lint_list: String,
    },
    CfgAttr {
        start: usize,
        end: usize,
        bang: String,
        condition: String,
        lint_list: String,
    },
}

impl AttrMatch {
    fn start(&self) -> usize {
        match self {
            AttrMatch::Bare { start, .. } | AttrMatch::CfgAttr { start, .. } => *start,
        }
    }

    fn end(&self) -> usize {
        match self {
            AttrMatch::Bare { end, .. } | AttrMatch::CfgAttr { end, .. } => *end,
        }
    }

    fn lint_list(&self) -> &str {
        match self {
            AttrMatch::Bare { lint_list, .. } | AttrMatch::CfgAttr { lint_list, .. } => lint_list,
        }
    }

    fn rewrite_with_remaining(&self, remaining: &[&str]) -> String {
        let joined = remaining.join(", ");
        match self {
            AttrMatch::Bare { bang, .. } => {
                format!("#{}[allow({})]", bang, joined)
            }
            AttrMatch::CfgAttr {
                bang, condition, ..
            } => {
                format!("#{}[cfg_attr({}, allow({}))]", bang, condition, joined)
            }
        }
    }
}

fn collect_attr_matches(content: &str) -> anyhow::Result<Vec<AttrMatch>> {
    // Bare: `#[allow(...)]` or `#![allow(...)]`
    let bare_re = regex::Regex::new(r"#(!?)\[allow\(([^)]*)\)\]")
        .context("failed to compile bare attribute regex")?;
    // cfg_attr: `#[cfg_attr(CONDITION, allow(...))]` or `#![cfg_attr(CONDITION, allow(...))]`
    // `.*?` lazily matches the condition (handles nested parens like `all(a, b)`).
    let cfg_re = regex::Regex::new(r"#(!?)\[cfg_attr\((.*?),\s*allow\(([^)]*)\)\)\]")
        .context("failed to compile cfg_attr attribute regex")?;

    let mut matches = Vec::new();

    for caps in bare_re.captures_iter(content) {
        let mat = caps.get(0).unwrap();
        matches.push(AttrMatch::Bare {
            start: mat.start(),
            end: mat.end(),
            bang: caps[1].to_string(),
            lint_list: caps[2].to_string(),
        });
    }

    for caps in cfg_re.captures_iter(content) {
        let mat = caps.get(0).unwrap();
        // Skip if this range overlaps with an already-collected bare match
        let start = mat.start();
        let end = mat.end();
        if matches.iter().any(|m| m.start() < end && start < m.end()) {
            continue;
        }
        matches.push(AttrMatch::CfgAttr {
            start,
            end,
            bang: caps[1].to_string(),
            condition: caps[2].to_string(),
            lint_list: caps[3].to_string(),
        });
    }
    matches.sort_by_key(|m| m.start());

    Ok(matches)
}

fn apply_fix(findings: &[UnusedAllow], project_root: &std::path::Path) -> anyhow::Result<usize> {
    let mut by_file: std::collections::BTreeMap<&str, Vec<&UnusedAllow>> =
        std::collections::BTreeMap::new();
    for f in findings {
        by_file.entry(f.file.as_str()).or_default().push(f);
    }

    let mut total_fixed: usize = 0;

    for (rel_path, file_findings) in &by_file {
        let abs_path = project_root.join(rel_path);
        let content = std::fs::read_to_string(&abs_path)
            .with_context(|| format!("failed to read {} for fix", abs_path.display()))?;
        let mut unused_by_line: std::collections::HashMap<usize, std::collections::HashSet<&str>> =
            std::collections::HashMap::new();

        for f in file_findings {
            unused_by_line
                .entry(f.line)
                .or_default()
                .insert(f.lint_name.as_str());
        }

        let attr_matches = collect_attr_matches(&content)?;

        let mut result = String::new();
        let mut last: usize = 0;

        for attr in &attr_matches {
            let match_start = attr.start();
            let match_end = attr.end();
            let match_text = &content[match_start..match_end];
            let start_line = content[..match_start]
                .chars()
                .filter(|&c| c == '\n')
                .count()
                + 1;
            let end_line = start_line + match_text.chars().filter(|&c| c == '\n').count();
            let mut unused_in_attr: std::collections::HashSet<&str> =
                std::collections::HashSet::new();

            for line in start_line..=end_line {
                if let Some(lints) = unused_by_line.get(&line) {
                    for lint in lints {
                        unused_in_attr.insert(lint);
                    }
                }
            }

            if unused_in_attr.is_empty() {
                continue;
            }

            let all_lints: Vec<&str> = attr
                .lint_list()
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();

            let remaining: Vec<&str> = all_lints
                .iter()
                .copied()
                .filter(|lint| !unused_in_attr.contains(lint))
                .collect();

            result.push_str(&content[last..match_start]);

            if remaining.is_empty() {
                let line_start = content[..match_start].rfind('\n').map_or(0, |p| p + 1);
                let line_end_excl = content[match_end..]
                    .find('\n')
                    .map_or(content.len(), |p| match_end + p + 1);

                let before_attr = &content[line_start..match_start];
                let after_attr_on_line = &content[match_end..line_end_excl]
                    .trim_end_matches('\n')
                    .trim_end_matches('\r');

                let only_ws_before = before_attr.chars().all(|c| c.is_whitespace());
                let only_ws_after = after_attr_on_line.chars().all(|c| c.is_whitespace());

                if only_ws_before && only_ws_after {
                    let excess = match_start - line_start;
                    result.truncate(result.len() - excess);
                    last = line_end_excl;
                } else {
                    let mut end = match_end;
                    while end < content.len() && matches!(content.as_bytes()[end], b' ' | b'\t') {
                        end += 1;
                    }
                    last = end;

                    let last_nl = result.rfind('\n').map_or(0, |p| p + 1);
                    let line_so_far = &result[last_nl..];
                    if line_so_far.chars().all(|c| c == ' ' || c == '\t') && last < content.len() {
                        if content[last..].starts_with("\r\n") {
                            result.truncate(last_nl);
                            last += 2;
                        } else if content.as_bytes()[last] == b'\n' {
                            result.truncate(last_nl);
                            last += 1;
                        }
                    }
                }

                total_fixed += all_lints.len();
            } else {
                let new_attr = attr.rewrite_with_remaining(&remaining);
                result.push_str(&new_attr);

                total_fixed += all_lints.len() - remaining.len();
                last = match_end;
            }
        }

        result.push_str(&content[last..]);

        if result != content {
            std::fs::write(&abs_path, &result)
                .with_context(|| format!("failed to write fix to {}", abs_path.display()))?;
            eprintln!("cargo-unused-allow: fixed {rel_path}");
        }
    }

    Ok(total_fixed)
}

const MINIMUM_RUST_MINOR: u32 = 81;

fn check_rust_version() -> anyhow::Result<()> {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .context("failed to run `rustc --version` — is rustc installed?")?;

    anyhow::ensure!(
        output.status.success(),
        "`rustc --version` exited with {}",
        output.status
    );

    let version_str = String::from_utf8_lossy(&output.stdout);
    let minor = parse_rust_minor(&version_str)
        .with_context(|| format!("failed to parse rustc version from: {version_str}"))?;

    anyhow::ensure!(
        minor >= MINIMUM_RUST_MINOR,
        "cargo-unused-allow requires Rust >= 1.{MINIMUM_RUST_MINOR} (for #[expect] support), \
         but the active toolchain is {}\n\
         hint: run `rustup update` or set a compatible toolchain with `rustup override`",
        version_str.trim()
    );

    Ok(())
}

fn parse_rust_minor(version_str: &str) -> Option<u32> {
    // "rustc 1.81.0 (hash date)" → split on whitespace → "1.81.0" → split on '.'
    let version_token = version_str.split_whitespace().nth(1)?;
    let minor_str = version_token.split('.').nth(1)?;

    minor_str.parse().ok()
}

fn run(args: Args) -> anyhow::Result<i32> {
    check_rust_version()?;

    let project_root = find_project_root()?;
    eprintln!(
        "cargo-unused-allow: project root: {}",
        project_root.display()
    );

    let rs_files = find_rs_files(&project_root)?;
    eprintln!("cargo-unused-allow: found {} .rs file(s)", rs_files.len());

    if rs_files.is_empty() {
        println!("No .rs files found.");
        return Ok(0);
    }

    let re_bare = regex::Regex::new(r"#(!?)\[allow\(")?;
    let re_cfg = regex::Regex::new(r",\s*allow\(")?;
    let mut guard = FileGuard::new();
    let mut modified_count: usize = 0;

    for path in &rs_files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "cargo-unused-allow: warning: skipping {} ({})",
                    path.display(),
                    e
                );
                continue;
            }
        };

        if let Some(new_content) = replace_allow_with_expect(&content, &re_bare, &re_cfg) {
            guard.modify_file(path, new_content.as_bytes())?;
            modified_count += 1;
        }
    }

    eprintln!(
        "cargo-unused-allow: modified {} file(s), running clippy...",
        modified_count
    );

    if modified_count == 0 {
        println!("No #[allow(...)] attributes found in the project.");

        return Ok(0);
    }

    let (user_cargo_args, user_lint_args) = {
        let mut cargo = Vec::new();
        let mut lint = Vec::new();
        let mut after_separator = false;
        for arg in &args.clippy_args {
            if !after_separator && arg == "--" {
                after_separator = true;
            } else if after_separator {
                lint.push(arg.as_str());
            } else {
                cargo.push(arg.as_str());
            }
        }
        (cargo, lint)
    };

    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("clippy");
    if args.all_targets {
        cmd.arg("--all-targets");
    }
    cmd.args(&user_cargo_args);
    cmd.arg("--message-format=json");
    cmd.arg("--");
    cmd.arg("-Wunfulfilled-lint-expectations");
    cmd.args(&user_lint_args);
    cmd.current_dir(&project_root);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::inherit());

    let output = cmd.output().context(
        "failed to run `cargo clippy`. Is clippy installed? (rustup component add clippy)",
    )?;

    guard.restore_all()?;
    guard.originals.clear();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut findings: Vec<UnusedAllow> = Vec::new();

    for line in stdout.lines() {
        let msg: CargoMessage = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if msg.reason != "compiler-message" {
            continue;
        }

        let message = match msg.message {
            Some(m) => m,
            None => continue,
        };

        let is_unfulfilled = message
            .code
            .as_ref()
            .is_some_and(|c| c.code == "unfulfilled_lint_expectations");

        if !is_unfulfilled {
            continue;
        }

        // Grab the primary span, skipping macro-expanded spans to avoid
        // false positives from #[allow] inside macro_rules! bodies.
        for span in &message.spans {
            if !span.is_primary {
                continue;
            }

            if span.expansion.is_some() {
                continue;
            }

            let original_text = span
                .text
                .first()
                .map(|t| t.text.trim().to_string())
                .unwrap_or_default();

            let lint_name = extract_lint_name(span);

            findings.push(UnusedAllow {
                file: span.file_name.clone(),
                line: span.line_start,
                column: span.column_start,
                lint_name,
                original_text,
            });
        }
    }

    if !args.excludes.is_empty() {
        findings.retain(|f| !args.excludes.contains(&f.lint_name));
    }

    // Also collect compilation errors so we can warn the user
    let mut compile_errors: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let msg: CargoMessage = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if msg.reason != "compiler-message" {
            continue;
        }
        if let Some(message) = &msg.message
            && message.level == "error"
            && let Some(rendered) = &message.rendered
        {
            compile_errors.push(rendered.clone());
        }
    }

    if !compile_errors.is_empty() {
        eprintln!(
            "\ncargo-unused-allow: WARNING: {} compilation error(s) occurred.",
            compile_errors.len()
        );
        eprintln!("  Results may be incomplete. Fix compilation errors and re-run.\n");
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    findings.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.column == b.column);

    println!();
    if findings.is_empty() {
        println!("No unused #[allow(...)] attributes found.");
        if !compile_errors.is_empty() {
            println!("  (note: there were compilation errors; results may be incomplete)");
        }
        return Ok(0);
    }

    println!(
        "Found {} unused #[allow(...)] attribute(s):\n",
        findings.len()
    );
    for (i, finding) in findings.iter().enumerate() {
        print_finding(finding, i + 1);
        println!();
    }

    if args.fix {
        let fixed = apply_fix(&findings, &project_root)?;
        println!("Removed {fixed} unused lint suppression(s).");
    } else {
        println!(
            "These #[allow(...)] attributes are not suppressing any lint and can be safely removed.\nHint: run with --fix to remove them automatically, or use #[expect(...)] instead."
        );
    }

    Ok(1)
}

fn main() {
    // When invoked as `cargo unused-allow ...`, cargo passes
    // "unused-allow" as the first argument.  Strip it so that clap sees
    // `["cargo-unused-allow", ...]`.
    let mut raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() > 1 && raw_args[1] == "unused-allow" {
        raw_args.remove(1);
    }

    let args = <Args as clap::Parser>::parse_from(raw_args);

    match run(args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("cargo-unused-allow: error: {e:#}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    fn make_regexes() -> (regex::Regex, regex::Regex) {
        (
            regex::Regex::new(r"#(!?)\[allow\(").unwrap(),
            regex::Regex::new(r",\s*allow\(").unwrap(),
        )
    }

    #[test]
    fn test_replace_allow_with_expect_basic() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#[allow(dead_code)]
fn foo() {}"#;
        let expected = r#"#[expect(dead_code)]
fn foo() {}"#;
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_replace_allow_with_expect_inner() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#![allow(clippy::pedantic)]
fn main() {}"#;
        let expected = r#"#![expect(clippy::pedantic)]
fn main() {}"#;
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_replace_allow_with_expect_multiple() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#[allow(dead_code)]
#[allow(unused_variables)]
fn foo() {}"#;
        let expected = r#"#[expect(dead_code)]
#[expect(unused_variables)]
fn foo() {}"#;
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_replace_allow_with_expect_multiple_lints() {
        let (re_bare, re_cfg) = make_regexes();

        let input = "#[allow(dead_code, unused_variables)]";
        let expected = "#[expect(dead_code, unused_variables)]";
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_replace_allow_with_expect_no_match() {
        let (re_bare, re_cfg) = make_regexes();

        let input = "fn foo() {}";
        assert!(super::replace_allow_with_expect(input, &re_bare, &re_cfg).is_none());
    }

    #[test]
    fn test_replace_allow_with_expect_does_not_match_non_attribute() {
        let (re_bare, re_cfg) = make_regexes();

        // `allow` as a method name should not be replaced
        let input = r#"config.allow("something");"#;
        assert!(super::replace_allow_with_expect(input, &re_bare, &re_cfg).is_none());
    }

    #[test]
    fn test_replace_allow_with_expect_multiline_attribute() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#[allow(
    dead_code,
    unused_variables,
)]
fn foo() {}"#;
        let expected = r#"#[expect(
    dead_code,
    unused_variables,
)]
fn foo() {}"#;
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_replace_allow_with_expect_cfg_attr() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#[cfg_attr(feature = "foo", allow(dead_code))]
fn foo() {}"#;
        let expected = r#"#[cfg_attr(feature = "foo", expect(dead_code))]
fn foo() {}"#;
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_replace_allow_with_expect_cfg_attr_inner() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#![cfg_attr(feature = "foo", allow(clippy::pedantic))]"#;
        let expected = r#"#![cfg_attr(feature = "foo", expect(clippy::pedantic))]"#;
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_replace_allow_with_expect_cfg_attr_complex_condition() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#[cfg_attr(all(feature = "a", feature = "b"), allow(dead_code))]
fn foo() {}"#;
        let expected = r#"#[cfg_attr(all(feature = "a", feature = "b"), expect(dead_code))]
fn foo() {}"#;
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_replace_allow_with_expect_cfg_attr_no_match_without_allow() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#[cfg_attr(feature = "foo", derive(Debug))]"#;
        assert!(super::replace_allow_with_expect(input, &re_bare, &re_cfg).is_none());
    }

    #[test]
    fn test_replace_allow_with_expect_mixed_bare_and_cfg_attr() {
        let (re_bare, re_cfg) = make_regexes();

        let input = r#"#[allow(unused_imports)]
#[cfg_attr(feature = "foo", allow(dead_code))]
fn foo() {}"#;
        let expected = r#"#[expect(unused_imports)]
#[cfg_attr(feature = "foo", expect(dead_code))]
fn foo() {}"#;
        assert_eq!(
            super::replace_allow_with_expect(input, &re_bare, &re_cfg).unwrap(),
            expected
        );
    }

    #[test]
    fn test_extract_lint_name_simple() {
        let span = super::DiagnosticSpan {
            file_name: "test.rs".to_string(),
            line_start: 1,
            column_start: 10,
            is_primary: true,
            text: vec![super::SpanText {
                text: "#[expect(dead_code)]".to_string(),
                highlight_start: 10,
                highlight_end: 19,
            }],
            expansion: None,
        };
        assert_eq!(super::extract_lint_name(&span), "dead_code");
    }

    #[test]
    fn test_extract_lint_name_clippy() {
        let span = super::DiagnosticSpan {
            file_name: "test.rs".to_string(),
            line_start: 1,
            column_start: 10,
            is_primary: true,
            text: vec![super::SpanText {
                text: "#[expect(clippy::needless_return)]".to_string(),
                highlight_start: 10,
                highlight_end: 33,
            }],
            expansion: None,
        };
        assert_eq!(super::extract_lint_name(&span), "clippy::needless_return");
    }

    #[test]
    fn test_extract_lint_name_multi_lint_first() {
        let span = super::DiagnosticSpan {
            file_name: "test.rs".to_string(),
            line_start: 1,
            column_start: 10,
            is_primary: true,
            text: vec![super::SpanText {
                text: "#[expect(dead_code, unused_variables)]".to_string(),
                highlight_start: 10,
                highlight_end: 19,
            }],
            expansion: None,
        };
        assert_eq!(super::extract_lint_name(&span), "dead_code");
    }

    #[test]
    fn test_extract_lint_name_multi_lint_second() {
        let span = super::DiagnosticSpan {
            file_name: "test.rs".to_string(),
            line_start: 1,
            column_start: 21,
            is_primary: true,
            text: vec![super::SpanText {
                text: "#[expect(dead_code, unused_variables)]".to_string(),
                highlight_start: 21,
                highlight_end: 37,
            }],
            expansion: None,
        };
        assert_eq!(super::extract_lint_name(&span), "unused_variables");
    }

    #[test]
    fn test_apply_fix_removes_single_lint_attribute() {
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_single");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "#[allow(dead_code)]\nfn foo() {}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 10,
            lint_name: "dead_code".to_string(),
            original_text: "#[expect(dead_code)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "fn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_partial_removal() {
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_partial");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "#[allow(dead_code, unused_variables)]\nfn foo() {}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        // Only dead_code is unused; unused_variables is still needed.
        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 10,
            lint_name: "dead_code".to_string(),
            original_text: "#[expect(dead_code, unused_variables)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "#[allow(unused_variables)]\nfn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_inner_attribute() {
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_inner");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "#![allow(non_camel_case_types)]\nfn main() {}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 11,
            lint_name: "non_camel_case_types".to_string(),
            original_text: "#![expect(non_camel_case_types)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "fn main() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_preserves_indentation_context() {
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_indent");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "fn main() {\n    #[allow(unused_variables)]\n    let x = 1;\n}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 2,
            column: 14,
            lint_name: "unused_variables".to_string(),
            original_text: "#[expect(unused_variables)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "fn main() {\n    let x = 1;\n}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_attr_before_other_attr_on_same_line() {
        // `#[allow(dead_code)] #[inline]` on one line — only the allow should
        // be removed; the `#[inline]` and the function must remain.
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_shared_line_before");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "#[allow(dead_code)] #[inline]\nfn foo() {}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 10,
            lint_name: "dead_code".to_string(),
            original_text: "#[expect(dead_code)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "#[inline]\nfn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_attr_after_code_on_same_line() {
        // Code before the attribute on the same line — only remove the
        // attribute, keep the code and newline intact.
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_shared_line_after");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "some_code(); #[allow(dead_code)]\nfn foo() {}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 15,
            lint_name: "dead_code".to_string(),
            original_text: "#[expect(dead_code)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "some_code(); \nfn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_inline_attr_with_function() {
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_inline_fn");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "#[allow(dead_code)] fn foo() {}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 10,
            lint_name: "dead_code".to_string(),
            original_text: "#[expect(dead_code)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "fn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_content_on_both_sides() {
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_both_sides");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "code_before(); #[allow(dead_code)] code_after();\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 17,
            lint_name: "dead_code".to_string(),
            original_text: "#[expect(dead_code)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "code_before(); code_after();\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_two_allows_on_same_line() {
        // Two separate `#[allow(...)]` on the same line, both unused.
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_two_allows");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "#[allow(dead_code)] #[allow(unused_mut)]\nfn foo() {}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![
            super::UnusedAllow {
                file: "test.rs".to_string(),
                line: 1,
                column: 10,
                lint_name: "dead_code".to_string(),
                original_text: "#[expect(dead_code)]".to_string(),
            },
            super::UnusedAllow {
                file: "test.rs".to_string(),
                line: 1,
                column: 22,
                lint_name: "unused_mut".to_string(),
                original_text: "#[expect(unused_mut)]".to_string(),
            },
        ];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 2);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "fn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_no_space_between_attrs() {
        // `#[allow(dead_code)]#[inline]` — no space between attributes.
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_no_space");
        let _ = std::fs::create_dir_all(&tmp);

        let src = "#[allow(dead_code)]#[inline]\nfn foo() {}\n";
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 10,
            lint_name: "dead_code".to_string(),
            original_text: "#[expect(dead_code)]".to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "#[inline]\nfn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_lint_from_expect_text_bare() {
        assert_eq!(
            super::extract_lint_from_expect_text("expect(dead_code)"),
            Some("dead_code".to_string())
        );
    }

    #[test]
    fn test_extract_lint_from_expect_text_clippy() {
        assert_eq!(
            super::extract_lint_from_expect_text("expect(clippy::needless_return)"),
            Some("clippy::needless_return".to_string())
        );
    }

    #[test]
    fn test_extract_lint_from_expect_text_cfg_attr() {
        assert_eq!(
            super::extract_lint_from_expect_text(r#"cfg_attr(feature = "foo", expect(dead_code))"#),
            Some("dead_code".to_string())
        );
    }

    #[test]
    fn test_extract_lint_from_expect_text_no_expect() {
        assert_eq!(
            super::extract_lint_from_expect_text("allow(dead_code)"),
            None
        );
    }

    #[test]
    fn test_extract_lint_from_expect_text_empty_lint() {
        assert_eq!(super::extract_lint_from_expect_text("expect()"), None);
    }

    #[test]
    fn test_extract_lint_name_cfg_attr_span() {
        // Simulate a span where the highlighted text covers a cfg_attr+expect.
        let span = super::DiagnosticSpan {
            file_name: "test.rs".to_string(),
            line_start: 1,
            column_start: 1,
            is_primary: true,
            text: vec![super::SpanText {
                text: r#"#[cfg_attr(feature = "foo", expect(dead_code))]"#.to_string(),
                highlight_start: 28,
                highlight_end: 46,
            }],
            expansion: None,
        };
        assert_eq!(super::extract_lint_name(&span), "dead_code");
    }

    #[test]
    fn test_collect_attr_matches_bare_only() {
        let content = "#[allow(dead_code)]\nfn foo() {}\n";
        let matches = super::collect_attr_matches(content).unwrap();
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0], super::AttrMatch::Bare { .. }));
        assert_eq!(matches[0].lint_list(), "dead_code");
    }

    #[test]
    fn test_collect_attr_matches_cfg_attr_only() {
        let content = r#"#[cfg_attr(feature = "foo", allow(dead_code))]
fn foo() {}
"#;
        let matches = super::collect_attr_matches(content).unwrap();
        assert_eq!(matches.len(), 1);
        match &matches[0] {
            super::AttrMatch::CfgAttr {
                condition,
                lint_list,
                ..
            } => {
                assert_eq!(condition, r#"feature = "foo""#);
                assert_eq!(lint_list, "dead_code");
            }
            _ => panic!("expected CfgAttr match"),
        }
    }

    #[test]
    fn test_collect_attr_matches_mixed() {
        let content = r#"#[allow(unused_imports)]
#[cfg_attr(feature = "foo", allow(dead_code))]
fn foo() {}
"#;
        let matches = super::collect_attr_matches(content).unwrap();
        assert_eq!(matches.len(), 2);
        assert!(matches!(matches[0], super::AttrMatch::Bare { .. }));
        assert!(matches!(matches[1], super::AttrMatch::CfgAttr { .. }));
    }

    #[test]
    fn test_collect_attr_matches_cfg_attr_complex_condition() {
        let content = r#"#[cfg_attr(all(feature = "a", feature = "b"), allow(dead_code))]
fn foo() {}
"#;
        let matches = super::collect_attr_matches(content).unwrap();
        assert_eq!(matches.len(), 1);
        match &matches[0] {
            super::AttrMatch::CfgAttr {
                condition,
                lint_list,
                ..
            } => {
                assert_eq!(condition, r#"all(feature = "a", feature = "b")"#);
                assert_eq!(lint_list, "dead_code");
            }
            _ => panic!("expected CfgAttr match"),
        }
    }

    #[test]
    fn test_apply_fix_cfg_attr_removes_entire_attribute() {
        // When all lints in a cfg_attr(cond, allow(...)) are unused,
        // the entire attribute should be removed.
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_cfg_attr_remove");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);

        let src = r#"#[cfg_attr(feature = "foo", allow(dead_code))]
fn foo() {}
"#;
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 1,
            lint_name: "dead_code".to_string(),
            original_text: r#"#[cfg_attr(feature = "foo", expect(dead_code))]"#.to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "fn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_cfg_attr_partial_removal() {
        // When only some lints in cfg_attr(cond, allow(a, b)) are unused,
        // the attribute should be rewritten to keep the remaining lints.
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_cfg_attr_partial");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);

        let src = r#"#[cfg_attr(feature = "foo", allow(dead_code, unused_imports))]
fn foo() {}
"#;
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 1,
            lint_name: "dead_code".to_string(),
            original_text: r#"#[cfg_attr(feature = "foo", expect(dead_code, unused_imports))]"#
                .to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            result,
            r#"#[cfg_attr(feature = "foo", allow(unused_imports))]
fn foo() {}
"#
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_cfg_attr_inner_attribute() {
        // Inner cfg_attr attribute: `#![cfg_attr(cond, allow(...))]`
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_cfg_attr_inner");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);

        let src = r#"#![cfg_attr(feature = "foo", allow(clippy::pedantic))]
fn main() {}
"#;
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 1,
            column: 1,
            lint_name: "clippy::pedantic".to_string(),
            original_text: r#"#![cfg_attr(feature = "foo", expect(clippy::pedantic))]"#.to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "fn main() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_cfg_attr_with_indentation() {
        // Indented cfg_attr attribute should have its line cleanly removed.
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_cfg_attr_indent");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);

        let src = r#"impl Foo {
    #[cfg_attr(feature = "foo", allow(dead_code))]
    fn bar() {}
}
"#;
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![super::UnusedAllow {
            file: "test.rs".to_string(),
            line: 2,
            column: 5,
            lint_name: "dead_code".to_string(),
            original_text: r#"#[cfg_attr(feature = "foo", expect(dead_code))]"#.to_string(),
        }];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 1);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "impl Foo {\n    fn bar() {}\n}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_apply_fix_mixed_bare_and_cfg_attr() {
        // Both a bare allow and a cfg_attr allow are unused in the same file.
        let tmp = std::env::temp_dir().join("cargo_unused_allow_test_fix_mixed");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);

        let src = r#"#[allow(unused_imports)]
#[cfg_attr(feature = "foo", allow(dead_code))]
fn foo() {}
"#;
        let file = tmp.join("test.rs");
        std::fs::write(&file, src).unwrap();

        let findings = vec![
            super::UnusedAllow {
                file: "test.rs".to_string(),
                line: 1,
                column: 10,
                lint_name: "unused_imports".to_string(),
                original_text: "#[expect(unused_imports)]".to_string(),
            },
            super::UnusedAllow {
                file: "test.rs".to_string(),
                line: 2,
                column: 1,
                lint_name: "dead_code".to_string(),
                original_text: r#"#[cfg_attr(feature = "foo", expect(dead_code))]"#.to_string(),
            },
        ];

        let count = super::apply_fix(&findings, &tmp).unwrap();
        assert_eq!(count, 2);

        let result = std::fs::read_to_string(&file).unwrap();
        assert_eq!(result, "fn foo() {}\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
