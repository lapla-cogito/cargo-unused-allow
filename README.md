# cargo-unused-allow

Detect unused `#[allow(...)]` attributes in Rust projects.

## How it works

1. Temporarily replaces every `#[allow(...)]` / `#![allow(...)]` with `#[expect(...)]` / `#![expect(...)]` in your source files.
2. Runs `cargo clippy --message-format=json -- -Wunfulfilled-lint-expectations` once.
3. Parses `unfulfilled_lint_expectations` diagnostics — each one corresponds to an `#[allow]` that was suppressing nothing.
4. Restores all original files (even on failure or panic).

## Requirements

- Rust toolchain 1.81 or later (for `#[expect]` support)
- `clippy` (`rustup component add clippy`)

## Installation

### From local source

```sh
cargo install --path .
```

### From crates.io

```sh
cargo install cargo-unused-allow
```

### From GitHub

```sh
cargo install --git https://github.com/lapla-cogito/cargo-unused-allow
```

## Usage

```sh
# Run in any Rust project directory
cd /path/to/your/rust/project
# Basic detection
cargo-unused-allow
# Also check tests, examples, and benches
cargo-unused-allow --all-targets
# Automatically remove unused #[allow] attributes
cargo-unused-allow --fix
# Exclude specific lints from detection
cargo-unused-allow --exclude dead_code --exclude unused_imports
# Combine options
cargo-unused-allow --all-targets --fix --exclude dead_code
```

When installed via `cargo install`, you can also invoke it as a cargo subcommand:

```sh
cargo unused-allow --all-targets
```

### Options

```
$ cargo unused-allow --help

Detect unused #[allow(...)] attributes in Rust projects

Usage: cargo-unused-allow [OPTIONS]

Options:
      --all-targets     Check all targets (tests, examples, etc...)
      --fix             Automatically remove unused #[allow(...)] attributes from source files
      --exclude <LINT>  Lint names to exclude from detection (can be specified multiple times)
  -h, --help            Print help
  -V, --version         Print version
```

### Exit codes

| Code | Meaning                              |
| ---- | ------------------------------------ |
| `0`  | No unused `#[allow]` found           |
| `1`  | Unused `#[allow]` attributes found   |
| `2`  | Internal error                       |

## Example output

See the [`examples`](./examples) directory for sample output. 
`*.rs` files are the original sources, `*.rs.output` files contain the tool's output, and `*.rs.fixed` files are generated with `--fix`.

### `--fix` behavior

When `--fix` is specified, the tool modifies source files directly:

- Single-lint attributes like `#[allow(dead_code)]` are removed entirely (including the line).
- Multi-lint attributes like `#[allow(dead_code, unused_variables)]` are rewritten to keep only the lints that are still needed (e.g., `#[allow(unused_variables)]`).
- Inner attributes like `#![allow(...)]` are handled the same way.
- `cfg_attr`-wrapped attributes like `#[cfg_attr(feature = "foo", allow(dead_code))]` are removed entirely when all lints are unused, or rewritten to keep remaining lints (e.g., `#[cfg_attr(feature = "foo", allow(unused_imports))]`).
- Indentation and surrounding code are preserved.

### `--exclude` behavior

You can exclude specific lint names from detection. This is useful when you intentionally keep certain `#[allow]` attributes (e.g., for forward compatibility):

```sh
# Ignore unused dead_code and unused_imports allows
cargo-unused-allow --exclude dead_code --exclude unused_imports
```

The `--exclude` flag can be specified multiple times. Clippy lints use their full path:

```sh
cargo-unused-allow --exclude clippy::needless_return
```

## Try with included examples

The repository includes example files in `examples/` that demonstrate detection:

```sh
# From the repository root — detect only
cargo-unused-allow --all-targets

# Detect and auto-fix
cargo-unused-allow --all-targets --fix
```

## License

MIT
