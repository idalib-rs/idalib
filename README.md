# idalib

[![crates.io](https://img.shields.io/crates/v/idalib)](https://crates.io/crates/idalib)
[![documentation](https://img.shields.io/badge/documentation-0.8.0%2B9.3.260213-blue?link=https%3A%2F%2Fidalib.rs%2Fidalib)](https://idalib.rs/idalib/)
[![license](https://img.shields.io/crates/l/idalib)](https://github.com/idalib-rs/idalib)
[![crates.io downloads](https://img.shields.io/crates/d/idalib)](https://crates.io/crates/idalib)

Idiomatic Rust bindings for the IDA SDK, enabling the development of standalone
analysis tools using IDA v9.x’s idalib.

## IDA support and dependencies

The bindings and examples have been tested against IDA Pro v9.3 on Windows
(11), Linux (Ubuntu 24.04 LTS), and macOS Sequoia (Apple Silicon). The latest
bindings are only guaranteed compatible with the latest official IDA Pro/SDK
release. See the table below for compatibility:

| IDA Pro version | Latest compatible idalib |
| --------------- | ------------------------ |
| v9.3            | 0.8.0                    |
| v9.2            | 0.7.2                    |
| v9.1            | 0.6.1                    |
| v9.0sp1         | 0.4.1                    |
| v9.0            | 0.3.0                    |

In addition to the latest IDA SDK and IDA itself, a recent version of
LLVM/Clang is required (this is to help generate bindings from the SDK), it can
be obtained from, e.g., [here](https://github.com/llvm/llvm-project/releases).
See the [bindgen
documentation](https://rust-lang.github.io/rust-bindgen/requirements.html) for
extended instructions for each supported operating system/environment.

## Developing with idalib

For development, only the IDA SDK is required, whereas to run tests, an IDA
installation (with a valid license) is required. During build, the crates
can locate an IDA installation using the following environment variable:

- `IDADIR` (optional) set to the directory containing the `ida` executable
  (e.g., `/Applications/IDA Professional v9.x/Contents/macOS` for macOS, or
  `$HOME/ida-pro-9.x` for Linux). If not set, the build script will check
  common locations.

### Projects using idalib

- [xorpse/idalib-mp](https://github.com/xorpse/idalib-mp): example project demonstrating idalib + multi-processing.
- [xorpse/parascope](https://github.com/xorpse/parascope): mass-scan source/decompiled code using weggli rulesets.
- [0xdea/rhabdomancer](https://github.com/0xdea/rhabdomancer): locate calls to insecure API functions in a binary file.
- [0xdea/haruspex](https://github.com/0xdea/haruspex): extract pseudo-code from the IDA Hex-Rays decompiler.
- [0xdea/augur](https://github.com/0xdea/augur): extract strings and related pseudo-code from a binary file.

### Examples

A minimal project to working with `idalib` requires the following components:

`Cargo.toml`:

```toml
name = "example-analyser"

# ...

[dependencies]
idalib = "0.8"

[build-dependencies]
idalib-build = "0.8"
```

`build.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    idalib_build::configure_linkage()?;
    Ok(())
}
```

`src/main.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let idb = idalib::IDB::open("/path/to/binary")?;

    // ...

    Ok(())
}
```

More comprehensive examples can be found in `idalib/examples`. To run them:

Linux/macOS:

```sh
export IDADIR=...

cargo run --example=dump_ls
```

Windows:

```powershell
$env:PATH="C:\Program Files\IDA Professional 9.3;$env:PATH"
$env:IDADIR="C:\Program Files\IDA Professional 9.3"

cargo run --example=dump_ls
```

### Linking

The `idalib-build` crate provides various build script helpers to simplify
linking:

- `idalib_build::configure_idalib_linkage`: links against `(lib)ida` and
  `(lib)idalib` in the IDA installation directory.
- `idalib_build::configure_idasdk_linkage`: links against the `(lib)ida` and
  `(lib)idalib` stub libraries bundled with the SDK.
- `idalib_build::configure_linkage`: links against the `(lib)ida` and
  `(lib)idalib` stub libraries and for Linux/macOS sets the RPATH to refer to
  the detected (or specified via `IDADIR`) installation directory.

⚠️ Warning: If you copy the `build.rs` from `idalib/examples`, you may encounter
unexpected behaviour when IDA is installed in a non-default location and
`IDADIR` is not set, for example:

```sh
error while loading shared libraries: [libida.so]
```

This issue can be worked around by ensuring `IDADIR` is correctly set at build
time, or by ensuring the `(lib)ida` and `(lib)idalib` shared libraries are
available to the dynamic linker at runtime, e.g., via `LD_LIBRARY_PATH` or
`/etc/ld.so.conf{,.d}`. Note that using the stub libraries provided by the SDK,
e.g., those located at `$IDASDK/lib/...` as opposed to the
libraries in the IDA installation directory will result in
[crashes](https://github.com/idalib-rs/idalib/issues/24).

For users wanting to use the `build.rs` from `idalib/examples`, e.g., so builds
succeed via GitHub Actions without an IDA installation, we recommend using the
following `build.rs` which will help debug issues related to linking:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);
    if !ida_path.exists() || !idalib_path.exists() {
        println!("cargo::warning=IDA installation not found.");
        idalib_build::configure_idasdk_linkage();
    } else {
        idalib_build::configure_linkage()?;
    }
    Ok(())
}
```

Note that for `idalib`-based tools being installed via
[crates.io](https://crates.io), e.g.,
[rhabdomancer](https://github.com/0xdea/rhabdomancer), the warning will only be
visible when installing with `cargo -vv`, as explained
in [the cargo documentation](https://doc.rust-lang.org/cargo/reference/build-scripts.html#cargo-warning):

> The warning instruction tells Cargo to display a warning after the build
> script has finished running. Warnings are only shown for path dependencies
> (that is, those you’re working on locally), so for example warnings printed
> out in crates.io crates are not emitted by default. The -vv “very verbose”
> flag may be used to have Cargo display warnings for all crates.

## Extending idalib

To expose unimplemented IDA SDK functionality, modify the `idasdk-sys` crate,
add appropriate high-level wrappers in `idalib`, and submit a pull request.
Ensure that the additions are portable and build with the latest SDK. We won't
accept PRs to support older beta releases.

⚠️ Warning: The IDA SDK submodule should be checked out prior to starting
development, otherwise the build will fail, e.g.:

```sh
git submodule update --init --recursive
```

## Contributing (and AI-assisted development)

For development with or without AI assistance via tools, such as Claude Code,
OpenCode, or Codex, consult the `skills` directory, which contains
[guidelines](https://github.com/idalib-rs/idalib/blob/master/skills/idalib-rust-style/SKILL.md)
to keep contributed code consistent with the project's coding style and best
practices.

## Contributors

Please see [CONTRIBUTORS.md](https://github.com/idalib-rs/idalib/blob/master/CONTRIBUTORS.md) for a full list of
acknowledgments.

## Support

If you have any questions, issues, or suggestions related to IDALIB Rust
bindings, join our [Slack
workspace](https://join.slack.com/t/idalib-rs/shared_invite/zt-3qhdxe9af-wM4a0XbTDD85DpW9nPCNUQ)
or open an issue.

## Acknowledgments

This project's development has been supported by the following organisations:

- [Binarly](https://binarly.io)
- [Hex-Rays](https://hex-rays.com) via their [contributor program](https://hex-rays.com/contributor-program)
