---
name: idalib-rust-style
description: Best practices for contributing to IDALIB Rust bindings
---

# Rust style guidelines

Ensure the entire codebase adheres to the guidelines below. There should be no exceptions to these guidelines, failure to enforce them will result in a failed review.

<guidelines>
Follow these instructions strictly to ensure high-quality Rust code:

- Do not use emojis and avoid excessive comments. Write self-explanatory code instead.

- Do not use decorations around println, etc.

- Consistentently name types and methods.

- Provide accessors and mutators for struct fields, avoid `pub` fields. E.g., for a field named `timeout`, provide:
  ```rust
  fn timeout(&self) -> ... { ... }
  fn set_timeout(&mut self, to: ...) { ... }

- Use fluent style method names.

- Organise imports in the following order: 1) standard library imports, 2) external library imports next, 3) same crate imports next. Use appropriate whitespace to separate groups of related imports. 

- Do not nest modules in imports--DO NOT do this: `use module1::blah::{module2::bleep::Type, module3::Bleh}`.

CORRECT:
  ```rust
  use module1::blah::module2::bleep::Type;
  use module1::blah::module3::Bleh;
  ```

CORRECT:
  ```rust
  use std::collections::{HashMap, HashSet};
  use std::path::{Path, PathBuf};

  use serde::Serialize;
  use tokio::fs;

  use crate::models::DataModel;
  use crate::utils::helper;
  ```

INCORRECT:
    ```rust
    use std::{collections::{HashMap, HashSet}, path::{Path, PathBuf}};
    ```

INCORRECT:
    ```rust
    use std::collections::HashMap;
    use std::collections::HashSet;
    ```

- For module layout, use mod.rs and directories when a module may have sub-modules or module_name.rs for leaf modules. Do not use new-style module paths.

- Handle errors, DO NOT silently ignore them without good reason.

- For error messages, always use lower-case unless you have a proper noun or acronym at the start of the string, i.e., prefer “component not found: reason” over “Component not found: Reason”, but keep "I/O error: reason" and "HTTP error: reason".

- Make use of “borrowed” types rather than owned variants if possible:
    - Prefer `impl AsRef<Borrowed>` vs `&Owned` or `impl AsRef<Owned>` unless the owned variant is really needed.
    - Prefer `impl AsRef<str>` or `&str` over `&String`
    - Prefer `impl AsRef<[u8]>` or `&[u8]` over `&Vec<u8>`
    - Prefer `impl AsRef<Path>` or `&Path` over `&PathBuf`

- Prefer to use methods that indicate intent: avoid usage of `to_string` on ``&str``  and opt for `to_owned` or `String::from` instead.

- Avoid useless imports, e.g, `use log;`; this is superfluous, since `log` will already be in scope if you have `log` as a dependency.

- For collections, prefer `Vec::new()` over `vec![]` for empty vectors.

- When using `Option` and `Result`, prefer the `?` operator for propagating errors and unwrapping values instead of using `.unwrap()` or `.expect()`.

- Do not annotate types via their let bindings, ALWAYS use turbo-fish syntax or rely on type inference. For example, use:
  ```rust
  let value = Vec::<u8>::new();
  ```
  or
  ```rust
  let value = Vec::new();
  ```
  over
  ```rust
  let value: Vec<u8> = Vec::new();
  ```

- When formatting to build strings, log, or to print to the console, ensure you format as below:

    ```rust
    let name = "Alice";
    let greeting = format!("Hello, {name}!");
    println!("Hello, {name}!");
    ```

    DO NOT:

    ```rust
    let name = "Alice";
    let greeting = format!("Hello, {}!", name);
    println!("Hello, {}!", name);
    ```

- DO NOT call FFI functions in methods that operate on an IDB or derived types without binding the owning type to the lifetime of the IDB. For exmaple:

```rust
pub struct MyStruct<'a> {
    _marker: PhantomData<&'a IDB>,
}
```

- Use the following tools to help enforce these guidelines:
  - `cargo fmt -- --config imports_granularity=Module,group_imports=StdExternalCrate` to format your code.
  - `cargo clippy --no-deps` to lint your code and `cargo clippy --fix` to automatically fix issues where possible.
  - `cargo dylint --git https://github.com/xorpse/rust-style --pattern '*'` to run the custom lints for this project. If `dylint` does not run correctly, ensure it is installed: `cargo install cargo-dylint dylint-link`.

</guidelines>
