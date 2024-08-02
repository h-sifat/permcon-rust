# Permcon

A simple library/CLI to parse Linux file permissions and convert them between
symbolic and octal notation. This package is a Rust port of my Node.js CLI
[permcon](https://github.com/h-sifat/permcon).

## Installation

```bash
cargo install permcon
```

## Library Usages

```rust
use permcon::{FilePermission, GroupPermission, SourceFormat, SpecialPermission};
use permcon::utils::get_filetype_from_char;

let perm = FilePermission::try_from("-rwxr-xr-T").unwrap();

assert_eq!(perm, FilePermission {
    user: GroupPermission {
        read: true,
        write: true,
        execute: true,
        special: false,
    },
    group: GroupPermission {
        read: true,
        write: false,
        execute: true,
        special: false,
    },
    other: GroupPermission {
        read: true,
        write: false,
        execute: false,
        special: true,
    },
    filetype_char: '-',
    filetype: get_filetype_from_char('-'),
    source_format: Some(SourceFormat::Symbolic),
    special: [SpecialPermission::Nil, SpecialPermission::Nil, SpecialPermission::StickyBit],
});
```

## CLI usages

```bash,ignore
❯ permcon 1754
# -rwxr-xr-T

❯ permcon rwxrwxr-t
# 1775

# Note: a `--` is required if the permission string starts with an `-`.
❯ permcon -- -rwxrwxr-t
# 1775

❯ permcon -a -- -rwxrwxr-t
# file type    : Regular File
# symbolic     : -rwxrwxr-t
# octal        : 1775
# ------------------------
# user (rwx, 7): read, write, execute
# group(rwx, 7): read, write, execute
# other(r-t, 5): read, _    , (execute, StickyBit)
# ------------------------
# special permissions: StickyBit

❯ permcon -a 1754
# file type    : Unknown
# symbolic     : -rwxr-xr-T
# octal        : 1754
# ------------------------
# user (rwx, 7): read, write, execute
# group(r-x, 5): read, _    , execute
# other(r-T, 4): read, _    , (_, StickyBit)
# ------------------------
# special permissions: StickyBit
```

If you find a bug or want to improve something then please feel free to open an
issue or create a pull request :).
