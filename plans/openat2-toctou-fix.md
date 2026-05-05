# Plan: Replace path-based file access with `openat2` to eliminate TOCTOU symlink races

> Source: Commit 31352b3 added `O_NOFOLLOW` to final-component opens, but this is insufficient — see "Problem" below.

## Problem

fuseshadow opens files in the source tree by constructing a full path (`real_path()`) and calling `open()` / `lstat()` / `read_dir()` etc. Between `classify()` (which checks the relative path) and the actual filesystem operation, an attacker who can write through the FUSE mount can replace an **intermediate directory** with a symlink. The kernel follows intermediate symlinks even with `O_NOFOLLOW` (which only checks the final component), so fuseshadow ends up opening arbitrary files outside the source tree in its own (root) process context.

**Confirmed attack vectors** include:

- Bypass subdirectory `.gitignore` patterns (though root-level blocked filenames like `.envx` are safe because they're rejected at `lookup` time before `open` is ever called)

The `O_NOFOLLOW` fix from 31352b3 only blocks the simplest case (symlink as the final path component). It does not address intermediate directory symlinks.

## Design decisions and rationale

### Use `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)` instead of manual traversal

We considered walking the path component-by-component with `openat(dirfd, component, O_NOFOLLOW)`. `openat2` is strictly better:

- **Atomic**: the entire path resolution happens in a single kernel call. Manual traversal has a TOCTOU between opening each component.
- **Single syscall**: less code, faster.
- **`RESOLVE_BENEATH`**: prevents `..` from escaping above the root fd, closing that attack vector for free.

`openat2` requires Linux 5.6+ (March 2020). The `libc` crate (already a dependency) exposes `SYS_openat2`, `open_how`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_BENEATH`. No new dependencies needed — call via `libc::syscall`.

### Why ELOOP is the correct error when a symlink is encountered

The FUSE kernel resolves paths by calling `lookup` for each component. If a component is a symlink, the kernel calls `readlink` and handles resolution itself. By the time `open(ino)` reaches fuseshadow, the stored relative path for that inode represents what was, at `lookup` time, a verified chain of real directories. Any symlink appearing in that path during the subsequent `open` is definitionally a TOCTOU race — returning ELOOP is correct and safe.

### Protect both source and overlay paths

The attacker operates through the FUSE mount, not by directly accessing the host filesystem. They can manipulate files in both:

- **Source tree** paths (via passthrough writes/renames)
- **Overlay** paths (via writable overlay operations)

Both need `openat2` protection. The `Overlay` struct will hold an `overlay_fd` alongside its `TempDir`, identical to `ShadowFs::source_fd`.

### Remove `real_path()` and `open_with_flags()` entirely

Leaving the old path-based functions available invites future code to accidentally use the unsafe path. A clean break eliminates this risk. All call sites are migrated.

### `rules.rs` is out of scope

`rules.rs` uses `io_path()` (similar to `real_path()`) for reading/writing the shadow config file and scanning `.gitignore` files. This is internal bookkeeping — the results are not returned to the FUSE caller. The attack surface is fuseshadow returning file contents or metadata to the attacker, which only happens through the FUSE handlers.

## Two primitives

All FUSE handlers are migrated to use two new free functions:

- **`safe_open(root_fd, rel, flags, mode) -> io::Result<File>`**
  Calls `openat2(root_fd, rel, {flags, mode, RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH})`.
  Used for: `open`, `create`, `readdir` (with `O_DIRECTORY`).

- **`safe_parent(root_fd, rel) -> io::Result<(File, &OsStr)>`**
  Opens the parent directory via `safe_open(root_fd, parent, O_RDONLY | O_DIRECTORY, 0)`, returns `(parent_dir_fd, final_component_name)`.
  For root-level files where parent is `""`, opens `"."` relative to `root_fd`.
  Used for: `lookup`/`getattr` (+ `fstatat`), `mkdir` (+ `mkdirat`), `unlink`/`rmdir` (+ `unlinkat`), `rename` (+ `renameat`), `readlink` (+ `readlinkat`).

## Complete call site inventory

| Handler    | Line    | Current code                                                      | Migration                                                                              |
| ---------- | ------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `lookup`   | 170     | `self.real_path(&child_rel).symlink_metadata()`                   | `safe_parent(source_fd, &child_rel)` → `fstatat(parent_fd, name, AT_SYMLINK_NOFOLLOW)` |
| `lookup`   | 183     | `overlay_path.symlink_metadata()`                                 | `safe_parent(overlay_fd, &child_rel)` → `fstatat`                                      |
| `getattr`  | 212     | `self.real_path(&rel).symlink_metadata()`                         | `safe_parent(source_fd, &rel)` → `fstatat`                                             |
| `getattr`  | 226     | `overlay_path.symlink_metadata()`                                 | `safe_parent(overlay_fd, &rel)` → `fstatat`                                            |
| `readdir`  | 262     | `fs::read_dir(self.real_path(&rel))`                              | `safe_open(source_fd, &rel, O_RDONLY \| O_DIRECTORY, 0)` → `fdopendir`                 |
| `readdir`  | 303     | `fs::read_dir(&overlay_dir)`                                      | `safe_open(overlay_fd, &rel, O_RDONLY \| O_DIRECTORY, 0)` → `fdopendir`                |
| `open`     | 386,388 | `self.real_path(&rel)` → `open_with_flags(&path, flags)`          | `safe_open(source_fd, &rel, flags, 0)`                                                 |
| `open`     | 375     | `self.overlay.resolve_if_exists(&rel)` → `open_with_flags`        | `safe_open(overlay_fd, &rel, flags, 0)`                                                |
| `create`   | 497     | `self.real_path(&child_rel)` → `OpenOptions::new()...open(&path)` | `safe_open(source_fd, &child_rel, O_RDWR \| O_CREAT \| ..., mode)`                     |
| `create`   | 488     | overlay path → `OpenOptions::new()...open(&path)`                 | `safe_open(overlay_fd, &child_rel, ..., mode)`                                         |
| `create`   | 512     | `fs::set_permissions(&path, ...)`                                 | `fchmod` on the returned fd                                                            |
| `create`   | 514     | `path.symlink_metadata()`                                         | `fstat` on the returned fd                                                             |
| `setattr`  | 550     | `self.real_path(&rel)` for `is_dir` check                         | `safe_parent(source_fd, &rel)` → `fstatat`                                             |
| `setattr`  | 573     | `OpenOptions::new().write(true)...open(&path)`                    | `safe_open(root_fd, &rel, O_WRONLY, 0)`                                                |
| `setattr`  | 579     | `fs::set_permissions(&path, ...)`                                 | `fchmod` on fd                                                                         |
| `setattr`  | 582     | `path.symlink_metadata()`                                         | `fstat` on fd                                                                          |
| `mkdir`    | 619     | `fs::create_dir(self.real_path(&child_rel))`                      | `safe_parent(source_fd, &child_rel)` → `mkdirat(parent_fd, name, mode)`                |
| `mkdir`    | 625     | `fs::set_permissions(&real, ...)`                                 | `fchmod` via `fstatat` fd                                                              |
| `mkdir`    | 627     | `real.symlink_metadata()`                                         | `fstatat(parent_fd, name, ...)`                                                        |
| `rmdir`    | 657     | `fs::remove_dir(self.real_path(&child_rel))`                      | `safe_parent(source_fd, &child_rel)` → `unlinkat(parent_fd, name, AT_REMOVEDIR)`       |
| `unlink`   | 688     | `fs::remove_file(&overlay_path)`                                  | `safe_parent(overlay_fd, &child_rel)` → `unlinkat(parent_fd, name, 0)`                 |
| `unlink`   | 696     | `fs::remove_file(self.real_path(&child_rel))`                     | `safe_parent(source_fd, &child_rel)` → `unlinkat(parent_fd, name, 0)`                  |
| `rename`   | 729-730 | `self.real_path(&old/new_rel).symlink_metadata()`                 | `safe_parent` → `fstatat` for both                                                     |
| `rename`   | 738-739 | `fs::rename(&old_real, &new_real)`                                | `safe_parent` for both → `renameat(old_parent_fd, old_name, new_parent_fd, new_name)`  |
| `rename`   | 746     | `new_real.symlink_metadata()`                                     | `fstatat` on new parent fd                                                             |
| `readlink` | 808     | `fs::read_link(self.real_path(&rel))`                             | `safe_parent(source_fd, &rel)` → `readlinkat(parent_fd, name)`                         |

---

## Phase 1: `safe_open` and `safe_parent` primitives + overlay fd

### What to build

Two free functions in `fs.rs` wrapping `openat2` via `libc::syscall(libc::SYS_openat2, dirfd, path, &open_how, size_of::<open_how>())`. Convert the raw fd result to `std::fs::File` via `FromRawFd`.

Add `overlay_fd: File` to `Overlay`, opened at construction. Expose via `fn fd(&self) -> RawFd`.

Delete `real_path()` and `open_with_flags()`.

### Acceptance criteria

- [ ] `safe_open` calls `openat2` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`
- [ ] `safe_parent` opens parent dir safely, returns `(dir_fd, filename)`, handles root-level files (empty parent → `"."`)
- [ ] `Overlay` holds and exposes `overlay_fd`
- [ ] `real_path()` and `open_with_flags()` deleted
- [ ] Existing `O_NOFOLLOW` / `custom_flags` from commit 31352b3 removed (subsumed)
- [ ] Unit test: `safe_open` with intermediate symlink in path → `ELOOP`
- [ ] Unit test: `safe_open` with `..` escape attempt → error

---

## Phase 2: Migrate `open`, `create`, `setattr` handlers

### What to build

Replace path-based opens in the three I/O handlers. Each handler picks `source_fd` or `overlay_fd` based on `classify()` result, then calls `safe_open`.

- **`open`**: `safe_open(root_fd, &rel, flags, 0)` for both Passthrough and WritableOverlay branches
- **`create`**: `safe_open(root_fd, &child_rel, O_RDWR | O_CREAT | O_TRUNC_if_needed, mode)`. Overlay parent dir creation (`create_dir_all`) needs to happen before the `safe_open`.
- **`setattr`**: `safe_open(root_fd, &rel, O_WRONLY, 0)` for truncation. `fchmod` for permissions. `fstat` for final metadata.

### Acceptance criteria

- [ ] All three handlers use `safe_open` for both source and overlay paths
- [ ] `setattr` uses `fchmod`/`fstat` instead of path-based `set_permissions`/`symlink_metadata`
- [ ] All existing tests pass
- [ ] `open_with_flags_rejects_symlinks` test replaced with `safe_open` equivalent

---

## Phase 3: Migrate `lookup`, `getattr`, `readdir` handlers

### What to build

Replace `symlink_metadata` and `read_dir` with fd-based equivalents.

- **`lookup`**: `safe_parent(root_fd, &child_rel)` → `fstatat(parent_fd, name, AT_SYMLINK_NOFOLLOW)` to get metadata without following symlinks on the final component (correctly reports symlinks as symlinks).
- **`getattr`**: Same pattern as `lookup`.
- **`readdir`**: `safe_open(root_fd, &rel, O_RDONLY | O_DIRECTORY, 0)` → `libc::fdopendir` on the raw fd to iterate entries.

### Acceptance criteria

- [ ] `lookup`/`getattr` use `safe_parent` + `fstatat` for both source and overlay
- [ ] `readdir` opens directories via `safe_open` with `O_DIRECTORY`
- [ ] Symlinks correctly reported as symlinks (via `AT_SYMLINK_NOFOLLOW`)
- [ ] All existing tests pass

---

## Phase 4: Migrate `readlink`, `mkdir`, `unlink`, `rmdir`, `rename` handlers

### What to build

Replace remaining `real_path()` usages with `safe_parent` + `*at` syscalls.

- **`readlink`**: `safe_parent(source_fd, &rel)` → `readlinkat(parent_fd, name)`
- **`mkdir`**: `safe_parent(source_fd, &child_rel)` → `mkdirat(parent_fd, name, mode)`. Post-creation stat via `fstatat`.
- **`unlink`**: `safe_parent(root_fd, &child_rel)` → `unlinkat(parent_fd, name, 0)`. Use `overlay_fd` for WritableOverlay.
- **`rmdir`**: `safe_parent(source_fd, &child_rel)` → `unlinkat(parent_fd, name, AT_REMOVEDIR)`.
- **`rename`**: `safe_parent` for both old and new paths → `renameat(old_parent_fd, old_name, new_parent_fd, new_name)`. Pre-rename metadata via `fstatat`.

### Acceptance criteria

- [ ] All five handlers use `safe_parent` + `*at` syscalls
- [ ] Overlay paths in `unlink` use `overlay_fd`
- [ ] All existing tests pass
- [ ] Zero remaining call sites of `real_path()` (confirmed deleted)

---

## Phase 5: TOCTOU regression tests

### What to build

Targeted tests reproducing the attack vectors from the security report:

- **Intermediate directory symlink**: Create `source/a/b/file.txt`, replace `source/a/b/` with a symlink to another directory, verify `open` through FUSE fails.
- **`..` escape**: Verify that a relative path with `..` cannot escape above the source root.
- **Cross-root absolute symlink**: Verify symlink to absolute path outside source is not followed during open.

Update or remove the three `O_NOFOLLOW`-specific tests from commit 31352b3.

### Acceptance criteria

- [ ] Test: intermediate directory symlink swap → open returns error
- [ ] Test: `..` traversal above source root → fails
- [ ] Test: absolute symlink target outside source → not followed on open
- [ ] Old `O_NOFOLLOW`-specific tests updated
- [ ] `cargo test` all green
