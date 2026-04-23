# Plan: fuseshadow

> Source PRD: `PRD.md`

## Architectural decisions

- **CLI**: `fuseshadow <source> <mountpoint>` — positional args, foreground process, Ctrl-C to unmount
- **FUSE library**: `fuser` crate — supports macFUSE (macOS) and FUSE3 (Linux) via the same API
- **Path classification**: five classes — `Hidden`, `Blocked`, `WritableOverlay`, `GitignoreFile`, `Passthrough` — resolved at mount time, static for the session
- **Gitignore scope**: walk up from source root to filesystem root for parent `.gitignore` files; walk down into all subdirectories for nested ones; snapshot taken once at mount
- **`.shadowconfig` scope**: only within the source tree (parent `.shadowconfig` files outside the root are ignored); each file governs its own subtree
- **Overlay storage**: `tempfile::TempDir` under the OS temp directory; auto-cleaned on process exit
- **Write semantics**: non-gitignored files write directly to source; `WritableOverlay` files write to temp overlay; all other classes reject writes
- **Inode strategy**: assign fresh monotonic inodes to paths on first `lookup`; maintain a bidirectional inode↔path map for the lifetime of the mount
- **Key models**: `PathClass` enum, `RuleSet` struct (loaded once, immutable), `Overlay` struct (wraps temp dir)

---

## Phase 1: Rules engine + dry-run CLI

**User stories**: 10, 11, 14, 15, 16, 23

### What to build

Set up the Cargo project with all dependencies declared. Implement the `rules` module completely: load all `.gitignore` files by walking up to the filesystem root and down through the entire source tree, load all `.shadowconfig` files within the source tree, and expose a `classify(path)` method that returns a `PathClass`. Write unit tests covering every classification case using real temporary directory trees (no mocks).

Add a `--dry-run` flag to the CLI. When passed, the tool walks the source directory, classifies every file, and prints a table of paths and their `PathClass`. This makes the rules engine immediately runnable and verifiable without FUSE installed.

### Acceptance criteria

- [ ] `cargo test` passes with tests covering: basic gitignored path → `Blocked`; nested `.gitignore` applies only to its subtree; parent directory `.gitignore` applies to source root; `.shadowconfig` `[ignore]` pattern → `Hidden`; `.shadowconfig` `[writable]` + gitignored → `WritableOverlay`; `[writable]` + NOT gitignored → `Passthrough`; `[ignore]` beats `[writable]` when both match; `.shadowconfig` itself → `Hidden`; `.gitignore` file → `GitignoreFile`; unmatched file → `Passthrough`
- [ ] `fuseshadow <source> --dry-run` walks the source dir and prints each file's path and classification
- [ ] Overlay module exists with `resolve(rel_path)` and `exists(rel_path)`, with passing tests confirming paths land inside the temp dir and `exists()` reflects written state
- [ ] `cargo clippy` and `cargo build` succeed with no warnings

---

## Phase 2: Read-only passthrough FUSE mount

**User stories**: 1, 19, 20, 21, 22

### What to build

Implement the FUSE filesystem layer as a pure passthrough — no access rules applied yet. Build inode management (assign inodes on `lookup`, maintain inode↔path map). Implement `lookup`, `getattr`, `readdir`, `open`, `read`, and `readlink` so that every file in the source tree is accessible through the mountpoint. Wire up the CLI to mount with `fuser::mount2` and handle Ctrl-C cleanly.

The result is a working FUSE mount that forwards all reads from source to mountpoint. Rules are not enforced — this phase establishes the plumbing.

### Acceptance criteria

- [ ] `fuseshadow <source> <mountpoint>` mounts successfully on macOS (with macFUSE) and on Linux (with FUSE3)
- [ ] Files readable through the mountpoint match the content of files in the source directory
- [ ] `ls` on the mountpoint shows the same directory structure as the source
- [ ] Symlinks appear in the mountpoint and their targets are readable
- [ ] Ctrl-C (SIGINT) unmounts cleanly with no stale mount left behind
- [ ] The process exits with a clear error message if macFUSE/FUSE3 is not available

---

## Phase 3: Access rule enforcement

**User stories**: 2, 3, 9, 12, 13

### What to build

Wire the `RuleSet` from Phase 1 into the FUSE layer from Phase 2. Each FUSE operation now checks the `PathClass` of the path being accessed:

- **`Hidden`** (`.shadowconfig`, `[ignore]` matches): `ENOENT` on all operations; omitted from `readdir`
- **`Blocked`** (gitignored, not writable): included in `readdir` with mode `0o000`; `EACCES` on `open`, `read`, `create`, `write`, `setattr`
- **`GitignoreFile`**: readable passthrough; `EACCES` on any write operation
- **`Passthrough`**: unchanged from Phase 2

No write operations for `Passthrough` files yet — the mount is still effectively read-only for non-blocked files.

### Acceptance criteria

- [ ] Gitignored files appear in `ls` output with `----------` permissions
- [ ] `cat` on a gitignored file returns permission denied
- [ ] Attempting to write to a gitignored file returns permission denied
- [ ] `.shadowconfig` files are absent from `ls` output and return "no such file or directory"
- [ ] Files matching `[ignore]` patterns in `.shadowconfig` are absent from `ls` output
- [ ] `.gitignore` files are readable (`cat .gitignore` works) but writing returns permission denied
- [ ] `--dry-run` output still works and matches what the mount enforces

---

## Phase 4: Full write support + writable overlay

**User stories**: 4, 5, 6, 7, 8

### What to build

Enable writes for `Passthrough` files (passthrough `create`, `write`, `mkdir`, `rmdir`, `rename`, `unlink`, `setattr` to the source directory).

Implement `WritableOverlay` behaviour: these paths are invisible (`ENOENT`, omitted from `readdir`) until the agent creates them. On `create`/`write`, the file is created in the temp overlay directory. Once written, it becomes visible in the mount and reads are served from the overlay. `unlink` removes the overlay file and returns the path to invisible. The `TempDir` Drop ensures full cleanup on unmount.

### Acceptance criteria

- [ ] Creating and editing a non-gitignored file through the mount modifies the real source file
- [ ] `mkdir`, `rmdir`, `rename`, `unlink` on non-gitignored paths work correctly against the source
- [ ] A path covered by `[writable]` + gitignored does not appear in `ls` before being written
- [ ] Writing to a `WritableOverlay` path succeeds; the file becomes visible and readable through the mount
- [ ] Reading a `WritableOverlay` path returns the content written by the agent, never the original source content
- [ ] Deleting a `WritableOverlay` file makes it invisible again; the agent can re-create it
- [ ] Unmounting removes the temp overlay directory completely
- [ ] Attempting to write to a `Blocked` path still returns `EACCES`

---

## Phase 5: Symlink rewriting + hardening

**User stories**: 17, 18

### What to build

Handle symlinks correctly end-to-end. Relative symlinks pass through unchanged. Absolute symlinks whose target begins with the source path have that prefix rewritten to the mountpoint path in `readlink` responses — so the agent follows them into the mount rather than escaping to the host path.

Add `SIGTERM` handling alongside the existing `SIGINT` (Ctrl-C) handler, ensuring clean unmount and overlay cleanup in both cases. Polish startup error messages (missing macFUSE, source not a directory, mountpoint doesn't exist, etc.).

### Acceptance criteria

- [ ] A relative symlink in the source tree is accessible through the mount and resolves correctly
- [ ] An absolute symlink pointing into the source directory, when read through the mount, has its target rewritten to the mountpoint prefix
- [ ] An absolute symlink pointing outside the source directory passes through unchanged
- [ ] `SIGTERM` unmounts cleanly (same as Ctrl-C)
- [ ] Launching with a non-existent source path prints a clear error and exits non-zero
- [ ] Launching with a source path that is a file (not a directory) prints a clear error and exits non-zero
