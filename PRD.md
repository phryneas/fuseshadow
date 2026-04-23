# fuseshadow — Product Requirements Document

## Problem Statement

When forwarding a source code directory into a podman-containerized AI agent, the agent gets access to secret files alongside the codebase (API keys, `.env` files, credentials, etc.). There is no practical way to give the agent full read/write access to the source tree while completely preventing it from ever reading those secrets — even accidentally. Standard Unix permissions are too coarse and require modifying the real source tree.

## Solution

`fuseshadow` is a FUSE filesystem that mounts a source directory at a separate mountpoint. The agent is given access to the mountpoint, not the source directory. The filesystem enforces a layered access policy:

- **Gitignored files** (typically secrets and build artifacts) appear in directory listings with zero permissions (`----------`), so the agent knows they exist but cannot read or write them.
- **Explicitly writable** gitignored files (configured via `.shadowconfig`) are invisible until the agent writes them. Once written, they exist only in a temporary overlay — the original secret content is never exposed.
- **Explicitly hidden** files and directories (also configured via `.shadowconfig`) are completely invisible inside the mount, as if they don't exist.
- `.shadowconfig` itself is always invisible inside the mount.
- `.gitignore` files are readable but not writable inside the mount.
- All other files pass through with full read/write access to the real source.

A `.shadowconfig` TOML file can be placed in any directory within the source tree. Its patterns apply to that directory's subtree, mirroring how `.gitignore` works.

## User Stories

1. As a developer, I want to mount my project directory through fuseshadow, so that a containerized AI agent can access my source files without ever reading my secrets.
2. As a developer, I want gitignored files to appear in directory listings with locked permissions, so that the agent knows those paths exist and won't try to create files at those paths.
3. As a developer, I want gitignored files to reject all read and write attempts, so that an agent cannot access secret content even if it tries.
4. As a developer, I want to configure specific gitignored paths as writable via `.shadowconfig`, so that an agent can generate config files at those paths without seeing the original secret values.
5. As a developer, I want writable overlay files to be invisible until the agent creates them, so that the agent has no way to know whether an original secret file existed at that path.
6. As a developer, I want overlay writes to go to a temporary directory, so that the source tree is never modified by the agent's generated files.
7. As a developer, I want the temporary overlay to be automatically cleaned up when the mount is unmounted, so that I don't need to manage cleanup manually.
8. As a developer, I want to delete a file the agent wrote to a writable overlay path, so that it becomes invisible again and the agent can re-create it from scratch.
9. As a developer, I want to hide arbitrary directories (like `.git`) via `.shadowconfig`'s `[ignore]` section, so that git history and objects are not accessible to the agent.
10. As a developer, I want `.shadowconfig` to use gitignore-style glob patterns, so that I can use the same syntax I already know from `.gitignore`.
11. As a developer, I want `.shadowconfig` files to be composable across subdirectories, so that different parts of the project can have different access rules without a single monolithic config.
12. As a developer, I want `.shadowconfig` itself to be completely invisible inside the mount, so that the agent cannot read or modify the access policy.
13. As a developer, I want `.gitignore` files to be readable but not writable inside the mount, so that the agent can understand the project structure without being able to subvert ignore rules.
14. As a developer, I want all nested `.gitignore` files to be respected, so that per-subdirectory ignore rules apply correctly.
15. As a developer, I want `.gitignore` files in parent directories above the source root to be respected, so that global patterns (like those in `~/.gitignore`) apply.
16. As a developer, I want the gitignore snapshot to be taken at mount time, so that the rules are stable while an agent session is running.
17. As a developer, I want symlinks to pass through the mount unchanged, so that the project's symlink structure works normally for the agent.
18. As a developer, I want absolute symlinks that point into the source directory to be rewritten to point into the mountpoint, so that the agent can follow them correctly without escaping the mount.
19. As a developer, I want to start the mount with a simple `fuseshadow <source> <mountpoint>` command, so that I don't need to learn a complex CLI.
20. As a developer, I want the process to run in the foreground and clean up on Ctrl-C, so that the lifecycle is easy to manage and I always know when the mount is active.
21. As a developer, I want fuseshadow to work on macOS with macFUSE, so that I can use it on my development machine.
22. As a developer, I want fuseshadow to also work on Linux, so that I can use it in CI or on Linux machines without changes.
23. As a developer, I want `[ignore]` to take priority over `[writable]` when both match a path, so that hiding a path is always safe regardless of other config entries.

## Implementation Decisions

### Modules

**`rules` module — Path Classification Engine**
The core deep module. Loads all gitignore and `.shadowconfig` files at mount time (static snapshot) and exposes a single `classify(path)` method. Internally holds three collections of per-directory pattern matchers: one for gitignore rules, one for `[ignore]` patterns, one for `[writable]` patterns. All collections are anchored at their respective containing directory, mirroring how git resolves nested `.gitignore` files.

Classification priority (highest wins):
1. Filename is `.shadowconfig` → **Hidden**
2. Matches any `[ignore]` pattern from an ancestor `.shadowconfig` → **Hidden**
3. Matches any `[writable]` pattern from an ancestor `.shadowconfig` AND also matches gitignore → **WritableOverlay**
4. Matches any gitignore rule → **Blocked**
5. Filename is `.gitignore` → **GitignoreFile** (readable, not writable)
6. Otherwise → **Passthrough**

Gitignore loading walks both upward (from source root to filesystem root) and downward (all nested subdirectories). Uses `ignore::gitignore::GitignoreBuilder` from the `ignore` crate, one builder per `.gitignore` file, each anchored at its containing directory.

**`overlay` module — Writable Temp Directory**
Wraps a `tempfile::TempDir`. Provides a mapping from relative source paths to physical paths inside the temp directory. Handles creation of intermediate directories. Drop of the overlay struct cleans up the temp directory automatically. Exposes `exists(rel_path)` and `resolve(rel_path)` to the filesystem layer.

**`fs` module — FUSE Filesystem**
Implements `fuser::Filesystem`. Composes `RuleSet` and `Overlay`. Maintains an inode-to-path mapping for the lifetime of the mount. Routes each FUSE operation through the classification result:
- **Hidden**: return `ENOENT` for all operations; omit from `readdir`
- **Blocked**: include in `readdir` with mode `0o000`; return `EACCES` for all open/read/write/create/setattr
- **WritableOverlay** (not yet written): return `ENOENT`; omit from `readdir`; allow `create`/`write` which land in the overlay dir
- **WritableOverlay** (written): serve from overlay dir; `unlink` removes overlay file making it invisible again
- **GitignoreFile**: serve reads from source; reject all writes with `EACCES`
- **Passthrough**: full read/write passthrough to source directory

Symlink handling: `readlink` returns the target unchanged for relative symlinks. For absolute symlinks whose target is prefixed by the source path, rewrites the prefix to the mountpoint path.

**`main` module — CLI Entry Point**
Parses `fuseshadow <source> <mountpoint>` with `clap`. Validates source is an existing directory. Builds `RuleSet`, creates `Overlay`, mounts with `fuser::mount2`. Registers a Ctrl-C / SIGTERM handler that triggers unmount and overlay cleanup.

### Key Technical Decisions

- **Static snapshot**: gitignore rules and `.shadowconfig` files are read once at mount time. Changes to these files while the mount is active are not picked up.
- **Temp overlay location**: determined by the OS (`tempfile::TempDir` uses the system temp dir). Not user-configurable; the overlay is ephemeral by design.
- **Gitignore parent traversal**: walks up to the filesystem root (not just the git repo root), naturally including `~/.gitignore` as the home directory's `.gitignore`.
- **Writable overlay requires gitignore match**: a `[writable]` pattern only activates if the path is also matched by gitignore rules. Non-gitignored files are always passthrough regardless of `[writable]` entries.
- **`[ignore]` beats `[writable]`**: when both match, the file is hidden. This is the safe default.
- **FUSE library**: `fuser` crate (supports macFUSE on macOS, FUSE3 on Linux).
- **Pattern syntax**: both `[ignore]` and `[writable]` use the same glob syntax as `.gitignore`.

## Testing Decisions

**What makes a good test**: test external behavior through the public interface of each module — not internal data structures or intermediate states. A test should set up a real temporary directory with actual files and `.gitignore`/`.shadowconfig` files, call the public API, and assert the result. Do not mock the filesystem.

**`rules` module** — primary testing target. Pure logic with a simple interface. Tests create a real directory tree with `.gitignore` and `.shadowconfig` files, build a `RuleSet`, and assert `classify()` results for various paths. Cases to cover:
- Basic gitignored path → Blocked
- Nested `.gitignore` applies only to its subtree
- Parent directory `.gitignore` applies to source root
- `.shadowconfig` `[ignore]` pattern → Hidden
- `.shadowconfig` `[writable]` pattern + gitignored → WritableOverlay
- `.shadowconfig` `[writable]` pattern + NOT gitignored → Passthrough (writable has no effect)
- `[ignore]` beats `[writable]` when both match
- `.shadowconfig` itself → Hidden
- `.gitignore` file → GitignoreFile
- Unmatched file → Passthrough

**`overlay` module** — secondary testing target. Tests confirm that `resolve()` returns a path inside the temp dir with correct relative structure, and that `exists()` returns false before a file is written and true after.

**`fs` module** — integration tests only, if at all. A full FUSE mount integration test requires macFUSE/FUSE3 installed in the test environment and is complex to set up. Defer to manual verification using the verification steps below.

## Out of Scope

- Live-reloading of `.gitignore` or `.shadowconfig` files while the mount is active
- Global git excludes via `core.excludesFile` in `~/.gitconfig` (parent dir walk naturally picks up `~/.gitignore` if it exists as a file)
- Copy-on-write for non-gitignored files (writes always go to the real source)
- Daemonization or background mount mode
- Publishing to crates.io or any package registry
- macOS Notification Center or system tray integration
- Network filesystems or remote sources
- Hard link handling beyond what FUSE passthrough provides
- Extended attribute (xattr) policy — xattrs pass through for Passthrough/GitignoreFile files; EACCES for Blocked/Hidden
- Performance optimization for very large repositories (no caching beyond the mount-time snapshot)

## Further Notes

- macFUSE must be installed separately on macOS (https://github.com/osxfuse/osxfuse/releases). The binary will fail at mount time with a clear error if macFUSE is not present.
- The `[writable]` section of `.shadowconfig` is designed for generated config files and build outputs that need to be writable but whose original secret values must never be exposed. It is NOT a general copy-on-write mechanism.
- The static snapshot design means that if the agent's session is long-lived and the developer adds new secrets to the source tree (that happen to match gitignore), those new files will be caught by the existing rules but any NEW `.gitignore` entries added during the session will not take effect until remount.
- `.shadowconfig` files in parent directories outside the source root are intentionally not loaded — only parent `.gitignore` files are. This prevents a malicious or misconfigured parent directory from affecting the mount's writable policy.