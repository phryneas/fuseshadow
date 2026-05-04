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
21. As a developer, I want fuseshadow to run inside a Docker container on Linux, so that the FUSE mount lifecycle is fully contained and I don't need to install any kernel extensions on my host machine.
23. As a developer, I want `[ignore]` to take priority over `[writable]` when both match a path, so that hiding a path is always safe regardless of other config entries.
24. As a developer, I want directory renames by the agent to not bypass gitignore rules, so that renaming a parent directory cannot expose files that were blocked by subdirectory `.gitignore` patterns.
25. As a developer, I want directory renames to be tracked in the root `.shadowconfig` with a human-readable comment, so that I know which renames happened during an agent session and can update my `.gitignore` files accordingly.
26. As a developer, I want rename tracking entries to include timestamps, so that I can correlate renames with agent session timelines.
27. As a developer, I want fuseshadow to automatically protect renamed paths using the original gitignore rules, so that protection is maintained both during the current session and across restarts until I clean up the entries.
28. As a developer, I want fuseshadow to monitor the root `.shadowconfig` for external changes, so that cleanup I perform (or entries added by another fuseshadow instance) take effect without restarting the mount.
29. As a developer, I want fuseshadow to exit with a clear error if a nested `.shadowconfig` contains `folder_renames`, so that misplaced rename tracking entries are caught immediately.

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

All pattern matching and filename checks (`.shadowconfig`, `.gitignore`) are case-insensitive by default (using Unicode `to_lowercase()`). Patterns are lowercased at load time; input paths are lowercased at classify time. The `case_sensitive` flag on `RuleSet` controls this behavior.

Gitignore loading walks both upward (from source root to filesystem root) and downward (all nested subdirectories). Uses `ignore::gitignore::GitignoreBuilder` from the `ignore` crate, one builder per `.gitignore` file, each anchored at its containing directory.

**`overlay` module — Writable Temp Directory**
Wraps a `tempfile::TempDir`. Provides a mapping from relative source paths to physical paths inside the temp directory. Handles creation of intermediate directories. Drop of the overlay struct cleans up the temp directory automatically. Exposes `exists(rel_path)` and `resolve(rel_path)` to the filesystem layer.

**`fs` module — FUSE Filesystem**
Implements `fuser::Filesystem`. Composes `RuleSet` and `Overlay`. Maintains an inode-to-path mapping for the lifetime of the mount. Routes each FUSE operation through the classification result.

On directory rename: purges the renamed directory and all child inodes from the inode-to-path mapping (the kernel re-resolves them via `lookup` on the new parent). Delegates to `RuleSet` to update matchers and persist the rename. See rename tracking below.
- **Hidden**: return `ENOENT` for all operations; omit from `readdir`
- **Blocked**: include in `readdir` with mode `0o000`; return `EACCES` for all open/read/write/create/setattr
- **WritableOverlay** (not yet written): return `ENOENT`; omit from `readdir`; allow `create`/`write` which land in the overlay dir
- **WritableOverlay** (written): serve from overlay dir; `unlink` removes overlay file making it invisible again
- **GitignoreFile**: serve reads from source; reject all writes with `EACCES`
- **Passthrough**: full read/write passthrough to source directory

Symlink handling: `readlink` returns the target unchanged for relative symlinks. For absolute symlinks whose target is prefixed by the source path, rewrites the prefix to the mountpoint path.

**Rename tracking in `rules` module**
Directory renames can bypass subdirectory `.gitignore` patterns because the `ignore` crate's matchers are anchored to the original directory path. Rename tracking closes this gap:

*Runtime rename handling*: When a directory is renamed, child-anchored matchers (anchored inside the old path) are dropped and re-read from the new path on disk. For parent-anchored matchers (anchored above the rename), a path alias is added so that classifying paths under the new name also checks the original name. The rename is persisted to the root `.shadowconfig` under `folder_renames`.

*Startup*: `folder_renames` entries are read from the root `.shadowconfig`. Chains are resolved eagerly into a flat `to → original_from` alias map. Child matchers are loaded naturally by `WalkDir` from their current disk locations; only the parent-matcher alias table is derived from `folder_renames`.

*Live monitoring*: Before each `classify()` call, the mtime of the root `.shadowconfig` is checked. On change, `folder_renames` is re-parsed and the alias table rebuilt. For rename entries not previously seen (added by developer or another fuseshadow instance), child matchers for the affected subtree are also dropped and re-read.

*Persistence format* in root `.shadowconfig`:
```toml
# fuseshadow: directory renames detected during agent session.
# Review and update your .gitignore files, then remove entries below.
folder_renames = [
  { from = "A/B", to = "A/D", at = "2026-05-04T14:32:00Z" },
]
```

Write coordination uses `flock` on the root `.shadowconfig` for safe concurrent access. If a nested (non-root) `.shadowconfig` contains `folder_renames`, fuseshadow exits with an error requesting cleanup.

**`main` module — CLI Entry Point**
Parses `fuseshadow <source> <mountpoint>` with `clap`. Validates source is an existing directory. Builds `RuleSet`, creates `Overlay`, mounts with `fuser::mount2`. Registers a Ctrl-C / SIGTERM handler that triggers unmount and overlay cleanup. Accepts `--case-sensitive-rules` to opt into case-sensitive pattern matching (default is case-insensitive).

### Key Technical Decisions

- **Static snapshot**: gitignore rules and `.shadowconfig` files are read once at mount time. Changes to these files while the mount is active are not picked up — with one exception: the `folder_renames` field of the root `.shadowconfig` is monitored via mtime and re-read on change.
- **Temp overlay location**: determined by the OS (`tempfile::TempDir` uses the system temp dir). Not user-configurable; the overlay is ephemeral by design.
- **Gitignore parent traversal**: walks up to the filesystem root (not just the git repo root), naturally including `~/.gitignore` as the home directory's `.gitignore`.
- **Writable overlay requires gitignore match**: a `[writable]` pattern only activates if the path is also matched by gitignore rules. Non-gitignored files are always passthrough regardless of `[writable]` entries.
- **`[ignore]` beats `[writable]`**: when both match, the file is hidden. This is the safe default.
- **Case-insensitive matching by default**: on case-insensitive source mounts (e.g., macOS shared folders in Docker), an agent could bypass rules by requesting `.eNv` instead of `.env`. To prevent this, all pattern matching is case-insensitive by default. `--case-sensitive-rules` opts into case-sensitive matching for environments where this is safe. Unicode `to_lowercase()` is used for normalization; `to_string_lossy()` is acceptable since the primary threat surface (macOS) guarantees UTF-8 filenames.
- **FUSE library**: `fuser` crate (FUSE3 on Linux).
- **Pattern syntax**: both `[ignore]` and `[writable]` use the same glob syntax as `.gitignore`.
- **Rename tracking**: directory renames are persisted to the root `.shadowconfig` rather than tracked purely in memory, so protection survives across fuseshadow restarts. The developer is expected to review rename entries, update their `.gitignore` files, and remove the entries. Rename chains are not collapsed in the file (to avoid losing nested renames) but are resolved eagerly into a flat alias map at load time.
- **`folder_renames` only at root**: only the root `.shadowconfig` may contain `folder_renames`. A nested `.shadowconfig` with this field causes an immediate error exit, preventing misconfiguration.
- **Inode purging on rename**: when a directory is renamed, all inodes for the directory and its children are removed from the inode-to-path mapping. The kernel re-resolves them via fresh `lookup` calls through the new parent. This avoids stale path references and ghost inode entries.

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

**`fs` module** — integration tests that mount a real FUSE filesystem. The build environment is a Docker container with `/dev/fuse` access, so mount-based tests are feasible. Each test mounts a temp source directory, exercises the operation under test through the mountpoint, and unmounts cleanly on completion.

## Out of Scope

- Live-reloading of `.gitignore` or `.shadowconfig` files while the mount is active
- Global git excludes via `core.excludesFile` in `~/.gitconfig` (parent dir walk naturally picks up `~/.gitignore` if it exists as a file)
- Copy-on-write for non-gitignored files (writes always go to the real source)
- Daemonization or background mount mode
- Publishing to crates.io or any package registry
- Network filesystems or remote sources
- Hard link handling beyond what FUSE passthrough provides
- Extended attribute (xattr) policy — xattrs pass through for Passthrough/GitignoreFile files; EACCES for Blocked/Hidden
- Performance optimization for very large repositories (no caching beyond the mount-time snapshot)
- macOS / macFUSE support

## Further Notes

- `fuseshadow` runs inside a Docker container on Linux. The source directory is typically bind-mounted into the container, while the mountpoint is a directory inside the container. The AI agent is given access only to the mountpoint path. The binary will fail at mount time with a clear error if FUSE is not available in the container environment.
- The `[writable]` section of `.shadowconfig` is designed for generated config files and build outputs that need to be writable but whose original secret values must never be exposed. It is NOT a general copy-on-write mechanism.
- The static snapshot design means that if the agent's session is long-lived and the developer adds new secrets to the source tree (that happen to match gitignore), those new files will be caught by the existing rules but any NEW `.gitignore` entries added during the session will not take effect until remount.
- Directory renames by the agent are a security-relevant mutation to the source tree. The `folder_renames` tracking in root `.shadowconfig` serves as both a runtime protection mechanism and a developer-facing audit trail. Developers should review these entries after each agent session and remove them once `.gitignore` files have been updated to match the new directory layout.
- `.shadowconfig` files in parent directories outside the source root are intentionally not loaded — only parent `.gitignore` files are. This prevents a malicious or misconfigured parent directory from affecting the mount's writable policy.