# fuseshadow — Product Requirements Document

## Problem Statement

When forwarding a source code directory into a podman-containerized AI agent, the agent gets access to secret files alongside the codebase (API keys, `.env` files, credentials, etc.). There is no practical way to give the agent full read/write access to the source tree while completely preventing it from ever reading those secrets — even accidentally. Standard Unix permissions are too coarse and require modifying the real source tree.

## Solution

`fuseshadow` is a FUSE filesystem that mounts a source directory at a separate mountpoint. The agent is given access to the mountpoint, not the source directory. The filesystem enforces a layered access policy:

- **Gitignored files** (typically secrets and build artifacts) appear in directory listings with zero permissions (`----------`), so the agent knows they exist but cannot read or write them.
- **Selectively unblocked** gitignored files (configured via `[[gitignore_drop]]` in `.shadowconfig`) are treated as if the matching gitignore pattern was never written. This allows build artifacts that happen to be gitignored to pass through with full access.
- **Explicitly hidden** files and directories (configured via `[ignore]` in `.shadowconfig`) are completely invisible inside the mount, as if they don't exist.
- `.shadowconfig` itself is always invisible inside the mount.
- `.gitignore` files are readable but not writable inside the mount.
- All other files pass through with full read/write access to the real source.

A single `.shadowconfig` TOML file is placed in the source root directory. Only the root-level `.shadowconfig` is loaded; nested `.shadowconfig` files in subdirectories cause an error exit (with `--ignore-child-shadowconfigs` to silently skip them, e.g., in monorepos).

## User Stories

1. As a developer, I want to mount my project directory through fuseshadow, so that a containerized AI agent can access my source files without ever reading my secrets.
2. As a developer, I want gitignored files to appear in directory listings with locked permissions, so that the agent knows those paths exist and won't try to create files at those paths.
3. As a developer, I want gitignored files to reject all read and write attempts, so that an agent cannot access secret content even if it tries.
4. As a developer, I want to drop specific gitignore patterns via `[[gitignore_drop]]` in `.shadowconfig`, so that build artifacts like `*.out` are not blocked inside the mount.
5. As a developer, I want `[[gitignore_drop]]` to perform exact pattern subtraction from a targeted `.gitignore` file, so that I can precisely control which patterns are removed without ambiguity.
6. As a developer, I want the `gitignore` key in `[[gitignore_drop]]` to default to the root `.gitignore`, so that the common case requires minimal configuration.
7. As a developer, I want the `gitignore` key to accept relative paths (relative to source root), absolute paths, and `~`-prefixed paths, so that I can target any `.gitignore` file including `~/.gitignore`.
8. As a developer, I want dropped patterns to be filtered out at load time before matchers are built, so that the gitignore pattern is removed as if it was never in the file.
9. As a developer, I want to hide arbitrary directories (like `.git`) via `.shadowconfig`'s `[ignore]` section, so that git history and objects are not accessible to the agent.
10. As a developer, I want `.shadowconfig` to use gitignore-style glob patterns in `[ignore]`, so that I can use the same syntax I already know from `.gitignore`.
11. As a developer, I want only the root-level `.shadowconfig` to be loaded, so that there is a single source of truth for the access policy.
12. As a developer, I want fuseshadow to error and exit if a nested `.shadowconfig` is found, so that I am alerted to configs that would otherwise be silently ignored.
13. As a developer, I want a `--ignore-child-shadowconfigs` flag, so that in monorepos I can suppress the error for nested `.shadowconfig` files.
14. As a developer, I want `.shadowconfig` itself to be completely invisible inside the mount, so that the agent cannot read or modify the access policy.
15. As a developer, I want `.gitignore` files to be readable but not writable inside the mount, so that the agent can understand the project structure without being able to subvert ignore rules.
16. As a developer, I want all nested `.gitignore` files to be respected, so that per-subdirectory ignore rules apply correctly.
17. As a developer, I want `.gitignore` files in parent directories above the source root to be respected, so that global patterns (like those in `~/.gitignore`) apply.
18. As a developer, I want the gitignore snapshot (with drops applied) to be taken at mount time, so that the rules are stable while an agent session is running.
19. As a developer, I want symlinks to pass through the mount unchanged, so that the project's symlink structure works normally for the agent.
20. As a developer, I want absolute symlinks that point into the source directory to be rewritten to point into the mountpoint, so that the agent can follow them correctly without escaping the mount.
21. As a developer, I want to start the mount with a simple `fuseshadow <source> <mountpoint>` command, so that I don't need to learn a complex CLI.
22. As a developer, I want the process to run in the foreground and clean up on Ctrl-C, so that the lifecycle is easy to manage and I always know when the mount is active.
23. As a developer, I want fuseshadow to run inside a Docker container on Linux, so that the FUSE mount lifecycle is fully contained and I don't need to install any kernel extensions on my host machine.
24. As a developer, I want `[ignore]` to take priority over `[[gitignore_drop]]` — if a path matches `[ignore]`, it is hidden regardless of whether its gitignore pattern was dropped.
25. As a developer, I want directory renames by the agent to not bypass gitignore rules, so that renaming a parent directory cannot expose files that were blocked by subdirectory `.gitignore` patterns.
26. As a developer, I want directory renames to be tracked in the root `.shadowconfig` with a human-readable comment, so that I know which renames happened during an agent session and can update my `.gitignore` files accordingly.
27. As a developer, I want rename tracking entries to include timestamps, so that I can correlate renames with agent session timelines.
28. As a developer, I want fuseshadow to automatically protect renamed paths using the original gitignore rules, so that protection is maintained both during the current session and across restarts until I clean up the entries.
29. As a developer, I want fuseshadow to monitor the root `.shadowconfig` for external changes, so that cleanup I perform (or entries added by another fuseshadow instance) take effect without restarting the mount.

## Implementation Decisions

### Modules

**`rules` module — Path Classification Engine**
The core deep module. Loads all gitignore files and the root `.shadowconfig` at mount time (static snapshot) and exposes a single `classify(path)` method. Internally holds two collections of per-directory pattern matchers: one for gitignore rules and one for `[ignore]` patterns. Both collections are anchored at their respective containing directory, mirroring how git resolves nested `.gitignore` files.

Before building gitignore matchers, `[[gitignore_drop]]` entries are applied: for each targeted `.gitignore` file, matching pattern strings are filtered out line-by-line (exact string match after whitespace trimming) before the `GitignoreBuilder` processes them. Dropped patterns are never added to the matcher — as if the line was never in the file.

Classification priority (highest wins):
1. Filename is `.shadowconfig` → **Hidden**
2. Matches any `[ignore]` pattern → **Hidden**
3. Matches any gitignore rule (after drops applied) → **Blocked**
4. Filename is `.gitignore` → **GitignoreFile** (readable, not writable)
5. Otherwise → **Passthrough**

All pattern matching and filename checks (`.shadowconfig`, `.gitignore`) are case-insensitive by default (using Unicode `to_lowercase()`). Patterns are lowercased at load time; input paths are lowercased at classify time. The `case_sensitive` flag on `RuleSet` controls this behavior.

Gitignore loading walks both upward (from source root to filesystem root) and downward (all nested subdirectories). Uses `ignore::gitignore::GitignoreBuilder` from the `ignore` crate, one builder per `.gitignore` file, each anchored at its containing directory.

**Root-only `.shadowconfig` enforcement**: during the downward walk, if a nested `.shadowconfig` is found (any `.shadowconfig` not at the source root), fuseshadow exits with an error requesting cleanup. The `--ignore-child-shadowconfigs` flag suppresses this error and silently skips nested configs.

**`fs` module — FUSE Filesystem**
Implements `fuser::Filesystem`. Composes `RuleSet`. Maintains an inode-to-path mapping for the lifetime of the mount. Routes each FUSE operation through the classification result.

On directory rename: purges the renamed directory and all child inodes from the inode-to-path mapping (the kernel re-resolves them via `lookup` on the new parent). Delegates to `RuleSet` to update matchers and persist the rename. See rename tracking below.
- **Hidden**: return `ENOENT` for all operations; omit from `readdir`
- **Blocked**: include in `readdir` with mode `0o000`; return `EACCES` for all open/read/write/create/setattr
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

Write coordination uses `flock` on the root `.shadowconfig` for safe concurrent access.

**`main` module — CLI Entry Point**
Parses `fuseshadow <source> <mountpoint>` with `clap`. Validates source is an existing directory. Builds `RuleSet`, mounts with `fuser::mount2`. Registers a Ctrl-C / SIGTERM handler that triggers unmount. Accepts `--case-sensitive-rules` to opt into case-sensitive pattern matching (default is case-insensitive). Accepts `--ignore-child-shadowconfigs` to silently skip nested `.shadowconfig` files instead of erroring.

### `.shadowconfig` Format

```toml
[ignore]
patterns = [".git"]

[[gitignore_drop]]
patterns = ["*.out", "build/"]
# gitignore key omitted → targets .gitignore in the source root

[[gitignore_drop]]
gitignore = "subdir/.gitignore"
patterns = ["dist/"]

[[gitignore_drop]]
gitignore = "~/.gitignore"
patterns = ["node_modules/"]

# fuseshadow: directory renames detected during agent session.
folder_renames = [
  { from = "A/B", to = "A/D", at = "2026-05-04T14:32:00Z" },
]
```

The `gitignore` key accepts:
- Relative paths (relative to the source root)
- Absolute paths
- `~`-prefixed paths (expanded to the user's home directory)
- Defaults to `.gitignore` in the source root directory when omitted

Pattern subtraction is exact string matching: the string in `patterns` must be character-for-character identical to the line in the targeted `.gitignore` file (after trimming whitespace).

### Key Technical Decisions

- **Static snapshot**: gitignore rules (with drops applied) and `.shadowconfig` are read once at mount time. Changes to these files while the mount is active are not picked up — with one exception: the `folder_renames` field of the root `.shadowconfig` is monitored via mtime and re-read on change.
- **Root-only `.shadowconfig`**: only the `.shadowconfig` at the source root is loaded. Nested `.shadowconfig` files cause an error exit unless `--ignore-child-shadowconfigs` is passed.
- **Gitignore parent traversal**: walks up to the filesystem root (not just the git repo root), naturally including `~/.gitignore` as the home directory's `.gitignore`.
- **`[[gitignore_drop]]` is exact pattern subtraction**: patterns are removed from the targeted `.gitignore` file's line list before the matcher is built. This is not a file-glob override — the pattern string must exactly match a line in the `.gitignore` file.
- **`[ignore]` takes priority**: if a path matches `[ignore]`, it is hidden regardless of gitignore drops or any other classification.
- **Case-insensitive matching by default**: on case-insensitive source mounts (e.g., macOS shared folders in Docker), an agent could bypass rules by requesting `.eNv` instead of `.env`. To prevent this, all pattern matching is case-insensitive by default. `--case-sensitive-rules` opts into case-sensitive matching for environments where this is safe. Unicode `to_lowercase()` is used for normalization; `to_string_lossy()` is acceptable since the primary threat surface (macOS) guarantees UTF-8 filenames.
- **FUSE library**: `fuser` crate (FUSE3 on Linux).
- **Pattern syntax**: `[ignore]` uses the same glob syntax as `.gitignore`.
- **Rename tracking**: directory renames are persisted to the root `.shadowconfig` rather than tracked purely in memory, so protection survives across fuseshadow restarts. The developer is expected to review rename entries, update their `.gitignore` files, and remove the entries. Rename chains are not collapsed in the file (to avoid losing nested renames) but are resolved eagerly into a flat alias map at load time.
- **Inode purging on rename**: when a directory is renamed, all inodes for the directory and its children are removed from the inode-to-path mapping. The kernel re-resolves them via fresh `lookup` calls through the new parent. This avoids stale path references and ghost inode entries.

## Testing Decisions

**What makes a good test**: test external behavior through the public interface of each module — not internal data structures or intermediate states. A test should set up a real temporary directory with actual files and `.gitignore`/`.shadowconfig` files, call the public API, and assert the result. Do not mock the filesystem.

**`rules` module** — primary testing target. Pure logic with a simple interface. Tests create a real directory tree with `.gitignore` and `.shadowconfig` files, build a `RuleSet`, and assert `classify()` results for various paths. Cases to cover:
- Basic gitignored path → Blocked
- Nested `.gitignore` applies only to its subtree
- Parent directory `.gitignore` applies to source root
- `.shadowconfig` `[ignore]` pattern → Hidden
- `[ignore]` hides a path even if its gitignore pattern was dropped
- `.shadowconfig` itself → Hidden
- `.gitignore` file → GitignoreFile
- Unmatched file → Passthrough
- `[[gitignore_drop]]` removes exact pattern from root `.gitignore` → file becomes Passthrough
- `[[gitignore_drop]]` targeting a subdirectory `.gitignore` only affects that file's patterns
- `[[gitignore_drop]]` with non-matching pattern string has no effect
- `[[gitignore_drop]]` with `~`-prefixed gitignore path resolves correctly
- `[[gitignore_drop]]` with absolute gitignore path resolves correctly
- Nested `.shadowconfig` causes error exit
- `--ignore-child-shadowconfigs` suppresses the nested config error

**`fs` module** — integration tests that mount a real FUSE filesystem. The build environment is a Docker container with `/dev/fuse` access, so mount-based tests are feasible. Each test mounts a temp source directory, exercises the operation under test through the mountpoint, and unmounts cleanly on completion.

## Out of Scope

- Live-reloading of `.gitignore` or `.shadowconfig` files while the mount is active
- Global git excludes via `core.excludesFile` in `~/.gitconfig` (parent dir walk naturally picks up `~/.gitignore` if it exists as a file)
- Copy-on-write or writable overlay for gitignored files (writes to blocked paths are rejected; if the agent needs to write a gitignored path, the pattern should be dropped via `[[gitignore_drop]]` or a future feature should be designed)
- Daemonization or background mount mode
- Publishing to crates.io or any package registry
- Network filesystems or remote sources
- Hard link handling beyond what FUSE passthrough provides
- Extended attribute (xattr) policy — xattrs pass through for Passthrough/GitignoreFile files; EACCES for Blocked/Hidden
- Performance optimization for very large repositories (no caching beyond the mount-time snapshot)
- macOS / macFUSE support
- Composable nested `.shadowconfig` files (root-only by design)

## Further Notes

- `fuseshadow` runs inside a Docker container on Linux. The source directory is typically bind-mounted into the container, while the mountpoint is a directory inside the container. The AI agent is given access only to the mountpoint path. The binary will fail at mount time with a clear error if FUSE is not available in the container environment.
- The static snapshot design means that if the agent's session is long-lived and the developer adds new secrets to the source tree (that happen to match gitignore), those new files will be caught by the existing rules but any NEW `.gitignore` entries added during the session will not take effect until remount.
- Directory renames by the agent are a security-relevant mutation to the source tree. The `folder_renames` tracking in root `.shadowconfig` serves as both a runtime protection mechanism and a developer-facing audit trail. Developers should review these entries after each agent session and remove them once `.gitignore` files have been updated to match the new directory layout.
- `.shadowconfig` files in parent directories outside the source root are intentionally not loaded — only parent `.gitignore` files are. This prevents a malicious or misconfigured parent directory from affecting the mount's policy.
- The `[[gitignore_drop]]` feature is designed for build artifacts and tooling outputs that happen to be gitignored but need to be writable inside the mount. It is NOT designed for exposing secrets — if a gitignore pattern protects secret files, dropping it will expose those files with full read/write access.
