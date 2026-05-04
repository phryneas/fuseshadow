# Plan: Directory rename bypass fix

> Source PRD: `PRD.md` — Rename tracking in `rules` module, user stories 24–29

## Why

Renaming a parent directory that contains a `.gitignore` file breaks the anchored pattern matching from the `ignore` crate. Patterns are rooted at the original directory path; after rename, `strip_prefix` fails and `matches()` silently returns `false`. This lets the agent read files that should be blocked by subdirectory `.gitignore` patterns.

## Architectural decisions

- **Persistence**: directory renames are tracked in the root `.shadowconfig` under `folder_renames`, not purely in memory — protection survives across restarts until the developer cleans up
- **Format**: `folder_renames = [{ from = "A/B", to = "A/D", at = "2026-05-04T14:32:00Z" }]` — paths relative to source root, TOML inline tables, timestamps for developer audit trail
- **Root-only constraint**: `folder_renames` is only valid in the root `.shadowconfig`; a nested one causes an immediate error exit
- **Parent vs child matchers**: parent-anchored matchers (above the rename) use a path alias table; child-anchored matchers (inside the renamed dir) are dropped and re-read from the new location
- **Alias resolution**: rename chains are stored raw in the file but resolved eagerly at load time into a flat `to → original_from` map
- **Write coordination**: `flock` on the root `.shadowconfig` for concurrent access between multiple fuseshadow instances
- **Live monitoring**: root `.shadowconfig` mtime is checked before `classify()`; on change, the alias table is rebuilt and new external renames trigger child matcher re-reads
- **Inode cleanup on rename**: the renamed directory and all child inodes are purged from the inode-to-path mapping; the kernel re-resolves via fresh `lookup` calls

---

## Phase 1: Fix ghost inode bug on directory rename

**User stories**: none (existing bug)

### What to build

When a directory is renamed, the current `rename` handler only updates the inode for the directory itself. All child inodes remain mapped to their old paths, creating ghost entries that reference non-existent paths. Fix the `rename` handler to purge the renamed directory's inode and all child inodes (anything prefixed by the old relative path) from both the `inode_to_path` and `path_to_inode` maps. The kernel will re-resolve children via `lookup` on the new parent.

### Acceptance criteria

- [ ] Rename handler removes all inodes prefixed by the old path from both maps
- [ ] After renaming a directory, accessing a child file through the mountpoint works (kernel re-resolves via lookup)
- [ ] After renaming a directory, `readdir` on the new path shows correct children
- [ ] No stale inode entries remain for the old path after rename

---

## Phase 2: `folder_renames` parsing and validation in `rules` module

**User stories**: 25, 26, 29

### What to build

Extend the `.shadowconfig` TOML schema to support an optional `folder_renames` field — a list of `{ from, to, at }` entries. During `RuleSet::load()`, parse `folder_renames` from the root `.shadowconfig` if present. If any non-root `.shadowconfig` in the tree contains `folder_renames`, exit with a clear error message.

Build the alias resolution logic: process entries in order, resolve chains eagerly into a flat `to → original_from` map. Expose the alias table for use by `classify()` but don't wire it in yet.

Add unit tests using real temp directories with `.shadowconfig` files containing `folder_renames`.

### Acceptance criteria

- [ ] `ShadowConfig` deserializes `folder_renames` as an optional field
- [ ] `RuleSet::load()` reads `folder_renames` from root `.shadowconfig` and builds an alias map
- [ ] Chains like `A→B, B→C` resolve to a flat map: `B→A, C→A`
- [ ] Nested `.shadowconfig` with `folder_renames` causes an error exit with a message requesting cleanup
- [ ] Empty or missing `folder_renames` is a no-op
- [ ] Unit tests cover: single rename, chain resolution, nested config rejection, missing field

---

## Phase 3: Alias-aware classification

**User stories**: 24, 27

### What to build

Wire the alias table into `classify()`. When classifying a path, if any prefix of the path matches a `to` key in the alias map, also check the path with that prefix replaced by the `original_from` against parent-anchored matchers. This makes parent `.gitignore` patterns follow directory renames.

Write unit tests that create a directory tree, build a `RuleSet` with `folder_renames`, rename the directory on disk, and verify that `classify()` still blocks the files at the new path.

### Acceptance criteria

- [ ] `classify()` checks aliased paths against parent-anchored matchers
- [ ] A file blocked by a parent `.gitignore` pattern remains blocked after its parent directory is renamed (with a corresponding `folder_renames` entry)
- [ ] The original path still classifies as blocked (for path recreation scenarios)
- [ ] Non-aliased paths are unaffected (no performance regression for the common case)
- [ ] Unit tests cover: single rename blocks new path, original path still blocked, chain resolution works end-to-end, unrelated paths unaffected

---

## Phase 4: Runtime rename tracking + persistence

**User stories**: 24, 25, 26

### What to build

When the FUSE `rename` handler processes a directory rename:
1. Drop child-anchored matchers (anchored inside the old path) and re-read `.gitignore`/`.shadowconfig` from the new path on disk
2. Add the rename to the in-memory alias table
3. Persist the rename to the root `.shadowconfig` `folder_renames` field — parse the existing file, append the entry with a UTC timestamp, rewrite under `flock`
4. If the root `.shadowconfig` doesn't exist, create it with the header comment

The write includes a human-readable comment block explaining what the entries are and that the developer should review them.

### Acceptance criteria

- [ ] Directory rename triggers child matcher drop + re-read from new location
- [ ] Directory rename adds an alias entry; `classify()` immediately protects the new path
- [ ] Root `.shadowconfig` is updated on disk with the new `folder_renames` entry
- [ ] Root `.shadowconfig` is created if it didn't exist
- [ ] Existing `.shadowconfig` content (`[ignore]`, `[writable]`) is preserved on rewrite
- [ ] `flock` is held during read-modify-write
- [ ] Timestamp is included in the persisted entry
- [ ] FUSE integration test: rename a directory containing blocked files, verify they remain inaccessible at the new path, verify `folder_renames` appears in the root `.shadowconfig` on disk

---

## Phase 5: Live mtime monitoring + cross-instance support

**User stories**: 27, 28

### What to build

Before each `classify()` call, stat the root `.shadowconfig` and compare mtime to a cached value. On change:
1. Re-parse `folder_renames` and rebuild the alias table
2. For rename entries not previously seen (new entries added by the developer or another fuseshadow instance), drop child matchers for the affected `from` subtree and re-read from the `to` location

This enables three scenarios: developer removes entries (aliases disappear), developer adds entries manually, and another fuseshadow instance adds entries.

### Acceptance criteria

- [ ] mtime is checked before `classify()` calls; no re-parse when unchanged
- [ ] Developer removing a `folder_renames` entry causes the alias to disappear on next access
- [ ] A new entry added externally (simulating another instance) is picked up and applied
- [ ] New external entries trigger child matcher re-read for the affected subtree
- [ ] FUSE integration test: mount, rename a directory, externally edit `.shadowconfig` to remove the entry, verify the alias is gone
- [ ] FUSE integration test: mount, externally add a `folder_renames` entry, verify the alias is applied

---

## Phase 6: Cross-restart persistence integration test

**User stories**: 27

### What to build

End-to-end integration test that verifies the full lifecycle: mount, rename a directory containing blocked files, unmount, verify `folder_renames` persists in the root `.shadowconfig`, remount, verify blocked files are still inaccessible at the renamed path.

### Acceptance criteria

- [ ] Mount → rename directory → unmount → `folder_renames` present in root `.shadowconfig`
- [ ] Remount with existing `folder_renames` → blocked files at renamed path are still blocked
- [ ] Remount → developer removes `folder_renames` entries → protection reflects current `.gitignore` state (no aliases)
