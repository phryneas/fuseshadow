# Plan: Simplify `.shadowconfig` — drop `[writable]`, add `[[gitignore_drop]]`

> Source PRD: `./PRD.md` (updated 2026-05-06)

## Architectural decisions

- **Root-only `.shadowconfig`**: only the `.shadowconfig` at the source root is loaded. Nested ones are an error (suppressible with `--ignore-child-shadowconfigs`).
- **No overlay**: there is no writable overlay filesystem. Blocked paths stay blocked; to unblock, drop the gitignore pattern.
- **Classification priority** (5 levels, down from 6):
  1. `.shadowconfig` → Hidden
  2. Matches `[ignore]` → Hidden
  3. Matches gitignore (after drops) → Blocked
  4. `.gitignore` file → GitignoreFile
  5. Otherwise → Passthrough
- **`[[gitignore_drop]]` is load-time pattern subtraction**: patterns are removed line-by-line from the targeted `.gitignore` before the matcher is built. Exact string match after whitespace trimming.
- **`gitignore` key in `[[gitignore_drop]]`**: relative paths (relative to source root), absolute paths, or `~`-prefixed paths. Defaults to the root `.gitignore`.

---

## Phase 1: Root-only `.shadowconfig` enforcement

**User stories**: 11, 12, 13

### What to build

Change the source-tree walk so that any nested `.shadowconfig` (not at the source root) causes an immediate error exit with a message explaining that only the root-level config is supported. Add a `--ignore-child-shadowconfigs` CLI flag that suppresses this error and silently skips nested configs. Remove the now-redundant per-field validation that checks whether `folder_renames` appears in a nested config — the whole-file check catches it first.

### Acceptance criteria

- [ ] fuseshadow errors and exits when a nested `.shadowconfig` exists anywhere in the source tree
- [ ] Error message names the offending file and explains that only root-level `.shadowconfig` is supported
- [ ] `--ignore-child-shadowconfigs` flag causes nested `.shadowconfig` files to be silently skipped (no error, no loading)
- [ ] The old `folder_renames`-specific nested validation is removed
- [ ] `[ignore]` patterns from nested `.shadowconfig` files are no longer loaded (even without `--ignore-child-shadowconfigs`, the error fires before they would be)
- [ ] `[writable]` patterns from nested `.shadowconfig` files are no longer loaded (same — error fires first; full removal comes in Phase 2)
- [ ] Unit tests cover: nested config triggers error, flag suppresses error, root config still loads normally

---

## Phase 2: Remove `[writable]` / WritableOverlay / overlay

**User stories**: removes old overlay behavior (PRD user stories 4-8 from previous revision)

### What to build

Remove the entire writable overlay feature. This touches every layer:

- Delete the `overlay` module entirely.
- Remove the `WritableOverlay` variant from the classification enum.
- Remove the `writable` field from the shadowconfig struct and the `shadow_writable_matchers` collection from the ruleset. Remove writable pattern serialization.
- Remove all WritableOverlay routing in the FUSE layer (lookup, getattr, readdir, open, create, setattr, mkdir, unlink).
- Remove overlay construction from the CLI entry point and the overlay parameter from the FUSE struct constructor.
- Remove all WritableOverlay-specific tests. Update any remaining tests that referenced writable configs or overlay behavior.
- `tempfile` dependency stays (used by test fixtures) but is no longer used in production code.

### Acceptance criteria

- [x] `PathClass` enum has 4 variants: Hidden, Blocked, GitignoreFile, Passthrough
- [x] `overlay.rs` module is deleted
- [x] `ShadowConfig` no longer has a `writable` field; a `.shadowconfig` with `[writable]` either errors or silently ignores it
- [x] No references to `overlay` or `WritableOverlay` remain in production code
- [x] FUSE operations for previously-WritableOverlay paths now return the same result as Blocked paths (EACCES for open/read/write, visible in readdir with mode 0o000)
- [x] All existing non-overlay tests still pass
- [x] Project compiles with no warnings related to the removal
- [x] README updated

---

## Phase 3: Add `[[gitignore_drop]]`

**User stories**: 4, 5, 6, 7, 8, 18

### What to build

Add `[[gitignore_drop]]` support to the `.shadowconfig` format and the rules engine. Each entry has a `patterns` list (required) and a `gitignore` path (optional, defaults to root `.gitignore`).

At load time, before building gitignore matchers, the drop entries are processed: for each targeted `.gitignore` file, its lines are read and any line whose trimmed content exactly matches a drop pattern is filtered out. The `GitignoreBuilder` then receives only the surviving lines. The dropped pattern is gone as if it was never written.

The `gitignore` key supports:

- Relative paths (relative to source root)
- Absolute paths
- `~`-prefixed paths (expanded to `$HOME`)

### Acceptance criteria

- [x] `[[gitignore_drop]]` with `patterns = ["*.out"]` and no `gitignore` key removes `*.out` from the root `.gitignore` matcher
- [x] Files that were blocked only by the dropped pattern are now classified as Passthrough
- [x] Files blocked by a non-dropped pattern in the same `.gitignore` remain Blocked
- [x] The same pattern in a different `.gitignore` file is unaffected (only the targeted file's pattern is dropped)
- [x] `gitignore` key with a relative path targets the correct `.gitignore` file
- [x] `gitignore` key with an absolute path works
- [x] `gitignore` key with `~/` prefix expands to `$HOME` and targets the correct file
- [x] Non-matching drop patterns (pattern string not found in the targeted file) have no effect and do not error
- [x] `[ignore]` still takes priority — a path matching `[ignore]` is Hidden even if its gitignore pattern was dropped
- [x] Case-insensitive mode applies to dropped patterns (both the `.gitignore` line and the drop pattern are lowercased before comparison)
- [x] Unit tests cover all the above cases
- [x] README updated

---

## Phase 4: End-to-end regression tests

**User stories**: validates the full simplified flow across all user stories

### What to build

FUSE-level integration tests that verify the complete simplified classification pipeline through real mount operations. These tests exercise `[[gitignore_drop]]` interacting with the rest of the system — not just the rules engine in isolation.

### Acceptance criteria

- [ ] Test: a dropped gitignore pattern makes a previously-blocked file readable and writable through the mount
- [ ] Test: a file matching both `[ignore]` and a dropped gitignore pattern is still Hidden (ENOENT)
- [ ] Test: `[[gitignore_drop]]` targeting a subdirectory `.gitignore` only unblocks files matched by that specific file's pattern
- [ ] Test: directory rename tracking still works correctly after gitignore_drop simplification — renamed directories maintain protection
- [ ] Test: case-insensitive matching works end-to-end with gitignore_drop (agent requests `BUILD.Out`, pattern `*.out` was dropped, file is accessible)
- [ ] Test: `.shadowconfig` with `[[gitignore_drop]]` is itself still Hidden inside the mount
