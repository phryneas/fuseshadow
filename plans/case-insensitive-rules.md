# Plan: Case-insensitive rule matching

> Source PRD: `PRD.md` — Key Technical Decisions, "Case-insensitive matching by default"

## Why

When the source directory lives on a case-insensitive filesystem (common scenario: macOS shared folder bind-mounted into a Docker container), an agent can bypass gitignore-based rules by requesting an alternate casing of the filename (e.g., `.eNv` instead of `.env`). The gitignore pattern matches `.env` but not `.eNv`, so the path falls through to Passthrough and the secret is exposed. Making pattern matching case-insensitive by default closes this bypass without requiring users to discover a CLI flag.

## Architectural decisions

- **Default behavior**: all pattern matching is case-insensitive; `--case-sensitive-rules` CLI flag opts into case-sensitive matching
- **Flag threading**: `case_sensitive: bool` field on `RuleSet`, set at `load()` time, read by `classify()`
- **Normalization strategy**: Unicode `str::to_lowercase()` applied to both patterns (at load time) and input paths (at classify time); `to_string_lossy()` acceptable for path-to-string conversion
- **Pattern loading**: in case-insensitive mode, `.gitignore` files are read line-by-line and lowercased via `add_line()` instead of `builder.add(file)`; `.shadowconfig` patterns lowercased before `add_line()`; anchor dirs lowercased for `GitignoreBuilder::new()`
- **Scope of case folding**: classification logic only — real filesystem access paths are never lowercased

---

## Phase 1: Case-insensitive classification engine

**User stories**: 1, 3, 10

### What to build

Add a `case_sensitive` flag to `RuleSet` that controls whether pattern matching is case-insensitive. When case-insensitive (the default), all patterns are lowercased at load time: `.gitignore` files are read line-by-line with each line lowercased before `add_line()`, `.shadowconfig` patterns are lowercased before `add_line()`, and anchor directories passed to `GitignoreBuilder::new()` are lowercased. At classify time, a lowercased copy of the input path is constructed for matching while the original-case path is preserved for filesystem access (the `is_dir` stat fallback). The `.shadowconfig` and `.gitignore` filename checks also respect the flag, comparing against lowercased filenames when case-insensitive.

Existing unit tests are updated to pass `case_sensitive: true` to `RuleSet::load()` so they continue to test the current behavior. New unit tests are added that construct a `RuleSet` with `case_sensitive: false` and verify that alternate-cased paths classify correctly.

### Acceptance criteria

- [ ] `RuleSet::load()` accepts a `case_sensitive: bool` parameter
- [ ] `RuleSet` stores the flag and `classify()` reads it
- [ ] In case-insensitive mode, `.gitignore` patterns are loaded line-by-line and lowercased
- [ ] In case-insensitive mode, `.shadowconfig` patterns are lowercased at load time
- [ ] In case-insensitive mode, anchor dirs are lowercased for `GitignoreBuilder::new()`
- [ ] `classify()` lowercases the input path for matching when case-insensitive; original-case path used for `is_dir` stat
- [ ] `.shadowconfig` filename check is case-insensitive when flag is off
- [ ] `.gitignore` filename check is case-insensitive when flag is off
- [ ] Existing tests pass with `case_sensitive: true`
- [ ] New tests: gitignored `.env` is `Blocked` when looked up as `.ENV`, `.Env`, etc.
- [ ] New tests: `[writable]` + gitignored path is `WritableOverlay` when looked up with alternate casing
- [ ] New tests: `[ignore]` pattern hides path when looked up with alternate casing
- [ ] New tests: `.SHADOWCONFIG` is `Hidden`, `.GITIGNORE` is `GitignoreFile` in case-insensitive mode

---

## Phase 2: CLI integration + dry-run

**User stories**: 19

### What to build

Add `--case-sensitive-rules` as a clap long flag to the `Cli` struct (default: false, so case-insensitive is the default). Wire the flag through to `RuleSet::load()`. When `--dry-run` is active, print a header line before the classification table indicating the active matching mode (e.g., "Matching mode: case-insensitive (default)" or "Matching mode: case-sensitive").

### Acceptance criteria

- [x] `--case-sensitive-rules` flag accepted by the CLI
- [x] Flag value passed to `RuleSet::load()`
- [x] `--dry-run` output includes a header line showing the matching mode
- [x] `--help` documents the flag
- [x] Integration test: `--case-sensitive-rules` flag is accepted without error

---

## Phase 3: FUSE-level integration tests

**User stories**: 1, 2, 3, 4, 5, 9, 12, 13

### What to build

Mount-based integration tests that exercise case-insensitive matching through the actual FUSE filesystem. These verify that the classification behavior survives the full path through inode lookup, readdir, open, and read/write operations — not just the `classify()` function in isolation.

Specific scenarios to cover at minimum:

- **Blocked file via alternate case**: `.env` is gitignored; lookup/open of `.ENV` through the mount returns `EACCES`, and `.ENV` appears in readdir with zero permissions
- **Hidden file via alternate case**: path matching `[ignore]` looked up with alternate casing returns `ENOENT` and is absent from readdir
- **WritableOverlay via alternate case**: `[writable]` + gitignored path accessed with alternate casing is invisible before write, writable, and readable from overlay after write
- **`.shadowconfig` hidden via alternate case**: lookup of `.SHADOWCONFIG` or `.ShadowConfig` returns `ENOENT`
- **`.gitignore` read-only via alternate case**: `.GITIGNORE` is readable but rejects writes
- **Passthrough unaffected**: regular files accessed with their real casing continue to work normally

Additional scenarios may be added as edge cases surface during implementation.

### Acceptance criteria

- [ ] Blocked file rejects access when looked up with alternate casing
- [ ] Hidden file is absent from readdir and lookup when accessed with alternate casing
- [ ] WritableOverlay works end-to-end (invisible → create → read → unlink → invisible) via alternate casing
- [ ] `.shadowconfig` is hidden regardless of casing
- [ ] `.gitignore` is read-only regardless of casing
- [ ] Passthrough files work normally
- [ ] All tests pass in the existing `unshare`-based test runner

---

## Phase 4: Remove `is_dir` optionality (cleanup)

**User stories**: none (internal cleanup)

### What to build

Change `classify()` signature from `is_dir: Option<bool>` to `is_dir: bool`. Remove the filesystem stat fallback (`abs_path.is_dir()`), which is dead code in production — all callers in `fs.rs` already pass `Some(true)` or `Some(false)`. Update all unit tests to pass explicit `bool` values instead of `None`.

### Acceptance criteria

- [x] `classify()` takes `is_dir: bool` (not `Option<bool>`)
- [x] No filesystem stat fallback in `classify()`
- [x] All unit tests updated to pass explicit `true` or `false`
- [x] All existing tests pass
