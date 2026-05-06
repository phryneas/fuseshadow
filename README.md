# Fuseshadow

A FUSE filesystem that mounts a source directory at a separate mountpoint and enforces a layered access policy — giving an AI agent full access to your source code while keeping secrets completely out of reach.

## Access Policy

Files inside the mount are classified in priority order:

| Classification            | Behavior                                                                                        |
| ------------------------- | ----------------------------------------------------------------------------------------------- |
| `.shadowconfig`           | Always invisible (`ENOENT`)                                                                     |
| `[ignore]` pattern match  | Invisible (`ENOENT`), omitted from directory listings                                           |
| Gitignored (after drops)  | Appears in listings with `----------` permissions; all open/read/write attempts return `EACCES` |
| `.gitignore` file         | Readable, not writable                                                                          |
| Everything else           | Full read/write passthrough to the source directory                                             |

Gitignore rules are read from all `.gitignore` files in the source tree and from parent directories up to the filesystem root (picking up `~/.gitignore` automatically). The snapshot is taken at mount time and is stable for the duration of the session.

## `.shadowconfig`

Place a `.shadowconfig` TOML file at the root of your source directory to configure access rules. Only the root-level `.shadowconfig` is loaded; nested ones cause an error (suppressible with `--ignore-child-shadowconfigs`). Patterns use gitignore-style glob syntax.

```toml
[ignore]
# Completely hide these paths (ENOENT, not in listings)
patterns = [".my_secret"]

[[gitignore_drop]]
# Remove these patterns from the root .gitignore before building matchers.
# Files matched only by dropped patterns become Passthrough (full access).
patterns = ["*.out", "build/"]

[[gitignore_drop]]
# Target a specific .gitignore file (relative to source root, absolute, or ~/…)
gitignore = "subdir/.gitignore"
patterns = ["dist/"]
```

`[[gitignore_drop]]` performs exact string subtraction: each pattern must match a line in the targeted `.gitignore` file character-for-character (after whitespace trimming). The `gitignore` key defaults to the root `.gitignore` when omitted. Supports relative paths, absolute paths, and `~/`-prefixed paths.

## Requirements

- FUSE3 (`/dev/fuse` accessible in the container)
- The `fuseshadow` binary in `PATH`

## Usage:

Assumptions:

- A mix of "secret" and accessible data is available in a source directory (e.g. `/mnt/deny/workspace-src`)
- This runs inside of a rootless podman container, with FUSE3 available

```sh
#!/bin/sh
# Enter a namespace where we can execute a mount
exec unshare -r --user --mount -- /bin/sh -c '
    # Mount the "wrapping filesystem" that will be used to hide certain sensitive data from the incoming bind mount
    fuseshadow --daemon /mnt/deny/workspace-src /home/agent/workspace
    # Hide the original incoming bind mount from the child namespace.
    mount -t tmpfs none /mnt/deny
    # Drop into another child namespace, executing the passed command $@
    exec unshare --user --map-user=1000 --map-group=1000 --mount -- "$@"
' -- "$@"
```

If this script is called `enter`, run `enter claude` to drop into a new namespace where `/home/agent/workspace` is the FUSE mount of the source directory, with access rules applied.

## Warning:

This is a "best-effort" tool to help mitigate risks of accidentally exposing secrets to an AI agent. It is not a security boundary. Do not rely on it to protect highly sensitive data — always use dedicated secret management tools for that.
