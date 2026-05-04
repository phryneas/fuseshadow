# Fuseshadow

A FUSE filesystem that mounts a source directory at a separate mountpoint and enforces a layered access policy — giving an AI agent full access to your source code while keeping secrets completely out of reach.

## Access Policy

Files inside the mount are classified in priority order:

| Classification | Behavior |
|---|---|
| `.shadowconfig` | Always invisible (`ENOENT`) |
| `[ignore]` pattern match | Invisible (`ENOENT`), omitted from directory listings |
| `[writable]` + gitignored | Invisible until the agent writes it; writes go to a temp overlay, never the source |
| Gitignored | Appears in listings with `----------` permissions; all open/read/write attempts return `EACCES` |
| `.gitignore` file | Readable, not writable |
| Everything else | Full read/write passthrough to the source directory |

Gitignore rules are read from all `.gitignore` files in the source tree and from parent directories up to the filesystem root (picking up `~/.gitignore` automatically). The snapshot is taken at mount time and is stable for the duration of the session.

## `.shadowconfig`

Place a `.shadowconfig` TOML file in any directory to configure access rules for that subtree. Patterns use gitignore-style glob syntax.

```toml
[ignore]
# Completely hide these paths (ENOENT, not in listings)
patterns = [".my_secret"]

[writable]
# Allow agent to write these paths (only activates if also gitignored)
# Agent sees nothing until it creates the file; original content is never exposed
patterns = ["build_output/*"]
```

`[ignore]` takes priority over `[writable]` when both match a path. `.shadowconfig` files outside the source root are never loaded.

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
