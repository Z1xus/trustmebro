> [!NOTE]
> vibecoding disclosure.<br>
> i did not care enough to read any of this, and you may not care enough to run it, which is fine either way

# trustmebro

Change what a command returns when a coding agent runs it.

## Install

Prebuilt binaries are available for `linux-x86_64`, `linux-arm64`,
`macos-arm64` and `macos-x86_64`:

```sh
curl -fsSLO https://github.com/z1xus/trustmebro/releases/latest/download/trustmebro-linux-x86_64.tar.gz
tar xzf trustmebro-linux-x86_64.tar.gz
./trustmebro init
```

`init` creates the starter config, installs trustmebro, copies the global
config, and enables interception.

Building from source needs a C11 compiler and libc. Releases include
`SHA256SUMS` and a provenance attestation:

```sh
gh attestation verify trustmebro-linux-x86_64.tar.gz --repo z1xus/trustmebro
```

## Use

```sh
cd my-project
trustmebro init
trustmebro run -- codex
```

`run` affects only the process it starts. Matching calls use the config and
everything else runs normally:

```console
$ dig marker.trustmebro.test TXT +short
"trustmebro-marker-7f3a9"      # from a rule

$ dig cloudflare.com A +short
104.16.132.229                 # no rule matched, real dig ran
```

## Codex and Claude apps, and Pi agent

Set the agents in `trustmebro.toml`:

```toml
activate = ["codex", "claude", "pi"]
```

If you already have a config, install directly:

```sh
./trustmebro install
```

`install` copies trustmebro to a writable user bin directory already on
`PATH`. It also copies the discovered config to
`~/.config/trustmebro/config.toml`, then adds links for the configured
commands. Existing binaries and global configs are not replaced. It does not
edit `PATH`, shell profiles, or agent settings.

Use `disable` and `enable` to toggle interception without installing or
removing the program:

```sh
trustmebro disable
trustmebro enable
```

`trustmebro status` checks the links. Run `disable` and `enable` again after
changing shim names. `TRUSTMEBRO=0` disables automatic activation for one
process. Remove the command links and installed binary with:

```sh
trustmebro uninstall
```

## Rules

`init` writes a `trustmebro.toml` with examples, then installs and enables
trustmebro. Config lookup starts in the working directory and searches upward.

```toml
activate = ["codex", "claude", "pi"]         # optional automatic activation
default = "passthrough"                       # or "reject"
log = "~/.local/state/trustmebro/log.jsonl"   # one JSON line per call

[[rule]]
name = "marker"
command = "dig"
match = "*trustmebro.test*txt*"
stdout = '''
marker.trustmebro.test. 300 IN TXT "trustmebro-marker-7f3a9"
'''

[[rule]]
name = "annotate"
command = "dig"
regex = "example\\.com"
find = "flags: qr rd ra"
replace = "flags: qr rd ra ;; verified"
```

The first matching rule wins. Every matcher on that rule must pass.

| Field | |
|---|---|
| `activate` | `codex`, `claude`, `pi`, or an array containing them. Optional. |
| `name` | Required, unique. |
| `command` | Shim it applies to. `*` or omitted matches any. |
| `match` | Case-insensitive glob over the arguments. |
| `regex` | POSIX extended regex over the arguments. |
| `stdout` `stderr` `exit` | Fixed output. Implies `spoof`. |
| `find` `replace` | Regex patch of the real stdout. Implies `rewrite`. `\0` or `&` is the whole match, `\1`..`\9` the groups. |
| `action` | Force `spoof`, `rewrite`, `passthrough`, or `reject`. |

Use `trustmebro check` to validate the config. `trustmebro -h` lists all
commands.

## Limits

trustmebro works through `PATH`. Absolute paths, a cleared environment, and
resolvers inside another process bypass it. It is a testing tool, not a
sandbox. A broken config exits 78 instead of running the real command.

## Credit

The idea came from
[DavidCarliez/trustmebro](https://github.com/DavidCarliez/trustmebro). This
rewrite contains none of its code.

The original implementation sucked. It created a separate shim directory and
added it to shell startup files. That was too intrusive. This rewrite also uses
`PATH` shims, but creates only configured links in an existing user bin
directory. It changes no shell config, refuses collisions, and can disable or
uninstall cleanly.

## License

Unlicense
