# cutter

Cutter is an interactive REPL/CLI for communicating with
[butlerd](https://docs.itch.zone/butlerd/master/) (the butler daemon) over
JSON-RPC via TCP. It launches a `butler daemon` subprocess, connects to it, and
lets you send requests, notifications, and receive responses interactively.

## Usage

```
cutter <butler-path> [flags]
```

### Arguments

- `butler-path` (required) — path to the butler repository (used for loading the spec and rebuilding)

### Flags

| Flag | Description |
|------|-------------|
| `--verbose` | Show JSON-RPC traffic and butler log lines |
| `--debug` | Show debug-level log notifications from butlerd |
| `--dbpath` | Explicit path for database |
| `--appname` | Application name for database lookup (default: `kitch`) |
| `-p, --profile` | Profile ID to auto-inject into requests that need one (default: `0`) |
| `-e, --exec` | Execute a single command and exit (non-interactive mode) |
| `--log-sql` | Log SQL queries from hades |
| `--log-http` | Log HTTP requests from go-itchio |
| `--raw` | Show raw JSON-RPC messages without formatting |

### Examples

```bash
# Start an interactive session
cutter ~/src/butler

# Execute a single command and exit
cutter ~/src/butler -e "r Version.Get"

# Start with verbose output and a specific profile
cutter ~/src/butler --verbose -p 1

# Show raw JSON-RPC messages
cutter ~/src/butler --raw

# Log SQL queries
cutter ~/src/butler --log-sql
```

## Interactive commands

| Command | Description |
|---------|-------------|
| `r <method> [params]` | Send a JSON-RPC request. `params` is a JSON object, defaults to `{}` |
| `n <method> [params]` | Send a JSON-RPC notification. `params` is a JSON object, defaults to `{}` |
| `<id> [result]` | Reply to a server request. `result` is a JSON object, defaults to `{}` |
| `doc [method]` | Show documentation for a method or type (defaults to last request sent/received) |
| `st` | Show stack trace from last error |
| `ed` | Show last error data |
| `p <id>` | Set profile ID for all future requests |
| `rb` | Rebuild butler and restart the daemon |
| `login` | Authenticate with itch.io using OAuth 2.0 + PKCE |
| `debug` | Toggle debug mode |
| `snip` | Toggle snip mode (truncate long responses) |
| `help` | Show help |
| `q` / `exit` | Quit |

### Command examples

```
r Version.Get
r Test.DoubleTwice {"number": 4}
0 {"number": 8}
doc Version.Get
p 1
```
## Links

  * <https://github.com/itchio/butler>
  * <https://docs.itch.zone/butlerd/master/>
