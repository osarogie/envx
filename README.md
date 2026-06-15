# envx

[![CI](https://github.com/osarogie/envx/actions/workflows/ci.yml/badge.svg)](https://github.com/osarogie/envx/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/osarogie/envx.svg)](https://pkg.go.dev/github.com/osarogie/envx)

A small, dependency-light Go library and CLI for working with encrypted `.env`
files, compatible with the [dotenvx](https://dotenvx.com) workflow of committing
encrypted secrets next to your code.

Unlike upstream dotenvx (which uses secp256k1 / ECIES), `envx` seals values
with **post-quantum cryptography**: ML-KEM-768 (FIPS 203) key encapsulation
combined with AES-256-GCM. Encrypted values carry the `encrypted_pqc:` prefix.

- **Library**: load and decrypt `.env` files into your process, or build a
  child-process environment, with no global state surprises.
- **CLI**: `encrypt`, `decrypt`, and `run` a command with secrets injected.
- **One dependency**: [`github.com/joho/godotenv`](https://github.com/joho/godotenv)
  for parsing; everything else is the Go standard library (`crypto/mlkem`,
  `crypto/aes`).

> Requires Go 1.24+ (for the stable `crypto/mlkem` package).

## Install

Library:

```bash
go get github.com/osarogie/envx
```

CLI:

```bash
go install github.com/osarogie/envx/cmd/envx@latest
```

## How it works

Each `.env` file has an associated key pair:

- A **public (encapsulation) key** lives in the env file itself as
  `DOTENV_PUBLIC_KEY` (or `DOTENV_PUBLIC_KEY_<SUFFIX>` for `.env.<suffix>`).
  This is safe to commit and is what `encrypt` uses.
- A **private (decapsulation) key** is read from the environment variable
  `DOTENV_PRIVATE_KEY` / `DOTENV_PRIVATE_KEY_<SUFFIX>`, or from a `.env.keys`
  file (never commit `.env.keys`). It is what `decrypt`/`run` use.

Filename → key-variable mapping:

| File              | Public key var               | Private key var               |
| ----------------- | ---------------------------- | ----------------------------- |
| `.env`            | `DOTENV_PUBLIC_KEY`          | `DOTENV_PRIVATE_KEY`          |
| `.env.production` | `DOTENV_PUBLIC_KEY_PRODUCTION` | `DOTENV_PRIVATE_KEY_PRODUCTION` |

Comma-separated private keys are supported (key rotation): decryption tries each
key in turn.

## CLI usage

```text
envx run [flags] -- <command> [args...]
envx encrypt [-f <file>]
envx decrypt --stdout [-f <file>]
```

Flags for `run`:

| Flag                  | Meaning                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------- |
| `-f <file>`           | Load a specific `.env` file (repeatable; later files override earlier ones).             |
| `--overload`          | Let file values override variables already present in the environment.                   |
| `--inject-only k1,k2` | Pass only the named keys into the child env (respects existing env unless `--overload`). |
| `--inject-all-merged` | Pass the full merged dotenv into the child env only, stripping `DOTENV_PRIVATE_KEY*`.    |

### Encrypt a file

```bash
# Generates a key pair on first run: writes DOTENV_PUBLIC_KEY into .env
# and the matching DOTENV_PRIVATE_KEY into .env.keys.
envx encrypt -f .env
```

Values are encrypted in place; comments, blank lines, and ordering are
preserved. Mark a value to stay plaintext with an inline `dotenvx:plain`
directive:

```dotenv
PUBLIC_BASE_URL=https://example.com # dotenvx:plain
```

### Decrypt to stdout

```bash
export DOTENV_PRIVATE_KEY="<base64 key>"   # or keep it in .env.keys
envx decrypt -f .env --stdout
```

### Run a command with secrets injected

```bash
export DOTENV_PRIVATE_KEY="<base64 key>"
envx run -f .env -- ./my-server
```

`run` decrypts in memory and unsets `DOTENV_PRIVATE_KEY*` before launching the
child, so decapsulation material is not handed to the subprocess.

## Library usage

```go
package main

import (
	"log"

	"github.com/osarogie/envx"
)

func main() {
	// Load .env files into os.Environ() (decrypting encrypted_pqc: values).
	// With nil options, files are auto-discovered from DOTENV_PRIVATE_KEY* vars.
	if _, err := envx.Load(&envx.LoadOptions{
		Files:    []string{".env"},
		Overload: false, // existing env vars win unless true
	}); err != nil {
		log.Fatal(err)
	}
}
```

Other useful entry points:

- `envx.MergeDotenvFiles(files)` — merge + decrypt files into a map without
  touching the process environment.
- `envx.EnvironWithMergedOverlay(base, merged, overload)` /
  `envx.EnvironMergedKeys(...)` — build a `[]string` environment for a child
  process (`exec.Cmd.Env`).
- `envx.Encrypt(plaintext, publicKeyB64)` /
  `envx.DecryptIfEncrypted(value, privateKeysB64)` — value-level crypto.
- `envx.GenerateKeypair()` — mint a new ML-KEM-768 key pair.
- `envx.EncryptFile(...)` / `envx.DecryptFile(...)` — file-level operations.

See the [package documentation](https://pkg.go.dev/github.com/osarogie/envx)
for the full API.

## License

[MIT](LICENSE)
