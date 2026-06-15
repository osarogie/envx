# Contributing to envx

Thanks for your interest in improving envx! This is a small, focused library, so
the workflow is light.

## Development setup

You need **Go 1.24 or newer** (the `crypto/mlkem` standard-library package, which
the encryption relies on, is only stable from 1.24).

```bash
git clone https://github.com/osarogie/envx
cd envx
go build ./...
```

There is one external dependency, [`github.com/joho/godotenv`](https://github.com/joho/godotenv),
for parsing. Please keep the dependency footprint minimal — prefer the standard
library where practical.

## Before you open a pull request

Run the same checks CI runs and make sure they pass:

```bash
gofmt -l .          # must print nothing (formatting is enforced)
go vet ./...
go test -race ./...
```

A few conventions:

- **Format with `gofmt`** (or `go fmt ./...`). CI fails on unformatted code.
- **Add a test** for any behavior change. Tests live next to the code as
  `*_test.go` in `package envx` (white-box) and use `t.TempDir()` for file I/O —
  never touch a real `.env` in the repo.
- **Keep the public API small and documented.** Exported identifiers need a doc
  comment. If you add a CLI subcommand, update `usageAndExit` in
  `cmd/envx/main.go` and the README.
- **Match the existing style** — the codebase favors small, single-purpose files
  and explicit error wrapping with `%w`.

## Commit and PR style

- Use clear, imperative commit subjects (e.g. `feat(cli): add list subcommand`,
  `fix: handle CRLF in .env.keys`).
- Keep PRs focused on one change; describe the motivation and how you tested it.

## Security-sensitive code

The crypto lives in `crypto.go` (ML-KEM-768 + AES-256-GCM, FIPS 203). Changes to
the wire format, key handling, or the `encrypted_pqc:` envelope deserve extra
scrutiny:

- Never change the wire format without bumping `pqcWireVersion` and keeping the
  decryptor able to read older payloads.
- **Never commit real secrets or `.env.keys`.** Use synthetic values in tests and
  examples. If you find a security issue, please report it privately to the
  maintainer rather than opening a public issue.

## Releases

Releases are cut by the maintainer with a semver tag (`vMAJOR.MINOR.PATCH`):

```bash
git tag v0.3.0
git push origin v0.3.0
gh release create v0.3.0 --generate-notes
```

Because consumers import the module by path, breaking changes to exported symbols
require a major-version bump per [Go module versioning](https://go.dev/ref/mod#major-version-suffixes).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
