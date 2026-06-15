package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/osarogie/envx"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usageAndExit(2)
	}

	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "encrypt":
		encryptCmd(os.Args[2:])
	case "decrypt":
		decryptCmd(os.Args[2:])
	case "-h", "--help", "help":
		usageAndExit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usageAndExit(2)
	}
}

func usageAndExit(code int) {
	fmt.Fprintln(os.Stderr, "envx")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  envx run [flags] -- <command> [args...]")
	fmt.Fprintln(os.Stderr, "  envx encrypt [-f <file>]")
	fmt.Fprintln(os.Stderr, "  envx decrypt --stdout [-f <file>]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  -f <file>        load a specific .env file (repeatable)")
	fmt.Fprintln(os.Stderr, "  --overload       override existing environment variables")
	fmt.Fprintln(os.Stderr, "  --inject-only k  comma-separated keys merged into the child; respects existing env unless --overload")
	fmt.Fprintln(os.Stderr, "  --inject-all-merged  merge dotenv into child env only; strip DOTENV_PRIVATE_KEY* (workers / asynqmon)")
	fmt.Fprintln(os.Stderr, "")
	os.Exit(code)
}

func runCmd(args []string) {
	cmdIdx := indexOf(args, "--")
	if cmdIdx == -1 {
		fmt.Fprintln(os.Stderr, "missing `--` before command")
		os.Exit(2)
	}
	flagArgs := args[:cmdIdx]
	cmdArgs := args[cmdIdx+1:]
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "missing command after `--`")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var files multiFlag
	var overload bool
	var injectOnly string
	var injectAllMerged bool
	fs.Var(&files, "f", "dotenv file path (repeatable)")
	fs.BoolVar(&overload, "overload", false, "override existing environment variables")
	fs.StringVar(&injectOnly, "inject-only", "", "comma-separated keys to pass from merged files to the child env only (no full process Load)")
	fs.BoolVar(&injectAllMerged, "inject-all-merged", false, "pass merged dotenv into the child env only (strip DOTENV_PRIVATE_KEY*); use for workers/UI")

	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(2)
	}
	if injectAllMerged && strings.TrimSpace(injectOnly) != "" {
		fmt.Fprintln(os.Stderr, "envx: use only one of --inject-only or --inject-all-merged")
		os.Exit(2)
	}

	loadFiles := []string(files)
	if len(loadFiles) == 0 {
		loadFiles = envx.FilesFromPrivateKeys(os.Environ())
		if len(loadFiles) == 0 {
			loadFiles = []string{".env"}
		}
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if strings.TrimSpace(injectOnly) != "" {
		merged, err := envx.MergeDotenvFiles(loadFiles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "envx: %v\n", err)
			os.Exit(1)
		}
		envx.UnsetDotenvPrivateKeysFromEnv()
		keys := splitCommaKeys(injectOnly)
		cmd.Env = envx.EnvironMergedKeys(os.Environ(), merged, keys, overload)
	} else if injectAllMerged {
		merged, err := envx.MergeDotenvFiles(loadFiles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "envx: %v\n", err)
			os.Exit(1)
		}
		envx.UnsetDotenvPrivateKeysFromEnv()
		cmd.Env = envx.EnvironWithMergedOverlay(os.Environ(), merged, overload)
	} else {
		_, err := envx.Load(&envx.LoadOptions{
			Files:    loadFiles,
			Overload: overload,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "envx: %v\n", err)
			os.Exit(1)
		}
		cmd.Env = os.Environ()
	}

	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "envx: %v\n", err)
		os.Exit(1)
	}
}

func splitCommaKeys(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func indexOf(ss []string, target string) int {
	for i, s := range ss {
		if s == target {
			return i
		}
	}
	return -1
}

func encryptCmd(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var file string
	fs.StringVar(&file, "f", ".env", "dotenv file path")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if err := envx.EncryptFile(envx.EncryptFileOptions{File: file}); err != nil {
		fmt.Fprintf(os.Stderr, "envx: %v\n", err)
		os.Exit(1)
	}
}

func decryptCmd(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var file string
	var stdout bool
	fs.StringVar(&file, "f", ".env", "dotenv file path")
	fs.BoolVar(&stdout, "stdout", false, "write decrypted contents to stdout")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if !stdout {
		fmt.Fprintln(os.Stderr, "missing required flag: --stdout")
		os.Exit(2)
	}

	values, err := envx.DecryptFile(envx.DecryptFileOptions{File: file})
	if err != nil {
		fmt.Fprintf(os.Stderr, "envx: %v\n", err)
		os.Exit(1)
	}

	// Print a normalized dotenv to stdout.
	// This is intended for piping and inspection (similar to `dotenvx decrypt --stdout`).
	for _, kv := range dotenvLines(values) {
		fmt.Fprintln(os.Stdout, kv)
	}
}

func dotenvLines(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		v := values[k]
		out = append(out, fmt.Sprintf("%s=%q", k, v))
	}
	return out
}
