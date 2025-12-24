// Package main provides a CLI tool for testing LockScript functionality
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dueldanov/lockbox/v2/internal/lockscript"
)

func main() {
	// Command flags
	storeKey := flag.String("store", "", "Store a key with format: key:tier (e.g., 'my-secret:Standard')")
	getKey := flag.String("get", "", "Get a key with format: bundleId:token")
	rotate := flag.String("rotate", "", "Rotate a key with format: bundleId:token")
	deriveKey := flag.String("derive", "", "Derive a key with format: purpose:index (e.g., 'shard:0')")
	registerUser := flag.String("register", "", "Register username with format: username:address")
	resolveUser := flag.String("resolve", "", "Resolve username to address")
	listFunctions := flag.Bool("list", false, "List all available LockScript functions")
	interactive := flag.Bool("i", false, "Interactive mode")
	jsonOutput := flag.Bool("json", false, "Output results as JSON")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "LockScript Test Tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -store 'my-secret-key:Standard'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -get 'bundleId:token'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -rotate 'bundleId:token'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -derive 'shard-encrypt:0'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -register 'alice:iota1abc123'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -resolve 'alice'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -list\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -i\n", os.Args[0])
	}

	flag.Parse()

	// Output helper
	output := func(result interface{}, err error) {
		if err != nil {
			if *jsonOutput {
				j, _ := json.Marshal(map[string]string{"error": err.Error()})
				fmt.Println(string(j))
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(1)
		}

		if *jsonOutput {
			j, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(j))
		} else {
			switch v := result.(type) {
			case map[string]interface{}:
				for k, val := range v {
					fmt.Printf("%s: %v\n", k, val)
				}
			default:
				fmt.Println(result)
			}
		}
	}

	// Handle commands
	switch {
	case *listFunctions:
		listAvailableFunctions()
		return

	case *interactive:
		runInteractive()
		return

	case *storeKey != "":
		parts := strings.SplitN(*storeKey, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Error: -store requires format 'key:tier'\n")
			os.Exit(1)
		}
		result, err := lockscript.FuncStoreKeyExported([]interface{}{parts[0], parts[1]})
		output(result, err)

	case *getKey != "":
		parts := strings.SplitN(*getKey, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Error: -get requires format 'bundleId:token'\n")
			os.Exit(1)
		}
		result, err := lockscript.FuncGetKeyExported([]interface{}{parts[0], parts[1]})
		output(result, err)

	case *rotate != "":
		parts := strings.SplitN(*rotate, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Error: -rotate requires format 'bundleId:token'\n")
			os.Exit(1)
		}
		result, err := lockscript.FuncRotateExported([]interface{}{parts[0], parts[1]})
		output(result, err)

	case *deriveKey != "":
		parts := strings.SplitN(*deriveKey, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Error: -derive requires format 'purpose:index'\n")
			os.Exit(1)
		}
		var index int64
		fmt.Sscanf(parts[1], "%d", &index)
		result, err := lockscript.FuncDeriveKeyExported([]interface{}{parts[0], index})
		output(result, err)

	case *registerUser != "":
		parts := strings.SplitN(*registerUser, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Error: -register requires format 'username:address'\n")
			os.Exit(1)
		}
		result, err := lockscript.FuncRegisterUsernameExported([]interface{}{parts[0], parts[1]})
		output(result, err)

	case *resolveUser != "":
		result, err := lockscript.FuncResolveUsernameExported([]interface{}{*resolveUser})
		output(result, err)

	default:
		flag.Usage()
	}
}

func listAvailableFunctions() {
	fmt.Println("Available LockScript Functions:")
	fmt.Println()
	fmt.Println("Time Functions:")
	fmt.Println("  now()                    - Returns current Unix timestamp")
	fmt.Println("  after(timestamp)         - Returns true if current time > timestamp")
	fmt.Println("  before(timestamp)        - Returns true if current time < timestamp")
	fmt.Println()
	fmt.Println("Crypto Functions:")
	fmt.Println("  sha256(data)             - Returns SHA256 hash of data")
	fmt.Println("  verify_sig(pk, msg, sig) - Verifies Ed25519 signature")
	fmt.Println("  require_sigs(sigs, n)    - Requires n valid signatures")
	fmt.Println()
	fmt.Println("Key Operations:")
	fmt.Println("  storeKey(key, tier)      - Stores key with security tier (Basic/Standard/Premium/Elite)")
	fmt.Println("  getKey(bundleId, token)  - Retrieves stored key")
	fmt.Println("  rotate(bundleId, token)  - Rotates key with new encryption")
	fmt.Println("  deriveKey(purpose, idx)  - Derives HKDF key for purpose")
	fmt.Println()
	fmt.Println("Username Operations:")
	fmt.Println("  registerUsername(name, addr) - Registers username to address")
	fmt.Println("  resolveUsername(name)        - Resolves username to address")
	fmt.Println()
	fmt.Println("Utility Functions:")
	fmt.Println("  check_geo(region)        - Checks if region is valid")
	fmt.Println("  min(a, b, ...)           - Returns minimum value")
	fmt.Println("  max(a, b, ...)           - Returns maximum value")
}

func runInteractive() {
	fmt.Println("LockScript Interactive Mode")
	fmt.Println("Type 'help' for commands, 'quit' to exit")
	fmt.Println()

	var input string
	for {
		fmt.Print("lockscript> ")
		_, err := fmt.Scanln(&input)
		if err != nil {
			continue
		}

		input = strings.TrimSpace(input)

		switch input {
		case "quit", "exit", "q":
			fmt.Println("Goodbye!")
			return
		case "help", "h":
			fmt.Println("Commands:")
			fmt.Println("  store <key> <tier>     - Store a key")
			fmt.Println("  get <bundleId> <token> - Get a key")
			fmt.Println("  rotate <bundleId> <token> - Rotate a key")
			fmt.Println("  derive <purpose> <index> - Derive a key")
			fmt.Println("  register <name> <addr> - Register username")
			fmt.Println("  resolve <name>         - Resolve username")
			fmt.Println("  list                   - List functions")
			fmt.Println("  quit                   - Exit")
		case "list":
			listAvailableFunctions()
		default:
			fmt.Println("Unknown command. Type 'help' for available commands.")
		}
	}
}
