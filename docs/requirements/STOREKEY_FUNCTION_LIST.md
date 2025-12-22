# LockBox storeKey Function - Verbose Logging Checklist

> Source: Client document "LockBox storeKey Function List Logging.docx"
> Date: 2025-12-21

## Overview

This document lists all 100 functions executed during the storeKey operation. The development team should implement verbose logging at each function call to verify complete execution flow.

---

## Phase 1: Input Validation & Configuration (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 1 | `validate_length()` | Validates private key length (max 256 chars) | Input length, pass/fail status |
| 2 | `set_tier_config()` | Sets tier-specific configuration | Tier level, decoy ratio applied |
| 3 | `get_tier_ratio()` | Retrieves decoy ratio for user tier | Ratio value (0.5x-2x) |
| 4 | `generate_bundle_id()` | Creates unique transaction bundle ID | Generated bundle ID |
| 5 | `runtime.NumCPU()` | Gets available CPU cores | Core count |
| 6 | `calculateGoroutineLimit()` | Calculates concurrent goroutine limit | Calculated limit (5-100) |
| 7 | `time.Now()` | Captures current timestamp | Timestamp value |
| 8 | `uuid.New()` | Generates UUID for tracking | UUID value |
| 9 | `len()` | Gets length of key/data structures | Length value |
| 10 | `crypto/rand.Read()` | Generates cryptographic random bytes | Bytes generated (count only) |

---

## Phase 2: Key Derivation (6 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 11 | `DeriveHKDFKey()` | Derives encryption keys via HKDF | Purpose parameter (real-char/decoy-char) |
| 12 | `hkdf.New()` | Initializes HKDF instance | Hash function used |
| 13 | `sha256.New()` | Creates SHA-256 hash instance | Instance creation success |
| 14 | `hkdf.Expand()` | Expands key material | Output length |
| 15 | `base64.StdEncoding.EncodeToString()` | Encodes bytes to base64 | Encoding success |
| 16 | `derive_key()` | Derives individual shard encryption key | Shard index, purpose |

---

## Phase 3: Encryption Operations (9 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 17 | `AES256GCMEncrypt()` | Primary AES-256-GCM encryption | Data type encrypted |
| 18 | `crypto/aes.NewCipher()` | Creates AES cipher block | Cipher creation success |
| 19 | `crypto/cipher.NewGCM()` | Creates GCM mode instance | GCM initialization success |
| 20 | `crypto/cipher.GCM.Seal()` | Performs authenticated encryption | Ciphertext length |
| 21 | `hmac.New()` | Creates HMAC instance | Hash function used |
| 22 | `hmac.Sum()` | Computes HMAC value | HMAC computation success |
| 23 | `sha256.Sum256()` | Computes SHA-256 hash | Hash computation success |
| 24 | `encrypt_chars()` | Encrypts character array | Character count encrypted |
| 25 | `encrypt_log()` | Encrypts audit log entry | Log encryption success |

---

## Phase 4: Digital Signatures (3 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 26 | `crypto/ed25519.GenerateKey()` | Generates Ed25519 keypair | Key generation success |
| 27 | `crypto/ed25519.Sign()` | Signs data with Ed25519 | Signature creation success |
| 28 | `bytes.Equal()` | Compares byte slices | Comparison result |

---

## Phase 5: Character Sharding & Decoy Generation (14 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 29 | `splitKeyWithKeysAndDecoys()` | Main sharding function | Total shards created |
| 30 | `to_char_array()` | Converts key to character array | Character count |
| 31 | `create_decoys()` | Generates decoy characters | Decoy count, ratio |
| 32 | `math.Floor()` | Calculates decoy quantities | Calculation result |
| 33 | `generate_random_chars()` | Creates random decoy characters | Characters generated |
| 34 | `crypto/rand.Int()` | Generates cryptographic random int | Generation success |
| 35 | `shuffle()` | Randomizes shard order | Shuffle execution success |
| 36 | `rand.Seed()` | Seeds random number generator | Seed applied |
| 37 | `rand.Shuffle()` | Performs Fisher-Yates shuffle | Shuffle complete |
| 38 | `append()` | Appends to slices | Elements appended |
| 39 | `copy()` | Copies byte slices | Bytes copied |
| 40 | `make()` | Allocates slices/maps | Allocation size |
| 41 | `create_shard()` | Creates individual shard structure | Shard index, type (real/decoy) |
| 42 | `string()` | Converts bytes to string | Conversion success |

---

## Phase 6: Zero-Knowledge Proof Generation (7 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 43 | `generate_zkp()` | Main ZKP generation | Proof type, tier level |
| 44 | `gnark.Compile()` | Compiles ZKP circuit | Circuit compilation success |
| 45 | `gnark.Setup()` | Performs trusted setup | Setup completion |
| 46 | `gnark.Prove()` | Generates zk-STARK proof | Proof generation success |
| 47 | `gnark.Verify()` | Verifies proof validity | Verification result |
| 48 | `frontend.Compile()` | Compiles frontend circuit | Frontend compilation success |
| 49 | `hash.Hash.Write()` | Writes to hash instance | Bytes written |
| 50 | `hash.Hash.Sum()` | Finalizes hash computation | Hash finalized |

---

## Phase 7: Metadata Creation (16 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 51 | `createMetadataFragmentsWithKey()` | Creates encrypted metadata | Fragment count |
| 52 | `json.Marshal()` | Serializes to JSON | Serialization success |
| 53 | `json.Unmarshal()` | Deserializes JSON | Deserialization success |
| 54 | `json.NewEncoder()` | Creates JSON encoder | Encoder created |
| 55 | `json.NewDecoder()` | Creates JSON decoder | Decoder created |
| 56 | `bytes.NewBuffer()` | Creates byte buffer | Buffer size |
| 57 | `bytes.Buffer.Write()` | Writes to buffer | Bytes written |
| 58 | `io.Copy()` | Copies data between streams | Bytes copied |
| 59 | `io.ReadFull()` | Reads exact byte count | Bytes read |
| 60 | `strconv.Itoa()` | Converts int to string | Conversion success |
| 61 | `strings.Join()` | Joins string slice | Result length |
| 62 | `strings.Split()` | Splits string | Parts created |
| 63 | `fmt.Sprintf()` | Formats string | Format success |
| 64 | `encoding/hex.EncodeToString()` | Hex encodes bytes | Encoding success |
| 65 | `base64.StdEncoding.DecodeString()` | Decodes base64 string | Decoding success |
| 66 | `int()` | Type conversion to int | Conversion success |

---

## Phase 8: Network Submission (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 67 | `SubmitBundle()` | Submits transaction bundle to DAG | Bundle ID, node count |
| 68 | `iota.SubmitMessage()` | Submits IOTA message | Message ID |
| 69 | `iota.NewMessageBuilder()` | Creates message builder | Builder initialized |
| 70 | `iota.WithPayload()` | Attaches payload to message | Payload size |
| 71 | `iota.WithReferences()` | Sets message references | Reference count |
| 72 | `http.NewRequest()` | Creates HTTP request | Request method, endpoint |
| 73 | `http.Client.Do()` | Executes HTTP request | Response status code |
| 74 | `net/url.Parse()` | Parses URL | URL validity |
| 75 | `tls.Config{}` | Configures TLS settings | TLS version |
| 76 | `x509.ParseCertificate()` | Parses X.509 certificate | Certificate validity |

---

## Phase 9: Connection & Synchronization (6 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 77 | `net.Dial()` | Establishes network connection | Connection target, success |
| 78 | `context.WithTimeout()` | Creates timeout context | Timeout duration |
| 79 | `context.Background()` | Creates background context | Context created |
| 80 | `sync.WaitGroup.Add()` | Adds to wait group counter | Delta added |
| 81 | `sync.WaitGroup.Wait()` | Waits for goroutines | Wait complete |
| 82 | `io.WriteString()` | Writes string to writer | Bytes written |

---

## Phase 10: Memory Security (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 83 | `secureWipe()` | Securely zeros sensitive memory | Bytes wiped |
| 84 | `runtime.GC()` | Forces garbage collection | GC triggered |
| 85 | `runtime.KeepAlive()` | Prevents premature GC | Keep-alive applied |
| 86 | `MonitorMemoryUsage()` | Monitors memory allocation | Current memory usage |
| 87 | `tryLockMemory()` | Locks memory pages (prevent swap) | Lock success/failure |
| 88 | `syscall.Syscall()` | Direct system call | Syscall number, result |
| 89 | `os.Getpagesize()` | Gets system page size | Page size |
| 90 | `unsafe.Pointer()` | Creates unsafe pointer | Pointer operation |
| 91 | `reflect.ValueOf()` | Gets reflection value | Type inspected |
| 92 | `runtime.SetFinalizer()` | Sets cleanup finalizer | Finalizer registered |

---

## Phase 11: Error Handling & Audit Logging (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 93 | `errors.New()` | Creates new error | Error message |
| 94 | `fmt.Errorf()` | Formats error with context | Error details |
| 95 | `log.Printf()` | Prints formatted log | Log message |
| 96 | `create_log_entry()` | Creates audit log entry | Entry type, timestamp |
| 97 | `anchor_log()` | Anchors log to blockchain | Anchor transaction ID |
| 98 | `time.RFC3339()` | Formats timestamp | Timestamp string |
| 99 | `os.OpenFile()` | Opens file for logging | File path, mode |
| 100 | `file.Close()` | Closes file handle | Close success |

---

## Critical Logging Points

### Security Alerts (Must Log)

Per the Knowledge Base, the system must trigger an alert whenever:
- Encryption failure occurs during character shard encryption (real or decoy)
- Any cryptographic operation fails
- Memory locking fails on sensitive data

### Recommended Log Format

```go
type LockBoxLogEntry struct {
    Timestamp time.Time `json:"timestamp"`
    Phase     string    `json:"phase"`
    Function  string    `json:"function"`
    Status    string    `json:"status"` // SUCCESS, FAILURE, WARNING
    Duration  int64     `json:"duration_ns"`
    Details   string    `json:"details"` // Non-sensitive context
    BundleID  string    `json:"bundle_id"`
}
```

### Log Placement Reminder

Per architecture: All error logging occurs exclusively in wallet software - not on SecureHornet nodes. Ensure verbose logging is implemented in:
- Firefly wallet rewrite
- B2B SDK implementations
- Chrome extension (WASM)

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total Functions** | **100** |
| Validation & Config | 10 |
| Key Derivation | 6 |
| Encryption | 9 |
| Signatures | 3 |
| Sharding | 14 |
| ZKP | 7 |
| Metadata | 16 |
| Network | 10 |
| Synchronization | 6 |
| Memory Security | 10 |
| Error/Logging | 8 |
