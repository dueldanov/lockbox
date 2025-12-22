# LockBox retrieveKey (getKey) Function - Verbose Logging Checklist

> Source: Client document "LockBox retrieveKey Logging.docx"
> Date: 2025-12-21

## Overview

This document lists all 200 functions executed during the retrieveKey (getKey) operation. The development team should implement verbose logging at each function call to verify complete execution flow. This is the most complex operation in the LockBox system, involving retrieval + verification across multiple coordinating nodes.

---

## Phase 1: Request Initialization & Token Validation (12 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 1 | `validate_access_token()` | Validates single-use API key | Token hash (not token), validity status |
| 2 | `check_token_nonce()` | Verifies nonce-based auth (5 min window) | Nonce value, timestamp check result |
| 3 | `get_tier_config()` | Retrieves user's tier configuration | Tier level (Basic/Standard/Premium/Elite) |
| 4 | `time.Now()` | Captures request timestamp | Timestamp value |
| 5 | `uuid.New()` | Generates request tracking ID | Request UUID |
| 6 | `context.WithTimeout()` | Creates timeout context for operation | Timeout duration |
| 7 | `context.Background()` | Creates background context | Context created |
| 8 | `runtime.NumCPU()` | Gets available CPU cores | Core count |
| 9 | `calculateGoroutineLimit()` | Calculates concurrent goroutine limit | Calculated limit (5-100) |
| 10 | `len()` | Gets length of request data | Data length |
| 11 | `crypto/rand.Read()` | Generates challenge nonce | Bytes generated (count only) |
| 12 | `base64.StdEncoding.EncodeToString()` | Encodes challenge for transmission | Encoding success |

---

## Phase 2: Payment Transaction Processing (18 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 13 | `validate_payment_tx()` | Validates payment transaction bytes | Payment type (LockBox/native token) |
| 14 | `parse_payment_tx()` | Parses payment transaction structure | Transaction format valid |
| 15 | `verify_payment_signature()` | Verifies payment transaction signature | Signature validity |
| 16 | `crypto/ed25519.Verify()` | Verifies Ed25519 signature on payment | Verification result |
| 17 | `calculate_retrieval_fee()` | Calculates tier-based retrieval fee | Fee amount, currency |
| 18 | `verify_payment_amount()` | Confirms payment meets requirement | Amount sufficient |
| 19 | `LockScript.signPayment()` | Signs payment with user key | Signature generated |
| 20 | `submit_payment_tx()` | Submits payment to blockchain/ledger | Transaction hash |
| 21 | `wait_payment_confirmation()` | Waits for payment confirmation | Confirmation status |
| 22 | `iota.SubmitMessage()` | Submits payment to DAG ledger | Message ID |
| 23 | `http.NewRequest()` | Creates HTTP request for bridge/oracle | Request method, endpoint |
| 24 | `http.Client.Do()` | Executes payment verification request | Response status code |
| 25 | `json.Unmarshal()` | Parses payment confirmation response | Parse success |
| 26 | `verify_ledger_tx()` | Verifies LedgerTx confirmation | Ledger entry confirmed |
| 27 | `record_revenue_share()` | Records B2B revenue share | Provider ID, share amount |
| 28 | `calculate_provider_share()` | Calculates 50% revenue share | Share calculated |
| 29 | `update_revenue_ledger()` | Updates provider revenue ledger | Ledger updated |
| 30 | `fmt.Sprintf()` | Formats payment confirmation message | Format success |

---

## Phase 3: ZKP Generation & Ownership Proof (16 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 31 | `generate_ownership_zkp()` | Generates ZKP proving key ownership | Proof type, tier complexity |
| 32 | `generate_nonce()` | Creates unique nonce for ZKP | Nonce generated |
| 33 | `gnark.Compile()` | Compiles ZKP circuit | Circuit compilation success |
| 34 | `gnark.Setup()` | Performs ZKP trusted setup | Setup completion |
| 35 | `gnark.Prove()` | Generates zk-STARK ownership proof | Proof generation success |
| 36 | `frontend.Compile()` | Compiles frontend circuit | Frontend compilation success |
| 37 | `hash.Hash.Write()` | Writes to hash for proof | Bytes written |
| 38 | `hash.Hash.Sum()` | Finalizes hash for proof | Hash finalized |
| 39 | `derive_proof_key()` | Derives key for proof generation | Key derivation success |
| 40 | `incorporate_challenge()` | Incorporates server challenge in proof | Challenge incorporated |
| 41 | `argon2id.Key()` | Derives master key from passphrase | Key derivation success |
| 42 | `serialize_proof()` | Serializes ZKP for transmission | Serialization success |
| 43 | `json.Marshal()` | Serializes proof to JSON | JSON created |
| 44 | `bytes.NewBuffer()` | Creates buffer for proof data | Buffer created |
| 45 | `io.Copy()` | Copies proof data | Bytes copied |
| 46 | `sha256.Sum256()` | Computes hash of proof | Hash computed |

---

## Phase 4: Multi-Signature Verification (Premium/Elite) (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 47 | `check_multisig_required()` | Checks if multi-sig enabled | Multi-sig status |
| 48 | `get_multisig_config()` | Gets m-of-n configuration | Required signatures count |
| 49 | `collect_signer_proofs()` | Collects proofs from signers | Signatures collected count |
| 50 | `verify_threshold_zkp()` | Validates threshold signatures | Threshold met |
| 51 | `aggregate_signatures()` | Aggregates multi-sig proofs | Aggregation success |
| 52 | `validate_signer_identity()` | Validates each signer's identity | Signer verified |
| 53 | `check_signer_authorization()` | Verifies signer has authority | Authorization confirmed |
| 54 | `verify_signature_freshness()` | Checks signature timestamps | Signatures fresh |
| 55 | `compute_aggregate_hash()` | Computes aggregate proof hash | Hash computed |
| 56 | `gnark.Verify()` | Verifies aggregated ZKP | Verification result |

---

## Phase 5: Dual Coordinating Node Selection (14 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 57 | `select_primary_coordinator()` | Randomly selects primary node | Primary node ID |
| 58 | `select_secondary_coordinator()` | Randomly selects secondary node | Secondary node ID |
| 59 | `verify_coordinator_eligibility()` | Confirms nodes can coordinate | Eligibility status |
| 60 | `check_node_reliability()` | Verifies >95% reliability score | Reliability score |
| 61 | `check_geographic_separation()` | Ensures nodes >1000km apart | Distance verified |
| 62 | `verify_no_shard_storage()` | Confirms coordinator has no shards | No shards stored |
| 63 | `establish_coordinator_channel()` | Opens secure channel to coordinator | Channel established |
| 64 | `tls.Config{}` | Configures TLS 1.3 for channel | TLS configured |
| 65 | `x509.ParseCertificate()` | Parses node certificate | Certificate valid |
| 66 | `net.Dial()` | Establishes network connection | Connection established |
| 67 | `mutual_tls_handshake()` | Performs mutual TLS auth | Handshake complete |
| 68 | `send_retrieval_request()` | Sends request to primary | Request sent |
| 69 | `send_oversight_request()` | Sends request to secondary | Oversight request sent |
| 70 | `sync.WaitGroup.Add()` | Adds coordinator tasks to wait group | Tasks added |

---

## Phase 6: Triple Verification Node Selection & Validation (20 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 71 | `select_verification_nodes()` | Selects 3 geographically diverse nodes | Node IDs selected |
| 72 | `verify_geographic_diversity()` | Confirms >1000km separation | Diversity confirmed |
| 73 | `check_node_uptime()` | Verifies >95% reliability | Uptime scores |
| 74 | `ensure_no_direct_comms()` | Confirms no direct communication | Isolation verified |
| 75 | `distribute_verification_request()` | Sends request to 3 nodes | Requests distributed |
| 76 | `verify_zkp_validity()` | Each node verifies ZKP | ZKP valid (per node) |
| 77 | `verify_payment_confirmation()` | Each node confirms payment | Payment confirmed (per node) |
| 78 | `verify_access_token_auth()` | Each node checks token | Token valid (per node) |
| 79 | `verify_user_tier_auth()` | Each node checks tier access | Tier authorized (per node) |
| 80 | `verify_shard_authenticity()` | Each node validates shard integrity | Shards authentic (per node) |
| 81 | `crypto/ed25519.Sign()` | Each node signs approval | Signature created (per node) |
| 82 | `collect_node_signatures()` | Collects Ed25519 signatures | 3 signatures collected |
| 83 | `aggregate_verifications()` | Primary aggregates approvals | Aggregation complete |
| 84 | `validate_aggregated_sigs()` | Validates all 3 signatures | All signatures valid |
| 85 | `secondary_validate_aggregation()` | Secondary confirms aggregation | Secondary approval |
| 86 | `check_coordinator_consensus()` | Confirms primary/secondary agree | Consensus reached |
| 87 | `handle_disagreement()` | Handles coordinator disagreement | Rejection reason if applicable |
| 88 | `crypto/ed25519.Verify()` | Verifies each node signature | Verification per signature |
| 89 | `bytes.Equal()` | Compares signature data | Comparison result |
| 90 | `time.Since()` | Measures verification duration | Duration in ms |

---

## Phase 7: Bundle & Metadata Retrieval (18 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 91 | `fetch_main_tx()` | Fetches main transaction from DAG | Transaction ID, fetch success |
| 92 | `iota.GetMessage()` | Gets message from IOTA DAG | Message retrieved |
| 93 | `parse_bundle_metadata()` | Parses encrypted bundle metadata | Metadata structure valid |
| 94 | `extract_salt()` | Extracts 32-byte salt from metadata | Salt extracted |
| 95 | `AES256GCMDecrypt()` | Decrypts metadata with master key | Decryption success |
| 96 | `crypto/aes.NewCipher()` | Creates AES cipher for decryption | Cipher created |
| 97 | `crypto/cipher.NewGCM()` | Creates GCM mode for decryption | GCM initialized |
| 98 | `crypto/cipher.GCM.Open()` | Performs authenticated decryption | Decryption success |
| 99 | `json.Unmarshal()` | Parses decrypted metadata JSON | JSON parsed |
| 100 | `validate_metadata_integrity()` | Validates metadata HMAC | HMAC valid |
| 101 | `hmac.New()` | Creates HMAC instance | HMAC created |
| 102 | `hmac.Equal()` | Compares HMAC values | HMAC match |
| 103 | `extract_shard_ids()` | Extracts shard transaction IDs | Shard count extracted |
| 104 | `extract_total_char_count()` | Gets total character count | Total count |
| 105 | `extract_real_char_count()` | Gets real character count | Real count |
| 106 | `extract_geographic_tags()` | Gets shard location tags | Geographic tags |
| 107 | `extract_zkp_hashes()` | Gets ZKP verification hashes | ZKP hashes |
| 108 | `strings.Split()` | Splits metadata fields | Fields parsed |

---

## Phase 8: Parallel Shard Fetching (22 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 109 | `initiate_parallel_fetch()` | Starts parallel shard retrieval | Goroutines launched |
| 110 | `sync.WaitGroup.Add()` | Adds shard fetch tasks | Tasks added |
| 111 | `go fetch_shard()` | Launches goroutine per shard | Goroutine started |
| 112 | `fetch_shard()` | Fetches individual shard from DAG | Shard ID, fetch status |
| 113 | `iota.GetMessage()` | Gets shard message from DAG | Message retrieved |
| 114 | `retry_fetch_shard()` | Retries on failure (3 attempts) | Attempt number, backoff |
| 115 | `calculate_backoff()` | Calculates exponential backoff | Backoff duration (100ms, 200ms, 400ms) |
| 116 | `time.Sleep()` | Waits for backoff period | Sleep duration |
| 117 | `context.WithTimeout()` | Creates 5s timeout per shard | Timeout set |
| 118 | `check_shard_availability()` | Verifies shard exists | Shard available |
| 119 | `select_optimal_node()` | Selects fastest node for shard | Node selected |
| 120 | `http.NewRequest()` | Creates fetch request | Request created |
| 121 | `http.Client.Do()` | Executes fetch request | Response status |
| 122 | `io.ReadFull()` | Reads complete shard data | Bytes read |
| 123 | `validate_shard_integrity()` | Validates shard ZKP | Integrity valid |
| 124 | `gnark.Verify()` | Verifies shard ZKP proof | ZKP valid |
| 125 | `collect_fetched_shards()` | Collects shards into array | Shards collected count |
| 126 | `sync.WaitGroup.Wait()` | Waits for all fetches | All fetches complete |
| 127 | `handle_fetch_failures()` | Handles failed fetches identically | Failures handled (decoy-safe) |
| 128 | `access_redundant_copy()` | Accesses backup shard copy | Backup retrieved |
| 129 | `append()` | Appends shard to collection | Shard appended |
| 130 | `make()` | Allocates shard collection | Collection allocated |

---

## Phase 9: Key Derivation for Decryption (12 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 131 | `DeriveHKDFKey()` | Derives decryption keys via HKDF | Purpose parameter |
| 132 | `hkdf.New()` | Initializes HKDF instance | Hash function used |
| 133 | `sha256.New()` | Creates SHA-256 hash instance | Instance created |
| 134 | `hkdf.Expand()` | Expands key material | Output length |
| 135 | `derive_real_char_keys()` | Derives keys for real chars (numeric index) | Key count derived |
| 136 | `construct_info_param()` | Constructs HKDF info (LockBox:real-char:N) | Info string |
| 137 | `incorporate_salt()` | Uses bundle salt in derivation | Salt incorporated |
| 138 | `base64.StdEncoding.DecodeString()` | Decodes salt from metadata | Salt decoded |
| 139 | `strconv.Itoa()` | Converts index to string | Index converted |
| 140 | `strings.Join()` | Joins info components | Info joined |
| 141 | `copy()` | Copies key material | Bytes copied |
| 142 | `fmt.Sprintf()` | Formats key derivation info | Format success |

---

## Phase 10: Shard Decryption & Real Character Identification (18 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 143 | `iterate_decrypt_shards()` | Iterates through all shards | Total iterations |
| 144 | `try_decrypt_with_key()` | Attempts decryption with derived key | Decryption attempt result |
| 145 | `AES256GCMDecrypt()` | Decrypts shard with AES-256-GCM | Decryption success/fail |
| 146 | `crypto/cipher.GCM.Open()` | Performs authenticated decryption | Auth tag valid |
| 147 | `identify_real_shard()` | Identifies successful decryption as real | Real shard found |
| 148 | `validate_hmac_signature()` | Validates real shard HMAC | HMAC valid (real) |
| 149 | `hmac.New()` | Creates HMAC for validation | HMAC instance created |
| 150 | `hmac.Equal()` | Compares shard HMAC | Match result |
| 151 | `discard_decoy_shard()` | Silently discards failed decryptions | Decoy discarded |
| 152 | `extract_character()` | Extracts decrypted character | Character extracted |
| 153 | `extract_position()` | Extracts character position | Position value |
| 154 | `verify_position_proof()` | Validates position proof | Position verified |
| 155 | `filter_real_chars()` | Filters real from decoy chars | Real chars filtered |
| 156 | `count_real_chars()` | Counts identified real chars | Count matches expected |
| 157 | `string()` | Converts bytes to character | Conversion success |
| 158 | `append()` | Appends real char to collection | Char appended |
| 159 | `int()` | Converts position to int | Conversion success |
| 160 | `make()` | Allocates character array | Array allocated |

---

## Phase 11: Key Reconstruction (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 161 | `order_characters()` | Orders chars by position | Characters ordered |
| 162 | `sort.Slice()` | Sorts character slice | Sort complete |
| 163 | `verify_position_sequence()` | Verifies continuous sequence | Sequence valid |
| 164 | `assemble_chars()` | Assembles final private key | Key assembled |
| 165 | `strings.Builder.WriteString()` | Builds key string | String built |
| 166 | `strings.Builder.String()` | Gets final key string | Key string retrieved |
| 167 | `validate_key_length()` | Validates reconstructed key length | Length matches expected |
| 168 | `verify_reconstruction_success()` | Confirms successful reconstruction | Reconstruction verified |
| 169 | `compute_key_checksum()` | Computes checksum for verification | Checksum computed |
| 170 | `len()` | Gets final key length | Key length |

---

## Phase 12: Token Rotation (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 171 | `generate_new_access_token()` | Generates new single-use token | New token generated |
| 172 | `crypto/rand.Read()` | Generates random token bytes | Bytes generated |
| 173 | `encrypt_new_token()` | Encrypts token with SEK | Token encrypted |
| 174 | `AES256GCMEncrypt()` | Performs token encryption | Encryption success |
| 175 | `invalidate_old_token()` | Invalidates used token | Old token invalidated |
| 176 | `store_token_mapping()` | Stores new token in wallet DB | Token stored |
| 177 | `commit_token_rotation()` | Two-phase commit for rotation | Rotation committed |
| 178 | `LedgerTx.Commit()` | Commits to ledger | Ledger commit success |

---

## Phase 13: Memory Security & Cleanup (14 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 179 | `secureWipe()` | Securely zeros all sensitive data | Bytes wiped |
| 180 | `clear_shard_memory()` | Clears shard data from memory | Shards cleared |
| 181 | `clear_decoy_data()` | Clears decoy data from memory | Decoys cleared |
| 182 | `clear_derived_keys()` | Clears derived encryption keys | Keys cleared |
| 183 | `clear_metadata_buffers()` | Clears metadata buffers | Buffers cleared |
| 184 | `runtime.GC()` | Forces garbage collection | GC triggered |
| 185 | `runtime.KeepAlive()` | Prevents premature GC during use | Keep-alive applied |
| 186 | `MonitorMemoryUsage()` | Monitors memory allocation | Current memory usage |
| 187 | `tryLockMemory()` | Locks memory pages (prevent swap) | Lock success/failure |
| 188 | `syscall.Syscall()` | Direct system call for mlock | Syscall result |
| 189 | `os.Getpagesize()` | Gets system page size | Page size |
| 190 | `unsafe.Pointer()` | Creates unsafe pointer for wipe | Pointer operation |
| 191 | `reflect.ValueOf()` | Gets reflection value for wipe | Type inspected |
| 192 | `runtime.SetFinalizer()` | Sets cleanup finalizer | Finalizer registered |

---

## Phase 14: Error Handling & Audit Logging (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 193 | `errors.New()` | Creates new error | Error message |
| 194 | `fmt.Errorf()` | Formats error with context | Error details |
| 195 | `log.Printf()` | Prints formatted log | Log message |
| 196 | `create_log_entry()` | Creates audit log entry | Entry type, timestamp |
| 197 | `encrypt_log()` | Encrypts log entry | Encryption success |
| 198 | `anchor_log()` | Anchors log to blockchain (Premium/Elite) | Anchor TX ID |
| 199 | `time.RFC3339()` | Formats timestamp | Timestamp string |
| 200 | `os.OpenFile()` | Opens file for logging | File path, mode |

---

## Critical Logging Points

### Security Alerts (Must Log)

The system **must trigger alerts** whenever:
- ZKP verification fails at any node
- Payment verification fails
- Access token validation fails
- Shard decryption fails unexpectedly (not normal decoy discard)
- Coordinator disagreement occurs
- Memory locking fails on sensitive data
- Triple verification consensus fails

### Recommended Log Format

```go
type LockBoxLogEntry struct {
    Timestamp     time.Time `json:"timestamp"`
    Phase         string    `json:"phase"`
    Function      string    `json:"function"`
    Status        string    `json:"status"` // SUCCESS, FAILURE, WARNING
    Duration      int64     `json:"duration_ns"`
    Details       string    `json:"details"` // Non-sensitive context
    BundleID      string    `json:"bundle_id"`
    RequestID     string    `json:"request_id"`
    CoordinatorID string    `json:"coordinator_id,omitempty"`
    VerifierCount int       `json:"verifier_count,omitempty"`
}
```

### Error Structure (Per Requirements)

```go
type LockBoxError struct {
    Code        string    // Machine-readable: ACCESS_DENIED, PROOF_INVALID, TOKEN_INVALID, etc.
    Message     string    // Human-readable description
    Details     string    // Optional context (non-sensitive)
    Severity    string    // "CRITICAL", "WARNING", or "INFO"
    Recoverable bool      // Whether automatic recovery is possible
    RetryAfter  int       // Suggested retry delay in seconds
    Component   string    // Which component generated the error
    Timestamp   time.Time // When the error occurred
}
```

### Log Placement Reminder

Per architecture: **All error logging occurs exclusively in wallet software** - not on SecureHornet nodes. Ensure verbose logging is implemented in:
- Firefly wallet rewrite
- B2B SDK implementations
- Chrome extension (WASM)

### Decoy Security Warning

When logging shard operations, **NEVER** log information that could distinguish real shards from decoys:
- Log all shard fetch attempts identically
- Log all decryption attempts identically (success/fail only)
- Handle real and decoy failures the same way in logs

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total Functions** | **200** |
| Request Initialization | 12 |
| Payment Processing | 18 |
| ZKP & Ownership | 16 |
| Multi-Signature | 10 |
| Coordinator Selection | 14 |
| Triple Verification | 20 |
| Bundle/Metadata Retrieval | 18 |
| Parallel Shard Fetching | 22 |
| Key Derivation | 12 |
| Shard Decryption | 18 |
| Key Reconstruction | 10 |
| Token Rotation | 8 |
| Memory Security | 14 |
| Error/Logging | 8 |
