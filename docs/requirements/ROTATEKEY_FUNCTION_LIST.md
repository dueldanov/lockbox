# LockBox rotateKey (rotate_and_reassign) Function - Verbose Logging Checklist

> Source: Client document "LockBox rotateKey Logging.docx"
> Date: 2025-12-21

## Overview

This document lists all 126 functions executed during the rotateKey (rotate_and_reassign) operation. The development team should implement verbose logging at each function call to verify complete execution flow. This operation re-encrypts all shards with fresh keys and redistributes them to new nodes, disrupting long-term attack vectors.

## Rotation Triggers

- **Voluntary:** User-prompted monthly (30 days ±3 days random variation)
- **Mandatory:** System-initiated every 6 months (±7 days random variation)

---

## Phase 1: Request Initialization & Interval Validation (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 1 | `validate_access_token()` | Validates single-use API key | Token hash (not token), validity status |
| 2 | `check_token_nonce()` | Verifies nonce-based auth (5 min window) | Nonce value, timestamp check result |
| 3 | `verify_interval()` | Validates minimum 30-day interval | Days since last rotation |
| 4 | `check_rotation_eligibility()` | Confirms rotation can proceed | Eligibility status |
| 5 | `get_last_rotation_timestamp()` | Gets timestamp of last rotation | Last rotation date |
| 6 | `time.Now()` | Captures current timestamp | Timestamp value |
| 7 | `uuid.New()` | Generates rotation request ID | Request UUID |
| 8 | `context.WithTimeout()` | Creates timeout context | Timeout duration |
| 9 | `context.Background()` | Creates background context | Context created |
| 10 | `calculate_jitter()` | Calculates ±3 day random jitter | Jitter value applied |

---

## Phase 2: Ownership Verification via ZKP (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 11 | `verify_ownership()` | Initiates ownership verification | Verification started |
| 12 | `generate_ownership_zkp()` | Generates ZKP proving key ownership | Proof type: "ownership" |
| 13 | `generate_nonce()` | Creates unique nonce for ZKP | Nonce generated |
| 14 | `gnark.Compile()` | Compiles ZKP circuit | Circuit compilation success |
| 15 | `gnark.Setup()` | Performs ZKP trusted setup | Setup completion |
| 16 | `gnark.Prove()` | Generates zk-STARK ownership proof | Proof generation success |
| 17 | `gnark.Verify()` | Verifies ownership proof | Verification result |
| 18 | `hash.Hash.Write()` | Writes to hash for proof | Bytes written |
| 19 | `hash.Hash.Sum()` | Finalizes hash for proof | Hash finalized |
| 20 | `crypto/ed25519.Verify()` | Verifies signature on proof | Signature valid |

---

## Phase 3: Existing Shard Retrieval (14 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 21 | `fetch_shards()` | Fetches all existing shards | Shard count (real + decoy) |
| 22 | `fetch_main_tx()` | Fetches main transaction from DAG | Transaction ID retrieved |
| 23 | `iota.GetMessage()` | Gets message from IOTA DAG | Message retrieved |
| 24 | `parse_bundle_metadata()` | Parses encrypted bundle metadata | Metadata structure valid |
| 25 | `extract_salt()` | Extracts existing 32-byte salt | Salt extracted |
| 26 | `AES256GCMDecrypt()` | Decrypts metadata with master key | Decryption success |
| 27 | `crypto/aes.NewCipher()` | Creates AES cipher for decryption | Cipher created |
| 28 | `crypto/cipher.NewGCM()` | Creates GCM mode for decryption | GCM initialized |
| 29 | `crypto/cipher.GCM.Open()` | Performs authenticated decryption | Decryption success |
| 30 | `json.Unmarshal()` | Parses decrypted metadata JSON | JSON parsed |
| 31 | `extract_shard_ids()` | Extracts all shard transaction IDs | Shard IDs extracted |
| 32 | `verify_shard_integrity()` | Validates existing shard integrity | Integrity verified |
| 33 | `parallel_fetch_shards()` | Fetches all shards in parallel | All shards retrieved |
| 34 | `sync.WaitGroup.Wait()` | Waits for all fetch operations | Fetch complete |

---

## Phase 4: New Key Generation (12 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 35 | `generate_new_salt()` | Generates new 32-byte random salt | New salt generated |
| 36 | `crypto/rand.Read()` | Generates cryptographic random bytes | Bytes generated (count only) |
| 37 | `derive_new_master_key()` | Derives new encryption master key | Key derivation success |
| 38 | `DeriveHKDFKey()` | Derives new HKDF keys for shards | Purpose parameter |
| 39 | `hkdf.New()` | Initializes HKDF instance | Hash function used |
| 40 | `sha256.New()` | Creates SHA-256 hash instance | Instance created |
| 41 | `hkdf.Expand()` | Expands key material | Output length |
| 42 | `derive_real_char_keys()` | Derives new keys for real chars (numeric) | Key count |
| 43 | `derive_decoy_char_keys()` | Derives new keys for decoys (alphabetic) | Key count |
| 44 | `base64.StdEncoding.EncodeToString()` | Encodes new salt for storage | Encoding success |
| 45 | `strconv.Itoa()` | Converts indices to strings | Conversions count |
| 46 | `strings.Join()` | Joins HKDF info components | Info string created |

---

## Phase 5: Shard Re-Encryption (14 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 47 | `reencrypt_shards()` | Re-encrypts all shards with new keys | Shards re-encrypted count |
| 48 | `decrypt_shard()` | Decrypts shard with old key | Shard decrypted |
| 49 | `AES256GCMDecrypt()` | Decrypts using old AES key | Decryption success |
| 50 | `AES256GCMEncrypt()` | Encrypts with new AES key | Encryption success |
| 51 | `crypto/aes.NewCipher()` | Creates new AES cipher | Cipher created |
| 52 | `crypto/cipher.NewGCM()` | Creates new GCM mode | GCM initialized |
| 53 | `crypto/cipher.GCM.Seal()` | Performs authenticated encryption | Ciphertext length |
| 54 | `generate_new_decoys()` | Generates fresh decoy shards | Decoy count per tier |
| 55 | `encrypt_decoy_shard()` | Encrypts new decoy with new key | Decoy encrypted |
| 56 | `hmac.New()` | Creates HMAC for real shards | HMAC instance created |
| 57 | `hmac.Sum()` | Computes HMAC value | HMAC computed |
| 58 | `generate_shard_zkp()` | Generates new ZKP for each shard | ZKP generated |
| 59 | `gnark.Prove()` | Creates validity proof per shard | Proof created |
| 60 | `append()` | Appends re-encrypted shard to list | Shard appended |

---

## Phase 6: New Node Selection & Geographic Distribution (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 61 | `select_new_nodes()` | Selects new nodes for redistribution | Node count selected |
| 62 | `get_tier_copies()` | Gets tier-specific redundancy (3-10+) | Copy count |
| 63 | `check_geographic_separation()` | Ensures nodes >1000km apart | Geographic diversity confirmed |
| 64 | `verify_node_reliability()` | Verifies >95% reliability score | Reliability scores |
| 65 | `check_shard_cap()` | Ensures <10% shards per node | Cap enforced |
| 66 | `exclude_previous_nodes()` | Excludes nodes from previous rotation | Previous nodes excluded |
| 67 | `calculate_latency_routing()` | Optimizes node selection by latency | Latency scores |
| 68 | `verify_node_capacity()` | Confirms nodes have storage capacity | Capacity confirmed |
| 69 | `randomize_node_selection()` | Adds randomness to node selection | Selection randomized |
| 70 | `create_distribution_plan()` | Creates shard distribution plan | Plan created |

---

## Phase 7: New Shard Submission to DAG (12 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 71 | `assign_shards()` | Assigns shards to selected nodes | Assignment complete |
| 72 | `submit_to_dag()` | Submits new shards to DAG | Submission started |
| 73 | `iota.NewMessageBuilder()` | Creates message builder per shard | Builder initialized |
| 74 | `iota.WithPayload()` | Attaches encrypted payload | Payload size |
| 75 | `iota.WithReferences()` | Sets 3 prior transaction references | References set |
| 76 | `iota.SubmitMessage()` | Submits message to DAG | Message ID |
| 77 | `collect_new_tx_ids()` | Collects new transaction IDs | TX IDs collected |
| 78 | `http.NewRequest()` | Creates HTTP request per node | Request created |
| 79 | `http.Client.Do()` | Executes submission request | Response status |
| 80 | `verify_submission_success()` | Confirms all shards submitted | All submissions confirmed |
| 81 | `tls.Config{}` | Configures TLS 1.3 | TLS configured |
| 82 | `net.Dial()` | Establishes connection to node | Connection established |

---

## Phase 8: Metadata Update & Version Increment (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 83 | `update_metadata()` | Updates bundle metadata | Metadata updated |
| 84 | `increment_version()` | Increments version (v1 → v2) | New version identifier |
| 85 | `create_new_main_tx()` | Creates new main transaction | New main TX ID |
| 86 | `update_shard_references()` | Updates references to new shards | References updated |
| 87 | `update_salt_in_metadata()` | Stores new salt in metadata | Salt updated |
| 88 | `AES256GCMEncrypt()` | Encrypts new metadata | Metadata encrypted |
| 89 | `json.Marshal()` | Serializes metadata to JSON | JSON created |
| 90 | `iota.SubmitMessage()` | Submits new main transaction | Main TX submitted |
| 91 | `generate_new_bundle_id()` | Generates new bundle ID | New bundle ID |
| 92 | `link_versions()` | Links new version to previous | Version chain updated |

---

## Phase 9: Token Rotation (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 93 | `generate_new_access_token()` | Generates new single-use token | New token generated |
| 94 | `crypto/rand.Read()` | Generates random token bytes | Bytes generated |
| 95 | `encrypt_new_token()` | Encrypts token with SEK | Token encrypted |
| 96 | `AES256GCMEncrypt()` | Performs token encryption | Encryption success |
| 97 | `invalidate_old_token()` | Invalidates used token | Old token invalidated |
| 98 | `store_token_mapping()` | Stores new token in wallet DB | Token stored |
| 99 | `commit_token_rotation()` | Two-phase commit for token | Rotation committed |
| 100 | `LedgerTx.Commit()` | Commits to ledger | Ledger commit success |

---

## Phase 10: Old Shard Garbage Collection (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 101 | `garbage_collect()` | Initiates garbage collection | GC initiated |
| 102 | `mark_for_deletion()` | Marks old shards for 24-hour delay | Shards marked count |
| 103 | `schedule_delayed_deletion()` | Schedules deletion after delay | Deletion scheduled |
| 104 | `time.AfterFunc()` | Sets 24-hour timer | Timer set |
| 105 | `secure_wipe_old_shards()` | Securely wipes old shard data | Old shards wiped |
| 106 | `remove_old_dag_references()` | Removes old DAG references | References removed |
| 107 | `handle_identical_cleanup()` | Ensures real/decoy cleanup identical | Timing variance <1ms |
| 108 | `confirm_gc_scheduled()` | Confirms GC properly scheduled | GC confirmed |

---

## Phase 11: Memory Security & Local Cleanup (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 109 | `secureWipe()` | Securely zeros all sensitive data | Bytes wiped |
| 110 | `clear_old_keys()` | Clears old encryption keys | Old keys cleared |
| 111 | `clear_new_keys()` | Clears new keys after use | New keys cleared |
| 112 | `clear_decrypted_shards()` | Clears decrypted shard data | Shards cleared |
| 113 | `clear_metadata_buffers()` | Clears metadata buffers | Buffers cleared |
| 114 | `runtime.GC()` | Forces garbage collection | GC triggered |
| 115 | `runtime.KeepAlive()` | Prevents premature GC during ops | Keep-alive applied |
| 116 | `MonitorMemoryUsage()` | Monitors memory allocation | Current memory usage |
| 117 | `tryLockMemory()` | Locks memory pages (prevent swap) | Lock success/failure |
| 118 | `syscall.Syscall()` | Direct system call for memory ops | Syscall result |

---

## Phase 12: Audit Logging & Finalization (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 119 | `create_log_entry()` | Creates audit log entry | Entry type: ROTATE, timestamp |
| 120 | `encrypt_log()` | Encrypts log entry | Encryption success |
| 121 | `anchor_log()` | Anchors log to blockchain (Premium/Elite) | Anchor TX ID |
| 122 | `record_rotation_timestamp()` | Records rotation for interval tracking | Timestamp recorded |
| 123 | `errors.New()` | Creates error if any step failed | Error message |
| 124 | `fmt.Errorf()` | Formats error with context | Error details |
| 125 | `log.Printf()` | Prints final status log | Operation complete |
| 126 | `return_new_bundle_id()` | Returns new bundle ID to wallet | New bundle ID returned |

---

## Critical Logging Points

### Security Alerts (Must Log)

The system **must trigger alerts** whenever:
- Ownership ZKP verification fails
- Interval validation fails (rotation too soon)
- Shard retrieval fails for any shard
- Re-encryption fails for any shard
- Node selection cannot meet geographic requirements
- New shard submission fails
- Version increment fails
- Token rotation fails
- Garbage collection scheduling fails

### Decoy Security Warning - CRITICAL

**The rotation process MUST handle real and decoy shards identically:**
- Re-encrypt all shards (real and decoy) with fresh keys
- Generate NEW decoy shards (don't just re-encrypt old ones)
- Timing for real and decoy operations must be indistinguishable (<1ms variance)
- Garbage collection for old real and decoy shards must be identical
- Cannot reveal which characters were decoys through rotation patterns

### Rotation Timing Requirements

Per the Knowledge Base:
- **Voluntary rotation:** 30-day minimum interval with ±3-day jitter
- **Mandatory rotation:** 6-month interval with ±7-day variation
- Jitter uses cryptographically secure RNG seeded with bundle ID + creation timestamp

### Recommended Log Format

```go
type LockBoxLogEntry struct {
    Timestamp     time.Time `json:"timestamp"`
    Phase         string    `json:"phase"`
    Function      string    `json:"function"`
    Status        string    `json:"status"` // SUCCESS, FAILURE, WARNING
    Duration      int64     `json:"duration_ns"`
    Details       string    `json:"details"` // Non-sensitive context
    OldBundleID   string    `json:"old_bundle_id"`
    NewBundleID   string    `json:"new_bundle_id,omitempty"`
    RequestID     string    `json:"request_id"`
    VersionFrom   string    `json:"version_from,omitempty"`
    VersionTo     string    `json:"version_to,omitempty"`
    NodesSelected int       `json:"nodes_selected,omitempty"`
    ShardsRotated int       `json:"shards_rotated,omitempty"`
}
```

### Error Structure (Per Requirements)

```go
type LockBoxError struct {
    Code        string    // Machine-readable: INTERVAL_TOO_SHORT, ROTATION_FAILED, etc.
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

---

## LockScript Implementation Reference

```lockscript
secure_operation rotate_and_reassign(bundle_id: BundleID, user_key: SecureString) -> BundleID {
    verify_interval(min_days: 30)
    old_shards = fetch_shards(bundle_id)
    new_shards = reencrypt_shards(old_shards, new_key: derive_key(user_key))
    new_tx_ids = assign_shards(new_shards, tier: get_current_tier())
    new_bundle_id = update_metadata(bundle_id, new_tx_ids, version: increment_version())
    garbage_collect(old_shards)
    return new_bundle_id
}
```

---

## Key Rotation Workflow Summary (Per Requirements)

1. Verify user authentication via ZKP
2. Generate new encryption keys for all shards (character and metadata)
3. Retrieve all existing shards from current locations
4. Re-encrypt all data with new keys
5. Select new target nodes following geographic distribution rules
6. Submit new shards to selected nodes
7. Create new main transaction with updated references
8. Update the version identifier (e.g., 'v1' to 'v2')
9. Return a new access token to the wallet
10. Mark old shards for garbage collection (with 24-hour delay)

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total Functions** | **126** |
| Request Initialization | 10 |
| Ownership Verification | 10 |
| Shard Retrieval | 14 |
| Key Generation | 12 |
| Re-Encryption | 14 |
| Node Selection | 10 |
| DAG Submission | 12 |
| Metadata Update | 10 |
| Token Rotation | 8 |
| Garbage Collection | 8 |
| Memory Security | 10 |
| Audit/Finalization | 8 |

---

## Comparison to Other Operations

| Operation | Function Count | Complexity |
|-----------|----------------|------------|
| storeKey | 100 | Complex crypto + storage |
| getKey | 200 | Most complex - retrieval + verification |
| **rotateKey** | **126** | **Re-encryption + redistribution** |
| destroyKey | 70 | Secure deletion across network |

The rotateKey operation combines elements of both retrieval and storage:
1. Retrieves existing shards (like getKey)
2. Re-encrypts with new keys
3. Redistributes to new nodes (like storeKey)
4. Manages versioning and garbage collection

---

## Rotation Fees (Per Tier)

- **Basic:** $5 per rotation
- **Standard:** $5 per rotation
- **Premium:** $10 per rotation
- **Elite:** $25 per rotation

Fees are configurable via wallet settings or B2B API.

---

## Version Chain Management

Each rotation creates a new version:
- Original storage: v1
- First rotation: v2
- Second rotation: v3
- etc.

The latest version ensures retrieval uses current shards. Old versions are discarded via garbage collection after the 24-hour delay period.
