# LockBox destroyKey (deleteKey) Function - Verbose Logging Checklist

> Source: Client document "LockBox deleteKey Logging.docx"
> Date: 2025-12-21

## Overview

This document lists all 70 functions executed during the destroyKey (deleteKey) operation. The development team should implement verbose logging at each function call to verify complete execution flow. This operation enables user-initiated destruction of key shards across the distributed network, rendering the key permanently irretrievable.

---

## Phase 1: Request Initialization & Token Validation (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 1 | `validate_access_token()` | Validates single-use API key | Token hash (not token), validity status |
| 2 | `check_token_nonce()` | Verifies nonce-based auth (5 min window) | Nonce value, timestamp check result |
| 3 | `time.Now()` | Captures request timestamp | Timestamp value |
| 4 | `uuid.New()` | Generates destruction request ID | Request UUID |
| 5 | `context.WithTimeout()` | Creates timeout context for operation | Timeout duration |
| 6 | `context.Background()` | Creates background context | Context created |
| 7 | `len()` | Gets length of request data | Data length |
| 8 | `validate_bundle_id()` | Validates bundle ID format | Bundle ID valid |

---

## Phase 2: Ownership Verification via ZKP (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 9 | `verify_ownership()` | Initiates ownership verification | Verification started |
| 10 | `generate_ownership_zkp()` | Generates ZKP proving key ownership | Proof type: "ownership" |
| 11 | `generate_nonce()` | Creates unique nonce for ZKP | Nonce generated |
| 12 | `gnark.Compile()` | Compiles ZKP circuit | Circuit compilation success |
| 13 | `gnark.Setup()` | Performs ZKP trusted setup | Setup completion |
| 14 | `gnark.Prove()` | Generates zk-STARK ownership proof | Proof generation success |
| 15 | `gnark.Verify()` | Verifies ownership proof | Verification result |
| 16 | `hash.Hash.Write()` | Writes to hash for proof | Bytes written |
| 17 | `hash.Hash.Sum()` | Finalizes hash for proof | Hash finalized |
| 18 | `crypto/ed25519.Verify()` | Verifies signature on proof | Signature valid |

---

## Phase 3: Shard Location & Enumeration (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 19 | `fetch_shards()` | Fetches all shard references for bundle | Shard count (real + decoy) |
| 20 | `fetch_main_tx()` | Fetches main transaction from DAG | Transaction ID retrieved |
| 21 | `iota.GetMessage()` | Gets message from IOTA DAG | Message retrieved |
| 22 | `parse_bundle_metadata()` | Parses encrypted bundle metadata | Metadata structure valid |
| 23 | `AES256GCMDecrypt()` | Decrypts metadata with master key | Decryption success |
| 24 | `extract_shard_ids()` | Extracts all shard transaction IDs | Shard IDs extracted |
| 25 | `extract_geographic_tags()` | Gets shard location tags | Node locations identified |
| 26 | `enumerate_all_nodes()` | Lists all nodes storing shards | Node count |

---

## Phase 4: Destruction Request Distribution (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 27 | `mark_for_destruction()` | Marks all shards for garbage collection | Shards marked count |
| 28 | `create_destruction_request()` | Creates signed destruction request | Request created |
| 29 | `crypto/ed25519.Sign()` | Signs destruction request | Signature created |
| 30 | `distribute_to_nodes()` | Sends destruction request to all nodes | Nodes contacted count |
| 31 | `http.NewRequest()` | Creates HTTP request per node | Request created |
| 32 | `http.Client.Do()` | Executes destruction request | Response status per node |
| 33 | `tls.Config{}` | Configures TLS 1.3 for request | TLS configured |
| 34 | `net.Dial()` | Establishes connection to each node | Connection established |

---

## Phase 5: Distributed Garbage Collection (10 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 35 | `initiate_garbage_collection()` | Triggers GC on all nodes | GC initiated |
| 36 | `secure_wipe_shard()` | Securely wipes shard data on node | Shard ID, wipe status |
| 37 | `overwrite_storage()` | Multi-pass overwrite of shard storage | Overwrite passes complete |
| 38 | `verify_data_unneeded()` | Confirms shard can be deleted | Verification pass |
| 39 | `remove_dag_references()` | Removes DAG transaction references | References removed |
| 40 | `update_node_metadata()` | Updates node's shard inventory | Metadata updated |
| 41 | `sync.WaitGroup.Add()` | Adds GC tasks to wait group | Tasks added |
| 42 | `sync.WaitGroup.Wait()` | Waits for all GC operations | All GC complete |
| 43 | `handle_identical_cleanup()` | Ensures real/decoy cleanup identical | Timing variance <1ms |
| 44 | `prevent_pattern_analysis()` | Randomizes cleanup order | Order randomized |

---

## Phase 6: Destruction Confirmation & Verification (6 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 45 | `confirm_destruction()` | Confirms all shards destroyed | Confirmation received |
| 46 | `collect_destruction_receipts()` | Collects receipts from all nodes | Receipts count |
| 47 | `verify_all_nodes_confirmed()` | Verifies all nodes acknowledged | All nodes confirmed |
| 48 | `validate_destruction_complete()` | Validates no shards remain | Destruction verified |
| 49 | `bytes.Equal()` | Compares confirmation hashes | Hash match |
| 50 | `time.Since()` | Measures total destruction time | Duration in ms |

---

## Phase 7: Token & Metadata Cleanup (6 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 51 | `invalidate_access_token()` | Permanently invalidates token | Token invalidated |
| 52 | `remove_token_mapping()` | Removes token from wallet DB | Mapping removed |
| 53 | `delete_main_transaction()` | Marks main TX for deletion | Main TX deleted |
| 54 | `clear_metadata_references()` | Clears all metadata references | References cleared |
| 55 | `update_bundle_status()` | Updates bundle status to DESTROYED | Status updated |
| 56 | `LedgerTx.Record()` | Records destruction in ledger | Ledger entry created |

---

## Phase 8: Memory Security & Local Cleanup (8 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 57 | `secureWipe()` | Securely zeros all sensitive data | Bytes wiped |
| 58 | `clear_local_cache()` | Clears any cached shard data | Cache cleared |
| 59 | `clear_metadata_buffers()` | Clears metadata buffers | Buffers cleared |
| 60 | `runtime.GC()` | Forces garbage collection | GC triggered |
| 61 | `runtime.KeepAlive()` | Prevents premature GC during wipe | Keep-alive applied |
| 62 | `MonitorMemoryUsage()` | Monitors memory after cleanup | Memory usage |
| 63 | `tryLockMemory()` | Ensures memory was properly cleared | Memory verified |
| 64 | `syscall.Syscall()` | Direct system call for memory ops | Syscall result |

---

## Phase 9: Audit Logging & Finalization (6 functions)

| # | Function | Purpose | Log Entry Should Include |
|---|----------|---------|--------------------------|
| 65 | `create_log_entry()` | Creates audit log entry | Entry type: DESTROY, timestamp |
| 66 | `encrypt_log()` | Encrypts log entry | Encryption success |
| 67 | `anchor_log()` | Anchors destruction log (Premium/Elite) | Anchor TX ID |
| 68 | `errors.New()` | Creates error if any step failed | Error message |
| 69 | `fmt.Errorf()` | Formats error with context | Error details |
| 70 | `log.Printf()` | Prints final status log | Operation complete |

---

## Critical Logging Points

### Security Alerts (Must Log)

The system **must trigger alerts** whenever:
- Ownership ZKP verification fails
- Any node fails to acknowledge destruction request
- Destruction confirmation is incomplete
- Timing variance between real/decoy cleanup exceeds 1ms
- Memory clearing verification fails

### Decoy Security Warning - CRITICAL

**The destruction process MUST handle real and decoy shards identically to prevent pattern analysis:**
- Cleanup timing for real and decoy shards must remain indistinguishable (<1ms variance)
- Cannot reveal which characters were decoys through cleanup patterns
- Must maintain consistent cleanup timing for all character types
- Should not create observable patterns in the DAG structure
- Must handle distributed cleanup across all nodes identically
- Randomize destruction order to prevent inference

### Garbage Collection Security Requirements

Per the Knowledge Base, secure garbage collection must:
- Verify data is truly no longer needed before removal
- Securely wipe all traces from storage (multi-pass overwrite)
- Update relevant metadata and references
- Maintain audit trails of removals
- Handle both real and decoy data identically

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
    NodesAffected int       `json:"nodes_affected,omitempty"`
    ShardsDeleted int       `json:"shards_deleted,omitempty"`
}
```

### Error Structure (Per Requirements)

```go
type LockBoxError struct {
    Code        string    // Machine-readable: OWNERSHIP_INVALID, DESTRUCTION_INCOMPLETE, etc.
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
secure_operation destroy_key(bundle_id: BundleID, user_key: SecureString) {
    verify_ownership(bundle_id, proof: generate_zkp(user_key, "ownership"))
    shards = fetch_shards(bundle_id)
    mark_for_destruction(shards)
    confirm_destruction(shards)
}
```

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total Functions** | **70** |
| Request Initialization | 8 |
| Ownership Verification | 10 |
| Shard Enumeration | 8 |
| Destruction Distribution | 8 |
| Garbage Collection | 10 |
| Destruction Confirmation | 6 |
| Token/Metadata Cleanup | 6 |
| Memory Security | 8 |
| Audit/Finalization | 6 |

---

## Comparison to Other Operations

| Operation | Function Count | Complexity |
|-----------|----------------|------------|
| storeKey | 100 | Complex crypto + storage |
| getKey | 200 | Most complex - retrieval + verification |
| rotateKey | 80-90 | Re-encryption + redistribution |
| **destroyKey** | **70** | **Secure deletion across network** |

The destroyKey operation is relatively simpler because it:
1. Does not require shard reconstruction
2. Does not require payment processing
3. Does not require new shard generation
4. Focuses on secure, verifiable deletion

However, it has unique complexity in:
1. Ensuring indistinguishable cleanup between real/decoy shards
2. Coordinating deletion across all geographic nodes
3. Verifying complete destruction with no traces
4. Preventing timing-based pattern analysis

---

## Irreversibility Warning

**Once destroyKey completes successfully, the private key is PERMANENTLY IRRETRIEVABLE.**

- All shards (real and decoy) are securely wiped
- All metadata references are deleted
- The access token is permanently invalidated
- This action cannot be undone

The wallet UI should require explicit user confirmation before executing this operation, including:
- Clear warning about irreversibility
- Confirmation dialog requiring typed acknowledgment
- Optional delay period before execution
