package logging

// FunctionDef defines a loggable function from client requirements
// These are the exact function names from client documentation for NEO AI verification
type FunctionDef struct {
	ID      int    // Function number (1-100, 1-200, etc.)
	Name    string // Function name from client docs (exact match required)
	Phase   string // Phase constant
	LogHint string // What should be logged (from docs)
}

// =============================================================================
// storeKey Functions (100 total, 11 phases)
// Source: STOREKEY_FUNCTION_LIST.md
// =============================================================================

var StoreKeyFunctions = []FunctionDef{
	// Phase 1: Input Validation & Configuration (10 functions)
	{1, "validate_length", PhaseInputValidation, "Input length, pass/fail status"},
	{2, "set_tier_config", PhaseInputValidation, "Tier level, decoy ratio applied"},
	{3, "get_tier_ratio", PhaseInputValidation, "Ratio value (0.5x-2x)"},
	{4, "generate_bundle_id", PhaseInputValidation, "Generated bundle ID"},
	{5, "runtime.NumCPU", PhaseInputValidation, "Core count"},
	{6, "calculateGoroutineLimit", PhaseInputValidation, "Calculated limit (5-100)"},
	{7, "time.Now", PhaseInputValidation, "Timestamp value"},
	{8, "uuid.New", PhaseInputValidation, "UUID value"},
	{9, "len", PhaseInputValidation, "Length value"},
	{10, "crypto/rand.Read", PhaseInputValidation, "Bytes generated (count only)"},

	// Phase 2: Key Derivation (6 functions)
	{11, "DeriveHKDFKey", PhaseKeyDerivation, "Purpose parameter (real-char/decoy-char)"},
	{12, "hkdf.New", PhaseKeyDerivation, "Hash function used"},
	{13, "sha256.New", PhaseKeyDerivation, "Instance creation success"},
	{14, "hkdf.Expand", PhaseKeyDerivation, "Output length"},
	{15, "base64.StdEncoding.EncodeToString", PhaseKeyDerivation, "Encoding success"},
	{16, "derive_key", PhaseKeyDerivation, "Shard index, purpose"},

	// Phase 3: Encryption Operations (9 functions)
	{17, "AES256GCMEncrypt", PhaseEncryption, "Data type encrypted"},
	{18, "crypto/aes.NewCipher", PhaseEncryption, "Cipher creation success"},
	{19, "crypto/cipher.NewGCM", PhaseEncryption, "GCM initialization success"},
	{20, "crypto/cipher.GCM.Seal", PhaseEncryption, "Ciphertext length"},
	{21, "hmac.New", PhaseEncryption, "Hash function used"},
	{22, "hmac.Sum", PhaseEncryption, "HMAC computation success"},
	{23, "sha256.Sum256", PhaseEncryption, "Hash computation success"},
	{24, "encrypt_chars", PhaseEncryption, "Character count encrypted"},
	{25, "encrypt_log", PhaseEncryption, "Log encryption success"},

	// Phase 4: Digital Signatures (3 functions)
	{26, "crypto/ed25519.GenerateKey", PhaseDigitalSignatures, "Key generation success"},
	{27, "crypto/ed25519.Sign", PhaseDigitalSignatures, "Signature creation success"},
	{28, "bytes.Equal", PhaseDigitalSignatures, "Comparison result"},

	// Phase 5: Character Sharding & Decoy Generation (14 functions)
	{29, "splitKeyWithKeysAndDecoys", PhaseSharding, "Total shards created"},
	{30, "to_char_array", PhaseSharding, "Character count"},
	{31, "create_decoys", PhaseSharding, "Decoy count, ratio"},
	{32, "math.Floor", PhaseSharding, "Calculation result"},
	{33, "generate_random_chars", PhaseSharding, "Characters generated"},
	{34, "crypto/rand.Int", PhaseSharding, "Generation success"},
	{35, "shuffle", PhaseSharding, "Shuffle execution success"},
	{36, "rand.Seed", PhaseSharding, "Seed applied"},
	{37, "rand.Shuffle", PhaseSharding, "Shuffle complete"},
	{38, "append", PhaseSharding, "Elements appended"},
	{39, "copy", PhaseSharding, "Bytes copied"},
	{40, "make", PhaseSharding, "Allocation size"},
	{41, "create_shard", PhaseSharding, "Shard index, type (real/decoy)"},
	{42, "string", PhaseSharding, "Conversion success"},

	// Phase 6: Zero-Knowledge Proof Generation (8 functions)
	{43, "generate_zkp", PhaseZKP, "Proof type, tier level"},
	{44, "gnark.Compile", PhaseZKP, "Circuit compilation success"},
	{45, "gnark.Setup", PhaseZKP, "Setup completion"},
	{46, "gnark.Prove", PhaseZKP, "Proof generation success"},
	{47, "gnark.Verify", PhaseZKP, "Verification result"},
	{48, "frontend.Compile", PhaseZKP, "Frontend compilation success"},
	{49, "hash.Hash.Write", PhaseZKP, "Bytes written"},
	{50, "hash.Hash.Sum", PhaseZKP, "Hash finalized"},

	// Phase 7: Metadata Creation (16 functions)
	{51, "createMetadataFragmentsWithKey", PhaseMetadata, "Fragment count"},
	{52, "json.Marshal", PhaseMetadata, "Serialization success"},
	{53, "json.Unmarshal", PhaseMetadata, "Deserialization success"},
	{54, "json.NewEncoder", PhaseMetadata, "Encoder created"},
	{55, "json.NewDecoder", PhaseMetadata, "Decoder created"},
	{56, "bytes.NewBuffer", PhaseMetadata, "Buffer size"},
	{57, "bytes.Buffer.Write", PhaseMetadata, "Bytes written"},
	{58, "io.Copy", PhaseMetadata, "Bytes copied"},
	{59, "io.ReadFull", PhaseMetadata, "Bytes read"},
	{60, "strconv.Itoa", PhaseMetadata, "Conversion success"},
	{61, "strings.Join", PhaseMetadata, "Result length"},
	{62, "strings.Split", PhaseMetadata, "Parts created"},
	{63, "fmt.Sprintf", PhaseMetadata, "Format success"},
	{64, "encoding/hex.EncodeToString", PhaseMetadata, "Encoding success"},
	{65, "base64.StdEncoding.DecodeString", PhaseMetadata, "Decoding success"},
	{66, "int", PhaseMetadata, "Conversion success"},

	// Phase 8: Network Submission (10 functions)
	{67, "SubmitBundle", PhaseNetworkSubmission, "Bundle ID, node count"},
	{68, "iota.SubmitMessage", PhaseNetworkSubmission, "Message ID"},
	{69, "iota.NewMessageBuilder", PhaseNetworkSubmission, "Builder initialized"},
	{70, "iota.WithPayload", PhaseNetworkSubmission, "Payload size"},
	{71, "iota.WithReferences", PhaseNetworkSubmission, "Reference count"},
	{72, "http.NewRequest", PhaseNetworkSubmission, "Request method, endpoint"},
	{73, "http.Client.Do", PhaseNetworkSubmission, "Response status code"},
	{74, "net/url.Parse", PhaseNetworkSubmission, "URL validity"},
	{75, "tls.Config", PhaseNetworkSubmission, "TLS version"},
	{76, "x509.ParseCertificate", PhaseNetworkSubmission, "Certificate validity"},

	// Phase 9: Connection & Synchronization (6 functions)
	{77, "net.Dial", PhaseConnection, "Connection target, success"},
	{78, "context.WithTimeout", PhaseConnection, "Timeout duration"},
	{79, "context.Background", PhaseConnection, "Context created"},
	{80, "sync.WaitGroup.Add", PhaseConnection, "Delta added"},
	{81, "sync.WaitGroup.Wait", PhaseConnection, "Wait complete"},
	{82, "io.WriteString", PhaseConnection, "Bytes written"},

	// Phase 10: Memory Security (10 functions)
	{83, "secureWipe", PhaseMemorySecurity, "Bytes wiped"},
	{84, "runtime.GC", PhaseMemorySecurity, "GC triggered"},
	{85, "runtime.KeepAlive", PhaseMemorySecurity, "Keep-alive applied"},
	{86, "MonitorMemoryUsage", PhaseMemorySecurity, "Current memory usage"},
	{87, "tryLockMemory", PhaseMemorySecurity, "Lock success/failure"},
	{88, "syscall.Syscall", PhaseMemorySecurity, "Syscall number, result"},
	{89, "os.Getpagesize", PhaseMemorySecurity, "Page size"},
	{90, "unsafe.Pointer", PhaseMemorySecurity, "Pointer operation"},
	{91, "reflect.ValueOf", PhaseMemorySecurity, "Type inspected"},
	{92, "runtime.SetFinalizer", PhaseMemorySecurity, "Finalizer registered"},

	// Phase 11: Error Handling & Audit Logging (8 functions)
	{93, "errors.New", PhaseAudit, "Error message"},
	{94, "fmt.Errorf", PhaseAudit, "Error details"},
	{95, "log.Printf", PhaseAudit, "Log message"},
	{96, "create_log_entry", PhaseAudit, "Entry type, timestamp"},
	{97, "anchor_log", PhaseAudit, "Anchor transaction ID"},
	{98, "time.RFC3339", PhaseAudit, "Timestamp string"},
	{99, "os.OpenFile", PhaseAudit, "File path, mode"},
	{100, "file.Close", PhaseAudit, "Close success"},
}

// =============================================================================
// retrieveKey Functions (200 total, 14 phases)
// Source: RETRIEVEKEY_FUNCTION_LIST.md
// =============================================================================

var RetrieveKeyFunctions = []FunctionDef{
	// Phase 1: Request Initialization & Token Validation (12 functions)
	{1, "validate_access_token", PhaseTokenValidation, "Token hash (not token), validity status"},
	{2, "check_token_nonce", PhaseTokenValidation, "Nonce value, timestamp check result"},
	{3, "get_tier_config", PhaseTokenValidation, "Tier level (Basic/Standard/Premium/Elite)"},
	{4, "time.Now", PhaseTokenValidation, "Timestamp value"},
	{5, "uuid.New", PhaseTokenValidation, "Request UUID"},
	{6, "context.WithTimeout", PhaseTokenValidation, "Timeout duration"},
	{7, "context.Background", PhaseTokenValidation, "Context created"},
	{8, "runtime.NumCPU", PhaseTokenValidation, "Core count"},
	{9, "calculateGoroutineLimit", PhaseTokenValidation, "Calculated limit (5-100)"},
	{10, "len", PhaseTokenValidation, "Data length"},
	{11, "crypto/rand.Read", PhaseTokenValidation, "Bytes generated (count only)"},
	{12, "base64.StdEncoding.EncodeToString", PhaseTokenValidation, "Encoding success"},

	// Phase 2: Payment Transaction Processing (18 functions)
	{13, "validate_payment_tx", PhasePayment, "Payment type (LockBox/native token)"},
	{14, "parse_payment_tx", PhasePayment, "Transaction format valid"},
	{15, "verify_payment_signature", PhasePayment, "Signature validity"},
	{16, "crypto/ed25519.Verify", PhasePayment, "Verification result"},
	{17, "calculate_retrieval_fee", PhasePayment, "Fee amount, currency"},
	{18, "verify_payment_amount", PhasePayment, "Amount sufficient"},
	{19, "LockScript.signPayment", PhasePayment, "Signature generated"},
	{20, "submit_payment_tx", PhasePayment, "Transaction hash"},
	{21, "wait_payment_confirmation", PhasePayment, "Confirmation status"},
	{22, "iota.SubmitMessage", PhasePayment, "Message ID"},
	{23, "http.NewRequest", PhasePayment, "Request method, endpoint"},
	{24, "http.Client.Do", PhasePayment, "Response status code"},
	{25, "json.Unmarshal", PhasePayment, "Parse success"},
	{26, "verify_ledger_tx", PhasePayment, "Ledger entry confirmed"},
	{27, "record_revenue_share", PhasePayment, "Provider ID, share amount"},
	{28, "calculate_provider_share", PhasePayment, "Share calculated"},
	{29, "update_revenue_ledger", PhasePayment, "Ledger updated"},
	{30, "fmt.Sprintf", PhasePayment, "Format success"},

	// Phase 3: ZKP Generation & Ownership Proof (16 functions)
	{31, "generate_ownership_zkp", PhaseOwnership, "Proof type, tier complexity"},
	{32, "generate_nonce", PhaseOwnership, "Nonce generated"},
	{33, "gnark.Compile", PhaseOwnership, "Circuit compilation success"},
	{34, "gnark.Setup", PhaseOwnership, "Setup completion"},
	{35, "gnark.Prove", PhaseOwnership, "Proof generation success"},
	{36, "frontend.Compile", PhaseOwnership, "Frontend compilation success"},
	{37, "hash.Hash.Write", PhaseOwnership, "Bytes written"},
	{38, "hash.Hash.Sum", PhaseOwnership, "Hash finalized"},
	{39, "derive_proof_key", PhaseOwnership, "Key derivation success"},
	{40, "incorporate_challenge", PhaseOwnership, "Challenge incorporated"},
	{41, "argon2id.Key", PhaseOwnership, "Key derivation success"},
	{42, "serialize_proof", PhaseOwnership, "Serialization success"},
	{43, "json.Marshal", PhaseOwnership, "JSON created"},
	{44, "bytes.NewBuffer", PhaseOwnership, "Buffer created"},
	{45, "io.Copy", PhaseOwnership, "Bytes copied"},
	{46, "sha256.Sum256", PhaseOwnership, "Hash computed"},

	// Phase 4: Multi-Signature Verification (Premium/Elite) (10 functions)
	{47, "check_multisig_required", PhaseMultiSig, "Multi-sig status"},
	{48, "get_multisig_config", PhaseMultiSig, "Required signatures count"},
	{49, "collect_signer_proofs", PhaseMultiSig, "Signatures collected count"},
	{50, "verify_threshold_zkp", PhaseMultiSig, "Threshold met"},
	{51, "aggregate_signatures", PhaseMultiSig, "Aggregation success"},
	{52, "validate_signer_identity", PhaseMultiSig, "Signer verified"},
	{53, "check_signer_authorization", PhaseMultiSig, "Authorization confirmed"},
	{54, "verify_signature_freshness", PhaseMultiSig, "Signatures fresh"},
	{55, "compute_aggregate_hash", PhaseMultiSig, "Hash computed"},
	{56, "gnark.Verify", PhaseMultiSig, "Verification result"},

	// Phase 5: Dual Coordinating Node Selection (14 functions)
	{57, "select_primary_coordinator", PhaseCoordinator, "Primary node ID"},
	{58, "select_secondary_coordinator", PhaseCoordinator, "Secondary node ID"},
	{59, "verify_coordinator_eligibility", PhaseCoordinator, "Eligibility status"},
	{60, "check_node_reliability", PhaseCoordinator, "Reliability score"},
	{61, "check_geographic_separation", PhaseCoordinator, "Distance verified"},
	{62, "verify_no_shard_storage", PhaseCoordinator, "No shards stored"},
	{63, "establish_coordinator_channel", PhaseCoordinator, "Channel established"},
	{64, "tls.Config", PhaseCoordinator, "TLS configured"},
	{65, "x509.ParseCertificate", PhaseCoordinator, "Certificate valid"},
	{66, "net.Dial", PhaseCoordinator, "Connection established"},
	{67, "mutual_tls_handshake", PhaseCoordinator, "Handshake complete"},
	{68, "send_retrieval_request", PhaseCoordinator, "Request sent"},
	{69, "send_oversight_request", PhaseCoordinator, "Oversight request sent"},
	{70, "sync.WaitGroup.Add", PhaseCoordinator, "Tasks added"},

	// Phase 6: Triple Verification Node Selection & Validation (20 functions)
	{71, "select_verification_nodes", PhaseTripleVerification, "Node IDs selected"},
	{72, "verify_geographic_diversity", PhaseTripleVerification, "Diversity confirmed"},
	{73, "check_node_uptime", PhaseTripleVerification, "Uptime scores"},
	{74, "ensure_no_direct_comms", PhaseTripleVerification, "Isolation verified"},
	{75, "distribute_verification_request", PhaseTripleVerification, "Requests distributed"},
	{76, "verify_zkp_validity", PhaseTripleVerification, "ZKP valid (per node)"},
	{77, "verify_payment_confirmation", PhaseTripleVerification, "Payment confirmed (per node)"},
	{78, "verify_access_token_auth", PhaseTripleVerification, "Token valid (per node)"},
	{79, "verify_user_tier_auth", PhaseTripleVerification, "Tier authorized (per node)"},
	{80, "verify_shard_authenticity", PhaseTripleVerification, "Shards authentic (per node)"},
	{81, "crypto/ed25519.Sign", PhaseTripleVerification, "Signature created (per node)"},
	{82, "collect_node_signatures", PhaseTripleVerification, "3 signatures collected"},
	{83, "aggregate_verifications", PhaseTripleVerification, "Aggregation complete"},
	{84, "validate_aggregated_sigs", PhaseTripleVerification, "All signatures valid"},
	{85, "secondary_validate_aggregation", PhaseTripleVerification, "Secondary approval"},
	{86, "check_coordinator_consensus", PhaseTripleVerification, "Consensus reached"},
	{87, "handle_disagreement", PhaseTripleVerification, "Rejection reason if applicable"},
	{88, "crypto/ed25519.Verify", PhaseTripleVerification, "Verification per signature"},
	{89, "bytes.Equal", PhaseTripleVerification, "Comparison result"},
	{90, "time.Since", PhaseTripleVerification, "Duration in ms"},

	// Phase 7: Bundle & Metadata Retrieval (18 functions)
	{91, "fetch_main_tx", PhaseBundleRetrieval, "Transaction ID, fetch success"},
	{92, "iota.GetMessage", PhaseBundleRetrieval, "Message retrieved"},
	{93, "parse_bundle_metadata", PhaseBundleRetrieval, "Metadata structure valid"},
	{94, "extract_salt", PhaseBundleRetrieval, "Salt extracted"},
	{95, "AES256GCMDecrypt", PhaseBundleRetrieval, "Decryption success"},
	{96, "crypto/aes.NewCipher", PhaseBundleRetrieval, "Cipher created"},
	{97, "crypto/cipher.NewGCM", PhaseBundleRetrieval, "GCM initialized"},
	{98, "crypto/cipher.GCM.Open", PhaseBundleRetrieval, "Decryption success"},
	{99, "json.Unmarshal", PhaseBundleRetrieval, "JSON parsed"},
	{100, "validate_metadata_integrity", PhaseBundleRetrieval, "HMAC valid"},
	{101, "hmac.New", PhaseBundleRetrieval, "HMAC created"},
	{102, "hmac.Equal", PhaseBundleRetrieval, "HMAC match"},
	{103, "extract_shard_ids", PhaseBundleRetrieval, "Shard count extracted"},
	{104, "extract_total_char_count", PhaseBundleRetrieval, "Total count"},
	{105, "extract_real_char_count", PhaseBundleRetrieval, "Real count"},
	{106, "extract_geographic_tags", PhaseBundleRetrieval, "Geographic tags"},
	{107, "extract_zkp_hashes", PhaseBundleRetrieval, "ZKP hashes"},
	{108, "strings.Split", PhaseBundleRetrieval, "Fields parsed"},

	// Phase 8: Parallel Shard Fetching (22 functions)
	{109, "initiate_parallel_fetch", PhaseShardFetch, "Goroutines launched"},
	{110, "sync.WaitGroup.Add", PhaseShardFetch, "Tasks added"},
	{111, "go fetch_shard", PhaseShardFetch, "Goroutine started"},
	{112, "fetch_shard", PhaseShardFetch, "Shard ID, fetch status"},
	{113, "iota.GetMessage", PhaseShardFetch, "Message retrieved"},
	{114, "retry_fetch_shard", PhaseShardFetch, "Attempt number, backoff"},
	{115, "calculate_backoff", PhaseShardFetch, "Backoff duration (100ms, 200ms, 400ms)"},
	{116, "time.Sleep", PhaseShardFetch, "Sleep duration"},
	{117, "context.WithTimeout", PhaseShardFetch, "Timeout set"},
	{118, "check_shard_availability", PhaseShardFetch, "Shard available"},
	{119, "select_optimal_node", PhaseShardFetch, "Node selected"},
	{120, "http.NewRequest", PhaseShardFetch, "Request created"},
	{121, "http.Client.Do", PhaseShardFetch, "Response status"},
	{122, "io.ReadFull", PhaseShardFetch, "Bytes read"},
	{123, "validate_shard_integrity", PhaseShardFetch, "Integrity valid"},
	{124, "gnark.Verify", PhaseShardFetch, "ZKP valid"},
	{125, "collect_fetched_shards", PhaseShardFetch, "Shards collected count"},
	{126, "sync.WaitGroup.Wait", PhaseShardFetch, "All fetches complete"},
	{127, "handle_fetch_failures", PhaseShardFetch, "Failures handled (decoy-safe)"},
	{128, "access_redundant_copy", PhaseShardFetch, "Backup retrieved"},
	{129, "append", PhaseShardFetch, "Shard appended"},
	{130, "make", PhaseShardFetch, "Collection allocated"},

	// Phase 9: Key Derivation for Decryption (12 functions)
	{131, "DeriveHKDFKey", PhaseKeyDerivation, "Purpose parameter"},
	{132, "hkdf.New", PhaseKeyDerivation, "Hash function used"},
	{133, "sha256.New", PhaseKeyDerivation, "Instance created"},
	{134, "hkdf.Expand", PhaseKeyDerivation, "Output length"},
	{135, "derive_real_char_keys", PhaseKeyDerivation, "Key count derived"},
	{136, "construct_info_param", PhaseKeyDerivation, "Info string"},
	{137, "incorporate_salt", PhaseKeyDerivation, "Salt incorporated"},
	{138, "base64.StdEncoding.DecodeString", PhaseKeyDerivation, "Salt decoded"},
	{139, "strconv.Itoa", PhaseKeyDerivation, "Index converted"},
	{140, "strings.Join", PhaseKeyDerivation, "Info joined"},
	{141, "copy", PhaseKeyDerivation, "Bytes copied"},
	{142, "fmt.Sprintf", PhaseKeyDerivation, "Format success"},

	// Phase 10: Shard Decryption & Real Character Identification (18 functions)
	{143, "iterate_decrypt_shards", PhaseShardDecryption, "Total iterations"},
	{144, "try_decrypt_with_key", PhaseShardDecryption, "Decryption attempt result"},
	{145, "AES256GCMDecrypt", PhaseShardDecryption, "Decryption success/fail"},
	{146, "crypto/cipher.GCM.Open", PhaseShardDecryption, "Auth tag valid"},
	{147, "identify_real_shard", PhaseShardDecryption, "Real shard found"},
	{148, "validate_hmac_signature", PhaseShardDecryption, "HMAC valid (real)"},
	{149, "hmac.New", PhaseShardDecryption, "HMAC instance created"},
	{150, "hmac.Equal", PhaseShardDecryption, "Match result"},
	{151, "discard_decoy_shard", PhaseShardDecryption, "Decoy discarded"},
	{152, "extract_character", PhaseShardDecryption, "Character extracted"},
	{153, "extract_position", PhaseShardDecryption, "Position value"},
	{154, "verify_position_proof", PhaseShardDecryption, "Position verified"},
	{155, "filter_real_chars", PhaseShardDecryption, "Real chars filtered"},
	{156, "count_real_chars", PhaseShardDecryption, "Count matches expected"},
	{157, "string", PhaseShardDecryption, "Conversion success"},
	{158, "append", PhaseShardDecryption, "Char appended"},
	{159, "int", PhaseShardDecryption, "Conversion success"},
	{160, "make", PhaseShardDecryption, "Array allocated"},

	// Phase 11: Key Reconstruction (10 functions)
	{161, "order_characters", PhaseKeyReconstruction, "Characters ordered"},
	{162, "sort.Slice", PhaseKeyReconstruction, "Sort complete"},
	{163, "verify_position_sequence", PhaseKeyReconstruction, "Sequence valid"},
	{164, "assemble_chars", PhaseKeyReconstruction, "Key assembled"},
	{165, "strings.Builder.WriteString", PhaseKeyReconstruction, "String built"},
	{166, "strings.Builder.String", PhaseKeyReconstruction, "Key string retrieved"},
	{167, "validate_key_length", PhaseKeyReconstruction, "Length matches expected"},
	{168, "verify_reconstruction_success", PhaseKeyReconstruction, "Reconstruction verified"},
	{169, "compute_key_checksum", PhaseKeyReconstruction, "Checksum computed"},
	{170, "len", PhaseKeyReconstruction, "Key length"},

	// Phase 12: Token Rotation (8 functions)
	{171, "generate_new_access_token", PhaseTokenRotation, "New token generated"},
	{172, "crypto/rand.Read", PhaseTokenRotation, "Bytes generated"},
	{173, "encrypt_new_token", PhaseTokenRotation, "Token encrypted"},
	{174, "AES256GCMEncrypt", PhaseTokenRotation, "Encryption success"},
	{175, "invalidate_old_token", PhaseTokenRotation, "Old token invalidated"},
	{176, "store_token_mapping", PhaseTokenRotation, "Token stored"},
	{177, "commit_token_rotation", PhaseTokenRotation, "Rotation committed"},
	{178, "LedgerTx.Commit", PhaseTokenRotation, "Ledger commit success"},

	// Phase 13: Memory Security & Cleanup (14 functions)
	{179, "secureWipe", PhaseMemoryCleanup, "Bytes wiped"},
	{180, "clear_shard_memory", PhaseMemoryCleanup, "Shards cleared"},
	{181, "clear_decoy_data", PhaseMemoryCleanup, "Decoys cleared"},
	{182, "clear_derived_keys", PhaseMemoryCleanup, "Keys cleared"},
	{183, "clear_metadata_buffers", PhaseMemoryCleanup, "Buffers cleared"},
	{184, "runtime.GC", PhaseMemoryCleanup, "GC triggered"},
	{185, "runtime.KeepAlive", PhaseMemoryCleanup, "Keep-alive applied"},
	{186, "MonitorMemoryUsage", PhaseMemoryCleanup, "Current memory usage"},
	{187, "tryLockMemory", PhaseMemoryCleanup, "Lock success/failure"},
	{188, "syscall.Syscall", PhaseMemoryCleanup, "Syscall result"},
	{189, "os.Getpagesize", PhaseMemoryCleanup, "Page size"},
	{190, "unsafe.Pointer", PhaseMemoryCleanup, "Pointer operation"},
	{191, "reflect.ValueOf", PhaseMemoryCleanup, "Type inspected"},
	{192, "runtime.SetFinalizer", PhaseMemoryCleanup, "Finalizer registered"},

	// Phase 14: Error Handling & Audit Logging (8 functions)
	{193, "errors.New", PhaseAudit, "Error message"},
	{194, "fmt.Errorf", PhaseAudit, "Error details"},
	{195, "log.Printf", PhaseAudit, "Log message"},
	{196, "create_log_entry", PhaseAudit, "Entry type, timestamp"},
	{197, "encrypt_log", PhaseAudit, "Encryption success"},
	{198, "anchor_log", PhaseAudit, "Anchor TX ID"},
	{199, "time.RFC3339", PhaseAudit, "Timestamp string"},
	{200, "os.OpenFile", PhaseAudit, "File path, mode"},
}

// =============================================================================
// deleteKey Functions (70 total, 9 phases)
// Source: DELETEKEY_FUNCTION_LIST.md
// =============================================================================

var DeleteKeyFunctions = []FunctionDef{
	// Phase 1: Request Initialization & Token Validation (8 functions)
	{1, "validate_access_token", PhaseTokenValidation, "Token hash (not token), validity status"},
	{2, "check_token_nonce", PhaseTokenValidation, "Nonce value, timestamp check result"},
	{3, "time.Now", PhaseTokenValidation, "Timestamp value"},
	{4, "uuid.New", PhaseTokenValidation, "Request UUID"},
	{5, "context.WithTimeout", PhaseTokenValidation, "Timeout duration"},
	{6, "context.Background", PhaseTokenValidation, "Context created"},
	{7, "len", PhaseTokenValidation, "Data length"},
	{8, "validate_bundle_id", PhaseTokenValidation, "Bundle ID valid"},

	// Phase 2: Ownership Verification via ZKP (10 functions)
	{9, "verify_ownership", PhaseOwnership, "Verification started"},
	{10, "generate_ownership_zkp", PhaseOwnership, "Proof type: ownership"},
	{11, "generate_nonce", PhaseOwnership, "Nonce generated"},
	{12, "gnark.Compile", PhaseOwnership, "Circuit compilation success"},
	{13, "gnark.Setup", PhaseOwnership, "Setup completion"},
	{14, "gnark.Prove", PhaseOwnership, "Proof generation success"},
	{15, "gnark.Verify", PhaseOwnership, "Verification result"},
	{16, "hash.Hash.Write", PhaseOwnership, "Bytes written"},
	{17, "hash.Hash.Sum", PhaseOwnership, "Hash finalized"},
	{18, "crypto/ed25519.Verify", PhaseOwnership, "Signature valid"},

	// Phase 3: Shard Location & Enumeration (8 functions)
	{19, "fetch_shards", PhaseShardEnumeration, "Shard count (real + decoy)"},
	{20, "fetch_main_tx", PhaseShardEnumeration, "Transaction ID retrieved"},
	{21, "iota.GetMessage", PhaseShardEnumeration, "Message retrieved"},
	{22, "parse_bundle_metadata", PhaseShardEnumeration, "Metadata structure valid"},
	{23, "AES256GCMDecrypt", PhaseShardEnumeration, "Decryption success"},
	{24, "extract_shard_ids", PhaseShardEnumeration, "Shard IDs extracted"},
	{25, "extract_geographic_tags", PhaseShardEnumeration, "Node locations identified"},
	{26, "enumerate_all_nodes", PhaseShardEnumeration, "Node count"},

	// Phase 4: Destruction Request Distribution (8 functions)
	{27, "mark_for_destruction", PhaseDestructionDistribution, "Shards marked count"},
	{28, "create_destruction_request", PhaseDestructionDistribution, "Request created"},
	{29, "crypto/ed25519.Sign", PhaseDestructionDistribution, "Signature created"},
	{30, "distribute_to_nodes", PhaseDestructionDistribution, "Nodes contacted count"},
	{31, "http.NewRequest", PhaseDestructionDistribution, "Request created"},
	{32, "http.Client.Do", PhaseDestructionDistribution, "Response status per node"},
	{33, "tls.Config", PhaseDestructionDistribution, "TLS configured"},
	{34, "net.Dial", PhaseDestructionDistribution, "Connection established"},

	// Phase 5: Distributed Garbage Collection (10 functions)
	{35, "initiate_garbage_collection", PhaseGarbageCollection, "GC initiated"},
	{36, "secure_wipe_shard", PhaseGarbageCollection, "Shard ID, wipe status"},
	{37, "overwrite_storage", PhaseGarbageCollection, "Overwrite passes complete"},
	{38, "verify_data_unneeded", PhaseGarbageCollection, "Verification pass"},
	{39, "remove_dag_references", PhaseGarbageCollection, "References removed"},
	{40, "update_node_metadata", PhaseGarbageCollection, "Metadata updated"},
	{41, "sync.WaitGroup.Add", PhaseGarbageCollection, "Tasks added"},
	{42, "sync.WaitGroup.Wait", PhaseGarbageCollection, "All GC complete"},
	{43, "handle_identical_cleanup", PhaseGarbageCollection, "Timing variance <1ms"},
	{44, "prevent_pattern_analysis", PhaseGarbageCollection, "Order randomized"},

	// Phase 6: Destruction Confirmation & Verification (6 functions)
	{45, "confirm_destruction", PhaseDestructionConfirmation, "Confirmation received"},
	{46, "collect_destruction_receipts", PhaseDestructionConfirmation, "Receipts count"},
	{47, "verify_all_nodes_confirmed", PhaseDestructionConfirmation, "All nodes confirmed"},
	{48, "validate_destruction_complete", PhaseDestructionConfirmation, "Destruction verified"},
	{49, "bytes.Equal", PhaseDestructionConfirmation, "Hash match"},
	{50, "time.Since", PhaseDestructionConfirmation, "Duration in ms"},

	// Phase 7: Token & Metadata Cleanup (6 functions)
	{51, "invalidate_access_token", PhaseTokenCleanup, "Token invalidated"},
	{52, "remove_token_mapping", PhaseTokenCleanup, "Mapping removed"},
	{53, "delete_main_transaction", PhaseTokenCleanup, "Main TX deleted"},
	{54, "clear_metadata_references", PhaseTokenCleanup, "References cleared"},
	{55, "update_bundle_status", PhaseTokenCleanup, "Status updated"},
	{56, "LedgerTx.Record", PhaseTokenCleanup, "Ledger entry created"},

	// Phase 8: Memory Security & Local Cleanup (8 functions)
	{57, "secureWipe", PhaseMemoryCleanup, "Bytes wiped"},
	{58, "clear_local_cache", PhaseMemoryCleanup, "Cache cleared"},
	{59, "clear_metadata_buffers", PhaseMemoryCleanup, "Buffers cleared"},
	{60, "runtime.GC", PhaseMemoryCleanup, "GC triggered"},
	{61, "runtime.KeepAlive", PhaseMemoryCleanup, "Keep-alive applied"},
	{62, "MonitorMemoryUsage", PhaseMemoryCleanup, "Memory usage"},
	{63, "tryLockMemory", PhaseMemoryCleanup, "Memory verified"},
	{64, "syscall.Syscall", PhaseMemoryCleanup, "Syscall result"},

	// Phase 9: Audit Logging & Finalization (6 functions)
	{65, "create_log_entry", PhaseAudit, "Entry type: DESTROY, timestamp"},
	{66, "encrypt_log", PhaseAudit, "Encryption success"},
	{67, "anchor_log", PhaseAudit, "Anchor TX ID"},
	{68, "errors.New", PhaseAudit, "Error message"},
	{69, "fmt.Errorf", PhaseAudit, "Error details"},
	{70, "log.Printf", PhaseAudit, "Operation complete"},
}

// =============================================================================
// rotateKey Functions (126 total, 12 phases)
// Source: ROTATEKEY_FUNCTION_LIST.md
// =============================================================================

var RotateKeyFunctions = []FunctionDef{
	// Phase 1: Request Initialization & Interval Validation (10 functions)
	{1, "validate_access_token", PhaseTokenValidation, "Token hash (not token), validity status"},
	{2, "check_token_nonce", PhaseTokenValidation, "Nonce value, timestamp check result"},
	{3, "verify_interval", PhaseIntervalValidation, "Days since last rotation"},
	{4, "check_rotation_eligibility", PhaseIntervalValidation, "Eligibility status"},
	{5, "get_last_rotation_timestamp", PhaseIntervalValidation, "Last rotation date"},
	{6, "time.Now", PhaseIntervalValidation, "Timestamp value"},
	{7, "uuid.New", PhaseIntervalValidation, "Request UUID"},
	{8, "context.WithTimeout", PhaseIntervalValidation, "Timeout duration"},
	{9, "context.Background", PhaseIntervalValidation, "Context created"},
	{10, "calculate_jitter", PhaseIntervalValidation, "Jitter value applied"},

	// Phase 2: Ownership Verification via ZKP (10 functions)
	{11, "verify_ownership", PhaseOwnership, "Verification started"},
	{12, "generate_ownership_zkp", PhaseOwnership, "Proof type: ownership"},
	{13, "generate_nonce", PhaseOwnership, "Nonce generated"},
	{14, "gnark.Compile", PhaseOwnership, "Circuit compilation success"},
	{15, "gnark.Setup", PhaseOwnership, "Setup completion"},
	{16, "gnark.Prove", PhaseOwnership, "Proof generation success"},
	{17, "gnark.Verify", PhaseOwnership, "Verification result"},
	{18, "hash.Hash.Write", PhaseOwnership, "Bytes written"},
	{19, "hash.Hash.Sum", PhaseOwnership, "Hash finalized"},
	{20, "crypto/ed25519.Verify", PhaseOwnership, "Signature valid"},

	// Phase 3: Existing Shard Retrieval (14 functions)
	{21, "fetch_shards", PhaseShardRetrieval, "Shard count (real + decoy)"},
	{22, "fetch_main_tx", PhaseShardRetrieval, "Transaction ID retrieved"},
	{23, "iota.GetMessage", PhaseShardRetrieval, "Message retrieved"},
	{24, "parse_bundle_metadata", PhaseShardRetrieval, "Metadata structure valid"},
	{25, "extract_salt", PhaseShardRetrieval, "Salt extracted"},
	{26, "AES256GCMDecrypt", PhaseShardRetrieval, "Decryption success"},
	{27, "crypto/aes.NewCipher", PhaseShardRetrieval, "Cipher created"},
	{28, "crypto/cipher.NewGCM", PhaseShardRetrieval, "GCM initialized"},
	{29, "crypto/cipher.GCM.Open", PhaseShardRetrieval, "Decryption success"},
	{30, "json.Unmarshal", PhaseShardRetrieval, "JSON parsed"},
	{31, "extract_shard_ids", PhaseShardRetrieval, "Shard IDs extracted"},
	{32, "verify_shard_integrity", PhaseShardRetrieval, "Integrity verified"},
	{33, "parallel_fetch_shards", PhaseShardRetrieval, "All shards retrieved"},
	{34, "sync.WaitGroup.Wait", PhaseShardRetrieval, "Fetch complete"},

	// Phase 4: New Key Generation (12 functions)
	{35, "generate_new_salt", PhaseNewKeyGeneration, "New salt generated"},
	{36, "crypto/rand.Read", PhaseNewKeyGeneration, "Bytes generated (count only)"},
	{37, "derive_new_master_key", PhaseNewKeyGeneration, "Key derivation success"},
	{38, "DeriveHKDFKey", PhaseNewKeyGeneration, "Purpose parameter"},
	{39, "hkdf.New", PhaseNewKeyGeneration, "Hash function used"},
	{40, "sha256.New", PhaseNewKeyGeneration, "Instance created"},
	{41, "hkdf.Expand", PhaseNewKeyGeneration, "Output length"},
	{42, "derive_real_char_keys", PhaseNewKeyGeneration, "Key count"},
	{43, "derive_decoy_char_keys", PhaseNewKeyGeneration, "Key count"},
	{44, "base64.StdEncoding.EncodeToString", PhaseNewKeyGeneration, "Encoding success"},
	{45, "strconv.Itoa", PhaseNewKeyGeneration, "Conversions count"},
	{46, "strings.Join", PhaseNewKeyGeneration, "Info string created"},

	// Phase 5: Shard Re-Encryption (14 functions)
	{47, "reencrypt_shards", PhaseReEncryption, "Shards re-encrypted count"},
	{48, "decrypt_shard", PhaseReEncryption, "Shard decrypted"},
	{49, "AES256GCMDecrypt", PhaseReEncryption, "Decryption success"},
	{50, "AES256GCMEncrypt", PhaseReEncryption, "Encryption success"},
	{51, "crypto/aes.NewCipher", PhaseReEncryption, "Cipher created"},
	{52, "crypto/cipher.NewGCM", PhaseReEncryption, "GCM initialized"},
	{53, "crypto/cipher.GCM.Seal", PhaseReEncryption, "Ciphertext length"},
	{54, "generate_new_decoys", PhaseReEncryption, "Decoy count per tier"},
	{55, "encrypt_decoy_shard", PhaseReEncryption, "Decoy encrypted"},
	{56, "hmac.New", PhaseReEncryption, "HMAC instance created"},
	{57, "hmac.Sum", PhaseReEncryption, "HMAC computed"},
	{58, "generate_shard_zkp", PhaseReEncryption, "ZKP generated"},
	{59, "gnark.Prove", PhaseReEncryption, "Proof created"},
	{60, "append", PhaseReEncryption, "Shard appended"},

	// Phase 6: New Node Selection & Geographic Distribution (10 functions)
	{61, "select_new_nodes", PhaseNodeSelection, "Node count selected"},
	{62, "get_tier_copies", PhaseNodeSelection, "Copy count"},
	{63, "check_geographic_separation", PhaseNodeSelection, "Geographic diversity confirmed"},
	{64, "verify_node_reliability", PhaseNodeSelection, "Reliability scores"},
	{65, "check_shard_cap", PhaseNodeSelection, "Cap enforced"},
	{66, "exclude_previous_nodes", PhaseNodeSelection, "Previous nodes excluded"},
	{67, "calculate_latency_routing", PhaseNodeSelection, "Latency scores"},
	{68, "verify_node_capacity", PhaseNodeSelection, "Capacity confirmed"},
	{69, "randomize_node_selection", PhaseNodeSelection, "Selection randomized"},
	{70, "create_distribution_plan", PhaseNodeSelection, "Plan created"},

	// Phase 7: New Shard Submission to DAG (12 functions)
	{71, "assign_shards", PhaseDAGSubmission, "Assignment complete"},
	{72, "submit_to_dag", PhaseDAGSubmission, "Submission started"},
	{73, "iota.NewMessageBuilder", PhaseDAGSubmission, "Builder initialized"},
	{74, "iota.WithPayload", PhaseDAGSubmission, "Payload size"},
	{75, "iota.WithReferences", PhaseDAGSubmission, "References set"},
	{76, "iota.SubmitMessage", PhaseDAGSubmission, "Message ID"},
	{77, "collect_new_tx_ids", PhaseDAGSubmission, "TX IDs collected"},
	{78, "http.NewRequest", PhaseDAGSubmission, "Request created"},
	{79, "http.Client.Do", PhaseDAGSubmission, "Response status"},
	{80, "verify_submission_success", PhaseDAGSubmission, "All submissions confirmed"},
	{81, "tls.Config", PhaseDAGSubmission, "TLS configured"},
	{82, "net.Dial", PhaseDAGSubmission, "Connection established"},

	// Phase 8: Metadata Update & Version Increment (10 functions)
	{83, "update_metadata", PhaseMetadataUpdate, "Metadata updated"},
	{84, "increment_version", PhaseMetadataUpdate, "New version identifier"},
	{85, "create_new_main_tx", PhaseMetadataUpdate, "New main TX ID"},
	{86, "update_shard_references", PhaseMetadataUpdate, "References updated"},
	{87, "update_salt_in_metadata", PhaseMetadataUpdate, "Salt updated"},
	{88, "AES256GCMEncrypt", PhaseMetadataUpdate, "Metadata encrypted"},
	{89, "json.Marshal", PhaseMetadataUpdate, "JSON created"},
	{90, "iota.SubmitMessage", PhaseMetadataUpdate, "Main TX submitted"},
	{91, "generate_new_bundle_id", PhaseMetadataUpdate, "New bundle ID"},
	{92, "link_versions", PhaseMetadataUpdate, "Version chain updated"},

	// Phase 9: Token Rotation (8 functions)
	{93, "generate_new_access_token", PhaseTokenRotation, "New token generated"},
	{94, "crypto/rand.Read", PhaseTokenRotation, "Bytes generated"},
	{95, "encrypt_new_token", PhaseTokenRotation, "Token encrypted"},
	{96, "AES256GCMEncrypt", PhaseTokenRotation, "Encryption success"},
	{97, "invalidate_old_token", PhaseTokenRotation, "Old token invalidated"},
	{98, "store_token_mapping", PhaseTokenRotation, "Token stored"},
	{99, "commit_token_rotation", PhaseTokenRotation, "Rotation committed"},
	{100, "LedgerTx.Commit", PhaseTokenRotation, "Ledger commit success"},

	// Phase 10: Old Shard Garbage Collection (8 functions)
	{101, "garbage_collect", PhaseGarbageCollection, "GC initiated"},
	{102, "mark_for_deletion", PhaseGarbageCollection, "Shards marked count"},
	{103, "schedule_delayed_deletion", PhaseGarbageCollection, "Deletion scheduled"},
	{104, "time.AfterFunc", PhaseGarbageCollection, "Timer set"},
	{105, "secure_wipe_old_shards", PhaseGarbageCollection, "Old shards wiped"},
	{106, "remove_old_dag_references", PhaseGarbageCollection, "References removed"},
	{107, "handle_identical_cleanup", PhaseGarbageCollection, "Timing variance <1ms"},
	{108, "confirm_gc_scheduled", PhaseGarbageCollection, "GC confirmed"},

	// Phase 11: Memory Security & Local Cleanup (10 functions)
	{109, "secureWipe", PhaseMemoryCleanup, "Bytes wiped"},
	{110, "clear_old_keys", PhaseMemoryCleanup, "Old keys cleared"},
	{111, "clear_new_keys", PhaseMemoryCleanup, "New keys cleared"},
	{112, "clear_decrypted_shards", PhaseMemoryCleanup, "Shards cleared"},
	{113, "clear_metadata_buffers", PhaseMemoryCleanup, "Buffers cleared"},
	{114, "runtime.GC", PhaseMemoryCleanup, "GC triggered"},
	{115, "runtime.KeepAlive", PhaseMemoryCleanup, "Keep-alive applied"},
	{116, "MonitorMemoryUsage", PhaseMemoryCleanup, "Current memory usage"},
	{117, "tryLockMemory", PhaseMemoryCleanup, "Lock success/failure"},
	{118, "syscall.Syscall", PhaseMemoryCleanup, "Syscall result"},

	// Phase 12: Audit Logging & Finalization (8 functions)
	{119, "create_log_entry", PhaseAudit, "Entry type: ROTATE, timestamp"},
	{120, "encrypt_log", PhaseAudit, "Encryption success"},
	{121, "anchor_log", PhaseAudit, "Anchor TX ID"},
	{122, "record_rotation_timestamp", PhaseAudit, "Timestamp recorded"},
	{123, "errors.New", PhaseAudit, "Error message"},
	{124, "fmt.Errorf", PhaseAudit, "Error details"},
	{125, "log.Printf", PhaseAudit, "Operation complete"},
	{126, "return_new_bundle_id", PhaseAudit, "New bundle ID returned"},
}

// =============================================================================
// Helper functions for looking up function definitions
// =============================================================================

// GetStoreKeyFunction returns a storeKey function definition by ID (1-100)
func GetStoreKeyFunction(id int) *FunctionDef {
	if id < 1 || id > len(StoreKeyFunctions) {
		return nil
	}
	return &StoreKeyFunctions[id-1]
}

// GetRetrieveKeyFunction returns a retrieveKey function definition by ID (1-200)
func GetRetrieveKeyFunction(id int) *FunctionDef {
	if id < 1 || id > len(RetrieveKeyFunctions) {
		return nil
	}
	return &RetrieveKeyFunctions[id-1]
}

// GetDeleteKeyFunction returns a deleteKey function definition by ID (1-70)
func GetDeleteKeyFunction(id int) *FunctionDef {
	if id < 1 || id > len(DeleteKeyFunctions) {
		return nil
	}
	return &DeleteKeyFunctions[id-1]
}

// GetRotateKeyFunction returns a rotateKey function definition by ID (1-126)
func GetRotateKeyFunction(id int) *FunctionDef {
	if id < 1 || id > len(RotateKeyFunctions) {
		return nil
	}
	return &RotateKeyFunctions[id-1]
}

// GetFunctionsByPhase returns all functions for a given phase in a workflow
func GetFunctionsByPhase(functions []FunctionDef, phase string) []FunctionDef {
	var result []FunctionDef
	for _, f := range functions {
		if f.Phase == phase {
			result = append(result, f)
		}
	}
	return result
}

// GetAllFunctions returns all 496 function definitions
func GetAllFunctions() []FunctionDef {
	all := make([]FunctionDef, 0, 496)
	all = append(all, StoreKeyFunctions...)
	all = append(all, RetrieveKeyFunctions...)
	all = append(all, DeleteKeyFunctions...)
	all = append(all, RotateKeyFunctions...)
	return all
}
