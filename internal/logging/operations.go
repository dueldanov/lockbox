// Package logging provides operation-specific logging helpers.
package logging

import (
	"fmt"
	"time"
)

// StoreKeyLogger is a specialized logger for storeKey operations.
type StoreKeyLogger struct {
	*OperationLogger
}

// NewStoreKeyLogger creates a logger for storeKey operation.
func NewStoreKeyLogger(bundleID, requestID string) *StoreKeyLogger {
	return &StoreKeyLogger{
		OperationLogger: NewOperationLogger(OpStoreKey, bundleID, requestID),
	}
}

// Phase 1: Input Validation
func (l *StoreKeyLogger) LogValidateLength(duration time.Duration, inputLen int, passed bool) {
	status := StatusSuccess
	if !passed {
		status = StatusFailure
	}
	l.Log(PhaseInputValidation, "validate_length()", status, duration,
		formatDetails("input_length", inputLen, "passed", passed))
}

func (l *StoreKeyLogger) LogSetTierConfig(duration time.Duration, tier string, decoyRatio float64) {
	l.Log(PhaseInputValidation, "set_tier_config()", StatusSuccess, duration,
		formatDetails("tier", tier, "decoy_ratio", decoyRatio))
}

func (l *StoreKeyLogger) LogGenerateBundleID(duration time.Duration, bundleID string) {
	l.Log(PhaseInputValidation, "generate_bundle_id()", StatusSuccess, duration,
		formatDetails("bundle_id", bundleID))
}

// Phase 2: Key Derivation
func (l *StoreKeyLogger) LogDeriveHKDFKey(duration time.Duration, purpose string) {
	l.Log(PhaseKeyDerivation, "DeriveHKDFKey()", StatusSuccess, duration,
		formatDetails("purpose", purpose))
}

func (l *StoreKeyLogger) LogDeriveKey(duration time.Duration, shardIndex int, purpose string) {
	l.Log(PhaseKeyDerivation, "derive_key()", StatusSuccess, duration,
		formatDetails("shard_index", shardIndex, "purpose", purpose))
}

// Phase 3: Encryption
func (l *StoreKeyLogger) LogEncrypt(duration time.Duration, dataType string, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
		l.SecurityAlert(PhaseEncryption, "XChaCha20Poly1305Encrypt()", "Encryption failed for "+dataType)
	}
	l.Log(PhaseEncryption, "XChaCha20Poly1305Encrypt()", status, duration,
		formatDetails("data_type", dataType))
}

func (l *StoreKeyLogger) LogHMAC(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseEncryption, "hmac.Sum()", status, duration, "")
}

// Phase 4: Signatures
func (l *StoreKeyLogger) LogGenerateKeyPair(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseDigitalSignatures, "ed25519.GenerateKey()", status, duration, "")
}

func (l *StoreKeyLogger) LogSign(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseDigitalSignatures, "ed25519.Sign()", status, duration, "")
}

// Phase 5: Sharding
func (l *StoreKeyLogger) LogSplitKey(duration time.Duration, totalShards int) {
	l.Log(PhaseSharding, "splitKeyWithKeysAndDecoys()", StatusSuccess, duration,
		formatDetails("total_shards", totalShards))
}

func (l *StoreKeyLogger) LogCreateDecoys(duration time.Duration, decoyCount int, ratio float64) {
	l.Log(PhaseSharding, "create_decoys()", StatusSuccess, duration,
		formatDetails("decoy_count", decoyCount, "ratio", ratio))
}

func (l *StoreKeyLogger) LogShuffle(duration time.Duration) {
	l.Log(PhaseSharding, "shuffle()", StatusSuccess, duration, "")
}

// Phase 6: ZKP
func (l *StoreKeyLogger) LogGenerateZKP(duration time.Duration, proofType string, tier string, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseZKP, "generate_zkp()", status, duration,
		formatDetails("proof_type", proofType, "tier", tier))
}

func (l *StoreKeyLogger) LogCompileCircuit(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseZKP, "gnark.Compile()", status, duration, "")
}

func (l *StoreKeyLogger) LogProve(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseZKP, "gnark.Prove()", status, duration, "")
}

// Phase 7: Metadata
func (l *StoreKeyLogger) LogCreateMetadata(duration time.Duration, fragmentCount int) {
	l.Log(PhaseMetadata, "createMetadataFragmentsWithKey()", StatusSuccess, duration,
		formatDetails("fragment_count", fragmentCount))
}

func (l *StoreKeyLogger) LogJSONMarshal(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseMetadata, "json.Marshal()", status, duration, "")
}

// Phase 8: Network
func (l *StoreKeyLogger) LogSubmitBundle(duration time.Duration, nodeCount int, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.LogWithExtras(PhaseNetworkSubmission, "SubmitBundle()", status, duration,
		map[string]interface{}{"nodes_selected": nodeCount})
}

func (l *StoreKeyLogger) LogSubmitMessage(duration time.Duration, messageID string, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseNetworkSubmission, "iota.SubmitMessage()", status, duration,
		formatDetails("message_id", messageID))
}

// Phase 10: Memory Security
func (l *StoreKeyLogger) LogSecureWipe(duration time.Duration, bytesWiped int, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
		l.SecurityAlert(PhaseMemorySecurity, "secureWipe()", "Memory wipe failed")
	}
	l.Log(PhaseMemorySecurity, "secureWipe()", status, duration,
		formatDetails("bytes_wiped", bytesWiped))
}

func (l *StoreKeyLogger) LogMemoryLock(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusWarning
		l.SecurityAlert(PhaseMemorySecurity, "tryLockMemory()", "Memory lock failed")
	}
	l.Log(PhaseMemorySecurity, "tryLockMemory()", status, duration, "")
}

// Phase 11: Audit
func (l *StoreKeyLogger) LogCreateAuditEntry(duration time.Duration, entryType string) {
	l.Log(PhaseAudit, "create_log_entry()", StatusSuccess, duration,
		formatDetails("entry_type", entryType))
}

func (l *StoreKeyLogger) LogAnchorToBlockchain(duration time.Duration, anchorTxID string, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusWarning
	}
	l.Log(PhaseAudit, "anchor_log()", status, duration,
		formatDetails("anchor_tx_id", anchorTxID))
}

// RetrieveKeyLogger is a specialized logger for retrieveKey operations.
type RetrieveKeyLogger struct {
	*OperationLogger
}

// NewRetrieveKeyLogger creates a logger for retrieveKey operation.
func NewRetrieveKeyLogger(bundleID, requestID string) *RetrieveKeyLogger {
	return &RetrieveKeyLogger{
		OperationLogger: NewOperationLogger(OpRetrieveKey, bundleID, requestID),
	}
}

// Phase 1: Token Validation
func (l *RetrieveKeyLogger) LogValidateAccessToken(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseTokenValidation, "validate_access_token()", status, duration, "")
}

func (l *RetrieveKeyLogger) LogCheckTokenNonce(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseTokenValidation, "check_token_nonce()", status, duration, "")
}

// Phase 2: Payment
func (l *RetrieveKeyLogger) LogValidatePayment(duration time.Duration, paymentType string, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhasePayment, "validate_payment_tx()", status, duration,
		formatDetails("payment_type", paymentType))
}

func (l *RetrieveKeyLogger) LogCalculateFee(duration time.Duration, feeAmount float64, currency string) {
	l.Log(PhasePayment, "calculate_retrieval_fee()", StatusSuccess, duration,
		formatDetails("fee_amount", feeAmount, "currency", currency))
}

func (l *RetrieveKeyLogger) LogRecordRevenueShare(duration time.Duration, providerID string, shareAmount float64) {
	l.Log(PhasePayment, "record_revenue_share()", StatusSuccess, duration,
		formatDetails("provider_id", providerID, "share_amount", shareAmount))
}

// Phase 3: ZKP Ownership
func (l *RetrieveKeyLogger) LogGenerateOwnershipZKP(duration time.Duration, proofType string, tier string, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseOwnership, "generate_ownership_zkp()", status, duration,
		formatDetails("proof_type", proofType, "tier", tier))
}

func (l *RetrieveKeyLogger) LogVerifyOwnershipZKP(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseOwnership, "gnark.Verify()", status, duration, "")
}

// Phase 4: Multi-sig
func (l *RetrieveKeyLogger) LogCheckMultiSig(duration time.Duration, required bool) {
	l.Log(PhaseMultiSig, "check_multisig_required()", StatusSuccess, duration,
		formatDetails("multi_sig_required", required))
}

func (l *RetrieveKeyLogger) LogVerifyThreshold(duration time.Duration, collected int, required int, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseMultiSig, "verify_threshold_zkp()", status, duration,
		formatDetails("collected", collected, "required", required))
}

// Phase 7: Bundle Retrieval
func (l *RetrieveKeyLogger) LogFetchMainTx(duration time.Duration, txID string, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseBundleRetrieval, "fetch_main_tx()", status, duration,
		formatDetails("tx_id", txID))
}

func (l *RetrieveKeyLogger) LogDecryptMetadata(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseBundleRetrieval, "XChaCha20Poly1305Decrypt()", status, duration, "")
}

// Phase 8: Shard Fetching
func (l *RetrieveKeyLogger) LogParallelFetch(duration time.Duration, shardCount int, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.LogWithExtras(PhaseShardFetch, "initiate_parallel_fetch()", status, duration,
		map[string]interface{}{"shards_count": shardCount})
}

func (l *RetrieveKeyLogger) LogFetchShard(duration time.Duration, shardID string, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseShardFetch, "fetch_shard()", status, duration,
		formatDetails("shard_id", shardID))
}

// Phase 11: Key Reconstruction
func (l *RetrieveKeyLogger) LogOrderCharacters(duration time.Duration) {
	l.Log(PhaseKeyReconstruction, "order_characters()", StatusSuccess, duration, "")
}

func (l *RetrieveKeyLogger) LogAssembleKey(duration time.Duration, keyLen int, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseKeyReconstruction, "assemble_chars()", status, duration,
		formatDetails("key_length", keyLen))
}

// Phase 12: Token Rotation
func (l *RetrieveKeyLogger) LogGenerateNewToken(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseTokenRotation, "generate_new_access_token()", status, duration, "")
}

func (l *RetrieveKeyLogger) LogInvalidateOldToken(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseTokenRotation, "invalidate_old_token()", status, duration, "")
}

// RotateKeyLogger is a specialized logger for rotateKey operations.
type RotateKeyLogger struct {
	*OperationLogger
	oldBundleID string
	newBundleID string
}

// NewRotateKeyLogger creates a logger for rotateKey operation.
func NewRotateKeyLogger(oldBundleID, requestID string) *RotateKeyLogger {
	return &RotateKeyLogger{
		OperationLogger: NewOperationLogger(OpRotateKey, oldBundleID, requestID),
		oldBundleID:     oldBundleID,
	}
}

// SetNewBundleID sets the new bundle ID after rotation.
func (l *RotateKeyLogger) SetNewBundleID(newBundleID string) {
	l.newBundleID = newBundleID
}

func (l *RotateKeyLogger) LogVerifyInterval(duration time.Duration, daysSinceLast int, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseIntervalValidation, "verify_interval()", status, duration,
		formatDetails("days_since_last", daysSinceLast))
}

func (l *RotateKeyLogger) LogReencryptShards(duration time.Duration, shardCount int, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.LogWithExtras(PhaseReEncryption, "reencrypt_shards()", status, duration,
		map[string]interface{}{"shards_count": shardCount})
}

func (l *RotateKeyLogger) LogIncrementVersion(duration time.Duration, versionFrom, versionTo string) {
	l.LogWithExtras(PhaseMetadataUpdate, "increment_version()", StatusSuccess, duration,
		map[string]interface{}{"version_from": versionFrom, "version_to": versionTo})
}

func (l *RotateKeyLogger) LogGarbageCollect(duration time.Duration, scheduled bool) {
	status := StatusSuccess
	if !scheduled {
		status = StatusWarning
	}
	l.Log(PhaseGarbageCollection, "garbage_collect()", status, duration, "")
}

// DeleteKeyLogger is a specialized logger for deleteKey operations.
type DeleteKeyLogger struct {
	*OperationLogger
}

// NewDeleteKeyLogger creates a logger for deleteKey operation.
func NewDeleteKeyLogger(bundleID, requestID string) *DeleteKeyLogger {
	return &DeleteKeyLogger{
		OperationLogger: NewOperationLogger(OpDeleteKey, bundleID, requestID),
	}
}

func (l *DeleteKeyLogger) LogEnumerateShards(duration time.Duration, shardCount int) {
	l.LogWithExtras(PhaseShardEnumeration, "fetch_shards()", StatusSuccess, duration,
		map[string]interface{}{"shards_count": shardCount})
}

func (l *DeleteKeyLogger) LogDistributeDestruction(duration time.Duration, nodeCount int, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.LogWithExtras(PhaseDestructionDistribution, "distribute_to_nodes()", status, duration,
		map[string]interface{}{"nodes_affected": nodeCount})
}

func (l *DeleteKeyLogger) LogConfirmDestruction(duration time.Duration, allConfirmed bool) {
	status := StatusSuccess
	if !allConfirmed {
		status = StatusFailure
	}
	l.Log(PhaseDestructionConfirmation, "confirm_destruction()", status, duration, "")
}

func (l *DeleteKeyLogger) LogCleanupTokens(duration time.Duration, success bool) {
	status := StatusSuccess
	if !success {
		status = StatusFailure
	}
	l.Log(PhaseTokenCleanup, "invalidate_access_token()", status, duration, "")
}

// Helper to format details as string
func formatDetails(keyvals ...interface{}) string {
	if len(keyvals) == 0 {
		return ""
	}
	result := ""
	for i := 0; i < len(keyvals)-1; i += 2 {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("%v=%v", keyvals[i], keyvals[i+1])
	}
	return result
}
