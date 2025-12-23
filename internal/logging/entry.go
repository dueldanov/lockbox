package logging

import (
	"time"
)

// LockBoxLogEntry represents a single log entry for AI verification
// Format matches client requirements from STOREKEY_FUNCTION_LIST.md
type LockBoxLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Phase      string    `json:"phase"`
	Function   string    `json:"function"`
	Status     string    `json:"status"` // SUCCESS, FAILURE, WARNING
	DurationNs int64     `json:"duration_ns"`
	Details    string    `json:"details"`
	BundleID   string    `json:"bundle_id"`
}

// LockBoxReport is the complete verification report
type LockBoxReport struct {
	Workflow        string            `json:"workflow"` // storeKey, retrieveKey, deleteKey, rotateKey
	BundleID        string            `json:"bundle_id"`
	Tier            string            `json:"tier"`
	StartedAt       time.Time         `json:"started_at"`
	CompletedAt     time.Time         `json:"completed_at"`
	TotalDurationMs int64             `json:"total_duration_ms"`
	Entries         []LockBoxLogEntry `json:"entries"`
	Summary         LockBoxSummary    `json:"summary"`
}

// LockBoxSummary provides aggregate statistics
type LockBoxSummary struct {
	TotalSteps int            `json:"total_steps"`
	Passed     int            `json:"passed"`
	Failed     int            `json:"failed"`
	Phases     map[string]int `json:"phases"`
}

// Status constants
const (
	StatusSuccess = "SUCCESS"
	StatusFailure = "FAILURE"
	StatusWarning = "WARNING"
)

// Workflow names
const (
	WorkflowStoreKey    = "storeKey"
	WorkflowRetrieveKey = "retrieveKey"
	WorkflowDeleteKey   = "deleteKey"
	WorkflowRotateKey   = "rotateKey"
)

// Phase constants for storeKey (11 phases, 100 functions)
const (
	PhaseInputValidation   = "Input Validation & Configuration"
	PhaseKeyDerivation     = "Key Derivation"
	PhaseEncryption        = "Encryption Operations"
	PhaseDigitalSignatures = "Digital Signatures"
	PhaseSharding          = "Character Sharding & Decoy Generation"
	PhaseZKP               = "Zero-Knowledge Proof Generation"
	PhaseMetadata          = "Metadata Creation"
	PhaseNetworkSubmission = "Network Submission"
	PhaseConnection        = "Connection & Synchronization"
	PhaseMemorySecurity    = "Memory Security"
	PhaseAudit             = "Error Handling & Audit Logging"
)

// Additional phases for retrieveKey (14 phases, 200 functions)
const (
	PhaseTokenValidation    = "Request Initialization & Token Validation"
	PhasePayment            = "Payment Transaction Processing"
	PhaseOwnership          = "ZKP Generation & Ownership Proof"
	PhaseMultiSig           = "Multi-Signature Verification"
	PhaseCoordinator        = "Dual Coordinating Node Selection"
	PhaseTripleVerification = "Triple Verification Node Selection"
	PhaseBundleRetrieval    = "Bundle & Metadata Retrieval"
	PhaseShardFetch         = "Parallel Shard Fetching"
	PhaseKeyDerivationDecrypt = "Key Derivation for Decryption"
	PhaseShardDecryption    = "Shard Decryption & Real Character ID"
	PhaseKeyReconstruction  = "Key Reconstruction"
	PhaseTokenRotation      = "Token Rotation"
	PhaseMemoryCleanup      = "Memory Security & Cleanup"
)

// Additional phases for deleteKey (9 phases, 70 functions)
const (
	PhaseShardEnumeration        = "Shard Location & Enumeration"
	PhaseDestructionDistribution = "Destruction Request Distribution"
	PhaseGarbageCollection       = "Distributed Garbage Collection"
	PhaseDestructionConfirmation = "Destruction Confirmation & Verification"
	PhaseTokenCleanup            = "Token & Metadata Cleanup"
)

// Additional phases for rotateKey (12 phases, 126 functions)
const (
	PhaseIntervalValidation = "Request Initialization & Interval Validation"
	PhaseShardRetrieval     = "Existing Shard Retrieval"
	PhaseNewKeyGeneration   = "New Key Generation"
	PhaseReEncryption       = "Shard Re-Encryption"
	PhaseNodeSelection      = "New Node Selection & Geographic Distribution"
	PhaseDAGSubmission      = "New Shard Submission to DAG"
	PhaseMetadataUpdate     = "Metadata Update & Version Increment"
)
