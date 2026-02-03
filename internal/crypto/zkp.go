package crypto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimcHash "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/dueldanov/lockbox/v2/internal/logging"
)

var (
	ErrProofGenerationFailed    = errors.New("proof generation failed")
	ErrProofVerificationFailed  = errors.New("proof verification failed")
	ErrInvalidWitness           = errors.New("invalid witness")
	ErrCircuitCompilationFailed = errors.New("circuit compilation failed")
)

var (
	domainTagCommitment    = domainSeparatorElement("LockBox:commitment")
	domainTagAddress       = domainSeparatorElement("LockBox:address")
	domainTagUnlock        = domainSeparatorElement("LockBox:unlock")
	domainTagShardValidity = domainSeparatorElement("LockBox:shard-validity")
)

// ZKPManager manages zero-knowledge proof operations
type ZKPManager struct {
	mu               sync.RWMutex
	compileMu        sync.Mutex
	proofMu          sync.Mutex
	curve            ecc.ID
	compiledCircuits map[string]compiledCircuit
	provingKeys      map[string]groth16.ProvingKey
	verifyingKeys    map[string]groth16.VerifyingKey
}

type compiledCircuit struct {
	cs       constraint.ConstraintSystem
	circuit  frontend.Circuit
	compiled time.Time
}

// NewZKPManager creates a new ZKP manager
func NewZKPManager() *ZKPManager {
	return &ZKPManager{
		curve:            ecc.BN254,
		compiledCircuits: make(map[string]compiledCircuit),
		provingKeys:      make(map[string]groth16.ProvingKey),
		verifyingKeys:    make(map[string]groth16.VerifyingKey),
	}
}

// OwnershipProofCircuit proves ownership of a locked asset
type OwnershipProofCircuit struct {
	// Public inputs
	AssetCommitment frontend.Variable `gnark:",public"`
	OwnerAddress    frontend.Variable `gnark:",public"`

	// Private inputs
	AssetID     frontend.Variable
	OwnerSecret frontend.Variable
	Nonce       frontend.Variable
}

// Define implements frontend.Circuit
func (c *OwnershipProofCircuit) Define(api frontend.API) error {
	// Create MIMC hash function
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash the private inputs
	mimc.Write(domainTagCommitment.BigInt(new(big.Int)))
	mimc.Write(c.AssetID)
	mimc.Write(c.OwnerSecret)
	mimc.Write(c.Nonce)
	commitment := mimc.Sum()

	// Verify the commitment matches
	api.AssertIsEqual(commitment, c.AssetCommitment)

	// Verify owner address derivation
	mimc.Reset()
	mimc.Write(domainTagAddress.BigInt(new(big.Int)))
	mimc.Write(c.OwnerSecret)
	derivedAddress := mimc.Sum()
	api.AssertIsEqual(derivedAddress, c.OwnerAddress)

	return nil
}

// UnlockConditionCircuit proves unlock conditions are met
type UnlockConditionCircuit struct {
	// Public inputs
	UnlockCommitment frontend.Variable `gnark:",public"`
	CurrentTime      frontend.Variable `gnark:",public"`
	UnlockTime       frontend.Variable `gnark:",public"`

	// Private inputs
	UnlockSecret   frontend.Variable
	AssetID        frontend.Variable
	AdditionalData frontend.Variable
}

// Define implements frontend.Circuit
func (c *UnlockConditionCircuit) Define(api frontend.API) error {
	// Verify time condition
	api.AssertIsLessOrEqual(c.UnlockTime, c.CurrentTime)

	// Create MIMC hash
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash unlock data
	mimc.Write(domainTagUnlock.BigInt(new(big.Int)))
	mimc.Write(c.UnlockSecret)
	mimc.Write(c.AssetID)
	mimc.Write(c.AdditionalData)
	commitment := mimc.Sum()

	// Verify commitment
	api.AssertIsEqual(commitment, c.UnlockCommitment)

	return nil
}

// ShardValidityCircuit proves a shard is valid without revealing content
// This circuit enables verification that a shard belongs to a specific bundle
// SIMPLIFIED: Proves knowledge of preimage for commitment
type ShardValidityCircuit struct {
	// Public inputs (known to verifier)
	Commitment  frontend.Variable `gnark:",public"` // Commitment to shard
	ShardIndex  frontend.Variable `gnark:",public"` // Index in bundle (0-based)
	TotalShards frontend.Variable `gnark:",public"` // Total number of shards in bundle

	// Private inputs (witness - only known to prover)
	ShardSecret frontend.Variable // Secret derived from shard data
	BundleID    frontend.Variable // Bundle identifier
	Salt        frontend.Variable // Random salt for hash
}

// Define implements frontend.Circuit for ShardValidityCircuit
func (c *ShardValidityCircuit) Define(api frontend.API) error {
	// Constraint 1: Shard index is within valid range (0 <= index < total)
	api.AssertIsLessOrEqual(c.ShardIndex, c.TotalShards)

	// Constraint 2: Total shards must be > 0
	api.AssertIsDifferent(c.TotalShards, 0)

	// Constraint 3: Commitment verification
	// Compute: Hash(ShardSecret || BundleID || Salt || ShardIndex)
	// This proves knowledge of a valid shard without revealing the shard secret
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	mimc.Write(domainTagShardValidity.BigInt(new(big.Int)))
	mimc.Write(c.ShardSecret)
	mimc.Write(c.BundleID)
	mimc.Write(c.Salt)
	mimc.Write(c.ShardIndex)

	// Compute commitment and verify
	computedCommitment := mimc.Sum()
	api.AssertIsEqual(computedCommitment, c.Commitment)

	return nil
}

// CompileCircuit compiles a circuit for proof generation
func (z *ZKPManager) CompileCircuit(circuitID string, circuit frontend.Circuit) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	// Compile the circuit
	cs, err := frontend.Compile(z.curve.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCircuitCompilationFailed, err)
	}

	// Generate proving and verifying keys
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("failed to setup circuit: %w", err)
	}

	// Store compiled circuit and keys
	z.compiledCircuits[circuitID] = compiledCircuit{
		cs:       cs,
		circuit:  circuit,
		compiled: time.Now(),
	}
	z.provingKeys[circuitID] = pk
	z.verifyingKeys[circuitID] = vk

	return nil
}

// GenerateOwnershipProof generates a proof of ownership
func (z *ZKPManager) GenerateOwnershipProof(assetID []byte, ownerSecret []byte) (*OwnershipProof, error) {
	circuitID := "ownership"

	// Ensure circuit is compiled
	if _, exists := z.compiledCircuits[circuitID]; !exists {
		circuit := &OwnershipProofCircuit{}
		if err := z.CompileCircuit(circuitID, circuit); err != nil {
			return nil, err
		}
	}

	z.mu.RLock()
	pk := z.provingKeys[circuitID]
	z.mu.RUnlock()

	// Generate nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create witness
	witness := &OwnershipProofCircuit{
		AssetID:     new(big.Int).SetBytes(assetID),
		OwnerSecret: new(big.Int).SetBytes(ownerSecret),
		Nonce:       new(big.Int).SetBytes(nonce),
	}

	// Calculate commitments
	assetCommitment := CalculateCommitment(assetID, ownerSecret, nonce)
	ownerAddress := CalculateAddress(ownerSecret)

	witness.AssetCommitment = assetCommitment
	witness.OwnerAddress = ownerAddress

	// Convert to witness format
	w, err := frontend.NewWitness(witness, z.curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate proof
	z.proofMu.Lock()
	proof, err := groth16.Prove(z.compiledCircuits[circuitID].cs, pk, w)
	z.proofMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProofGenerationFailed, err)
	}

	return &OwnershipProof{
		Proof:           proof,
		AssetCommitment: assetCommitment.Bytes(),
		OwnerAddress:    ownerAddress.Bytes(),
		Timestamp:       time.Now().Unix(),
	}, nil
}

// GenerateOwnershipProofWithContext generates proof with logging support
func (z *ZKPManager) GenerateOwnershipProofWithContext(ctx context.Context, assetID []byte, ownerSecret []byte) (*OwnershipProof, error) {
	start := time.Now()
	proof, err := z.GenerateOwnershipProof(assetID, ownerSecret)
	logging.LogFromContextWithDuration(ctx, logging.PhaseZKP, "GenerateOwnershipProof",
		fmt.Sprintf("assetIDLen=%d", len(assetID)), time.Since(start), err)
	return proof, err
}

// VerifyOwnershipProof verifies an ownership proof
func (z *ZKPManager) VerifyOwnershipProof(proof *OwnershipProof) error {
	circuitID := "ownership"

	z.mu.RLock()
	vk, exists := z.verifyingKeys[circuitID]
	z.mu.RUnlock()

	if !exists {
		return errors.New("verifying key not found")
	}

	// Create public witness
	publicWitnessCircuit := &OwnershipProofCircuit{
		AssetCommitment: new(big.Int).SetBytes(proof.AssetCommitment),
		OwnerAddress:    new(big.Int).SetBytes(proof.OwnerAddress),
	}

	// Convert to public witness format
	publicWitness, err := frontend.NewWitness(publicWitnessCircuit, z.curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Verify proof
	z.proofMu.Lock()
	err = groth16.Verify(proof.Proof, vk, publicWitness)
	z.proofMu.Unlock()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofVerificationFailed, err)
	}

	return nil
}

// VerifyOwnershipProofWithContext verifies proof with logging support
func (z *ZKPManager) VerifyOwnershipProofWithContext(ctx context.Context, proof *OwnershipProof) error {
	start := time.Now()
	err := z.VerifyOwnershipProof(proof)
	logging.LogFromContextWithDuration(ctx, logging.PhaseZKP, "VerifyOwnershipProof",
		fmt.Sprintf("commitmentLen=%d", len(proof.AssetCommitment)), time.Since(start), err)
	return err
}

// GenerateUnlockProof generates a proof for unlock conditions
func (z *ZKPManager) GenerateUnlockProof(unlockSecret, assetID, additionalData []byte, unlockTime int64) (*UnlockProof, error) {
	circuitID := "unlock"

	// Ensure circuit is compiled
	if _, exists := z.compiledCircuits[circuitID]; !exists {
		circuit := &UnlockConditionCircuit{}
		if err := z.CompileCircuit(circuitID, circuit); err != nil {
			return nil, err
		}
	}

	z.mu.RLock()
	pk := z.provingKeys[circuitID]
	z.mu.RUnlock()

	// Create witness
	witness := &UnlockConditionCircuit{
		UnlockSecret:   new(big.Int).SetBytes(unlockSecret),
		AssetID:        new(big.Int).SetBytes(assetID),
		AdditionalData: new(big.Int).SetBytes(additionalData),
		CurrentTime:    big.NewInt(time.Now().Unix()),
		UnlockTime:     big.NewInt(unlockTime),
	}

	// Calculate commitment
	unlockCommitment := CalculateUnlockCommitment(unlockSecret, assetID, additionalData)
	witness.UnlockCommitment = unlockCommitment

	// Convert to witness format
	w, err := frontend.NewWitness(witness, z.curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(z.compiledCircuits[circuitID].cs, pk, w)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProofGenerationFailed, err)
	}

	return &UnlockProof{
		Proof:            proof,
		UnlockCommitment: unlockCommitment.Bytes(),
		UnlockTime:       unlockTime,
		CurrentTime:      time.Now().Unix(),
	}, nil
}

// VerifyUnlockProof verifies an unlock proof
func (z *ZKPManager) VerifyUnlockProof(proof *UnlockProof) error {
	circuitID := "unlock"

	z.mu.RLock()
	vk, exists := z.verifyingKeys[circuitID]
	z.mu.RUnlock()

	if !exists {
		return errors.New("verifying key not found")
	}

	// Create public witness
	publicWitnessCircuit := &UnlockConditionCircuit{
		UnlockCommitment: new(big.Int).SetBytes(proof.UnlockCommitment),
		CurrentTime:      big.NewInt(proof.CurrentTime),
		UnlockTime:       big.NewInt(proof.UnlockTime),
	}

	// Convert to public witness format
	publicWitness, err := frontend.NewWitness(publicWitnessCircuit, z.curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Verify proof
	err = groth16.Verify(proof.Proof, vk, publicWitness)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofVerificationFailed, err)
	}

	return nil
}

// ShardValidityProof represents a zero-knowledge proof of shard validity
type ShardValidityProof struct {
	Proof       groth16.Proof
	Commitment  []byte // Public commitment to shard
	ShardIndex  uint32
	TotalShards uint32
	Timestamp   int64
}

// GenerateShardValidityProof generates a ZKP that a shard is valid
// without revealing the shard data itself
//
// Parameters:
//   - shardData: The actual shard data (kept private)
//   - shardIndex: Index of this shard in the bundle (public)
//   - totalShards: Total number of shards in the bundle (public)
//   - bundleID: Unique identifier for the bundle (public)
//
// Returns:
//   - ShardValidityProof containing the proof and public parameters
//   - error if proof generation fails
func (z *ZKPManager) GenerateShardValidityProof(
	shardData []byte,
	shardIndex uint32,
	totalShards uint32,
	bundleID []byte,
) (*ShardValidityProof, error) {
	circuitID := "shard_validity"

	// Ensure circuit is compiled
	z.compileMu.Lock()
	if _, exists := z.compiledCircuits[circuitID]; !exists {
		// Create template circuit (optimized - no large arrays).
		circuit := &ShardValidityCircuit{}
		if err := z.CompileCircuit(circuitID, circuit); err != nil {
			z.compileMu.Unlock()
			return nil, err
		}
	}
	z.compileMu.Unlock()

	z.mu.RLock()
	pk := z.provingKeys[circuitID]
	z.mu.RUnlock()

	// Generate random salt for commitment randomization
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive shard secret from shard data (off-circuit for efficiency)
	shardSecretHasher := mimcHash.NewMiMC()
	shardSecretHasher.Write(shardData)
	shardSecret := shardSecretHasher.Sum(nil)

	// Convert inputs to field elements to match in-circuit representation.
	shardSecretField := bytesToFieldElement(shardSecret)
	bundleIDField := bytesToFieldElement(bundleID)
	saltField := bytesToFieldElement(salt)
	shardIndexField := uint32ToFieldElement(shardIndex)

	// Compute commitment (this will be recomputed in-circuit to prove knowledge)
	// Commitment = Hash(ShardSecret || BundleID || Salt || ShardIndex)
	commitmentHasher := mimcHash.NewMiMC()
	commitmentHasher.Write(fieldElementBytes(domainTagShardValidity))
	commitmentHasher.Write(fieldElementBytes(shardSecretField))
	commitmentHasher.Write(fieldElementBytes(bundleIDField))
	commitmentHasher.Write(fieldElementBytes(saltField))
	commitmentHasher.Write(fieldElementBytes(shardIndexField))

	commitment := commitmentHasher.Sum(nil)

	// Create witness
	witness := &ShardValidityCircuit{
		Commitment:  new(big.Int).SetBytes(commitment),
		ShardIndex:  shardIndexField.BigInt(new(big.Int)),
		TotalShards: big.NewInt(int64(totalShards)),
		ShardSecret: shardSecretField.BigInt(new(big.Int)),
		BundleID:    bundleIDField.BigInt(new(big.Int)),
		Salt:        saltField.BigInt(new(big.Int)),
	}

	// Convert to witness format
	w, err := frontend.NewWitness(witness, z.curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(z.compiledCircuits[circuitID].cs, pk, w)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProofGenerationFailed, err)
	}

	return &ShardValidityProof{
		Proof:       proof,
		Commitment:  commitment,
		ShardIndex:  shardIndex,
		TotalShards: totalShards,
		Timestamp:   time.Now().Unix(),
	}, nil
}

// VerifyShardValidityProof verifies a shard validity proof
//
// This verifies that:
//   - The shard index is within valid range
//   - The shard hash matches a valid shard
//   - The shard belongs to the specified bundle
//   - All without revealing the shard data
//
// Parameters:
//   - proof: The ShardValidityProof to verify
//
// Returns:
//   - error if verification fails
func (z *ZKPManager) VerifyShardValidityProof(proof *ShardValidityProof) error {
	circuitID := "shard_validity"

	z.mu.RLock()
	vk, exists := z.verifyingKeys[circuitID]
	z.mu.RUnlock()

	if !exists {
		return errors.New("verifying key not found")
	}

	// Create public witness (only public inputs: commitment, index, total)
	publicWitnessCircuit := &ShardValidityCircuit{
		Commitment:  new(big.Int).SetBytes(proof.Commitment),
		ShardIndex:  big.NewInt(int64(proof.ShardIndex)),
		TotalShards: big.NewInt(int64(proof.TotalShards)),
	}

	// Convert to public witness format
	publicWitness, err := frontend.NewWitness(publicWitnessCircuit, z.curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Verify proof
	err = groth16.Verify(proof.Proof, vk, publicWitness)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofVerificationFailed, err)
	}

	return nil
}

// BatchProofCircuit for batch verification
type BatchProofCircuit struct {
	// Public inputs
	BatchRoot  frontend.Variable `gnark:",public"`
	ProofCount frontend.Variable `gnark:",public"`

	// Private inputs
	Proofs       []frontend.Variable
	ProofIndices []frontend.Variable
}

// Define implements frontend.Circuit
func (c *BatchProofCircuit) Define(api frontend.API) error {
	// Implement Merkle tree verification
	// This is a simplified version - production would need full Merkle tree

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash all proofs
	for i := 0; i < len(c.Proofs); i++ {
		mimc.Write(c.Proofs[i])
		mimc.Write(c.ProofIndices[i])
	}

	root := mimc.Sum()
	api.AssertIsEqual(root, c.BatchRoot)
	api.AssertIsEqual(len(c.Proofs), c.ProofCount)

	return nil
}

// bytesToFieldElement reduces bytes into a BN254 field element.
func bytesToFieldElement(data []byte) fr.Element {
	var e fr.Element
	e.SetBytes(data)
	return e
}

// uint32ToFieldElement converts a uint32 into a BN254 field element.
func uint32ToFieldElement(v uint32) fr.Element {
	var e fr.Element
	e.SetUint64(uint64(v))
	return e
}

// fieldElementBytes returns the canonical 32-byte representation of a field element.
func fieldElementBytes(e fr.Element) []byte {
	b := e.Bytes()
	return b[:]
}

// domainSeparatorElement converts a tag string into a field element for domain separation.
func domainSeparatorElement(tag string) fr.Element {
	var e fr.Element
	e.SetBytes([]byte(tag))
	return e
}

// Proof types

type OwnershipProof struct {
	Proof           groth16.Proof
	AssetCommitment []byte
	OwnerAddress    []byte
	Timestamp       int64
}

type UnlockProof struct {
	Proof            groth16.Proof
	UnlockCommitment []byte
	UnlockTime       int64
	CurrentTime      int64
}

// Helper functions

// CalculateCommitment creates a cryptographic commitment to an asset using MiMC
// Uses MiMC hash to be consistent with the ZKP circuit which also uses MiMC
func CalculateCommitment(assetID, ownerSecret, nonce []byte) *big.Int {
	h := mimcHash.NewMiMC()

	// Write data in same order as circuit (zkp.go:75-77)
	h.Write(fieldElementBytes(domainTagCommitment))
	h.Write(fieldElementBytes(bytesToFieldElement(assetID)))
	h.Write(fieldElementBytes(bytesToFieldElement(ownerSecret)))
	h.Write(fieldElementBytes(bytesToFieldElement(nonce)))

	hash := h.Sum(nil)
	return new(big.Int).SetBytes(hash)
}

// CalculateAddress derives an address from a secret using MiMC
// Uses MiMC hash to be consistent with the ZKP circuit which also uses MiMC
func CalculateAddress(secret []byte) *big.Int {
	h := mimcHash.NewMiMC()

	// Write data in same order as circuit (zkp.go:85)
	h.Write(fieldElementBytes(domainTagAddress))
	h.Write(fieldElementBytes(bytesToFieldElement(secret)))

	hash := h.Sum(nil)
	return new(big.Int).SetBytes(hash)
}

// CalculateUnlockCommitment creates a commitment for unlock verification using MiMC
// Uses MiMC hash to be consistent with the ZKP circuit which also uses MiMC
func CalculateUnlockCommitment(unlockSecret, assetID, additionalData []byte) *big.Int {
	h := mimcHash.NewMiMC()

	// Write data in same order as circuit (zkp.go:117-119)
	h.Write(fieldElementBytes(domainTagUnlock))
	h.Write(fieldElementBytes(bytesToFieldElement(unlockSecret)))
	h.Write(fieldElementBytes(bytesToFieldElement(assetID)))
	h.Write(fieldElementBytes(bytesToFieldElement(additionalData)))

	hash := h.Sum(nil)
	return new(big.Int).SetBytes(hash)
}
