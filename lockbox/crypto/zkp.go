package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

var (
	ErrProofGenerationFailed   = errors.New("proof generation failed")
	ErrProofVerificationFailed = errors.New("proof verification failed")
	ErrInvalidWitness          = errors.New("invalid witness")
	ErrCircuitCompilationFailed = errors.New("circuit compilation failed")
)

// ZKPManager manages zero-knowledge proof operations
type ZKPManager struct {
	mu              sync.RWMutex
	curve           ecc.ID
	compiledCircuits map[string]compiledCircuit
	provingKeys     map[string]groth16.ProvingKey
	verifyingKeys   map[string]groth16.VerifyingKey
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
	AssetID      frontend.Variable
	OwnerSecret  frontend.Variable
	Nonce        frontend.Variable
}

// Define implements frontend.Circuit
func (c *OwnershipProofCircuit) Define(api frontend.API) error {
	// Create MIMC hash function
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash the private inputs
	mimc.Write(c.AssetID)
	mimc.Write(c.OwnerSecret)
	mimc.Write(c.Nonce)
	commitment := mimc.Sum()

	// Verify the commitment matches
	api.AssertIsEqual(commitment, c.AssetCommitment)

	// Verify owner address derivation
	mimc.Reset()
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
	UnlockSecret     frontend.Variable
	AssetID          frontend.Variable
	AdditionalData   frontend.Variable
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
	mimc.Write(c.UnlockSecret)
	mimc.Write(c.AssetID)
	mimc.Write(c.AdditionalData)
	commitment := mimc.Sum()

	// Verify commitment
	api.AssertIsEqual(commitment, c.UnlockCommitment)

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
	assetCommitment := calculateCommitment(assetID, ownerSecret, nonce)
	ownerAddress := calculateAddress(ownerSecret)

	witness.AssetCommitment = assetCommitment
	witness.OwnerAddress = ownerAddress

	// Generate proof
	proof, err := groth16.Prove(z.compiledCircuits[circuitID].cs, pk, witness)
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
	publicWitness := &OwnershipProofCircuit{
		AssetCommitment: new(big.Int).SetBytes(proof.AssetCommitment),
		OwnerAddress:    new(big.Int).SetBytes(proof.OwnerAddress),
	}

	// Verify proof
	err := groth16.Verify(proof.Proof, vk, publicWitness)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofVerificationFailed, err)
	}

	return nil
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
	unlockCommitment := calculateUnlockCommitment(unlockSecret, assetID, additionalData)
	witness.UnlockCommitment = unlockCommitment

	// Generate proof
	proof, err := groth16.Prove(z.compiledCircuits[circuitID].cs, pk, witness)
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
	publicWitness := &UnlockConditionCircuit{
		UnlockCommitment: new(big.Int).SetBytes(proof.UnlockCommitment),
		CurrentTime:      big.NewInt(proof.CurrentTime),
		UnlockTime:       big.NewInt(proof.UnlockTime),
	}

	// Verify proof
	err := groth16.Verify(proof.Proof, vk, publicWitness)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofVerificationFailed, err)
	}

	return nil
}

// BatchProofCircuit for batch verification
type BatchProofCircuit struct {
	// Public inputs
	BatchRoot     frontend.Variable `gnark:",public"`
	ProofCount    frontend.Variable `gnark:",public"`
	
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

func calculateCommitment(assetID, ownerSecret, nonce []byte) *big.Int {
	// Simplified - use proper hash in production
	h := make([]byte, 32)
	copy(h, assetID)
	for i := range ownerSecret {
		h[i%32] ^= ownerSecret[i]
	}
	for i := range nonce {
		h[i%32] ^= nonce[i]
	}
	return new(big.Int).SetBytes(h)
}

func calculateAddress(secret []byte) *big.Int {
	// Simplified - use proper derivation in production
	h := make([]byte, 32)
	copy(h, secret)
	return new(big.Int).SetBytes(h)
}

func calculateUnlockCommitment(unlockSecret, assetID, additionalData []byte) *big.Int {
	// Simplified - use proper hash in production
	h := make([]byte, 32)
	copy(h, unlockSecret)
	for i := range assetID {
		h[i%32] ^= assetID[i]
	}
	for i := range additionalData {
		h[i%32] ^= additionalData[i]
	}
	return new(big.Int).SetBytes(h)
}