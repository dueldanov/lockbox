package dag

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/blake2b"

	iotago "github.com/iotaledger/iota.go/v3"
)

const (
	ParentsSignatureTag     = "lockbox.parents.v1"
	parentsSignatureHashLen = 32
)

var (
	ErrParentsSignatureMissing  = errors.New("parents signature missing")
	ErrParentsSignatureInvalid  = errors.New("parents signature invalid")
	ErrParentsSignatureMismatch = errors.New("parents signature mismatch")
)

// ParentsSignatureHash returns the hash over sorted parent block IDs.
func ParentsSignatureHash(parents iotago.BlockIDs) []byte {
	sorted := parents.RemoveDupsAndSort()
	buf := make([]byte, 0, len(sorted)*iotago.BlockIDLength)
	for _, parent := range sorted {
		buf = append(buf, parent[:]...)
	}
	sum := blake2b.Sum256(buf)
	return sum[:]
}

// ParentsSignatureTaggedData builds a tagged payload containing the parents hash.
func ParentsSignatureTaggedData(parents iotago.BlockIDs) *iotago.TaggedData {
	return &iotago.TaggedData{
		Tag:  []byte(ParentsSignatureTag),
		Data: ParentsSignatureHash(parents),
	}
}

// ValidateParentsSignature checks that transaction payload includes parents hash.
func ValidateParentsSignature(block *iotago.Block) error {
	if block == nil {
		return ErrParentsSignatureMissing
	}
	if block.Payload == nil {
		return nil
	}

	tx, ok := block.Payload.(*iotago.Transaction)
	if !ok {
		return nil
	}

	if tx.Essence == nil {
		return ErrParentsSignatureMissing
	}
	if tx.Essence.Payload == nil {
		return ErrParentsSignatureMissing
	}
	tagged, ok := tx.Essence.Payload.(*iotago.TaggedData)
	if !ok {
		return ErrParentsSignatureMissing
	}
	if string(tagged.Tag) != ParentsSignatureTag {
		return ErrParentsSignatureInvalid
	}
	if len(tagged.Data) != parentsSignatureHashLen {
		return ErrParentsSignatureInvalid
	}

	expected := ParentsSignatureHash(block.Parents)
	if !bytes.Equal(tagged.Data, expected) {
		return ErrParentsSignatureMismatch
	}

	return nil
}
