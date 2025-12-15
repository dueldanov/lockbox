package service

import (
	"encoding/hex"
	"testing"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
)

func TestDeserializeShard_Valid(t *testing.T) {
	svc := &Service{}

	// Create a sample shard
	original := &crypto.CharacterShard{
		ID:        12345,
		Index:     2,
		Total:     10,
		Data:      []byte("encrypted data here"),
		Nonce:     make([]byte, 24),
		Timestamp: 1702500000,
		Checksum:  []byte{0x01, 0x02, 0x03, 0x04},
	}

	// Serialize
	serialized, err := svc.serializeShard(original)
	if err != nil {
		t.Fatalf("serializeShard failed: %v", err)
	}

	// Deserialize
	result, err := svc.deserializeShard(serialized)
	if err != nil {
		t.Fatalf("deserializeShard failed: %v", err)
	}

	// Verify all fields
	if result.ID != original.ID {
		t.Errorf("ID mismatch: got %d, want %d", result.ID, original.ID)
	}
	if result.Index != original.Index {
		t.Errorf("Index mismatch: got %d, want %d", result.Index, original.Index)
	}
	if result.Total != original.Total {
		t.Errorf("Total mismatch: got %d, want %d", result.Total, original.Total)
	}
	if result.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", result.Timestamp, original.Timestamp)
	}
	if string(result.Data) != string(original.Data) {
		t.Errorf("Data mismatch: got %s, want %s", result.Data, original.Data)
	}
	if string(result.Nonce) != string(original.Nonce) {
		t.Errorf("Nonce mismatch")
	}
	if string(result.Checksum) != string(original.Checksum) {
		t.Errorf("Checksum mismatch")
	}
}

func TestDeserializeShard_InvalidFormat(t *testing.T) {
	svc := &Service{}

	tests := []struct {
		name string
		data string
	}{
		{"empty string", ""},
		{"too few fields", "1|2|3"},
		{"missing field", "1|2|3|4|aabb|ccdd"},
		{"too many fields", "1|2|3|4|aa|bb|cc|dd"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.deserializeShard([]byte(tc.data))
			if err == nil {
				t.Error("expected error for invalid format, got nil")
			}
		})
	}
}

func TestDeserializeShard_InvalidNumericFields(t *testing.T) {
	svc := &Service{}

	tests := []struct {
		name string
		data string
	}{
		{"invalid ID", "abc|2|10|1702500000|aabb|ccdd|eeff"},
		{"invalid Index", "123|xyz|10|1702500000|aabb|ccdd|eeff"},
		{"invalid Total", "123|2|bad|1702500000|aabb|ccdd|eeff"},
		{"invalid Timestamp", "123|2|10|notanumber|aabb|ccdd|eeff"},
		{"negative ID (overflow)", "-1|2|10|1702500000|aabb|ccdd|eeff"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.deserializeShard([]byte(tc.data))
			if err == nil {
				t.Error("expected error for invalid numeric field, got nil")
			}
		})
	}
}

func TestDeserializeShard_InvalidHexFields(t *testing.T) {
	svc := &Service{}

	tests := []struct {
		name string
		data string
	}{
		{"invalid Data hex", "123|2|10|1702500000|gggg|aabb|ccdd"},
		{"invalid Nonce hex", "123|2|10|1702500000|aabb|zzzz|ccdd"},
		{"invalid Checksum hex", "123|2|10|1702500000|aabb|ccdd|!!@@"},
		{"odd length Data hex", "123|2|10|1702500000|aab|ccdd|eeff"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.deserializeShard([]byte(tc.data))
			if err == nil {
				t.Error("expected error for invalid hex field, got nil")
			}
		})
	}
}

func TestDeserializeShard_LargeValues(t *testing.T) {
	svc := &Service{}

	// Test with maximum uint32 values
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	original := &crypto.CharacterShard{
		ID:        4294967295, // max uint32
		Index:     4294967294,
		Total:     4294967295,
		Data:      largeData,
		Nonce:     make([]byte, 24),
		Timestamp: 9223372036854775807, // max int64
		Checksum:  []byte{0xff, 0xff, 0xff, 0xff},
	}

	serialized, err := svc.serializeShard(original)
	if err != nil {
		t.Fatalf("serializeShard failed: %v", err)
	}

	result, err := svc.deserializeShard(serialized)
	if err != nil {
		t.Fatalf("deserializeShard failed: %v", err)
	}

	if result.ID != original.ID {
		t.Errorf("ID mismatch with large value")
	}
	if result.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch with large value")
	}
	if len(result.Data) != len(original.Data) {
		t.Errorf("Data length mismatch: got %d, want %d", len(result.Data), len(original.Data))
	}
}

func TestDeserializeShard_EmptyData(t *testing.T) {
	svc := &Service{}

	original := &crypto.CharacterShard{
		ID:        1,
		Index:     0,
		Total:     1,
		Data:      []byte{},
		Nonce:     []byte{},
		Timestamp: 0,
		Checksum:  []byte{},
	}

	serialized, err := svc.serializeShard(original)
	if err != nil {
		t.Fatalf("serializeShard failed: %v", err)
	}

	result, err := svc.deserializeShard(serialized)
	if err != nil {
		t.Fatalf("deserializeShard failed: %v", err)
	}

	if len(result.Data) != 0 {
		t.Errorf("Data should be empty, got %d bytes", len(result.Data))
	}
}

func TestDeserializeShard_KnownGoodData(t *testing.T) {
	svc := &Service{}

	// Manually construct known-good serialized data
	// Format: ID|Index|Total|Timestamp|DataHex|NonceHex|ChecksumHex
	knownGood := "100|0|5|1700000000|48656c6c6f|" + hex.EncodeToString(make([]byte, 24)) + "|aabbccdd"

	result, err := svc.deserializeShard([]byte(knownGood))
	if err != nil {
		t.Fatalf("deserializeShard failed for known-good data: %v", err)
	}

	if result.ID != 100 {
		t.Errorf("ID: got %d, want 100", result.ID)
	}
	if result.Index != 0 {
		t.Errorf("Index: got %d, want 0", result.Index)
	}
	if result.Total != 5 {
		t.Errorf("Total: got %d, want 5", result.Total)
	}
	if result.Timestamp != 1700000000 {
		t.Errorf("Timestamp: got %d, want 1700000000", result.Timestamp)
	}
	if string(result.Data) != "Hello" {
		t.Errorf("Data: got %s, want Hello", string(result.Data))
	}
}
