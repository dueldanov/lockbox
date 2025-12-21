package lockscript

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// logNEO outputs structured log for NEO AI verification
func logNEO(t *testing.T, category, function, purpose, reqRef string, input, expected, actual interface{}, assertion string, passed bool) {
	result := "PASS"
	if !passed {
		result = "FAIL"
	}
	t.Logf(`
=== NEO_VERIFY: %s ===
FUNCTION: %s
PURPOSE: %s
REQUIREMENT_REF: %s
INPUT: %v
EXPECTED: %v
ACTUAL: %v
ASSERTION: %s
RESULT: %s
=== END_VERIFY ===`, category, function, purpose, reqRef, input, expected, actual, assertion, result)
}

// ============================================
// BUILTIN: now()
// ============================================

func TestBuiltin_Now(t *testing.T) {
	before := time.Now().Unix()
	result, err := funcNow(nil)
	after := time.Now().Unix()

	if err != nil {
		t.Fatalf("funcNow failed: %v", err)
	}

	ts, ok := result.(int64)
	if !ok {
		t.Fatal("funcNow should return int64")
	}

	passed := ts >= before && ts <= after
	logNEO(t, "LockScript.Builtin.Now",
		"now() -> int64",
		"Returns current Unix timestamp",
		"docs/requirements/08_APPENDICES.md#lockscript-builtins",
		"(no args)",
		fmt.Sprintf("timestamp between %d and %d", before, after),
		ts,
		"Returned timestamp is within execution window",
		passed)

	if !passed {
		t.Errorf("now() returned %d, expected between %d and %d", ts, before, after)
	}
}

// ============================================
// BUILTIN: after(timestamp)
// ============================================

func TestBuiltin_After_True(t *testing.T) {
	// Timestamp in the past
	pastTime := time.Now().Add(-1 * time.Hour).Unix()
	result, err := funcAfter([]interface{}{pastTime})

	if err != nil {
		t.Fatalf("funcAfter failed: %v", err)
	}

	passed := result.(bool) == true
	logNEO(t, "LockScript.Builtin.After",
		"after(timestamp int64) -> bool",
		"Time-lock verification - returns true if current time > timestamp",
		"docs/requirements/02_SECURITY_MECHANISMS.md#time-locks",
		fmt.Sprintf("{timestamp: %d (1 hour ago)}", pastTime),
		true,
		result,
		"Current time is after past timestamp, should return true",
		passed)

	if !passed {
		t.Error("after() with past timestamp should return true")
	}
}

func TestBuiltin_After_False(t *testing.T) {
	// Timestamp in the future
	futureTime := time.Now().Add(1 * time.Hour).Unix()
	result, err := funcAfter([]interface{}{futureTime})

	if err != nil {
		t.Fatalf("funcAfter failed: %v", err)
	}

	passed := result.(bool) == false
	logNEO(t, "LockScript.Builtin.After",
		"after(timestamp int64) -> bool",
		"Time-lock verification - returns false if current time <= timestamp",
		"docs/requirements/02_SECURITY_MECHANISMS.md#time-locks",
		fmt.Sprintf("{timestamp: %d (1 hour from now)}", futureTime),
		false,
		result,
		"Current time is before future timestamp, should return false",
		passed)

	if !passed {
		t.Error("after() with future timestamp should return false")
	}
}

// ============================================
// BUILTIN: before(timestamp)
// ============================================

func TestBuiltin_Before_True(t *testing.T) {
	// Timestamp in the future
	futureTime := time.Now().Add(1 * time.Hour).Unix()
	result, err := funcBefore([]interface{}{futureTime})

	if err != nil {
		t.Fatalf("funcBefore failed: %v", err)
	}

	passed := result.(bool) == true
	logNEO(t, "LockScript.Builtin.Before",
		"before(timestamp int64) -> bool",
		"Deadline check - returns true if current time < timestamp",
		"docs/requirements/02_SECURITY_MECHANISMS.md#time-locks",
		fmt.Sprintf("{timestamp: %d (1 hour from now)}", futureTime),
		true,
		result,
		"Current time is before future timestamp, should return true",
		passed)

	if !passed {
		t.Error("before() with future timestamp should return true")
	}
}

func TestBuiltin_Before_False(t *testing.T) {
	// Timestamp in the past
	pastTime := time.Now().Add(-1 * time.Hour).Unix()
	result, err := funcBefore([]interface{}{pastTime})

	if err != nil {
		t.Fatalf("funcBefore failed: %v", err)
	}

	passed := result.(bool) == false
	logNEO(t, "LockScript.Builtin.Before",
		"before(timestamp int64) -> bool",
		"Deadline check - returns false if current time >= timestamp",
		"docs/requirements/02_SECURITY_MECHANISMS.md#time-locks",
		fmt.Sprintf("{timestamp: %d (1 hour ago)}", pastTime),
		false,
		result,
		"Current time is after past timestamp, should return false",
		passed)

	if !passed {
		t.Error("before() with past timestamp should return false")
	}
}

// ============================================
// BUILTIN: sha256(data)
// ============================================

func TestBuiltin_Sha256(t *testing.T) {
	input := "Hello, LockBox!"
	result, err := funcSHA256([]interface{}{input})

	if err != nil {
		t.Fatalf("funcSHA256 failed: %v", err)
	}

	// Compute expected hash
	hash := sha256.Sum256([]byte(input))
	expected := hex.EncodeToString(hash[:])

	passed := result.(string) == expected
	logNEO(t, "LockScript.Builtin.SHA256",
		"sha256(data string) -> string",
		"SHA256 hash of input data as hex string",
		"docs/requirements/02_SECURITY_MECHANISMS.md#cryptographic-functions",
		fmt.Sprintf("{data: %q}", input),
		expected,
		result,
		"SHA256 hash matches expected value",
		passed)

	if !passed {
		t.Errorf("sha256() returned %v, expected %s", result, expected)
	}
}

func TestBuiltin_Sha256_Empty(t *testing.T) {
	input := ""
	result, err := funcSHA256([]interface{}{input})

	if err != nil {
		t.Fatalf("funcSHA256 failed: %v", err)
	}

	// SHA256 of empty string
	hash := sha256.Sum256([]byte(""))
	expected := hex.EncodeToString(hash[:])

	passed := result.(string) == expected
	logNEO(t, "LockScript.Builtin.SHA256.Empty",
		"sha256(data string) -> string",
		"SHA256 hash of empty string",
		"docs/requirements/02_SECURITY_MECHANISMS.md#cryptographic-functions",
		"{data: \"\"}",
		expected,
		result,
		"SHA256 of empty string matches expected",
		passed)

	if !passed {
		t.Errorf("sha256('') returned %v, expected %s", result, expected)
	}
}

// ============================================
// BUILTIN: verify_sig(pubKey, message, signature)
// ============================================

func TestBuiltin_VerifySig_Valid(t *testing.T) {
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := "unlock_asset_12345"
	signatureHex := SignMessage(privKey, message)

	result, err := funcVerifySig([]interface{}{pubKeyHex, message, signatureHex})
	if err != nil {
		t.Fatalf("funcVerifySig failed: %v", err)
	}

	passed := result.(bool) == true
	logNEO(t, "LockScript.Builtin.VerifySig.Valid",
		"verify_sig(pubKey, message, signature) -> bool",
		"Ed25519 signature verification - valid signature",
		"docs/requirements/02_SECURITY_MECHANISMS.md#signature-verification",
		fmt.Sprintf("{pubKey: %s..., message: %q, signature: %s...}", pubKeyHex[:16], message, signatureHex[:16]),
		true,
		result,
		"Valid Ed25519 signature should verify successfully",
		passed)

	if !passed {
		t.Error("verify_sig() with valid signature should return true")
	}
}

func TestBuiltin_VerifySig_Invalid(t *testing.T) {
	pubKeyHex, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := "unlock_asset_12345"
	fakeSignature := "0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"

	result, err := funcVerifySig([]interface{}{pubKeyHex, message, fakeSignature})
	if err != nil {
		t.Fatalf("funcVerifySig failed: %v", err)
	}

	passed := result.(bool) == false
	logNEO(t, "LockScript.Builtin.VerifySig.Invalid",
		"verify_sig(pubKey, message, signature) -> bool",
		"Ed25519 signature verification - invalid signature rejected",
		"docs/requirements/02_SECURITY_MECHANISMS.md#signature-verification",
		fmt.Sprintf("{pubKey: %s..., message: %q, signature: (fake zeros)}", pubKeyHex[:16], message),
		false,
		result,
		"Invalid Ed25519 signature should be rejected",
		passed)

	if !passed {
		t.Error("verify_sig() with invalid signature should return false")
	}
}

// ============================================
// BUILTIN: require_sigs(signatures, threshold)
// ============================================

func TestBuiltin_RequireSigs_Threshold_Met(t *testing.T) {
	signatures := []interface{}{"sig1", "sig2", "sig3"}
	threshold := int64(2)

	result, err := funcRequireSigs([]interface{}{signatures, threshold})
	if err != nil {
		t.Fatalf("funcRequireSigs failed: %v", err)
	}

	passed := result.(bool) == true
	logNEO(t, "LockScript.Builtin.RequireSigs.ThresholdMet",
		"require_sigs(signatures []string, threshold int) -> bool",
		"M-of-N multisig - threshold met",
		"docs/requirements/02_SECURITY_MECHANISMS.md#multi-signature",
		fmt.Sprintf("{signatures: 3 provided, threshold: %d}", threshold),
		true,
		result,
		"3 signatures >= 2 threshold, should return true",
		passed)

	if !passed {
		t.Error("require_sigs() with 3 sigs and threshold 2 should return true")
	}
}

func TestBuiltin_RequireSigs_Threshold_NotMet(t *testing.T) {
	signatures := []interface{}{"sig1"}
	threshold := int64(2)

	result, err := funcRequireSigs([]interface{}{signatures, threshold})
	if err != nil {
		t.Fatalf("funcRequireSigs failed: %v", err)
	}

	passed := result.(bool) == false
	logNEO(t, "LockScript.Builtin.RequireSigs.ThresholdNotMet",
		"require_sigs(signatures []string, threshold int) -> bool",
		"M-of-N multisig - threshold not met",
		"docs/requirements/02_SECURITY_MECHANISMS.md#multi-signature",
		fmt.Sprintf("{signatures: 1 provided, threshold: %d}", threshold),
		false,
		result,
		"1 signature < 2 threshold, should return false",
		passed)

	if !passed {
		t.Error("require_sigs() with 1 sig and threshold 2 should return false")
	}
}

// ============================================
// BUILTIN: check_geo(location)
// ============================================

func TestBuiltin_CheckGeo_Valid(t *testing.T) {
	validLocations := []string{"us-east", "eu-west", "asia-pacific"}

	for _, loc := range validLocations {
		result, err := funcCheckGeo([]interface{}{loc})
		if err != nil {
			t.Fatalf("funcCheckGeo failed: %v", err)
		}

		passed := result.(bool) == true
		logNEO(t, "LockScript.Builtin.CheckGeo.Valid",
			"check_geo(location string) -> bool",
			"Geographic region verification - valid region",
			"docs/requirements/02_SECURITY_MECHANISMS.md#geographic-distribution",
			fmt.Sprintf("{location: %q}", loc),
			true,
			result,
			fmt.Sprintf("Region %q is in allowed list", loc),
			passed)

		if !passed {
			t.Errorf("check_geo(%q) should return true", loc)
		}
	}
}

func TestBuiltin_CheckGeo_Invalid(t *testing.T) {
	result, err := funcCheckGeo([]interface{}{"unknown-region"})
	if err != nil {
		t.Fatalf("funcCheckGeo failed: %v", err)
	}

	passed := result.(bool) == false
	logNEO(t, "LockScript.Builtin.CheckGeo.Invalid",
		"check_geo(location string) -> bool",
		"Geographic region verification - invalid region rejected",
		"docs/requirements/02_SECURITY_MECHANISMS.md#geographic-distribution",
		"{location: \"unknown-region\"}",
		false,
		result,
		"Unknown region should be rejected",
		passed)

	if !passed {
		t.Error("check_geo('unknown-region') should return false")
	}
}

// ============================================
// BUILTIN: min(a, b, ...)
// ============================================

func TestBuiltin_Min(t *testing.T) {
	args := []interface{}{int64(5), int64(3), int64(8), int64(1), int64(9)}
	result, err := funcMin(args)
	if err != nil {
		t.Fatalf("funcMin failed: %v", err)
	}

	passed := result.(int64) == 1
	logNEO(t, "LockScript.Builtin.Min",
		"min(a, b, ...) -> int64",
		"Returns minimum value from arguments",
		"docs/requirements/08_APPENDICES.md#lockscript-builtins",
		"{values: [5, 3, 8, 1, 9]}",
		int64(1),
		result,
		"Minimum of [5,3,8,1,9] should be 1",
		passed)

	if !passed {
		t.Errorf("min(5,3,8,1,9) returned %v, expected 1", result)
	}
}

func TestBuiltin_Min_TwoArgs(t *testing.T) {
	result, err := funcMin([]interface{}{int64(10), int64(20)})
	if err != nil {
		t.Fatalf("funcMin failed: %v", err)
	}

	passed := result.(int64) == 10
	logNEO(t, "LockScript.Builtin.Min.TwoArgs",
		"min(a, b) -> int64",
		"Returns minimum of two values",
		"docs/requirements/08_APPENDICES.md#lockscript-builtins",
		"{values: [10, 20]}",
		int64(10),
		result,
		"Minimum of [10, 20] should be 10",
		passed)

	if !passed {
		t.Errorf("min(10, 20) returned %v, expected 10", result)
	}
}

// ============================================
// BUILTIN: max(a, b, ...)
// ============================================

func TestBuiltin_Max(t *testing.T) {
	args := []interface{}{int64(5), int64(3), int64(8), int64(1), int64(9)}
	result, err := funcMax(args)
	if err != nil {
		t.Fatalf("funcMax failed: %v", err)
	}

	passed := result.(int64) == 9
	logNEO(t, "LockScript.Builtin.Max",
		"max(a, b, ...) -> int64",
		"Returns maximum value from arguments",
		"docs/requirements/08_APPENDICES.md#lockscript-builtins",
		"{values: [5, 3, 8, 1, 9]}",
		int64(9),
		result,
		"Maximum of [5,3,8,1,9] should be 9",
		passed)

	if !passed {
		t.Errorf("max(5,3,8,1,9) returned %v, expected 9", result)
	}
}

func TestBuiltin_Max_TwoArgs(t *testing.T) {
	result, err := funcMax([]interface{}{int64(10), int64(20)})
	if err != nil {
		t.Fatalf("funcMax failed: %v", err)
	}

	passed := result.(int64) == 20
	logNEO(t, "LockScript.Builtin.Max.TwoArgs",
		"max(a, b) -> int64",
		"Returns maximum of two values",
		"docs/requirements/08_APPENDICES.md#lockscript-builtins",
		"{values: [10, 20]}",
		int64(20),
		result,
		"Maximum of [10, 20] should be 20",
		passed)

	if !passed {
		t.Errorf("max(10, 20) returned %v, expected 20", result)
	}
}
