package lockscript

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// logNEOOpcode outputs structured log for NEO AI verification of opcodes
func logNEOOpcode(t *testing.T, category, opcode, purpose, reqRef string, input, expected, actual interface{}, assertion string, passed bool, gasUsed uint64) {
	result := "PASS"
	if !passed {
		result = "FAIL"
	}
	t.Logf(`
=== NEO_VERIFY: %s ===
OPCODE: %s
PURPOSE: %s
REQUIREMENT_REF: %s
INPUT: %v
EXPECTED: %v
ACTUAL: %v
ASSERTION: %s
GAS_USED: %d
RESULT: %s
=== END_VERIFY ===`, category, opcode, purpose, reqRef, input, expected, actual, assertion, gasUsed, result)
}

// ============================================
// STACK OPERATIONS: OpPush, OpPop
// ============================================

func TestOpcode_Push(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 42
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(42)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpPush failed: %v", err)
	}

	passed := result.Value.(int64) == 42
	logNEOOpcode(t, "LockScript.Opcode.Stack",
		"OpPush",
		"Push 64-bit integer onto stack",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{value: 42}",
		int64(42),
		result.Value,
		"Stack top should contain pushed value",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpPush expected 42, got %v", result.Value)
	}
}

func TestOpcode_Push_Multiple(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 10, PUSH 20, PUSH 30
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(10)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(30)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpPush multiple failed: %v", err)
	}

	passed := result.Value.(int64) == 30
	logNEOOpcode(t, "LockScript.Opcode.Stack",
		"OpPush (multiple)",
		"Push multiple values - last pushed is stack top",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{values: [10, 20, 30]}",
		int64(30),
		result.Value,
		"Stack top should be last pushed value (30)",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpPush multiple expected 30 on top, got %v", result.Value)
	}
}

func TestOpcode_Pop(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 100, PUSH 200, POP
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(100)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(200)
	writer.WriteOpCode(OpPop)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpPop failed: %v", err)
	}

	passed := result.Value.(int64) == 100
	logNEOOpcode(t, "LockScript.Opcode.Stack",
		"OpPop",
		"Remove top element from stack",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{stack: [100, 200], operation: POP}",
		int64(100),
		result.Value,
		"After POP, stack top should be 100",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpPop expected 100 remaining, got %v", result.Value)
	}
}

// ============================================
// MEMORY OPERATIONS: OpLoad, OpStore
// ============================================

func TestOpcode_Store_Load(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 999, STORE var_0, PUSH 0, POP, LOAD var_0
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(999)
	writer.WriteOpCode(OpStore)
	writer.bytecode = append(writer.bytecode, 0) // var_0
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(0) // Clear stack
	writer.WriteOpCode(OpPop)
	writer.WriteOpCode(OpLoad)
	writer.bytecode = append(writer.bytecode, 0) // var_0

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpStore/OpLoad failed: %v", err)
	}

	passed := result.Value.(int64) == 999
	logNEOOpcode(t, "LockScript.Opcode.Memory",
		"OpStore + OpLoad",
		"Store value to memory and retrieve it",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{store: 999 to var_0, load: var_0}",
		int64(999),
		result.Value,
		"Loaded value should match stored value",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpStore/OpLoad expected 999, got %v", result.Value)
	}
}

// ============================================
// ARITHMETIC OPERATIONS: OpAdd, OpSub, OpMul, OpDiv
// ============================================

func TestOpcode_Add(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 10, PUSH 20, ADD
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(10)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpAdd)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpAdd failed: %v", err)
	}

	passed := result.Value.(int64) == 30
	logNEOOpcode(t, "LockScript.Opcode.Arithmetic",
		"OpAdd",
		"Add top two stack values",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 10, b: 20}",
		int64(30),
		result.Value,
		"10 + 20 = 30",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpAdd expected 30, got %v", result.Value)
	}
}

func TestOpcode_Sub(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 50, PUSH 20, SUB
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(50)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpSub)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpSub failed: %v", err)
	}

	passed := result.Value.(int64) == 30
	logNEOOpcode(t, "LockScript.Opcode.Arithmetic",
		"OpSub",
		"Subtract top from second-to-top",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 50, b: 20}",
		int64(30),
		result.Value,
		"50 - 20 = 30",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpSub expected 30, got %v", result.Value)
	}
}

func TestOpcode_Mul(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 6, PUSH 7, MUL
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(6)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(7)
	writer.WriteOpCode(OpMul)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpMul failed: %v", err)
	}

	passed := result.Value.(int64) == 42
	logNEOOpcode(t, "LockScript.Opcode.Arithmetic",
		"OpMul",
		"Multiply top two stack values",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 6, b: 7}",
		int64(42),
		result.Value,
		"6 * 7 = 42",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpMul expected 42, got %v", result.Value)
	}
}

func TestOpcode_Div(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 100, PUSH 4, DIV
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(100)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(4)
	writer.WriteOpCode(OpDiv)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpDiv failed: %v", err)
	}

	passed := result.Value.(int64) == 25
	logNEOOpcode(t, "LockScript.Opcode.Arithmetic",
		"OpDiv",
		"Integer division",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 100, b: 4}",
		int64(25),
		result.Value,
		"100 / 4 = 25",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpDiv expected 25, got %v", result.Value)
	}
}

func TestOpcode_Div_ByZero(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 100, PUSH 0, DIV
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(100)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(0)
	writer.WriteOpCode(OpDiv)

	env := &Environment{Variables: make(map[string]interface{})}
	_, err := vm.Execute(ctx, writer.Bytes(), env)

	passed := err != nil && err.Error() == "division by zero"
	logNEOOpcode(t, "LockScript.Opcode.Arithmetic",
		"OpDiv (division by zero)",
		"Division by zero should return error",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 100, b: 0}",
		"error: division by zero",
		fmt.Sprintf("error: %v", err),
		"Division by zero must raise error",
		passed,
		0)

	if !passed {
		t.Errorf("OpDiv by zero should error, got: %v", err)
	}
}

// ============================================
// COMPARISON OPERATIONS: OpEq, OpNe, OpLt, OpGt
// ============================================

func TestOpcode_Eq_True(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 42, PUSH 42, EQ
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(42)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(42)
	writer.WriteOpCode(OpEq)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpEq failed: %v", err)
	}

	passed := result.Value.(bool) == true
	logNEOOpcode(t, "LockScript.Opcode.Comparison",
		"OpEq (equal)",
		"Compare two values for equality",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 42, b: 42}",
		true,
		result.Value,
		"42 == 42 should be true",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpEq expected true, got %v", result.Value)
	}
}

func TestOpcode_Eq_False(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 42, PUSH 43, EQ
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(42)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(43)
	writer.WriteOpCode(OpEq)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpEq failed: %v", err)
	}

	passed := result.Value.(bool) == false
	logNEOOpcode(t, "LockScript.Opcode.Comparison",
		"OpEq (not equal)",
		"Compare two different values",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 42, b: 43}",
		false,
		result.Value,
		"42 == 43 should be false",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpEq expected false, got %v", result.Value)
	}
}

func TestOpcode_Ne(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 10, PUSH 20, NE
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(10)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpNe)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpNe failed: %v", err)
	}

	passed := result.Value.(bool) == true
	logNEOOpcode(t, "LockScript.Opcode.Comparison",
		"OpNe",
		"Check inequality of two values",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 10, b: 20}",
		true,
		result.Value,
		"10 != 20 should be true",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpNe expected true, got %v", result.Value)
	}
}

func TestOpcode_Lt(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 10, PUSH 20, LT
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(10)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpLt)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpLt failed: %v", err)
	}

	passed := result.Value.(bool) == true
	logNEOOpcode(t, "LockScript.Opcode.Comparison",
		"OpLt",
		"Less than comparison",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 10, b: 20}",
		true,
		result.Value,
		"10 < 20 should be true",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpLt expected true, got %v", result.Value)
	}
}

func TestOpcode_Gt(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 30, PUSH 20, GT
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(30)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpGt)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpGt failed: %v", err)
	}

	passed := result.Value.(bool) == true
	logNEOOpcode(t, "LockScript.Opcode.Comparison",
		"OpGt",
		"Greater than comparison",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: 30, b: 20}",
		true,
		result.Value,
		"30 > 20 should be true",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpGt expected true, got %v", result.Value)
	}
}

// ============================================
// LOGICAL OPERATIONS: OpAnd, OpOr, OpNot
// ============================================

func TestOpcode_And_True(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 1, PUSH 1, AND (non-zero = true)
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(1)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(1)
	writer.WriteOpCode(OpAnd)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpAnd failed: %v", err)
	}

	passed := result.Value.(bool) == true
	logNEOOpcode(t, "LockScript.Opcode.Logical",
		"OpAnd (both true)",
		"Logical AND of two boolean values",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: true, b: true}",
		true,
		result.Value,
		"true AND true = true",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpAnd expected true, got %v", result.Value)
	}
}

func TestOpcode_And_False(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 1, PUSH 0, AND
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(1)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(0)
	writer.WriteOpCode(OpAnd)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpAnd failed: %v", err)
	}

	passed := result.Value.(bool) == false
	logNEOOpcode(t, "LockScript.Opcode.Logical",
		"OpAnd (one false)",
		"Logical AND with one false operand",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: true, b: false}",
		false,
		result.Value,
		"true AND false = false",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpAnd expected false, got %v", result.Value)
	}
}

func TestOpcode_Or_True(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 0, PUSH 1, OR
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(0)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(1)
	writer.WriteOpCode(OpOr)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpOr failed: %v", err)
	}

	passed := result.Value.(bool) == true
	logNEOOpcode(t, "LockScript.Opcode.Logical",
		"OpOr",
		"Logical OR - true if either operand is true",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: false, b: true}",
		true,
		result.Value,
		"false OR true = true",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpOr expected true, got %v", result.Value)
	}
}

func TestOpcode_Not(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH 1, NOT
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(1)
	writer.WriteOpCode(OpNot)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpNot failed: %v", err)
	}

	passed := result.Value.(bool) == false
	logNEOOpcode(t, "LockScript.Opcode.Logical",
		"OpNot",
		"Logical NOT - inverts boolean value",
		"docs/requirements/08_APPENDICES.md#lockscript-opcodes",
		"{a: true}",
		false,
		result.Value,
		"NOT true = false",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpNot expected false, got %v", result.Value)
	}
}

// ============================================
// SPECIAL OPERATIONS: OpTimeCheck, OpSigVerify, OpHashCheck
// ============================================

func TestOpcode_TimeCheck_Passed(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Past timestamp
	pastTime := time.Now().Add(-1 * time.Hour).Unix()

	// Build bytecode: PUSH pastTime, TIMECHECK
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(pastTime)
	writer.WriteOpCode(OpTimeCheck)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpTimeCheck failed: %v", err)
	}

	passed := result.Value.(bool) == true
	logNEOOpcode(t, "LockScript.Opcode.Special",
		"OpTimeCheck (time passed)",
		"Check if current time >= required time",
		"docs/requirements/02_SECURITY_MECHANISMS.md#time-locks",
		fmt.Sprintf("{requiredTime: %d (1 hour ago)}", pastTime),
		true,
		result.Value,
		"Current time is after required time, should return true",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpTimeCheck expected true for past time, got %v", result.Value)
	}
}

func TestOpcode_TimeCheck_NotPassed(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Future timestamp
	futureTime := time.Now().Add(1 * time.Hour).Unix()

	// Build bytecode: PUSH futureTime, TIMECHECK
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(futureTime)
	writer.WriteOpCode(OpTimeCheck)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("OpTimeCheck failed: %v", err)
	}

	passed := result.Value.(bool) == false
	logNEOOpcode(t, "LockScript.Opcode.Special",
		"OpTimeCheck (time not passed)",
		"Check if current time >= required time",
		"docs/requirements/02_SECURITY_MECHANISMS.md#time-locks",
		fmt.Sprintf("{requiredTime: %d (1 hour from now)}", futureTime),
		false,
		result.Value,
		"Current time is before required time, should return false",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("OpTimeCheck expected false for future time, got %v", result.Value)
	}
}

func TestOpcode_SigVerify_Valid(t *testing.T) {
	vm := NewVirtualMachine()

	// Generate valid key pair and signature
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := "unlock_asset_test"
	signatureHex := SignMessage(privKey, message)

	// Test the VM's verifySignature directly (since OpSigVerify uses it)
	result := vm.verifySignature(pubKeyHex, message, signatureHex)

	passed := result == true
	logNEOOpcode(t, "LockScript.Opcode.Special",
		"OpSigVerify (valid)",
		"Ed25519 signature verification",
		"docs/requirements/02_SECURITY_MECHANISMS.md#signature-verification",
		fmt.Sprintf("{pubKey: %s..., message: %q, signature: %s...}", pubKeyHex[:16], message, signatureHex[:16]),
		true,
		result,
		"Valid Ed25519 signature should verify",
		passed,
		3000) // Gas cost for signature verification

	if !passed {
		t.Error("OpSigVerify should return true for valid signature")
	}
}

func TestOpcode_SigVerify_Invalid(t *testing.T) {
	vm := NewVirtualMachine()

	pubKeyHex, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := "unlock_asset_test"
	fakeSignature := "0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"

	result := vm.verifySignature(pubKeyHex, message, fakeSignature)

	passed := result == false
	logNEOOpcode(t, "LockScript.Opcode.Special",
		"OpSigVerify (invalid)",
		"Ed25519 signature verification rejects invalid signature",
		"docs/requirements/02_SECURITY_MECHANISMS.md#signature-verification",
		fmt.Sprintf("{pubKey: %s..., message: %q, signature: (fake zeros)}", pubKeyHex[:16], message),
		false,
		result,
		"Invalid signature should be rejected",
		passed,
		3000)

	if !passed {
		t.Error("OpSigVerify should return false for invalid signature")
	}
}

// ============================================
// GAS CONSUMPTION TESTS
// ============================================

func TestOpcode_Gas_BasicOps(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH (3 gas) + PUSH (3 gas) + ADD (3 gas) = 9 gas
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(10)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpAdd)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("Gas test failed: %v", err)
	}

	expectedGas := uint64(9) // 3 + 3 + 3
	passed := result.GasUsed == expectedGas
	logNEOOpcode(t, "LockScript.Opcode.Gas",
		"Gas consumption (PUSH+PUSH+ADD)",
		"Track gas usage for basic operations",
		"docs/requirements/08_APPENDICES.md#gas-costs",
		"{operations: [PUSH(3), PUSH(3), ADD(3)]}",
		expectedGas,
		result.GasUsed,
		fmt.Sprintf("Gas should be %d", expectedGas),
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("Gas expected %d, got %d", expectedGas, result.GasUsed)
	}
}

func TestOpcode_Gas_ExpensiveOps(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Build bytecode: PUSH (3) + PUSH (3) + MUL (5) + PUSH (3) + DIV (5) = 19 gas
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(10)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(5)
	writer.WriteOpCode(OpMul)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(2)
	writer.WriteOpCode(OpDiv)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("Gas test failed: %v", err)
	}

	expectedGas := uint64(19) // 3 + 3 + 5 + 3 + 5
	passed := result.GasUsed == expectedGas
	logNEOOpcode(t, "LockScript.Opcode.Gas",
		"Gas consumption (expensive ops)",
		"MUL and DIV cost more gas than ADD/SUB",
		"docs/requirements/08_APPENDICES.md#gas-costs",
		"{operations: [PUSH(3), PUSH(3), MUL(5), PUSH(3), DIV(5)]}",
		expectedGas,
		result.GasUsed,
		fmt.Sprintf("Gas should be %d (MUL/DIV cost 5)", expectedGas),
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("Gas expected %d, got %d", expectedGas, result.GasUsed)
	}
}

// ============================================
// COMBINED BYTECODE TESTS
// ============================================

func TestOpcode_ComplexExpression(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Expression: (10 + 20) > 25 AND (100 / 5) == 20
	// Build: PUSH 10, PUSH 20, ADD, PUSH 25, GT, PUSH 100, PUSH 5, DIV, PUSH 20, EQ, AND
	writer := NewBytecodeWriter()
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(10)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpAdd)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(25)
	writer.WriteOpCode(OpGt)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(100)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(5)
	writer.WriteOpCode(OpDiv)
	writer.WriteOpCode(OpPush)
	writer.WriteInt64(20)
	writer.WriteOpCode(OpEq)
	writer.WriteOpCode(OpAnd)

	env := &Environment{Variables: make(map[string]interface{})}
	result, err := vm.Execute(ctx, writer.Bytes(), env)

	if err != nil {
		t.Fatalf("Complex expression failed: %v", err)
	}

	// (10 + 20) = 30 > 25 = true
	// (100 / 5) = 20 == 20 = true
	// true AND true = true
	passed := result.Value.(bool) == true
	logNEOOpcode(t, "LockScript.Opcode.Complex",
		"Complex expression",
		"Evaluate compound boolean expression",
		"docs/requirements/08_APPENDICES.md#lockscript-examples",
		"{expr: (10 + 20) > 25 AND (100 / 5) == 20}",
		true,
		result.Value,
		"(30 > 25) AND (20 == 20) = true AND true = true",
		passed,
		result.GasUsed)

	if !passed {
		t.Errorf("Complex expression expected true, got %v", result.Value)
	}
}
