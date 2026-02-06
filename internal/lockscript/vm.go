package lockscript

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"
)

type VirtualMachine struct {
	stack       []interface{}
	memory      map[string]interface{}
	gasUsed     uint64
	gasLimit    uint64
	ctx         context.Context
}

func NewVirtualMachine() *VirtualMachine {
	return &VirtualMachine{
		stack:    make([]interface{}, 0, 256),
		memory:   make(map[string]interface{}),
		gasLimit: 1000000, // Default gas limit
	}
}

func (vm *VirtualMachine) Execute(ctx context.Context, bytecode []byte, env *Environment) (result *ExecutionResult, err error) {
	// SECURITY: Catch panics from stack underflow and convert to errors
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("VM execution panic: %v", r)
			result = nil
		}
	}()

	vm.ctx = ctx
	vm.stack = vm.stack[:0]
	vm.gasUsed = 0

	// Initialize VM environment
	for k, v := range env.Variables {
		vm.memory[k] = v
	}
	
	// Execute bytecode
	pc := 0
	for pc < len(bytecode) {
		select {
		case <-ctx.Done():
			return nil, ErrExecutionTimeout
		default:
		}
		
		if vm.gasUsed > vm.gasLimit {
			return nil, errors.New("gas limit exceeded")
		}
		
		opcode := OpCode(bytecode[pc])
		pc++
		
		switch opcode {
		case OpPush:
			if pc+8 > len(bytecode) {
				return nil, errors.New("invalid push operation")
			}
			// Read 8 bytes as value
			value := int64(0)
			for i := 0; i < 8; i++ {
				value = (value << 8) | int64(bytecode[pc])
				pc++
			}
			vm.push(value)
			vm.gasUsed += 3
			
		case OpPop:
			if len(vm.stack) == 0 {
				return nil, errors.New("stack underflow")
			}
			vm.pop()
			vm.gasUsed += 2
			
		case OpLoad:
			if pc >= len(bytecode) {
				return nil, errors.New("invalid load operation")
			}
			varIndex := bytecode[pc]
			pc++
			varName := fmt.Sprintf("var_%d", varIndex)
			if val, ok := vm.memory[varName]; ok {
				vm.push(val)
			} else {
				vm.push(nil)
			}
			vm.gasUsed += 3
			
		case OpStore:
			if pc >= len(bytecode) {
				return nil, errors.New("invalid store operation")
			}
			varIndex := bytecode[pc]
			pc++
			val := vm.pop()
			varName := fmt.Sprintf("var_%d", varIndex)
			vm.memory[varName] = val
			vm.gasUsed += 5
			
		case OpAdd:
			b, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			a, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			// SECURITY: Check for integer overflow
			if (b > 0 && a > math.MaxInt64-b) || (b < 0 && a < math.MinInt64-b) {
				return nil, errors.New("SECURITY ERROR: integer overflow in addition")
			}
			vm.push(a + b)
			vm.gasUsed += 3

		case OpSub:
			b, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			a, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			// SECURITY: Check for integer overflow in subtraction
			if (b < 0 && a > math.MaxInt64+b) || (b > 0 && a < math.MinInt64+b) {
				return nil, errors.New("SECURITY ERROR: integer overflow in subtraction")
			}
			vm.push(a - b)
			vm.gasUsed += 3

		case OpMul:
			b, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			a, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			// SECURITY: Check for integer overflow in multiplication
			if a != 0 && b != 0 {
				result := a * b
				if result/a != b {
					return nil, errors.New("SECURITY ERROR: integer overflow in multiplication")
				}
			}
			vm.push(a * b)
			vm.gasUsed += 5

		case OpDiv:
			b, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			if b == 0 {
				return nil, errors.New("division by zero")
			}
			a, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			vm.push(a / b)
			vm.gasUsed += 5
			
		case OpEq:
			b := vm.pop()
			a := vm.pop()
			vm.push(vm.equal(a, b))
			vm.gasUsed += 3
			
		case OpNe:
			b := vm.pop()
			a := vm.pop()
			vm.push(!vm.equal(a, b))
			vm.gasUsed += 3
			
		case OpLt:
			b, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			a, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			vm.push(a < b)
			vm.gasUsed += 3

		case OpGt:
			b, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			a, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			vm.push(a > b)
			vm.gasUsed += 3

		case OpAnd:
			b, err := vm.popBool()
			if err != nil {
				return nil, err
			}
			a, err := vm.popBool()
			if err != nil {
				return nil, err
			}
			vm.push(a && b)
			vm.gasUsed += 3

		case OpOr:
			b, err := vm.popBool()
			if err != nil {
				return nil, err
			}
			a, err := vm.popBool()
			if err != nil {
				return nil, err
			}
			vm.push(a || b)
			vm.gasUsed += 3

		case OpNot:
			a, err := vm.popBool()
			if err != nil {
				return nil, err
			}
			vm.push(!a)
			vm.gasUsed += 3

		case OpIf:
			if pc+2 > len(bytecode) {
				return nil, errors.New("invalid if operation")
			}
			jumpOffset := int(bytecode[pc])<<8 | int(bytecode[pc+1])
			pc += 2

			condition, err := vm.popBool()
			if err != nil {
				return nil, err
			}
			if !condition {
				pc += jumpOffset
			}
			vm.gasUsed += 8

		case OpTimeCheck:
			currentTime := time.Now().Unix()
			requiredTime, err := vm.popInt()
			if err != nil {
				return nil, err
			}
			vm.push(currentTime >= requiredTime)
			vm.gasUsed += 5
			
		case OpSigVerify:
			// Ed25519 signature verification
			signature := vm.popString()
			message := vm.popString()
			pubKey := vm.popString()

			verified := vm.verifySignature(pubKey, message, signature)
			vm.push(verified)
			vm.gasUsed += 3000
			
		case OpHashCheck:
			data := vm.popString()
			expectedHash := vm.popString()
			
			hasher := sha256.New()
			hasher.Write([]byte(data))
			actualHash := hex.EncodeToString(hasher.Sum(nil))
			
			vm.push(actualHash == expectedHash)
			vm.gasUsed += 100
			
		default:
			return nil, fmt.Errorf("unknown opcode: %v", opcode)
		}
	}

	// Get result from stack
	var stackResult interface{}
	success := true

	if len(vm.stack) > 0 {
		stackResult = vm.stack[len(vm.stack)-1]
		if b, ok := stackResult.(bool); ok {
			success = b
		}
	}

	return &ExecutionResult{
		Success: success,
		Value:   stackResult,
		GasUsed: vm.gasUsed,
		Logs:    []string{}, // TODO: Implement logging
	}, nil
}

func (vm *VirtualMachine) push(value interface{}) {
	vm.stack = append(vm.stack, value)
}

func (vm *VirtualMachine) pop() interface{} {
	if len(vm.stack) == 0 {
		return nil
	}
	val := vm.stack[len(vm.stack)-1]
	vm.stack = vm.stack[:len(vm.stack)-1]
	return val
}

func (vm *VirtualMachine) popInt() (int64, error) {
	val := vm.pop()
	if val == nil {
		// SECURITY: Stack underflow should fail execution, not silently return 0
		// Returning 0 allows bypass of time-lock checks (unlock_time = 0 allows immediate unlock)
		return 0, errors.New("SECURITY ERROR: stack underflow in popInt - execution aborted")
	}
	switch v := val.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case bool:
		if v {
			return 1, nil
		}
		return 0, nil
	default:
		// SECURITY: Unknown type should fail, not default to 0
		return 0, fmt.Errorf("SECURITY ERROR: invalid type %T for integer operation", val)
	}
}

func (vm *VirtualMachine) popBool() (bool, error) {
	val := vm.pop()
	if val == nil {
		return false, errors.New("SECURITY ERROR: stack underflow in popBool - execution aborted")
	}
	switch v := val.(type) {
	case bool:
		return v, nil
	case int64:
		return v != 0, nil
	case string:
		return v != "", nil
	default:
		return false, fmt.Errorf("SECURITY ERROR: invalid type %T for boolean operation", val)
	}
}

func (vm *VirtualMachine) popString() string {
	val := vm.pop()
	switch v := val.(type) {
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (vm *VirtualMachine) equal(a, b interface{}) bool {
	// Type-aware equality comparison
	switch av := a.(type) {
	case int64:
		if bv, ok := b.(int64); ok {
			return av == bv
		}
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	case bool:
		if bv, ok := b.(bool); ok {
			return av == bv
		}
	}
	return false
}

func (vm *VirtualMachine) verifySignature(pubKeyHex, message, signatureHex string) bool {
	// Ed25519 signature verification
	// pubKeyHex: hex-encoded 32-byte public key
	// message: plaintext message that was signed
	// signatureHex: hex-encoded 64-byte signature
	verified, err := VerifyEd25519Signature(pubKeyHex, message, signatureHex)
	if err != nil {
		// Invalid format - return false instead of error
		// This matches expected behavior in LockScript execution
		return false
	}
	return verified
}