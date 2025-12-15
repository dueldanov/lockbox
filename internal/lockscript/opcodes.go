package lockscript

import "fmt"

// Suppress unused import warning
var _ = fmt.Errorf

// OpCode represents a bytecode operation
type OpCode byte

const (
    // Stack operations
    OpPush OpCode = iota
    OpPop
    OpDup
    OpSwap
    
    // Memory operations
    OpLoad
    OpStore
    
    // Arithmetic operations
    OpAdd
    OpSub
    OpMul
    OpDiv
    OpMod
    
    // Comparison operations
    OpEq
    OpNe
    OpLt
    OpGt
    OpLe
    OpGe
    
    // Logical operations
    OpAnd
    OpOr
    OpNot
    
    // Control flow
    OpIf
    OpElse
    OpEndIf
    OpJump
    OpJumpIf
    OpReturn
    
    // Function calls
    OpCall
    OpCallBuiltin
    
    // Special operations
    OpTimeCheck
    OpSigVerify
    OpHashCheck
    OpGeoCheck
    
    // Constants
    OpTrue
    OpFalse
    OpNull
)

// Instruction represents a bytecode instruction
type Instruction struct {
    OpCode   OpCode
    Operands []interface{}
}

// BytecodeWriter helps write bytecode
type BytecodeWriter struct {
    bytecode []byte
}

// NewBytecodeWriter creates a new bytecode writer
func NewBytecodeWriter() *BytecodeWriter {
    return &BytecodeWriter{
        bytecode: make([]byte, 0, 1024),
    }
}

// WriteOpCode writes an opcode
func (w *BytecodeWriter) WriteOpCode(op OpCode) {
    w.bytecode = append(w.bytecode, byte(op))
}

// WriteInt64 writes an int64 value
func (w *BytecodeWriter) WriteInt64(val int64) {
    // Write as 8 bytes, big-endian
    for i := 7; i >= 0; i-- {
        w.bytecode = append(w.bytecode, byte(val>>(i*8)))
    }
}

// WriteString writes a string
func (w *BytecodeWriter) WriteString(s string) {
    // Write length first
    w.WriteInt64(int64(len(s)))
    // Then write string bytes
    w.bytecode = append(w.bytecode, []byte(s)...)
}

// Bytes returns the bytecode
func (w *BytecodeWriter) Bytes() []byte {
    return w.bytecode
}

// BytecodeReader helps read bytecode
type BytecodeReader struct {
    bytecode []byte
    pos      int
}

// NewBytecodeReader creates a new bytecode reader
func NewBytecodeReader(bytecode []byte) *BytecodeReader {
    return &BytecodeReader{
        bytecode: bytecode,
        pos:      0,
    }
}

// ReadOpCode reads an opcode
func (r *BytecodeReader) ReadOpCode() (OpCode, error) {
    if r.pos >= len(r.bytecode) {
        return 0, fmt.Errorf("unexpected end of bytecode")
    }
    op := OpCode(r.bytecode[r.pos])
    r.pos++
    return op, nil
}

// ReadInt64 reads an int64 value
func (r *BytecodeReader) ReadInt64() (int64, error) {
    if r.pos+8 > len(r.bytecode) {
        return 0, fmt.Errorf("unexpected end of bytecode")
    }
    
    var val int64
    for i := 0; i < 8; i++ {
        val = (val << 8) | int64(r.bytecode[r.pos])
        r.pos++
    }
    
    return val, nil
}

// ReadString reads a string
func (r *BytecodeReader) ReadString() (string, error) {
    length, err := r.ReadInt64()
    if err != nil {
        return "", err
    }
    
    if r.pos+int(length) > len(r.bytecode) {
        return "", fmt.Errorf("unexpected end of bytecode")
    }
    
    s := string(r.bytecode[r.pos : r.pos+int(length)])
    r.pos += int(length)
    
    return s, nil
}

// HasMore returns true if there's more bytecode to read
func (r *BytecodeReader) HasMore() bool {
    return r.pos < len(r.bytecode)
}