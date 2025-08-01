package lockscript

import (
    "errors"
    "time"
)

var (
    ErrScriptTooLarge    = errors.New("script size exceeds maximum allowed")
    ErrExecutionTimeout  = errors.New("script execution timeout")
    ErrInvalidSyntax     = errors.New("invalid syntax")
    ErrUndefinedVariable = errors.New("undefined variable")
    ErrTypeMismatch      = errors.New("type mismatch")
)

// CompiledScript represents a compiled LockScript
type CompiledScript struct {
    Source    string
    Bytecode  []byte
    Timestamp time.Time
}

// Environment provides execution context for scripts
type Environment struct {
    Variables map[string]interface{}
    Functions map[string]Function
    Sender    string
    Timestamp time.Time
}

// ExecutionResult contains the result of script execution
type ExecutionResult struct {
    Success bool
    Output  interface{}
    GasUsed uint64
    Logs    []string
}

// AST represents the abstract syntax tree
type AST struct {
    Nodes []ASTNode
}

// ASTNode is the interface for all AST nodes
type ASTNode interface {
    Type() string
}

// IfNode represents an IF statement
type IfNode struct {
    Condition Expression
    Then      []ASTNode
    Else      []ASTNode
}

func (n *IfNode) Type() string { return "IF" }

// RequireNode represents a REQUIRE statement
type RequireNode struct {
    Condition Expression
    Message   string
}

func (n *RequireNode) Type() string { return "REQUIRE" }

// TransferNode represents a TRANSFER statement
type TransferNode struct {
    To     string
    Amount Expression
    Token  string
}

func (n *TransferNode) Type() string { return "TRANSFER" }

// CallNode represents a function call
type CallNode struct {
    Function string
    Args     []Expression
}

func (n *CallNode) Type() string { return "CALL" }

// Expression represents an expression in LockScript
type Expression interface {
    Evaluate(env *Environment) (interface{}, error)
}

// Function represents a callable function in LockScript
type Function interface {
    Call(args []interface{}) (interface{}, error)
}