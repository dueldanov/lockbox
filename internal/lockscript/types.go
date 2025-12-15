package lockscript

import (
	"context"
	"errors"
	"time"
)

// Errors
var (
	ErrUndefinedVariable = errors.New("undefined variable")
	ErrExecutionTimeout  = errors.New("execution timeout")
	ErrScriptTooLarge    = errors.New("script too large")
)

// Token types
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenIdent
	TokenNumber
	TokenString
	TokenKeyword
	TokenOperator
)

// Token represents a lexical token
type Token struct {
	Type  TokenType
	Value string
}

// Expression interface for all expression types
type Expression interface {
	Evaluate(env *Environment) (interface{}, error)
}

// ASTNode interface for all AST node types
type ASTNode interface {
	Type() string
}

// AST represents the abstract syntax tree
type AST struct {
	Nodes []ASTNode
}

// Function interface for callable functions
type Function interface {
	Call(args []interface{}) (interface{}, error)
}

// Environment holds variables and functions for script execution
type Environment struct {
	Variables map[string]interface{}
	Functions map[string]Function
}

// NewEnvironment creates a new environment
func NewEnvironment() *Environment {
	return &Environment{
		Variables: make(map[string]interface{}),
		Functions: make(map[string]Function),
	}
}

// CompiledScript represents a compiled LockScript
type CompiledScript struct {
	Source   string
	Bytecode []byte
	AST      *AST
}

// Engine is the LockScript execution engine
type Engine struct {
	cache         *ScriptCache
	functions     map[string]Function
	maxScriptSize int
	timeout       time.Duration
}

// NewEngine creates a new LockScript engine
func NewEngine(cache *ScriptCache, maxScriptSize int, timeout time.Duration) *Engine {
	if cache == nil {
		cache = NewScriptCache()
	}
	e := &Engine{
		cache:         cache,
		functions:     make(map[string]Function),
		maxScriptSize: maxScriptSize,
		timeout:       timeout,
	}
	e.RegisterBuiltinFunctions()
	return e
}

// CompileScript compiles a LockScript source into bytecode
func (e *Engine) CompileScript(ctx context.Context, source string) (*CompiledScript, error) {
	// Check cache first
	if cached := e.cache.Get(source); cached != nil {
		return cached, nil
	}

	// Tokenize
	lexer := NewLexer()
	tokens, err := lexer.Tokenize(source)
	if err != nil {
		return nil, err
	}

	// Parse
	parser := NewParser()
	ast, err := parser.Parse(tokens)
	if err != nil {
		return nil, err
	}

	// Validate
	validator := NewValidator()
	if err := validator.Validate(ast); err != nil {
		return nil, err
	}

	// Compile to bytecode
	compiler := NewCompiler()
	bytecode, err := compiler.Compile(ast)
	if err != nil {
		return nil, err
	}

	script := &CompiledScript{
		Source:   source,
		Bytecode: bytecode,
		AST:      ast,
	}

	// Store in cache
	e.cache.Put(source, script)

	return script, nil
}

// ExecuteScript executes a compiled script
func (e *Engine) ExecuteScript(ctx context.Context, script *CompiledScript, env *Environment) (*ExecutionResult, error) {
	// Create context with timeout
	if e.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	// Execute using VM
	vm := NewVirtualMachine()
	return vm.Execute(ctx, script.Bytecode, env)
}

// Compiler compiles AST to bytecode
type Compiler struct {
	// Internal state
}

// NewCompiler creates a new compiler
func NewCompiler() *Compiler {
	return &Compiler{}
}

// Compile compiles an AST to bytecode
func (c *Compiler) Compile(ast *AST) ([]byte, error) {
	writer := NewBytecodeWriter()

	for _, node := range ast.Nodes {
		bytecode, err := c.compileNode(node)
		if err != nil {
			return nil, err
		}
		writer.bytecode = append(writer.bytecode, bytecode...)
	}

	return writer.Bytes(), nil
}

// AST node types for control flow and statements

// IfNode represents an if statement
type IfNode struct {
	Condition Expression
	Then      []ASTNode
	Else      []ASTNode
}

func (n *IfNode) Type() string {
	return "IF"
}

// RequireNode represents a require statement
type RequireNode struct {
	Condition Expression
	Message   string
}

func (n *RequireNode) Type() string {
	return "REQUIRE"
}

// TransferNode represents a transfer statement
type TransferNode struct {
	To     string
	Amount Expression
	Token  string
}

func (n *TransferNode) Type() string {
	return "TRANSFER"
}

// CallNode represents a function call statement
type CallNode struct {
	Function string
	Args     []Expression
}

func (n *CallNode) Type() string {
	return "CALL"
}
