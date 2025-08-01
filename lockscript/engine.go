package lockscript

import (
    "context"
    "fmt"
    "time"
    
    "github.com/iotaledger/hive.go/logger"
)

// Engine handles LockScript DSL compilation and execution
type Engine struct {
    *logger.WrappedLogger
    
    compiler   *Compiler
    vm         *VirtualMachine
    cache      *ScriptCache
    
    maxScriptSize    int
    executionTimeout time.Duration
}

// NewEngine creates a new LockScript engine
func NewEngine(log *logger.Logger, maxScriptSize int, executionTimeout time.Duration) *Engine {
    return &Engine{
        WrappedLogger:    logger.NewWrappedLogger(log),
        compiler:         NewCompiler(),
        vm:               NewVirtualMachine(),
        cache:            NewScriptCache(),
        maxScriptSize:    maxScriptSize,
        executionTimeout: executionTimeout,
    }
}

// CompileScript compiles LockScript DSL to bytecode
func (e *Engine) CompileScript(ctx context.Context, source string) (*CompiledScript, error) {
    if len(source) > e.maxScriptSize {
        return nil, ErrScriptTooLarge
    }
    
    // Check cache first
    if cached := e.cache.Get(source); cached != nil {
        return cached, nil
    }
    
    // Parse the script
    ast, err := e.compiler.Parse(source)
    if err != nil {
        return nil, fmt.Errorf("parse error: %w", err)
    }
    
    // Compile to bytecode
    bytecode, err := e.compiler.Compile(ast)
    if err != nil {
        return nil, fmt.Errorf("compilation error: %w", err)
    }
    
    compiled := &CompiledScript{
        Source:    source,
        Bytecode:  bytecode,
        Timestamp: time.Now(),
    }
    
    // Cache the compiled script
    e.cache.Put(source, compiled)
    
    return compiled, nil
}

// ExecuteScript executes compiled LockScript
func (e *Engine) ExecuteScript(ctx context.Context, script *CompiledScript, env *Environment) (*ExecutionResult, error) {
    // Create execution context with timeout
    execCtx, cancel := context.WithTimeout(ctx, e.executionTimeout)
    defer cancel()
    
    // Execute in VM
    result, err := e.vm.Execute(execCtx, script.Bytecode, env)
    if err != nil {
        return nil, fmt.Errorf("execution error: %w", err)
    }
    
    return result, nil
}

// ValidateScript performs static analysis on a script
func (e *Engine) ValidateScript(source string) error {
    ast, err := e.compiler.Parse(source)
    if err != nil {
        return err
    }
    
    return e.compiler.Validate(ast)
}