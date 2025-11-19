package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/lockscript"
)

// CompilerService handles script compilation to Go and WASM
type CompilerService struct {
	scriptEngine *lockscript.Engine
	cache        map[string]*CompilationResult
}

type CompilationResult struct {
	ScriptID   string
	Source     string
	GoCode     string
	WASMBinary []byte
	CompiledAt time.Time
	Hash       string
}

func NewCompilerService(scriptEngine *lockscript.Engine) *CompilerService {
	return &CompilerService{
		scriptEngine: scriptEngine,
		cache:        make(map[string]*CompilationResult),
	}
}

// CompileToGo compiles LockScript to Go code
func (cs *CompilerService) CompileToGo(ctx context.Context, source string) (*CompilationResult, error) {
	// Generate hash for caching
	hash := cs.generateHash(source)
	
	// Check cache
	if cached, ok := cs.cache[hash]; ok {
		return cached, nil
	}

	// Parse script
	ast, err := cs.scriptEngine.ParseScript(source)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	// Generate Go code
	var buf bytes.Buffer
	if err := cs.generateGoCode(&buf, ast); err != nil {
		return nil, fmt.Errorf("code generation error: %w", err)
	}

	result := &CompilationResult{
		ScriptID:   hash[:8],
		Source:     source,
		GoCode:     buf.String(),
		CompiledAt: time.Now(),
		Hash:       hash,
	}

	cs.cache[hash] = result
	return result, nil
}

// CompileToWASM compiles LockScript to WASM
func (cs *CompilerService) CompileToWASM(ctx context.Context, source string) (*CompilationResult, error) {
	// First compile to Go
	goResult, err := cs.CompileToGo(ctx, source)
	if err != nil {
		return nil, err
	}

	// Generate WASM binary
	wasmBinary, err := cs.generateWASM(goResult.GoCode)
	if err != nil {
		return nil, fmt.Errorf("WASM generation error: %w", err)
	}

	goResult.WASMBinary = wasmBinary
	return goResult, nil
}

func (cs *CompilerService) generateGoCode(buf *bytes.Buffer, ast *lockscript.AST) error {
	// Write package header
	buf.WriteString("package lockscript_generated\n\n")
	buf.WriteString("import (\n")
	buf.WriteString("\t\"time\"\n")
	buf.WriteString("\t\"crypto/sha256\"\n")
	buf.WriteString("\t\"encoding/hex\"\n")
	buf.WriteString(")\n\n")

	// Write main function
	buf.WriteString("func Execute(env map[string]interface{}) (bool, interface{}, error) {\n")
	
	// Generate code for each node
	for _, node := range ast.Nodes {
		if err := cs.generateNodeCode(buf, node, 1); err != nil {
			return err
		}
	}

	buf.WriteString("\treturn true, nil, nil\n")
	buf.WriteString("}\n")

	return nil
}

func (cs *CompilerService) generateNodeCode(buf *bytes.Buffer, node lockscript.ASTNode, indent int) error {
	tabs := cs.getTabs(indent)

	switch n := node.(type) {
	case *lockscript.IfNode:
		buf.WriteString(tabs + "if ")
		cs.generateExpressionCode(buf, n.Condition)
		buf.WriteString(" {\n")
		
		for _, stmt := range n.Then {
			cs.generateNodeCode(buf, stmt, indent+1)
		}
		
		if len(n.Else) > 0 {
			buf.WriteString(tabs + "} else {\n")
			for _, stmt := range n.Else {
				cs.generateNodeCode(buf, stmt, indent+1)
			}
		}
		
		buf.WriteString(tabs + "}\n")

	case *lockscript.RequireNode:
		buf.WriteString(tabs + "if !(")
		cs.generateExpressionCode(buf, n.Condition)
		buf.WriteString(") {\n")
		buf.WriteString(tabs + "\treturn false, nil, fmt.Errorf(\"" + n.Message + "\")\n")
		buf.WriteString(tabs + "}\n")

	case *lockscript.TransferNode:
		buf.WriteString(fmt.Sprintf("%s// Transfer %s to %s\n", tabs, n.Token, n.To))
		buf.WriteString(tabs + "_ = transfer(\"" + n.To + "\", ")
		cs.generateExpressionCode(buf, n.Amount)
		buf.WriteString(", \"" + n.Token + "\")\n")

	case *lockscript.ReturnNode:
		buf.WriteString(tabs + "return true, ")
		if n.Value != nil {
			cs.generateExpressionCode(buf, n.Value)
		} else {
			buf.WriteString("nil")
		}
		buf.WriteString(", nil\n")
	}

	return nil
}

func (cs *CompilerService) generateExpressionCode(buf *bytes.Buffer, expr lockscript.Expression) {
	switch e := expr.(type) {
	case *lockscript.LiteralExpr:
		switch v := e.Value.(type) {
		case string:
			buf.WriteString("\"" + v + "\"")
		case bool:
			if v {
				buf.WriteString("true")
			} else {
				buf.WriteString("false")
			}
		case int64:
			buf.WriteString(fmt.Sprintf("%d", v))
		}

	case *lockscript.VariableExpr:
		buf.WriteString("env[\"" + e.Name + "\"]")

	case *lockscript.BinaryExpr:
		buf.WriteString("(")
		cs.generateExpressionCode(buf, e.Left)
		buf.WriteString(" " + e.Operator + " ")
		cs.generateExpressionCode(buf, e.Right)
		buf.WriteString(")")

	case *lockscript.CallExpr:
		buf.WriteString(e.Function + "(")
		for i, arg := range e.Args {
			if i > 0 {
				buf.WriteString(", ")
			}
			cs.generateExpressionCode(buf, arg)
		}
		buf.WriteString(")")
	}
}

func (cs *CompilerService) generateWASM(goCode string) ([]byte, error) {
	// TODO: Implement actual Go to WASM compilation
	// For now, return placeholder
	return []byte("WASM_PLACEHOLDER"), nil
}

func (cs *CompilerService) generateHash(source string) string {
	h := sha256.New()
	h.Write([]byte(source))
	return hex.EncodeToString(h.Sum(nil))
}

func (cs *CompilerService) getTabs(indent int) string {
	tabs := ""
	for i := 0; i < indent; i++ {
		tabs += "\t"
	}
	return tabs
}

// Helper function for generated code
func transfer(to string, amount interface{}, token string) error {
	// Placeholder for actual transfer logic
	return nil
}