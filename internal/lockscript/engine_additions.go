package lockscript

import (
    "fmt"
)

// Additional Engine fields and methods

var functions map[string]Function

// ExecutionResult represents the result of script execution
type ExecutionResult struct {
    Success bool
    Value   interface{}
    GasUsed uint64
    Logs    []string
}

// Additional Expression types implementation

// CompileNode compiles an AST node to bytecode
func (c *Compiler) compileNode(node ASTNode) ([]byte, error) {
    writer := NewBytecodeWriter()
    
    switch n := node.(type) {
    case *IfNode:
        return c.compileIf(n)
    case *RequireNode:
        return c.compileRequire(n)
    case *TransferNode:
        return c.compileTransfer(n)
    case *CallNode:
        return c.compileCall(n)
    case *ExpressionStatement:
        return c.compileExpression(n.Expression)
    default:
        return nil, fmt.Errorf("unknown node type: %T", node)
    }
}

func (c *Compiler) compileIf(node *IfNode) ([]byte, error) {
    writer := NewBytecodeWriter()
    
    // Compile condition
    condBytecode, err := c.compileExpression(node.Condition)
    if err != nil {
        return nil, err
    }
    writer.bytecode = append(writer.bytecode, condBytecode...)
    
    // Jump if false
    writer.WriteOpCode(OpJumpIf)
    jumpPos := len(writer.bytecode)
    writer.WriteInt64(0) // Placeholder for jump offset
    
    // Compile then branch
    for _, stmt := range node.Then {
        stmtBytecode, err := c.compileNode(stmt)
        if err != nil {
            return nil, err
        }
        writer.bytecode = append(writer.bytecode, stmtBytecode...)
    }
    
    // Jump over else branch
    var elseJumpPos int
    if len(node.Else) > 0 {
        writer.WriteOpCode(OpJump)
        elseJumpPos = len(writer.bytecode)
        writer.WriteInt64(0) // Placeholder
    }
    
    // Update condition jump offset
    thenEnd := len(writer.bytecode)
    offset := int64(thenEnd - jumpPos - 8)
    for i := 0; i < 8; i++ {
        writer.bytecode[jumpPos+i] = byte(offset >> ((7 - i) * 8))
    }
    
    // Compile else branch
    if len(node.Else) > 0 {
        for _, stmt := range node.Else {
            stmtBytecode, err := c.compileNode(stmt)
            if err != nil {
                return nil, err
            }
            writer.bytecode = append(writer.bytecode, stmtBytecode...)
        }
        
        // Update else jump offset
        elseEnd := len(writer.bytecode)
        offset := int64(elseEnd - elseJumpPos - 8)
        for i := 0; i < 8; i++ {
            writer.bytecode[elseJumpPos+i] = byte(offset >> ((7 - i) * 8))
        }
    }
    
    return writer.Bytes(), nil
}

func (c *Compiler) compileRequire(node *RequireNode) ([]byte, error) {
    writer := NewBytecodeWriter()
    
    // Compile condition
    condBytecode, err := c.compileExpression(node.Condition)
    if err != nil {
        return nil, err
    }
    writer.bytecode = append(writer.bytecode, condBytecode...)
    
    // Check condition
    writer.WriteOpCode(OpNot)
    writer.WriteOpCode(OpJumpIf)
    writer.WriteInt64(16) // Jump over error
    
    // Push error message
    writer.WriteOpCode(OpPush)
    writer.WriteString(node.Message)
    
    // Return with error
    writer.WriteOpCode(OpReturn)
    
    return writer.Bytes(), nil
}

func (c *Compiler) compileTransfer(node *TransferNode) ([]byte, error) {
    writer := NewBytecodeWriter()
    
    // Push recipient
    writer.WriteOpCode(OpPush)
    writer.WriteString(node.To)
    
    // Compile amount
    amountBytecode, err := c.compileExpression(node.Amount)
    if err != nil {
        return nil, err
    }
    writer.bytecode = append(writer.bytecode, amountBytecode...)
    
    // Push token
    writer.WriteOpCode(OpPush)
    writer.WriteString(node.Token)
    
    // Call transfer function
    writer.WriteOpCode(OpCallBuiltin)
    writer.WriteString("transfer")
    writer.WriteInt64(3) // 3 arguments
    
    return writer.Bytes(), nil
}

func (c *Compiler) compileCall(node *CallNode) ([]byte, error) {
    writer := NewBytecodeWriter()
    
    // Compile arguments
    for _, arg := range node.Args {
        argBytecode, err := c.compileExpression(arg)
        if err != nil {
            return nil, err
        }
        writer.bytecode = append(writer.bytecode, argBytecode...)
    }
    
    // Call function
    writer.WriteOpCode(OpCallBuiltin)
    writer.WriteString(node.Function)
    writer.WriteInt64(int64(len(node.Args)))
    
    return writer.Bytes(), nil
}

func (c *Compiler) compileExpression(expr Expression) ([]byte, error) {
    writer := NewBytecodeWriter()
    
    switch e := expr.(type) {
    case *LiteralExpr:
        writer.WriteOpCode(OpPush)
        switch v := e.Value.(type) {
        case bool:
            if v {
                writer.WriteInt64(1)
            } else {
                writer.WriteInt64(0)
            }
        case int64:
            writer.WriteInt64(v)
        case string:
            writer.WriteString(v)
        default:
            return nil, fmt.Errorf("unsupported literal type: %T", v)
        }
        
    case *VariableExpr:
        writer.WriteOpCode(OpLoad)
        writer.WriteString(e.Name)
        
    case *BinaryExpr:
        // Compile left operand
        leftBytecode, err := c.compileExpression(e.Left)
        if err != nil {
            return nil, err
        }
        writer.bytecode = append(writer.bytecode, leftBytecode...)
        
        // Compile right operand
        rightBytecode, err := c.compileExpression(e.Right)
        if err != nil {
            return nil, err
        }
        writer.bytecode = append(writer.bytecode, rightBytecode...)
        
        // Add operator
        switch e.Operator {
        case "+":
            writer.WriteOpCode(OpAdd)
        case "-":
            writer.WriteOpCode(OpSub)
        case "*":
            writer.WriteOpCode(OpMul)
        case "/":
            writer.WriteOpCode(OpDiv)
        case "==":
            writer.WriteOpCode(OpEq)
        case "!=":
            writer.WriteOpCode(OpNe)
        case "<":
            writer.WriteOpCode(OpLt)
        case "<=":
            writer.WriteOpCode(OpLe)
        case ">":
            writer.WriteOpCode(OpGt)
        case ">=":
            writer.WriteOpCode(OpGe)
        case "&&":
            writer.WriteOpCode(OpAnd)
        case "||":
            writer.WriteOpCode(OpOr)
        default:
            return nil, fmt.Errorf("unsupported operator: %s", e.Operator)
        }
        
    case *UnaryExpr:
        // Compile operand
        operandBytecode, err := c.compileExpression(e.Expr)
        if err != nil {
            return nil, err
        }
        writer.bytecode = append(writer.bytecode, operandBytecode...)
        
        // Add operator
        switch e.Operator {
        case "!":
            writer.WriteOpCode(OpNot)
        case "-":
            writer.WriteOpCode(OpPush)
            writer.WriteInt64(-1)
            writer.WriteOpCode(OpMul)
        default:
            return nil, fmt.Errorf("unsupported unary operator: %s", e.Operator)
        }
        
    case *CallExpr:
        // Compile arguments
        for _, arg := range e.Args {
            argBytecode, err := c.compileExpression(arg)
            if err != nil {
                return nil, err
            }
            writer.bytecode = append(writer.bytecode, argBytecode...)
        }
        
        // Call function
        writer.WriteOpCode(OpCallBuiltin)
        writer.WriteString(e.Function)
        writer.WriteInt64(int64(len(e.Args)))
        
    default:
        return nil, fmt.Errorf("unsupported expression type: %T", e)
    }
    
    return writer.Bytes(), nil
}