package lockscript

import (
    "fmt"
    "strconv"
)

// Parser parses tokens into an AST
type Parser struct {
    tokens  []Token
    current int
}

// NewParser creates a new parser
func NewParser() *Parser {
    return &Parser{}
}

// Parse parses tokens into an AST
func (p *Parser) Parse(tokens []Token) (*AST, error) {
    p.tokens = tokens
    p.current = 0
    
    ast := &AST{
        Nodes: make([]ASTNode, 0),
    }
    
    for !p.isAtEnd() {
        node, err := p.parseStatement()
        if err != nil {
            return nil, err
        }
        if node != nil {
            ast.Nodes = append(ast.Nodes, node)
        }
    }
    
    return ast, nil
}

func (p *Parser) parseStatement() (ASTNode, error) {
    if p.match(TokenKeyword) {
        switch p.previous().Value {
        case "if":
            return p.parseIf()
        case "require":
            return p.parseRequire()
        case "transfer":
            return p.parseTransfer()
        default:
            return nil, fmt.Errorf("unknown keyword: %s", p.previous().Value)
        }
    }
    
    // Try to parse expression statement
    expr, err := p.parseExpression()
    if err != nil {
        return nil, err
    }
    
    // Consume semicolon if present
    p.match(TokenOperator, ";")
    
    return &ExpressionStatement{Expression: expr}, nil
}

func (p *Parser) parseIf() (*IfNode, error) {
    // Parse condition
    condition, err := p.parseExpression()
    if err != nil {
        return nil, fmt.Errorf("expected condition after 'if': %w", err)
    }
    
    // Expect '{'
    if !p.consume(TokenOperator, "{") {
        return nil, fmt.Errorf("expected '{' after if condition")
    }
    
    // Parse then branch
    thenNodes := make([]ASTNode, 0)
    for !p.check(TokenOperator, "}") && !p.isAtEnd() {
        node, err := p.parseStatement()
        if err != nil {
            return nil, err
        }
        if node != nil {
            thenNodes = append(thenNodes, node)
        }
    }
    
    if !p.consume(TokenOperator, "}") {
        return nil, fmt.Errorf("expected '}' after if body")
    }
    
    // Parse optional else
    var elseNodes []ASTNode
    if p.match(TokenKeyword, "else") {
        if !p.consume(TokenOperator, "{") {
            return nil, fmt.Errorf("expected '{' after else")
        }
        
        elseNodes = make([]ASTNode, 0)
        for !p.check(TokenOperator, "}") && !p.isAtEnd() {
            node, err := p.parseStatement()
            if err != nil {
                return nil, err
            }
            if node != nil {
                elseNodes = append(elseNodes, node)
            }
        }
        
        if !p.consume(TokenOperator, "}") {
            return nil, fmt.Errorf("expected '}' after else body")
        }
    }
    
    return &IfNode{
        Condition: condition,
        Then:      thenNodes,
        Else:      elseNodes,
    }, nil
}

func (p *Parser) parseRequire() (*RequireNode, error) {
    // Parse condition
    condition, err := p.parseExpression()
    if err != nil {
        return nil, fmt.Errorf("expected condition after 'require': %w", err)
    }
    
    // Optional message
    message := "requirement failed"
    if p.match(TokenOperator, ",") {
        if p.check(TokenString) {
            message = p.advance().Value
        }
    }
    
    p.consume(TokenOperator, ";")
    
    return &RequireNode{
        Condition: condition,
        Message:   message,
    }, nil
}

func (p *Parser) parseTransfer() (*TransferNode, error) {
    // Parse recipient
    if !p.check(TokenIdent) && !p.check(TokenString) {
        return nil, fmt.Errorf("expected recipient address after 'transfer'")
    }
    to := p.advance().Value
    
    // Expect comma
    if !p.consume(TokenOperator, ",") {
        return nil, fmt.Errorf("expected ',' after recipient")
    }
    
    // Parse amount
    amount, err := p.parseExpression()
    if err != nil {
        return nil, fmt.Errorf("expected amount: %w", err)
    }
    
    // Optional token type
    token := "IOTA"
    if p.match(TokenOperator, ",") {
        if p.check(TokenString) || p.check(TokenIdent) {
            token = p.advance().Value
        }
    }
    
    p.consume(TokenOperator, ";")
    
    return &TransferNode{
        To:     to,
        Amount: amount,
        Token:  token,
    }, nil
}

func (p *Parser) parseExpression() (Expression, error) {
    return p.parseOr()
}

func (p *Parser) parseOr() (Expression, error) {
    expr, err := p.parseAnd()
    if err != nil {
        return nil, err
    }
    
    for p.match(TokenOperator, "||") {
        op := p.previous()
        right, err := p.parseAnd()
        if err != nil {
            return nil, err
        }
        expr = &BinaryExpr{
            Left:     expr,
            Operator: op.Value,
            Right:    right,
        }
    }
    
    return expr, nil
}

func (p *Parser) parseAnd() (Expression, error) {
    expr, err := p.parseEquality()
    if err != nil {
        return nil, err
    }
    
    for p.match(TokenOperator, "&&") {
        op := p.previous()
        right, err := p.parseEquality()
        if err != nil {
            return nil, err
        }
        expr = &BinaryExpr{
            Left:     expr,
            Operator: op.Value,
            Right:    right,
        }
    }
    
    return expr, nil
}

func (p *Parser) parseEquality() (Expression, error) {
    expr, err := p.parseComparison()
    if err != nil {
        return nil, err
    }
    
    for p.matchAny(TokenOperator, "==", "!=") {
        op := p.previous()
        right, err := p.parseComparison()
        if err != nil {
            return nil, err
        }
        expr = &BinaryExpr{
            Left:     expr,
            Operator: op.Value,
            Right:    right,
        }
    }
    
    return expr, nil
}

func (p *Parser) parseComparison() (Expression, error) {
    expr, err := p.parseTerm()
    if err != nil {
        return nil, err
    }
    
    for p.matchAny(TokenOperator, ">", ">=", "<", "<=") {
        op := p.previous()
        right, err := p.parseTerm()
        if err != nil {
            return nil, err
        }
        expr = &BinaryExpr{
            Left:     expr,
            Operator: op.Value,
            Right:    right,
        }
    }
    
    return expr, nil
}

func (p *Parser) parseTerm() (Expression, error) {
    expr, err := p.parseFactor()
    if err != nil {
        return nil, err
    }
    
    for p.matchAny(TokenOperator, "+", "-") {
        op := p.previous()
        right, err := p.parseFactor()
        if err != nil {
            return nil, err
        }
        expr = &BinaryExpr{
            Left:     expr,
            Operator: op.Value,
            Right:    right,
        }
    }
    
    return expr, nil
}

func (p *Parser) parseFactor() (Expression, error) {
    expr, err := p.parseUnary()
    if err != nil {
        return nil, err
    }
    
    for p.matchAny(TokenOperator, "*", "/", "%") {
        op := p.previous()
        right, err := p.parseUnary()
        if err != nil {
            return nil, err
        }
        expr = &BinaryExpr{
            Left:     expr,
            Operator: op.Value,
            Right:    right,
        }
    }
    
    return expr, nil
}

func (p *Parser) parseUnary() (Expression, error) {
    if p.matchAny(TokenOperator, "!", "-") {
        op := p.previous()
        expr, err := p.parseUnary()
        if err != nil {
            return nil, err
        }
        return &UnaryExpr{
            Operator: op.Value,
            Expr:     expr,
        }, nil
    }
    
    return p.parseCall()
}

func (p *Parser) parseCall() (Expression, error) {
    expr, err := p.parsePrimary()
    if err != nil {
        return nil, err
    }
    
    for p.match(TokenOperator, "(") {
        args := make([]Expression, 0)
        
        if !p.check(TokenOperator, ")") {
            for {
                arg, err := p.parseExpression()
                if err != nil {
                    return nil, err
                }
                args = append(args, arg)
                
                if !p.match(TokenOperator, ",") {
                    break
                }
            }
        }
        
        if !p.consume(TokenOperator, ")") {
            return nil, fmt.Errorf("expected ')' after arguments")
        }
        
        // If expr is a variable, it's a function call
        if varExpr, ok := expr.(*VariableExpr); ok {
            expr = &CallExpr{
                Function: varExpr.Name,
                Args:     args,
            }
        } else {
            return nil, fmt.Errorf("invalid function call")
        }
    }
    
    return expr, nil
}

func (p *Parser) parsePrimary() (Expression, error) {
    if p.match(TokenKeyword, "true") {
        return &LiteralExpr{Value: true}, nil
    }
    
    if p.match(TokenKeyword, "false") {
        return &LiteralExpr{Value: false}, nil
    }
    
    if p.match(TokenNumber) {
        val, err := strconv.ParseInt(p.previous().Value, 10, 64)
        if err != nil {
            return nil, fmt.Errorf("invalid number: %w", err)
        }
        return &LiteralExpr{Value: val}, nil
    }
    
    if p.match(TokenString) {
        return &LiteralExpr{Value: p.previous().Value}, nil
    }
    
    if p.match(TokenIdent) {
        return &VariableExpr{Name: p.previous().Value}, nil
    }
    
    if p.match(TokenOperator, "(") {
        expr, err := p.parseExpression()
        if err != nil {
            return nil, err
        }
        if !p.consume(TokenOperator, ")") {
            return nil, fmt.Errorf("expected ')' after expression")
        }
        return expr, nil
    }
    
    return nil, fmt.Errorf("expected expression")
}

// Helper methods

func (p *Parser) match(tokenType TokenType, values ...string) bool {
    if p.check(tokenType, values...) {
        p.advance()
        return true
    }
    return false
}

func (p *Parser) matchAny(tokenType TokenType, values ...string) bool {
    for _, v := range values {
        if p.check(tokenType, v) {
            p.advance()
            return true
        }
    }
    return false
}

func (p *Parser) check(tokenType TokenType, values ...string) bool {
    if p.isAtEnd() {
        return false
    }
    
    if p.peek().Type != tokenType {
        return false
    }
    
    if len(values) == 0 {
        return true
    }
    
    for _, v := range values {
        if p.peek().Value == v {
            return true
        }
    }
    
    return false
}

func (p *Parser) advance() Token {
    if !p.isAtEnd() {
        p.current++
    }
    return p.previous()
}

func (p *Parser) isAtEnd() bool {
    return p.current >= len(p.tokens) || p.peek().Type == TokenEOF
}

func (p *Parser) peek() Token {
    if p.current >= len(p.tokens) {
        return Token{Type: TokenEOF}
    }
    return p.tokens[p.current]
}

func (p *Parser) previous() Token {
    return p.tokens[p.current-1]
}

func (p *Parser) consume(tokenType TokenType, value string) bool {
    if p.check(tokenType, value) {
        p.advance()
        return true
    }
    return false
}

// Additional AST node types

type ExpressionStatement struct {
    Expression Expression
}

func (n *ExpressionStatement) Type() string { return "EXPRESSION" }

type BinaryExpr struct {
    Left     Expression
    Operator string
    Right    Expression
}

func (e *BinaryExpr) Evaluate(env *Environment) (interface{}, error) {
    left, err := e.Left.Evaluate(env)
    if err != nil {
        return nil, err
    }
    
    right, err := e.Right.Evaluate(env)
    if err != nil {
        return nil, err
    }
    
    switch e.Operator {
    case "+":
        return toInt64(left) + toInt64(right), nil
    case "-":
        return toInt64(left) - toInt64(right), nil
    case "*":
        return toInt64(left) * toInt64(right), nil
    case "/":
        r := toInt64(right)
        if r == 0 {
            return nil, fmt.Errorf("division by zero")
        }
        return toInt64(left) / r, nil
    case "==":
        return equalValues(left, right), nil
    case "!=":
        return !equalValues(left, right), nil
    case "<":
        return toInt64(left) < toInt64(right), nil
    case "<=":
        return toInt64(left) <= toInt64(right), nil
    case ">":
        return toInt64(left) > toInt64(right), nil
    case ">=":
        return toInt64(left) >= toInt64(right), nil
    case "&&":
        return toBool(left) && toBool(right), nil
    case "||":
        return toBool(left) || toBool(right), nil
    default:
        return nil, fmt.Errorf("unknown operator: %s", e.Operator)
    }
}

type UnaryExpr struct {
    Operator string
    Expr     Expression
}

func (e *UnaryExpr) Evaluate(env *Environment) (interface{}, error) {
    val, err := e.Expr.Evaluate(env)
    if err != nil {
        return nil, err
    }
    
    switch e.Operator {
    case "!":
        return !toBool(val), nil
    case "-":
        return -toInt64(val), nil
    default:
        return nil, fmt.Errorf("unknown unary operator: %s", e.Operator)
    }
}

type CallExpr struct {
    Function string
    Args     []Expression
}

func (e *CallExpr) Evaluate(env *Environment) (interface{}, error) {
    // Look up function
    fn, exists := env.Functions[e.Function]
    if !exists {
        return nil, fmt.Errorf("undefined function: %s", e.Function)
    }
    
    // Evaluate arguments
    args := make([]interface{}, len(e.Args))
    for i, arg := range e.Args {
        val, err := arg.Evaluate(env)
        if err != nil {
            return nil, err
        }
        args[i] = val
    }
    
    // Call function
    return fn.Call(args)
}

type VariableExpr struct {
    Name string
}

func (e *VariableExpr) Evaluate(env *Environment) (interface{}, error) {
    val, exists := env.Variables[e.Name]
    if !exists {
        return nil, fmt.Errorf("undefined variable: %s", e.Name)
    }
    return val, nil
}

type LiteralExpr struct {
    Value interface{}
}

func (e *LiteralExpr) Evaluate(env *Environment) (interface{}, error) {
    return e.Value, nil
}

// Helper functions

func toInt64(v interface{}) int64 {
    switch val := v.(type) {
    case int64:
        return val
    case int:
        return int64(val)
    case bool:
        if val {
            return 1
        }
        return 0
    default:
        return 0
    }
}

func toBool(v interface{}) bool {
    switch val := v.(type) {
    case bool:
        return val
    case int64:
        return val != 0
    case string:
        return val != ""
    default:
        return false
    }
}

func equalValues(a, b interface{}) bool {
    return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}