package lockscript

import (
	"fmt"
	"strconv"
	"strings"
)

type Parser struct {
	tokens []Token
	pos    int
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(tokens []Token) (*AST, error) {
	p.tokens = tokens
	p.pos = 0
	
	nodes, err := p.parseStatements()
	if err != nil {
		return nil, err
	}
	
	return &AST{Nodes: nodes}, nil
}

func (p *Parser) parseStatements() ([]ASTNode, error) {
	var nodes []ASTNode
	
	for !p.isAtEnd() {
		node, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	
	return nodes, nil
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
	
	if p.match(TokenIdent) {
		name := p.previous().Value
		if p.match(TokenOperator) && p.previous().Value == "(" {
			return p.parseCall(name)
		}
		p.pos-- // backtrack
	}
	
	// Skip empty statements
	if p.match(TokenOperator) && p.previous().Value == ";" {
		return nil, nil
	}
	
	return nil, fmt.Errorf("unexpected token: %v", p.peek())
}

func (p *Parser) parseIf() (ASTNode, error) {
	condition, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	
	if !p.match(TokenOperator) || p.previous().Value != "{" {
		return nil, fmt.Errorf("expected '{' after if condition")
	}
	
	thenBranch, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	
	var elseBranch []ASTNode
	if p.match(TokenKeyword) && p.previous().Value == "else" {
		if !p.match(TokenOperator) || p.previous().Value != "{" {
			return nil, fmt.Errorf("expected '{' after else")
		}
		elseBranch, err = p.parseBlock()
		if err != nil {
			return nil, err
		}
	}
	
	return &IfNode{
		Condition: condition,
		Then:      thenBranch,
		Else:      elseBranch,
	}, nil
}

func (p *Parser) parseRequire() (ASTNode, error) {
	condition, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	
	message := ""
	if p.match(TokenOperator) && p.previous().Value == "," {
		if p.match(TokenString) {
			message = p.previous().Value
		}
	}
	
	return &RequireNode{
		Condition: condition,
		Message:   message,
	}, nil
}

func (p *Parser) parseTransfer() (ASTNode, error) {
	if !p.match(TokenIdent) {
		return nil, fmt.Errorf("expected recipient address")
	}
	to := p.previous().Value
	
	if !p.match(TokenOperator) || p.previous().Value != "," {
		return nil, fmt.Errorf("expected ',' after recipient")
	}
	
	amount, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	
	token := "IOTA"
	if p.match(TokenOperator) && p.previous().Value == "," {
		if p.match(TokenString) {
			token = p.previous().Value
		}
	}
	
	return &TransferNode{
		To:     to,
		Amount: amount,
		Token:  token,
	}, nil
}

func (p *Parser) parseCall(name string) (ASTNode, error) {
	var args []Expression
	
	for !p.check(TokenOperator) || p.peek().Value != ")" {
		arg, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		
		if !p.match(TokenOperator) || (p.previous().Value != "," && p.previous().Value != ")") {
			break
		}
		if p.previous().Value == ")" {
			break
		}
	}
	
	if !p.match(TokenOperator) || p.previous().Value != ")" {
		return nil, fmt.Errorf("expected ')' after function arguments")
	}
	
	return &CallNode{
		Function: name,
		Args:     args,
	}, nil
}

func (p *Parser) parseBlock() ([]ASTNode, error) {
	var nodes []ASTNode
	
	for !p.check(TokenOperator) || p.peek().Value != "}" {
		node, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	
	if !p.match(TokenOperator) || p.previous().Value != "}" {
		return nil, fmt.Errorf("expected '}' to close block")
	}
	
	return nodes, nil
}

func (p *Parser) parseExpression() (Expression, error) {
	return p.parseOr()
}

func (p *Parser) parseOr() (Expression, error) {
	expr, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	
	for p.match(TokenOperator) && p.previous().Value == "||" {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:  expr,
			Op:    "||",
			Right: right,
		}
	}
	
	return expr, nil
}

func (p *Parser) parseAnd() (Expression, error) {
	expr, err := p.parseEquality()
	if err != nil {
		return nil, err
	}
	
	for p.match(TokenOperator) && p.previous().Value == "&&" {
		right, err := p.parseEquality()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:  expr,
			Op:    "&&",
			Right: right,
		}
	}
	
	return expr, nil
}

func (p *Parser) parseEquality() (Expression, error) {
	expr, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	
	for p.match(TokenOperator) {
		op := p.previous().Value
		if op != "==" && op != "!=" {
			p.pos--
			break
		}
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:  expr,
			Op:    op,
			Right: right,
		}
	}
	
	return expr, nil
}

func (p *Parser) parseComparison() (Expression, error) {
	expr, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	
	for p.match(TokenOperator) {
		op := p.previous().Value
		if op != "<" && op != ">" && op != "<=" && op != ">=" {
			p.pos--
			break
		}
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:  expr,
			Op:    op,
			Right: right,
		}
	}
	
	return expr, nil
}

func (p *Parser) parseTerm() (Expression, error) {
	expr, err := p.parseFactor()
	if err != nil {
		return nil, err
	}
	
	for p.match(TokenOperator) {
		op := p.previous().Value
		if op != "+" && op != "-" {
			p.pos--
			break
		}
		right, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:  expr,
			Op:    op,
			Right: right,
		}
	}
	
	return expr, nil
}

func (p *Parser) parseFactor() (Expression, error) {
	expr, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	
	for p.match(TokenOperator) {
		op := p.previous().Value
		if op != "*" && op != "/" && op != "%" {
			p.pos--
			break
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:  expr,
			Op:    op,
			Right: right,
		}
	}
	
	return expr, nil
}

func (p *Parser) parseUnary() (Expression, error) {
	if p.match(TokenOperator) {
		op := p.previous().Value
		if op == "!" || op == "-" {
			expr, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			return &UnaryExpr{
				Op:   op,
				Expr: expr,
			}, nil
		}
		p.pos--
	}
	
	return p.parsePrimary()
}

func (p *Parser) parsePrimary() (Expression, error) {
	if p.match(TokenNumber) {
		val, err := strconv.ParseInt(p.previous().Value, 10, 64)
		if err != nil {
			return nil, err
		}
		return &LiteralExpr{Value: val}, nil
	}
	
	if p.match(TokenString) {
		return &LiteralExpr{Value: p.previous().Value}, nil
	}
	
	if p.match(TokenIdent) {
		name := p.previous().Value
		if p.match(TokenOperator) && p.previous().Value == "(" {
			return p.parseFunctionCall(name)
		}
		return &VariableExpr{Name: name}, nil
	}
	
	if p.match(TokenOperator) && p.previous().Value == "(" {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.match(TokenOperator) || p.previous().Value != ")" {
			return nil, fmt.Errorf("expected ')' after expression")
		}
		return expr, nil
	}
	
	return nil, fmt.Errorf("unexpected token in expression: %v", p.peek())
}

func (p *Parser) parseFunctionCall(name string) (Expression, error) {
	var args []Expression
	
	for !p.check(TokenOperator) || p.peek().Value != ")" {
		arg, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		
		if !p.match(TokenOperator) || (p.previous().Value != "," && p.previous().Value != ")") {
			break
		}
		if p.previous().Value == ")" {
			break
		}
	}
	
	if !p.match(TokenOperator) || p.previous().Value != ")" {
		return nil, fmt.Errorf("expected ')' after function arguments")
	}
	
	return &CallExpr{
		Function: name,
		Args:     args,
	}, nil
}

func (p *Parser) match(types ...TokenType) bool {
	for _, t := range types {
		if p.check(t) {
			p.advance()
			return true
		}
	}
	return false
}

func (p *Parser) check(t TokenType) bool {
	if p.isAtEnd() {
		return false
	}
	return p.peek().Type == t
}

func (p *Parser) advance() Token {
	if !p.isAtEnd() {
		p.pos++
	}
	return p.previous()
}

func (p *Parser) isAtEnd() bool {
	return p.pos >= len(p.tokens) || p.peek().Type == TokenEOF
}

func (p *Parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) previous() Token {
	if p.pos == 0 {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos-1]
}

// Expression implementations
type BinaryExpr struct {
	Left  Expression
	Op    string
	Right Expression
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
	
	switch e.Op {
	case "+":
		return toInt64(left) + toInt64(right), nil
	case "-":
		return toInt64(left) - toInt64(right), nil
	case "*":
		return toInt64(left) * toInt64(right), nil
	case "/":
		if toInt64(right) == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return toInt64(left) / toInt64(right), nil
	case "==":
		return left == right, nil
	case "!=":
		return left != right, nil
	case "<":
		return toInt64(left) < toInt64(right), nil
	case ">":
		return toInt64(left) > toInt64(right), nil
	case "<=":
		return toInt64(left) <= toInt64(right), nil
	case ">=":
		return toInt64(left) >= toInt64(right), nil
	case "&&":
		return toBool(left) && toBool(right), nil
	case "||":
		return toBool(left) || toBool(right), nil
	default:
		return nil, fmt.Errorf("unknown operator: %s", e.Op)
	}
}

type UnaryExpr struct {
	Op   string
	Expr Expression
}

func (e *UnaryExpr) Evaluate(env *Environment) (interface{}, error) {
	val, err := e.Expr.Evaluate(env)
	if err != nil {
		return nil, err
	}
	
	switch e.Op {
	case "!":
		return !toBool(val), nil
	case "-":
		return -toInt64(val), nil
	default:
		return nil, fmt.Errorf("unknown unary operator: %s", e.Op)
	}
}

type LiteralExpr struct {
	Value interface{}
}

func (e *LiteralExpr) Evaluate(env *Environment) (interface{}, error) {
	return e.Value, nil
}

type VariableExpr struct {
	Name string
}

func (e *VariableExpr) Evaluate(env *Environment) (interface{}, error) {
	if val, ok := env.Variables[e.Name]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("undefined variable: %s", e.Name)
}

type CallExpr struct {
	Function string
	Args     []Expression
}

func (e *CallExpr) Evaluate(env *Environment) (interface{}, error) {
	if fn, ok := env.Functions[e.Function]; ok {
		var args []interface{}
		for _, arg := range e.Args {
			val, err := arg.Evaluate(env)
			if err != nil {
				return nil, err
			}
			args = append(args, val)
		}
		return fn.Call(args)
	}
	return nil, fmt.Errorf("undefined function: %s", e.Function)
}

// Helper functions
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