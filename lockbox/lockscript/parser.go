package lockscript

import (
	"fmt"
	"strconv"
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
	if p.match("if") {
		return p.parseIf()
	}
	if p.match("require") {
		return p.parseRequire()
	}
	if p.match("transfer") {
		return p.parseTransfer()
	}
	if p.match("return") {
		return p.parseReturn()
	}

	// Try to parse as expression statement
	expr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if !p.consume(";") {
		return nil, fmt.Errorf("expected ';' after expression")
	}

	return &ExpressionStatement{Expression: expr}, nil
}

func (p *Parser) parseIf() (*IfNode, error) {
	if !p.consume("(") {
		return nil, fmt.Errorf("expected '(' after 'if'")
	}

	condition, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if !p.consume(")") {
		return nil, fmt.Errorf("expected ')' after if condition")
	}

	if !p.consume("{") {
		return nil, fmt.Errorf("expected '{' after if condition")
	}

	thenStmts := make([]ASTNode, 0)
	for !p.check("}") && !p.isAtEnd() {
		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		thenStmts = append(thenStmts, stmt)
	}

	if !p.consume("}") {
		return nil, fmt.Errorf("expected '}' after if body")
	}

	var elseStmts []ASTNode
	if p.match("else") {
		if !p.consume("{") {
			return nil, fmt.Errorf("expected '{' after 'else'")
		}

		elseStmts = make([]ASTNode, 0)
		for !p.check("}") && !p.isAtEnd() {
			stmt, err := p.parseStatement()
			if err != nil {
				return nil, err
			}
			elseStmts = append(elseStmts, stmt)
		}

		if !p.consume("}") {
			return nil, fmt.Errorf("expected '}' after else body")
		}
	}

	return &IfNode{
		Condition: condition,
		Then:      thenStmts,
		Else:      elseStmts,
	}, nil
}

func (p *Parser) parseRequire() (*RequireNode, error) {
	if !p.consume("(") {
		return nil, fmt.Errorf("expected '(' after 'require'")
	}

	condition, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	message := "requirement failed"
	if p.consume(",") {
		if p.current().Type != TokenString {
			return nil, fmt.Errorf("expected string message after ','")
		}
		message = p.current().Value
		p.advance()
	}

	if !p.consume(")") {
		return nil, fmt.Errorf("expected ')' after require arguments")
	}

	if !p.consume(";") {
		return nil, fmt.Errorf("expected ';' after require")
	}

	return &RequireNode{
		Condition: condition,
		Message:   message,
	}, nil
}

func (p *Parser) parseTransfer() (*TransferNode, error) {
	if !p.consume("(") {
		return nil, fmt.Errorf("expected '(' after 'transfer'")
	}

	// Parse recipient address
	to, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if !p.consume(",") {
		return nil, fmt.Errorf("expected ',' after recipient")
	}

	// Parse amount
	amount, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	// Optional token parameter
	token := "IOTA"
	if p.consume(",") {
		tokenExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if lit, ok := tokenExpr.(*LiteralExpr); ok {
			if strVal, ok := lit.Value.(string); ok {
				token = strVal
			}
		}
	}

	if !p.consume(")") {
		return nil, fmt.Errorf("expected ')' after transfer arguments")
	}

	if !p.consume(";") {
		return nil, fmt.Errorf("expected ';' after transfer")
	}

	// Convert to string if it's a literal
	var toStr string
	if lit, ok := to.(*LiteralExpr); ok {
		if str, ok := lit.Value.(string); ok {
			toStr = str
		}
	}

	return &TransferNode{
		To:     toStr,
		Amount: amount,
		Token:  token,
	}, nil
}

func (p *Parser) parseReturn() (*ReturnNode, error) {
	var value Expression
	if !p.check(";") {
		var err error
		value, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
	}

	if !p.consume(";") {
		return nil, fmt.Errorf("expected ';' after return")
	}

	return &ReturnNode{Value: value}, nil
}

func (p *Parser) parseExpression() (Expression, error) {
	return p.parseOr()
}

func (p *Parser) parseOr() (Expression, error) {
	expr, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	for p.match("||") {
		op := p.previous().Value
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:     expr,
			Operator: op,
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

	for p.match("&&") {
		op := p.previous().Value
		right, err := p.parseEquality()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:     expr,
			Operator: op,
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

	for p.match("==", "!=") {
		op := p.previous().Value
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:     expr,
			Operator: op,
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

	for p.match(">", ">=", "<", "<=") {
		op := p.previous().Value
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:     expr,
			Operator: op,
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

	for p.match("+", "-") {
		op := p.previous().Value
		right, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:     expr,
			Operator: op,
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

	for p.match("*", "/", "%") {
		op := p.previous().Value
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		expr = &BinaryExpr{
			Left:     expr,
			Operator: op,
			Right:    right,
		}
	}

	return expr, nil
}

func (p *Parser) parseUnary() (Expression, error) {
	if p.match("!", "-") {
		op := p.previous().Value
		expr, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &UnaryExpr{
			Operator: op,
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

	for {
		if p.match("(") {
			expr, err = p.finishCall(expr)
			if err != nil {
				return nil, err
			}
		} else {
			break
		}
	}

	return expr, nil
}

func (p *Parser) finishCall(callee Expression) (Expression, error) {
	args := make([]Expression, 0)

	if !p.check(")") {
		for {
			arg, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			args = append(args, arg)

			if !p.match(",") {
				break
			}
		}
	}

	if !p.consume(")") {
		return nil, fmt.Errorf("expected ')' after arguments")
	}

	// Extract function name from callee
	var funcName string
	if varExpr, ok := callee.(*VariableExpr); ok {
		funcName = varExpr.Name
	} else {
		return nil, fmt.Errorf("invalid function call")
	}

	return &CallExpr{
		Function: funcName,
		Args:     args,
	}, nil
}

func (p *Parser) parsePrimary() (Expression, error) {
	if p.match("true") {
		return &LiteralExpr{Value: true}, nil
	}

	if p.match("false") {
		return &LiteralExpr{Value: false}, nil
	}

	if p.current().Type == TokenNumber {
		val, err := strconv.ParseInt(p.current().Value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number: %s", p.current().Value)
		}
		p.advance()
		return &LiteralExpr{Value: val}, nil
	}

	if p.current().Type == TokenString {
		val := p.current().Value
		p.advance()
		return &LiteralExpr{Value: val}, nil
	}

	if p.current().Type == TokenIdent {
		name := p.current().Value
		p.advance()
		return &VariableExpr{Name: name}, nil
	}

	if p.match("(") {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.consume(")") {
			return nil, fmt.Errorf("expected ')' after expression")
		}
		return expr, nil
	}

	return nil, fmt.Errorf("unexpected token: %s", p.current().Value)
}

// Helper methods
func (p *Parser) match(values ...string) bool {
	for _, value := range values {
		if p.check(value) {
			p.advance()
			return true
		}
	}
	return false
}

func (p *Parser) check(value string) bool {
	if p.isAtEnd() {
		return false
	}
	return p.current().Value == value
}

func (p *Parser) advance() Token {
	if !p.isAtEnd() {
		p.pos++
	}
	return p.previous()
}

func (p *Parser) isAtEnd() bool {
	return p.pos >= len(p.tokens) || p.current().Type == TokenEOF
}

func (p *Parser) current() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) previous() Token {
	return p.tokens[p.pos-1]
}

func (p *Parser) consume(value string) bool {
	if p.check(value) {
		p.advance()
		return true
	}
	return false
}