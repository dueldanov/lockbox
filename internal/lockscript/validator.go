package lockscript

import (
	"fmt"
	"strings"
)

type Validator struct {
	errors []string
}

func NewValidator() *Validator {
	return &Validator{
		errors: make([]string, 0),
	}
}

func (v *Validator) Validate(ast *AST) error {
	v.errors = v.errors[:0]
	
	for _, node := range ast.Nodes {
		v.validateNode(node)
	}
	
	if len(v.errors) > 0 {
		return fmt.Errorf("validation errors: %s", strings.Join(v.errors, "; "))
	}
	
	return nil
}

func (v *Validator) validateNode(node ASTNode) {
	switch n := node.(type) {
	case *IfNode:
		v.validateExpression(n.Condition)
		for _, thenNode := range n.Then {
			v.validateNode(thenNode)
		}
		for _, elseNode := range n.Else {
			v.validateNode(elseNode)
		}
		
	case *RequireNode:
		v.validateExpression(n.Condition)
		
	case *TransferNode:
		if n.To == "" {
			v.addError("transfer requires recipient address")
		}
		v.validateExpression(n.Amount)
		
	case *CallNode:
		v.validateFunction(n.Function)
		for _, arg := range n.Args {
			v.validateExpression(arg)
		}
	}
}

func (v *Validator) validateExpression(expr Expression) {
	switch e := expr.(type) {
	case *BinaryExpr:
		v.validateExpression(e.Left)
		v.validateExpression(e.Right)
		
	case *UnaryExpr:
		v.validateExpression(e.Expr)
		
	case *CallExpr:
		v.validateFunction(e.Function)
		for _, arg := range e.Args {
			v.validateExpression(arg)
		}
		
	case *VariableExpr:
		// Variable validation would check if variable is defined
		// For now, we allow all variables
		
	case *LiteralExpr:
		// Literals are always valid
	}
}

func (v *Validator) validateFunction(name string) {
	validFunctions := map[string]bool{
		"now":          true,
		"after":        true,
		"before":       true,
		"sha256":       true,
		"verify_sig":   true,
		"require_sigs": true,
		"check_geo":    true,
		"min":          true,
		"max":          true,
	}
	
	if !validFunctions[name] {
		v.addError(fmt.Sprintf("unknown function: %s", name))
	}
}

func (v *Validator) addError(err string) {
	v.errors = append(v.errors, err)
}