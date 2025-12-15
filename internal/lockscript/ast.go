package lockscript

import (
	"errors"
	"fmt"
)

// Suppress unused import warnings
var _ = errors.New
var _ = fmt.Errorf

// AST node types
type ExpressionStatement struct {
	Expression Expression
}

func (n *ExpressionStatement) Type() string {
	return "EXPRESSION_STATEMENT"
}

type ReturnNode struct {
	Value Expression
}

func (n *ReturnNode) Type() string {
	return "RETURN"
}

// Expression types
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
	return nil, ErrUndefinedVariable
}

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
		rightVal := toInt64(right)
		if rightVal == 0 {
			return nil, errors.New("division by zero")
		}
		return toInt64(left) / rightVal, nil
	case "%":
		rightVal := toInt64(right)
		if rightVal == 0 {
			return nil, errors.New("modulo by zero")
		}
		return toInt64(left) % rightVal, nil
	case "==":
		return isEqual(left, right), nil
	case "!=":
		return !isEqual(left, right), nil
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
	if fn, ok := env.Functions[e.Function]; ok {
		return fn.Call(args)
	}

	return nil, fmt.Errorf("undefined function: %s", e.Function)
}

// Helper functions
func toInt64(v interface{}) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case int:
		return int64(val)
	case float64:
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

func isEqual(a, b interface{}) bool {
	switch av := a.(type) {
	case int64:
		if bv, ok := b.(int64); ok {
			return av == bv
		}
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	case bool:
		if bv, ok := b.(bool); ok {
			return av == bv
		}
	}
	return false
}