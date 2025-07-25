package lockscript

import (
	"fmt"
	"strings"
	"unicode"
)

type Lexer struct {
	input   string
	pos     int
	readPos int
	ch      byte
}

func NewLexer() *Lexer {
	return &Lexer{}
}

func (l *Lexer) Tokenize(input string) ([]Token, error) {
	l.input = input
	l.pos = 0
	l.readPos = 0
	l.ch = 0
	
	l.readChar()
	
	var tokens []Token
	
	for l.ch != 0 {
		l.skipWhitespace()
		
		if l.ch == 0 {
			break
		}
		
		token, err := l.nextToken()
		if err != nil {
			return nil, err
		}
		
		tokens = append(tokens, token)
	}
	
	tokens = append(tokens, Token{Type: TokenEOF})
	return tokens, nil
}

func (l *Lexer) nextToken() (Token, error) {
	var token Token
	
	switch l.ch {
	case '=':
		if l.peekChar() == '=' {
			l.readChar()
			token = Token{Type: TokenOperator, Value: "=="}
		} else {
			token = Token{Type: TokenOperator, Value: "="}
		}
	case '!':
		if l.peekChar() == '=' {
			l.readChar()
			token = Token{Type: TokenOperator, Value: "!="}
		} else {
			token = Token{Type: TokenOperator, Value: "!"}
		}
	case '<':
		if l.peekChar() == '=' {
			l.readChar()
			token = Token{Type: TokenOperator, Value: "<="}
		} else {
			token = Token{Type: TokenOperator, Value: "<"}
		}
	case '>':
		if l.peekChar() == '=' {
			l.readChar()
			token = Token{Type: TokenOperator, Value: ">="}
		} else {
			token = Token{Type: TokenOperator, Value: ">"}
		}
	case '&':
		if l.peekChar() == '&' {
			l.readChar()
			token = Token{Type: TokenOperator, Value: "&&"}
		} else {
			return Token{}, fmt.Errorf("unexpected character: %c", l.ch)
		}
	case '|':
		if l.peekChar() == '|' {
			l.readChar()
			token = Token{Type: TokenOperator, Value: "||"}
		} else {
			return Token{}, fmt.Errorf("unexpected character: %c", l.ch)
		}
	case '+', '-', '*', '/', '%', '(', ')', '{', '}', ',', ';':
		token = Token{Type: TokenOperator, Value: string(l.ch)}
	case '"':
		str, err := l.readString()
		if err != nil {
			return Token{}, err
		}
		token = Token{Type: TokenString, Value: str}
	case '/':
		if l.peekChar() == '/' {
			l.skipComment()
			return l.nextToken()
		}
		token = Token{Type: TokenOperator, Value: "/"}
	default:
		if isLetter(l.ch) {
			ident := l.readIdentifier()
			if isKeyword(ident) {
				token = Token{Type: TokenKeyword, Value: ident}
			} else {
				token = Token{Type: TokenIdent, Value: ident}
			}
			return token, nil
		} else if isDigit(l.ch) {
			num := l.readNumber()
			token = Token{Type: TokenNumber, Value: num}
			return token, nil
		} else {
			return Token{}, fmt.Errorf("unexpected character: %c", l.ch)
		}
	}
	
	l.readChar()
	return token, nil
}

func (l *Lexer) readChar() {
	if l.readPos >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.readPos]
	}
	l.pos = l.readPos
	l.readPos++
}

func (l *Lexer) peekChar() byte {
	if l.readPos >= len(l.input) {
		return 0
	}
	return l.input[l.readPos]
}

func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\n' || l.ch == '\r' {
		l.readChar()
	}
}

func (l *Lexer) skipComment() {
	for l.ch != '\n' && l.ch != 0 {
		l.readChar()
	}
}

func (l *Lexer) readString() (string, error) {
	var str strings.Builder
	
	l.readChar() // skip opening quote
	
	for l.ch != '"' && l.ch != 0 {
		if l.ch == '\\' {
			l.readChar()
			switch l.ch {
			case 'n':
				str.WriteByte('\n')
			case 't':
				str.WriteByte('\t')
			case 'r':
				str.WriteByte('\r')
			case '\\':
				str.WriteByte('\\')
			case '"':
				str.WriteByte('"')
			default:
				return "", fmt.Errorf("invalid escape sequence: \\%c", l.ch)
			}
		} else {
			str.WriteByte(l.ch)
		}
		l.readChar()
	}
	
	if l.ch != '"' {
		return "", fmt.Errorf("unterminated string")
	}
	
	return str.String(), nil
}

func (l *Lexer) readIdentifier() string {
	position := l.pos
	for isLetter(l.ch) || isDigit(l.ch) || l.ch == '_' {
		l.readChar()
	}
	return l.input[position:l.pos]
}

func (l *Lexer) readNumber() string {
	position := l.pos
	for isDigit(l.ch) {
		l.readChar()
	}
	return l.input[position:l.pos]
}

func isLetter(ch byte) bool {
	return unicode.IsLetter(rune(ch))
}

func isDigit(ch byte) bool {
	return unicode.IsDigit(rune(ch))
}

func isKeyword(ident string) bool {
	keywords := map[string]bool{
		"if":       true,
		"else":     true,
		"require":  true,
		"transfer": true,
		"return":   true,
		"true":     true,
		"false":    true,
	}
	return keywords[ident]
}