package lockscript

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"
)

// BuiltinFunction represents a built-in function
type BuiltinFunction struct {
    Name     string
    MinArgs  int
    MaxArgs  int
    Handler  func(args []interface{}) (interface{}, error)
}

// RegisterBuiltinFunctions registers all built-in functions
func (e *Engine) RegisterBuiltinFunctions() {
    builtins := []BuiltinFunction{
        {
            Name:    "now",
            MinArgs: 0,
            MaxArgs: 0,
            Handler: funcNow,
        },
        {
            Name:    "after",
            MinArgs: 1,
            MaxArgs: 1,
            Handler: funcAfter,
        },
        {
            Name:    "before",
            MinArgs: 1,
            MaxArgs: 1,
            Handler: funcBefore,
        },
        {
            Name:    "sha256",
            MinArgs: 1,
            MaxArgs: 1,
            Handler: funcSHA256,
        },
        {
            Name:    "verify_sig",
            MinArgs: 3,
            MaxArgs: 3,
            Handler: funcVerifySig,
        },
        {
            Name:    "require_sigs",
            MinArgs: 2,
            MaxArgs: 2,
            Handler: funcRequireSigs,
        },
        {
            Name:    "check_geo",
            MinArgs: 1,
            MaxArgs: 1,
            Handler: funcCheckGeo,
        },
        {
            Name:    "min",
            MinArgs: 2,
            MaxArgs: -1,
            Handler: funcMin,
        },
        {
            Name:    "max",
            MinArgs: 2,
            MaxArgs: -1,
            Handler: funcMax,
        },
    }
    
    for _, fn := range builtins {
        e.RegisterFunction(fn.Name, &builtinFunctionWrapper{fn})
    }
}

type builtinFunctionWrapper struct {
    fn BuiltinFunction
}

func (w *builtinFunctionWrapper) Call(args []interface{}) (interface{}, error) {
    // Check argument count
    if w.fn.MinArgs >= 0 && len(args) < w.fn.MinArgs {
        return nil, fmt.Errorf("%s: expected at least %d arguments, got %d", 
            w.fn.Name, w.fn.MinArgs, len(args))
    }
    if w.fn.MaxArgs >= 0 && len(args) > w.fn.MaxArgs {
        return nil, fmt.Errorf("%s: expected at most %d arguments, got %d", 
            w.fn.Name, w.fn.MaxArgs, len(args))
    }
    
    return w.fn.Handler(args)
}

// RegisterFunction registers a custom function
func (e *Engine) RegisterFunction(name string, fn Function) {
    if e.functions == nil {
        e.functions = make(map[string]Function)
    }
    e.functions[name] = fn
}

// Built-in function implementations

func funcNow(args []interface{}) (interface{}, error) {
    return time.Now().Unix(), nil
}

func funcAfter(args []interface{}) (interface{}, error) {
    timestamp, ok := args[0].(int64)
    if !ok {
        return nil, fmt.Errorf("after: expected timestamp as int64")
    }
    
    return time.Now().Unix() > timestamp, nil
}

func funcBefore(args []interface{}) (interface{}, error) {
    timestamp, ok := args[0].(int64)
    if !ok {
        return nil, fmt.Errorf("before: expected timestamp as int64")
    }
    
    return time.Now().Unix() < timestamp, nil
}

func funcSHA256(args []interface{}) (interface{}, error) {
    data, ok := args[0].(string)
    if !ok {
        return nil, fmt.Errorf("sha256: expected string argument")
    }
    
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:]), nil
}

func funcVerifySig(args []interface{}) (interface{}, error) {
    pubKeyHex, ok1 := args[0].(string)
    message, ok2 := args[1].(string)
    signatureHex, ok3 := args[2].(string)

    if !ok1 || !ok2 || !ok3 {
        return nil, fmt.Errorf("verify_sig: invalid arguments")
    }

    // Ed25519 signature verification
    verified, err := VerifyEd25519Signature(pubKeyHex, message, signatureHex)
    if err != nil {
        // Return false for invalid format rather than error
        // This allows scripts to handle verification failures gracefully
        return false, nil
    }
    return verified, nil
}

func funcRequireSigs(args []interface{}) (interface{}, error) {
    signatures, ok1 := args[0].([]interface{})
    threshold, ok2 := args[1].(int64)
    
    if !ok1 || !ok2 {
        return nil, fmt.Errorf("require_sigs: invalid arguments")
    }
    
    validSigs := 0
    for _, sig := range signatures {
        if s, ok := sig.(string); ok && len(s) > 0 {
            validSigs++
        }
    }
    
    return int64(validSigs) >= threshold, nil
}

func funcCheckGeo(args []interface{}) (interface{}, error) {
    location, ok := args[0].(string)
    if !ok {
        return nil, fmt.Errorf("check_geo: expected location string")
    }
    
    // Simplified geographic check
    // In production, this would check actual node locations
    validLocations := map[string]bool{
        "us-east": true,
        "eu-west": true,
        "asia-pacific": true,
    }
    
    return validLocations[location], nil
}

func funcMin(args []interface{}) (interface{}, error) {
    if len(args) == 0 {
        return nil, fmt.Errorf("min: no arguments provided")
    }
    
    min := toInt64(args[0])
    for i := 1; i < len(args); i++ {
        val := toInt64(args[i])
        if val < min {
            min = val
        }
    }
    
    return min, nil
}

func funcMax(args []interface{}) (interface{}, error) {
    if len(args) == 0 {
        return nil, fmt.Errorf("max: no arguments provided")
    }
    
    max := toInt64(args[0])
    for i := 1; i < len(args); i++ {
        val := toInt64(args[i])
        if val > max {
            max = val
        }
    }
    
    return max, nil
}

// LoadScript loads a compiled script into the engine
func (e *Engine) LoadScript(script *CompiledScript) error {
    // Validate script
    if len(script.Bytecode) > e.maxScriptSize {
        return ErrScriptTooLarge
    }
    
    // Store in cache
    e.cache.Put(script.Source, script)
    
    return nil
}

// toInt64 is defined in ast.go to avoid redeclaration