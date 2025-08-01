package vault

import "errors"

var (
    ErrVaultNotFound      = errors.New("vault not found")
    ErrKeyNotFound        = errors.New("key not found")
    ErrAccessDenied       = errors.New("access denied")
    ErrUnsupportedKeyType = errors.New("unsupported key type")
    ErrKeyExpired         = errors.New("key has expired")
)