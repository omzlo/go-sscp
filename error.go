package sscp

import (
	"fmt"
)

type CryptoError struct {
	reason string
}

func NewCryptoError(reason string) *CryptoError {
	return &CryptoError{reason}
}

func (cerr CryptoError) Error() string {
	return "Cryptographic error"
}

func (cerr CryptoError) Reason() string {
	return cerr.reason
}

func UnsafeCryptoError(err error) error {
	if cerr, ok := err.(*CryptoError); ok {
		return fmt.Errorf("%s: %s", cerr.Error(), cerr.Reason())
	}
	return err
}
