package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func newKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
