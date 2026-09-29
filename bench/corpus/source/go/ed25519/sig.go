package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

func keys() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, _ = pub, priv
}
