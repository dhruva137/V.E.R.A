package main

import "crypto/aes"

func block(key []byte) {
	c, _ := aes.NewCipher(key)
	_ = c
}
