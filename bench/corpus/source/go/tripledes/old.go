package main

import "crypto/des"

func legacy(key []byte) {
	c, _ := des.NewTripleDESCipher(key)
	_ = c
}
