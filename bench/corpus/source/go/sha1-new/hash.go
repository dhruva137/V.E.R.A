package main

import "crypto/sha1"

func hasher() {
	h := sha1.New()
	_ = h
}
