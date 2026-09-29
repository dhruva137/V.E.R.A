package main

import "crypto/md5"

func digest(data []byte) [16]byte {
	return md5.Sum(data)
}
