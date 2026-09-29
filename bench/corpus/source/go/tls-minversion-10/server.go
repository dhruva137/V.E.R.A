package main

import "crypto/tls"

var cfg = &tls.Config{
	MinVersion: tls.VersionTLS10,
}
