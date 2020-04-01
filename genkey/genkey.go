package main

import (
	"encoding/base64"
	"log"

	"github.com/gorilla/securecookie"
)

func main() {
	log.Printf("%s", b(securecookie.GenerateRandomKey(64))) // hash key -- HMAC
	log.Printf("%s", b(securecookie.GenerateRandomKey(32))) // block key -- AES-256
}

func b(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}
