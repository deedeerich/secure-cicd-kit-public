package main

import (
    "crypto/md5"
    "fmt"
)

// gosec G401 in a SECOND go module
func weak(s string) string { h := md5.Sum([]byte(s)); return fmt.Sprintf("%x", h) }

func main() { fmt.Println(weak("x")) }
