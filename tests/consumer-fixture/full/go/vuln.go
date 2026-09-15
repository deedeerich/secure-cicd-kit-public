package main

import (
    "crypto/md5"
    "fmt"
    "os/exec"
)

func weak(s string) string {
    h := md5.Sum([]byte(s)) // gosec G401: weak crypto
    return fmt.Sprintf("%x", h)
}

func run(userInput string) ([]byte, error) {
    return exec.Command("sh", "-c", "ls "+userInput).Output() // gosec G204
}

func main() { fmt.Println(weak("x")); _, _ = run("y") }
