package utils

import "log"

func Info(msg string) {
	log.Printf("[*] %s", msg)
}

func Success(msg string) {
	log.Printf("[+] %s", msg)
}

func Error(msg string) {
	log.Printf("[-] %s", msg)
}
