package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1, syscall.SIGINT)
	<-sigs
	path, err := which(os.Args[0])
	if err != nil {
		log.Fatal(err)
	}
	if err := syscall.Exec(path+".orig", os.Args, os.Environ()); err != nil {
		log.Fatal(err)
	}
}

func which(cmd string) (string, error) {
	if strings.Contains(cmd, "/") {
		return cmd, nil
	}
	pathEnv := os.Getenv("PATH")
	paths := strings.Split(pathEnv, string(os.PathListSeparator))

	for _, path := range paths {
		executablePath := filepath.Join(path, cmd)
		_, err := os.Stat(executablePath)
		if err == nil {
			return executablePath, nil
		}
	}

	return "", fmt.Errorf("command not found: %s", cmd)
}
