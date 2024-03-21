package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/jschwinger233/go-spy/proc"
)

func main() {
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	p := proc.Get(pid)
	snapshot, err := p.Snapshot()
	if err != nil {
		log.Fatal(err)
	}
	addr, err := strconv.ParseUint(os.Args[2], 16, 64)
	if err != nil {
		log.Fatal(err)
	}
	size, err := strconv.ParseUint(os.Args[3], 16, 64)
	if err != nil {
		log.Fatal(err)
	}
	data := snapshot.X(addr, size)
	fmt.Printf("%x\n", data)
}
