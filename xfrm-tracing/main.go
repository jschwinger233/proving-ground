package main

import (
	"errors"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native Bpf ./bpf.c -- -I./headers -I. -Wall
func main() {
	objs := &BpfObjects{}
	if err := LoadBpfObjects(objs, nil); err != nil {
		ve := &ebpf.VerifierError{}
		if errors.As(err, &ve) {
			log.Printf("%+v", ve)
		}
		log.Fatal(err)
	}
	kp, err := link.Kprobe("kfree_skbmem", objs.OnKfreeSkbmem, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer kp.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill)
	<-sigs
}
