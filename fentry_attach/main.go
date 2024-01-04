package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native bpf ./bpf.c -- -I./headers -Wall

// ./fentry_attach <prog_id1> <func_name1> <prog_id2> <func_name2>
func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatal(err)
	}

	progID1, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	funcname1 := os.Args[2]
	progID2, err := strconv.Atoi(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	funcname2 := os.Args[4]

	attach := func(progID int, funcname string) (err error, closers []func() error) {
		targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
		if err != nil {
			return
		}
		spec.Programs["trace_on_entry"].AttachTarget = targetProg
		spec.Programs["trace_on_entry"].AttachTo = funcname

		objs := bpfObjects{}
		if err = spec.LoadAndAssign(&objs, nil); err != nil {
			return
		}
		closers = append(closers, objs.Close)

		link, err := link.AttachTracing(link.TracingOptions{
			Program: objs.bpfPrograms.TraceOnEntry,
		})
		if err != nil {
			return
		}
		closers = append(closers, link.Close)
		return
	}

	err, closers1 := attach(progID1, funcname1)
	if err != nil {
		log.Fatal(err)
	}
	err, closers2 := attach(progID2, funcname2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Attached, press Ctrl+C to stop")
	<-stopper
	for _, closer := range append(closers1, closers2...) {
		closer()
	}
}
