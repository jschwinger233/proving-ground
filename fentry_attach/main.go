package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native bpf ./bpf.c -- -I./headers -Wall

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	spec, err := loadBpf()
	if err != nil {
		log.Fatal(err)
	}

	progID, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		log.Fatal(err)
	}
	spec.Programs["trace_on_entry"].AttachTarget = targetProg
	targetInfo, err := targetProg.Info()
	if err != nil {
		log.Fatal(err)
	}
	btfID, ok := targetInfo.BTFID()
	if !ok {
		log.Fatal("no btf id")
	}
	handle, err := btf.NewHandleFromID(btfID)
	if err != nil {
		log.Fatal(err)
	}
	btfSpec, err := handle.Spec(nil)
	if err != nil {
		log.Fatal(err)
	}
	ty, err := btfSpec.TypeByID(btf.TypeID(targetInfo.FuncInfo.TypeID))
	if err != nil {
		log.Fatal(err)
	}
	funcType, ok := ty.(*btf.Func)
	if !ok {
		log.Fatal("not a func")
	}
	spec.Programs["trace_on_entry"].AttachTo = funcType.Name
	println(targetInfo.Name, funcType.Name)

	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		fmt.Printf("%+v\n", err)
		return
	}
	defer objs.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TraceOnEntry,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	<-stopper
}
