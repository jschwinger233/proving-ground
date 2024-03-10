package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native bpf ./bpf.c -- -I./headers -I. -Wall

func main() {
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("Failed to load BPF: %v\n", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}

	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Program: objs.TcpSockops, // todo@gray: rename
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup: %w", err)
	}
	defer cg.Close()

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.FastSock.FD(),
		Program: objs.SkMsgFastRedirect,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		log.Fatalf("failed to attach sk_skb stream verdict: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	<-ctx.Done()
}
