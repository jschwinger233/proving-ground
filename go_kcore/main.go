package main

import (
	"debug/elf"
	"fmt"
	"os"

	"golang.org/x/arch/x86/x86asm"
)

func main() {
	bin, err := os.Open("/proc/kcore")
	if err != nil {
		fmt.Println(err)
	}
	defer bin.Close()
	elfFile, err := elf.NewFile(bin)
	if err != nil {
		fmt.Println(err)
	}
	targetAddr := uint64(0xffffffffb9711400)
	for _, prog := range elfFile.Progs {
		if prog.Vaddr <= targetAddr && prog.Vaddr+prog.Memsz >= targetAddr {
			bytes := make([]byte, 600)
			if _, err = bin.ReadAt(bytes, int64(prog.Off+targetAddr-prog.Vaddr)); err != nil {
				fmt.Println(err)
			}
			if len(bytes) == 0 {
				continue
			}
			for {
				inst, err := x86asm.Decode(bytes, 64)
				if err != nil {
					inst = x86asm.Inst{Len: 1}
				}
				for _, prefix := range inst.Prefix {
					if prefix == 0 {
						break
					}
					fmt.Printf("%s|", prefix.String())
				}
				fmt.Printf(".%s.", inst.Op.String())
				for _, arg := range inst.Args {
					if arg == nil {
						break
					}
					fmt.Printf("%s ", arg.String())
				}
				fmt.Printf("\n")
				for i := 0; i < inst.Len; i++ {
					fmt.Printf("%02x ", bytes[i])
				}
				fmt.Printf("\n")
				//insts = append(insts, inst)
				bytes = bytes[inst.Len:]
				if len(bytes) == 0 {
					break
				}
			}
		}
	}
}
