module github.com/jschwinger233/proving-ground/fentry_attach

go 1.20

require github.com/cilium/ebpf v0.11.0

require (
	golang.org/x/exp v0.0.0-20230713183714-613f0c0eb8a1 // indirect
	golang.org/x/sys v0.10.0 // indirect
)

replace github.com/cilium/ebpf => ../../../cilium/ebpf
