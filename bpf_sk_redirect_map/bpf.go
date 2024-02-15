package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native bpf ./bpf.c -- -I./headers -I. -Wall
