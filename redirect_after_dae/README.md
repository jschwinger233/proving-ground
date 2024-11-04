clang -O2 -target bpf -D REDIRECT_IFINDEX=1 -Wall -I./headers -c ./bpf.c -o bpf.o
tc filter add dev enx58ef687e15eb ingress bpf da obj ./bpf.o sec tc/redirect
