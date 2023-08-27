#!/usr/bin/env python
import os
import sys
import bisect
import syscall
import subprocess

from elftools.elf.elffile import ELFFile

pid = int(sys.argv[1])
elf_for_sym = f"/proc/{pid}/exe"
if len(sys.argv) > 2:
    elf_for_sym = sys.argv[2]

proc = subprocess.run(
    f"cat /proc/{pid}/maps | awk '$2 ~ /r/ {{print $1}}'",
    shell=True,
    check=True,
    capture_output=True,
)
vecs = []
for line in proc.stdout.decode().splitlines():
    start, end = line.split("-")
    if start.startswith("7f"):
        continue
    start, end = int(start, 16), int(end, 16)
    vecs.append((start, end - start))
pieces = syscall.process_vm_readv(pid, vecs)
memory = {}
for idx, piece in enumerate(pieces):
    memory[tuple(vecs[idx])] = piece

elf_running = os.readlink(f"/proc/{pid}/exe")
proc = subprocess.run(
    f'''cat /proc/{pid}/maps | awk '$NF ~ v {{print $1; exit;}}' v="{elf_running}"''',
    shell=True,
    check=True,
    capture_output=True,
)
vecs = []
for line in proc.stdout.decode().splitlines():
    start, _ = line.split("-")
    real_init_addr = int(start, 16)


def x(address: int, size: int = 8) -> int:
    for (start, length), piece in memory.items():
        if start <= address < start + length:
            buf = piece[address - start: address - start + size]
            res = int.from_bytes(buf, byteorder="little")
            # print(f'{address=} {size=} {res=}')
            return res
    raise ValueError("address not found: 0x%x" % address)


sym = []
with open(elf_for_sym, "rb") as f:
    elf = ELFFile(f)
    text_header = elf.get_section_by_name(".text").header
    init_addr = text_header["sh_addr"] - text_header["sh_offset"]
    symtab = elf.get_section_by_name(".symtab")
    for s in symtab.iter_symbols():
        sym.append((s.entry.st_value - init_addr, s.name))
        if s.name == "runtime.allgs":
            off_allgs = s.entry.st_value - init_addr

with open(f"/proc/{pid}/root/{elf_running}", "rb") as f1, open(
    elf_for_sym, "rb"
) as f2:
    off_allgs += (
        ELFFile(f1).get_section_by_name(".bss").header.sh_addr
        - ELFFile(f2).get_section_by_name(".bss").header.sh_addr
    )

print(f"{off_allgs=:x} {real_init_addr=:x}")
goroutine_count = x(off_allgs + real_init_addr + 8)
print(f"goroutines in total: {goroutine_count}")

status_map = {
    1: "runnable",
    2: "running",
    3: "syscall",
    4: "waiting",
    5: "moribund_unused",
    6: "dead",
    7: "enqueue_unused",
    8: "copystack",
    9: "preempty",
}

sym.sort(key=lambda x: x[0])


def addr2sym(addr: int) -> str:
    idx = bisect.bisect_left(sym, addr - real_init_addr, key=lambda x: x[0])
    return sym[idx - 1][1]


addr_array_g = x(off_allgs + real_init_addr)
for idx in range(goroutine_count):
    addr_g = x(addr_array_g + idx * 8)
    status = x(addr_g + 144, 4)
    print(f"\n--- goroutine {idx}: {status_map[status]}")
    pc = x(addr_g + 56 + 8)
    print(f"0x{pc:x} {addr2sym(pc)}")
    bp = x(addr_g + 56 + 48)
    while True:
        try:
            pc = x(bp + 8)
        except ValueError:
            break
        print(f"0x{pc:x} {addr2sym(pc)}")
        caller_bp = x(bp)
        if caller_bp == 0 or caller_bp == bp:
            break
        bp = caller_bp
