# 365 digital forensics project 2 - hexdump 

import sys 
from io import BufferedReader

def read_file(file: BufferedReader):
    data  = file.read().hex()
    create_hexdump(data)

def create_hexdump(data: str):
    for num in range (0, len(data), 32):     #32 bits - 16 bytes 
        l = [data[num:num+16], data[num+16:num+32]]
        s = [(" ".join(l[0][i:i+2] for i in range(0, len(l[0]), 2))).strip(), " ".join(l[1][i:i+2] for i in range(0, len(l[1]), 2)).strip()]
        final_str = (f"{format(num//2, '#010x')[2:]}  {s[0]}  {s[1]}").ljust(58)

        print(f"{final_str}  |{printable_ascii(data[num:num+32])}|")
    print(format(len(data)//2, "#010x")[2:]) if len(data) != 0 else None  

def printable_ascii(data: str) ->str:
    temp_str = ""
    for num in range(0, len(data), 2):  #2 nibbles are inseperable as taught by professor Brian in class
        hex  = data[num:num+2]
        if int(hex, 16) in range(0x20, 0x7F):
            temp_str += bytes.fromhex(hex).decode("utf-8")
        else:
            temp_str += "."   # print a period if not printable 
    return temp_str


if __name__ == "__main__":
    if len(sys.argv) == 2:
        with open(sys.argv[1], 'rb') as f:
            read_file(f)
